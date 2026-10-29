"""Runtime configuration: which host exists and how to reach its services.

Separated from the manifest on purpose. The manifest says what to check and
what it means; this says where to check it. Credarr is co-located with one
Docker environment, so a host is a deployment fact rather than a remote login:
URLs point at local service endpoints. Container names are optional discovery
metadata; no restart is performed through Docker.

There is no service config path here. credarr reads and writes only through
service APIs; a local bind of an application's config directory is not part of
the product.

No secret may be stored in this file. It is committed.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ConfigError, ManifestError
from .model import _StrictLoader
from .names import CONTAINER_NAME

CONFIG_VERSION = 1

_TOP_LEVEL_KEYS = frozenset(
    {"version", "default_host", "hosts", "manifest", "fingerprint", "vault_password_file"}
)
_HOST_KEYS = frozenset({"urls", "containers"})
_FINGERPRINT_KEYS = frozenset({"pinned_salt"})


@dataclass(frozen=True, slots=True)
class HostConfig:
    name: str
    # Base URLs for services driven over HTTP, keyed by service name.
    urls: Mapping[str, str] = field(default_factory=dict)
    # Container name per service, used only by read-only discovery and image
    # observation. A deployment fact, so it belongs in configuration.
    containers: Mapping[str, str] = field(default_factory=dict)

    def url(self, service: str) -> str:
        try:
            return self.urls[service]
        except KeyError as exc:
            raise ConfigError(
                f"host {self.name!r} has no url configured for {service!r}",
                hint=f"add it under hosts.{self.name}.urls.{service}",
            ) from exc

    def api_url(self, service: str, version: str) -> str:
        return f"{self.url(service).rstrip('/')}/api/{version}"


@dataclass(frozen=True, slots=True)
class Config:
    version: int
    default_host: str
    hosts: Mapping[str, HostConfig]
    manifest: Path
    fingerprint_salt: str | None = None

    def host(self, name: str) -> HostConfig:
        try:
            return self.hosts[name]
        except KeyError as exc:
            raise ConfigError(
                f"unknown host {name!r}",
                hint=f"known hosts: {', '.join(sorted(self.hosts)) or 'none'}",
            ) from exc


def _reject_unknown_keys(
    mapping: Mapping, allowed: frozenset[str], where: str
) -> None:
    unknown = sorted({str(key) for key in mapping if key not in allowed})
    if unknown:
        raise ConfigError(
            f"{where}: unknown key(s) {', '.join(repr(key) for key in unknown)}; "
            "remove them - an ignored key is a setting that silently does nothing"
        )


def load_config(path: Path, *, base_dir: Path | None = None) -> Config:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc

    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - PyYAML is a hard dependency
        raise ConfigError("PyYAML is required") from exc

    try:
        # The manifest's strict loader rejects a repeated key instead of
        # silently keeping the last one, which is the same failure the config
        # must not have.
        document = yaml.load(text, Loader=_StrictLoader) or {}  # noqa: S506
    except (yaml.YAMLError, ManifestError) as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc

    if not isinstance(document, Mapping):
        raise ConfigError(f"{path}: config must be a mapping at the top level")

    version = document.get("version")
    if type(version) is not int or version != CONFIG_VERSION:
        raise ConfigError(
            f"{path}: config version {version!r} is not supported "
            f"(this build understands {CONFIG_VERSION})"
        )

    # Retired settings get their own sentence before the general allowlist, so
    # an old remote-shell or paths config is told what changed, not just "key".
    _refuse_retired_settings(document, str(path))
    _reject_unknown_keys(document, _TOP_LEVEL_KEYS, str(path))

    root = base_dir or path.parent.resolve()

    raw_hosts = document.get("hosts")
    if not isinstance(raw_hosts, Mapping) or not raw_hosts:
        raise ConfigError(f"{path}: 'hosts' must be a non-empty mapping")

    hosts: dict[str, HostConfig] = {}
    for name, spec in raw_hosts.items():
        hosts[name] = _parse_host(str(name), spec, path)

    configured_default = document.get("default_host")
    if configured_default is not None and not isinstance(configured_default, str):
        raise ConfigError(f"{path}: 'default_host' must be a string")
    default_host = configured_default or next(iter(hosts))
    if default_host not in hosts:
        raise ConfigError(f"{path}: default_host {default_host!r} is not a configured host")

    manifest_value = document.get("manifest")
    if not manifest_value or not isinstance(manifest_value, str):
        raise ConfigError(f"{path}: 'manifest' must be a non-empty path string")
    manifest = Path(manifest_value)
    if not manifest.is_absolute():
        manifest = root / manifest

    password_file = document.get("vault_password_file")
    if password_file is not None and not isinstance(password_file, str):
        raise ConfigError(f"{path}: 'vault_password_file' must be a path string")

    fingerprint = document.get("fingerprint") or {}
    if not isinstance(fingerprint, Mapping):
        raise ConfigError(f"{path}: 'fingerprint' must be a mapping")
    _reject_unknown_keys(fingerprint, _FINGERPRINT_KEYS, f"{path}: fingerprint")
    salt = fingerprint.get("pinned_salt")
    if salt is not None and not isinstance(salt, str):
        raise ConfigError(f"{path}: fingerprint.pinned_salt must be a string")

    return Config(
        version=version,
        default_host=default_host,
        hosts=hosts,
        manifest=manifest,
        fingerprint_salt=str(salt) if salt else None,
    )


def _refuse_retired_settings(settings: Mapping, where: str) -> None:
    """Refuse the retired remote-shell and restart settings, including unknown ones.

    Ignoring an old setting is how an operator keeps believing credarr will
    log in remotely or restart a container when it no longer can. The whole
    restart family is gone, so any key in it is refused by name.
    """
    for key in settings:
        if str(key).startswith("restart"):
            raise ConfigError(
                f"{where}: '{key}' is a retired restart setting; credarr now "
                "asks each service to restart itself over its own API - "
                "remove the field"
            )
        if key in ("transport", "ssh", "sudo"):
            raise ConfigError(
                f"{where}: '{key}' is gone; credarr runs beside the stack "
                "and talks to service APIs only - remove the field"
            )


def _parse_host(name: str, spec: object, origin: Path) -> HostConfig:
    where = f"{origin}: host {name!r}"
    if not isinstance(spec, Mapping):
        raise ConfigError(f"{where}: must be a mapping")

    # Refused loudly rather than ignored: a configuration that still asks for a
    # remote shell or the retired restart settings must be told they are gone,
    # not silently treated as local and then fail at the first API call.
    _refuse_retired_settings(spec, where)

    if "paths" in spec:
        raise ConfigError(
            f"{where}: 'paths' is gone; credarr is API-only and never reads "
            "a service's config directory - remove the field"
        )

    urls = spec.get("urls") or {}
    if not isinstance(urls, Mapping):
        raise ConfigError(f"{where}: 'urls' must be a mapping")
    for key, value in urls.items():
        if not isinstance(value, str) or not value.startswith(("http://", "https://")):
            raise ConfigError(f"{where}: urls.{key} must be an http(s) URL")

    # Container name per service, used by read-only discovery to observe the
    # running image. No rotation acts on it.
    containers = spec.get("containers") or {}
    if not isinstance(containers, Mapping):
        raise ConfigError(f"{where}: 'containers' must be a mapping")
    for key, value in containers.items():
        if not isinstance(value, str) or not CONTAINER_NAME.fullmatch(value):
            raise ConfigError(
                f"{where}: containers.{key} must be a Docker container name or ID"
            )

    # Both jellyfin key fields are retired: in Jellyfin any API key is a
    # global administrator, so the credential being rotated authorises the
    # mint itself and a second key would only be another standing credential.
    # Refused loudly rather than ignored, so a config that still names one is
    # told why instead of quietly having a field nobody reads.
    for retired in ("jellyfin_auth_key", "jellyfin_auth_key_env"):
        if retired in spec:
            raise ConfigError(
                f"{where}: '{retired}' is gone; the Jellyfin mint "
                "authenticates with the credential being rotated, so no "
                "second key is needed or read - remove the field"
            )

    _reject_unknown_keys(spec, _HOST_KEYS, where)

    return HostConfig(
        name=name,
        urls={str(k): str(v) for k, v in urls.items()},
        containers={str(k): str(v) for k, v in containers.items()},
    )
