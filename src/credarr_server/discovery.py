"""Read-only Docker discovery: containers in, proposals out.

Discovery is off until an operator points it at a Docker API (normally a
read-only socket proxy). It only reads ``GET /containers/json``: there is no
create, stop, restart or inspect call here, and the endpoint never writes the
topology. A proposal is a sentence for a human, not a pending declaration.

The response deliberately carries only the fields a proposal needs - container
name, image identity and port - never a container's environment, labels or
mounts. Those routinely hold secrets, and a config mount is not product input:
strict API-only has no path to suggest.

Rescan diffs are limited to changes a rotation's capability depends on:
container identity, image family, and a declared URL whose host is the
container itself. A declared URL on a LAN address or a reverse proxy is allowed
to differ from the in-network name, so it is not a diff; otherwise every normal
deployment would produce noise on every scan.
"""

from __future__ import annotations

import time
import urllib.parse
from dataclasses import dataclass

from credarr.config import Config
from credarr.docker_api import (
    DockerApiError as DiscoveryError,
)
from credarr.docker_api import (
    containers as _read_containers,
)
from credarr.docker_api import (
    endpoint as _endpoint,
)
from credarr.model import Manifest
from credarr.services import declared_services

# The final component of an image repository is enough for the families this
# build knows. It is a proposal, never a managed claim: a human still confirms
# the service, and an unknown image is simply not proposed.
IMAGE_SYSTEMS: dict[str, str] = {
    "sonarr": "sonarr",
    "radarr": "radarr",
    "lidarr": "lidarr",
    "readarr": "readarr",
    "whisparr": "whisparr",
    "prowlarr": "prowlarr",
    "seerr": "seerr",
    "jellyseerr": "seerr",
    "jellyfin": "jellyfin",
    "qbittorrent": "qbittorrent",
    "qui": "qui",
    "homepage": "homepage",
}

# The port a service is normally reached on inside a Docker network. A
# container that publishes a different private port keeps that port; this is
# only a fallback for the common image shapes.
DEFAULT_PORTS: dict[str, int] = {
    "sonarr": 8989,
    "radarr": 7878,
    "lidarr": 8686,
    "readarr": 8787,
    "whisparr": 6969,
    "prowlarr": 9696,
    "seerr": 5055,
    "jellyfin": 8096,
    "qbittorrent": 8080,
    "qui": 7476,
    "homepage": 3000,
}


@dataclass(frozen=True, slots=True)
class _Container:
    system: str
    name: str
    image: str
    image_id: str
    port: int | None
    url: str | None


def _display_source(raw: str) -> str:
    """The endpoint without userinfo, for a response the browser can show."""
    try:
        parts = urllib.parse.urlsplit(raw)
        host = parts.hostname
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return "the configured Docker endpoint"
    if not host:
        return "the configured Docker endpoint"
    scheme = "http" if parts.scheme == "tcp" else (parts.scheme or "http")
    shown = f"[{host}]" if ":" in host else host
    return f"{scheme}://{shown}{port}"


def _image_system(image: object) -> str | None:
    if not isinstance(image, str) or not image:
        return None
    # Drop a digest and a tag before taking the repository's final component.
    repository = image.split("@", 1)[0]
    if ":" in repository.rsplit("/", 1)[-1]:
        repository = repository.rsplit(":", 1)[0]
    family = repository.rsplit("/", 1)[-1].lower()
    return IMAGE_SYSTEMS.get(family)


def _name(row: dict) -> str | None:
    names = row.get("Names")
    if not isinstance(names, list):
        return None
    for raw in names:
        if isinstance(raw, str) and raw.strip("/"):
            return raw.strip("/")
    return None


def _port(row: dict, system: str) -> int | None:
    ports = row.get("Ports")
    tcp: list[int] = []
    if isinstance(ports, list):
        for entry in ports:
            if not isinstance(entry, dict) or entry.get("Type") != "tcp":
                continue
            port = entry.get("PrivatePort")
            if isinstance(port, int) and not isinstance(port, bool) and port > 0:
                tcp.append(port)
    default = DEFAULT_PORTS.get(system)
    if default in tcp:
        return default
    if tcp:
        return tcp[0]
    return default


def _containers(rows: list[dict]) -> list[_Container]:
    found: list[_Container] = []
    for row in rows:
        system = _image_system(row.get("Image"))
        name = _name(row)
        if system is None or name is None:
            continue
        port = _port(row, system)
        found.append(
            _Container(
                system=system,
                name=name,
                image=row["Image"] if isinstance(row.get("Image"), str) else "",
                image_id=(
                    row["ImageID"] if isinstance(row.get("ImageID"), str) else ""
                ),
                port=port,
                url=f"http://{name}:{port}" if port else None,
            )
        )
    return found


def _proposal_text(containers: list[_Container], declared: set[str]) -> str:
    if not containers:
        return "no recognised running services were found"
    if not declared:
        return "the topology is empty; every recognised running service is a proposal"
    if all(container.system in declared for container in containers):
        return "every recognised running service is already declared"
    return ""


def discover(
    docker_url: str | None, manifest: Manifest, config: Config
) -> dict:
    """Scan Docker once and return proposals and capability diffs.

    The result is a plain JSON document: the SPA is the only caller, and the
    endpoint has no side effects. ``enabled: false`` is the default posture,
    not an error - the product must work without a Docker socket.
    """
    if not docker_url:
        return {
            "enabled": False,
            "source": None,
            "observed_at": None,
            "proposals": [],
            "diffs": [],
            "error": None,
            "note": "Docker discovery is off. Set CREDARR_DOCKER_URL to a "
            "read-only socket proxy to propose undeclared services.",
        }

    source = _display_source(docker_url)
    try:
        base = _endpoint(docker_url)
        rows = _read_containers(base)
    except DiscoveryError as exc:
        return {
            "enabled": True,
            "source": source,
            "observed_at": None,
            "proposals": [],
            "diffs": [],
            "error": str(exc),
            "note": "",
        }

    containers = sorted(
        _containers(rows), key=lambda item: (item.system, item.name)
    )
    observed_names = {container.name for container in containers}
    declared = set(declared_services(manifest))
    on_host = set(declared_services(manifest, default_host=config.default_host))
    host = config.host(config.default_host)
    expected: dict[str, str] = {
        host.containers[system]: system
        for system in on_host
        if system in host.containers
    }

    counts: dict[str, int] = {}
    for container in containers:
        counts[container.system] = counts.get(container.system, 0) + 1

    proposals = [
        {
            "system": container.system,
            "container": container.name,
            "image": container.image,
            "image_id": container.image_id,
            "url": container.url,
            "port": container.port,
            "duplicate": counts[container.system] > 1,
            "note": "not in the declared topology",
        }
        for container in containers
        if container.system not in declared
    ]

    diffs: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    def add_diff(
        system: str, kind: str, declared_value: str, observed_value: str, note: str
    ) -> None:
        key = (system, kind, observed_value)
        if key in seen:
            return
        seen.add(key)
        diffs.append(
            {
                "system": system,
                "kind": kind,
                "declared": declared_value,
                "observed": observed_value,
                "note": note,
            }
        )

    for container in containers:
        wanted = host.containers.get(container.system)
        if container.system in on_host:
            if wanted is not None and wanted not in observed_names:
                add_diff(
                    container.system,
                    "container",
                    wanted,
                    container.name,
                    f"the host config names container {wanted!r}, but Docker sees "
                    f"{container.name!r}; the image observation would target the "
                    "wrong container",
                )
            # URL belongs to the declared container when there is one. A second
            # container of the same family is not evidence that this one moved;
            # with one renamed container there is no ambiguity, so its URL is
            # still worth comparing. Without a declaration, the observation is
            # still useful but is not an identity match.
            if wanted is not None and container.name != wanted and (
                wanted in observed_names or counts[container.system] > 1
            ):
                pass
            else:
                declared_url = host.urls.get(container.system)
                if declared_url and container.port:
                    try:
                        parsed = urllib.parse.urlsplit(declared_url)
                        declared_port = parsed.port
                    except ValueError:
                        parsed = None
                        declared_port = None
                    if (
                        parsed is not None
                        and parsed.hostname == (wanted or container.name)
                        and declared_port is not None
                        and declared_port != container.port
                    ):
                        add_diff(
                            container.system,
                            "url",
                            declared_url,
                            container.url or "",
                            f"the declared url uses port {declared_port}, but "
                            f"{container.name!r} exposes {container.port}",
                        )

        if (
            container.name in expected
            and expected[container.name] != container.system
        ):
            add_diff(
                expected[container.name],
                "image_family",
                expected[container.name],
                container.system,
                f"the container {container.name!r} is declared as "
                f"{expected[container.name]!r}, but its image looks like "
                f"{container.system!r}",
            )

    return {
        "enabled": True,
        "source": source,
        "observed_at": time.time(),
        "proposals": proposals,
        "diffs": diffs,
        "error": None,
        "note": _proposal_text(containers, declared),
    }
