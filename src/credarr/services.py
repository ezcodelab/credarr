"""What each declared service is, what can be done about it, and what runs.

The console's Services view asks three questions per service, and they have
three different sources, kept apart on purpose - answering one with another is
how a capability view starts lying:

  * what the topology needs: which credentials name the service, which holders
    they declare into it, and which mechanism mints it. All of it is read from
    the manifest and the engine's own registries (`writers.py`, the same ones
    the planner refuses from), so a view cannot promise a capability the plan
    would refuse.
  * what the deployment is missing: whether the host the engine would act on
    declares a URL and a container for the service. There is no config path to
    check: every write and read goes through a service API.
  * what is running: asked of the host the same way, read-only and best
    effort. The version the service's own API reports and the image its
    container runs; nothing is inferred from a name, and an observation that
    could not be made is a sentence rather than a guess.

The display gate stays `provenance`'s: a running version never lifts `managed`.
The measured version is what a live adapter run recorded, and the two are shown
beside each other so they can disagree in front of a human.

The report covers the default host - the one `facade.plan_rotation_for` hands
the planner, which is the host a rotation's API calls touch - and a
consumer that named another one is not evaluated separately (multi-host is
deferred; the row's host is the one the engine acts on).

A system gets a row when a consumer target names it, or when a credential's own
service is a mechanism this build can mint for. A credential that names neither
(the class-B values this build only watches) has no row here: its state is the
Credential view's, and inventing a service from its name would put a capability
on screen that no plan can deliver.
"""

from __future__ import annotations

from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from . import provenance
from .audit import build_transport
from .config import Config, HostConfig
from .docker_api import DockerApiError
from .docker_api import containers as docker_containers
from .docker_api import endpoint as docker_endpoint
from .errors import ConfigError, RotationError, TransportError
from .executor import _servarr_call
from .model import Manifest
from .redact import Secret
from .rotate import service_for
from .transport import Transport
from .writers import MINT_SOURCES, holder_for

# The Services view is answering a human, so an observation is bounded tighter
# than a rotation's own calls: a blackholed host becomes a timeout sentence in
# one row instead of holding the whole screen.
OBSERVE_TIMEOUT = 5
# Version probes are independent read-only GETs. They used to run one after
# another, so N slow hosts cost N x OBSERVE_TIMEOUT before the report answered.
# Four short-lived probes is enough to collapse the common handful of services
# without assuming a NAS has memory for one interpreter per declared service.
OBSERVE_CONCURRENCY = 4

@dataclass(frozen=True)
class VersionProbe:
    """How to ask a service for the version it is running.

    `key_from` describes where a key comes from: the runtime store's copy of
    the service's own key, or no key for a public status route.
    """

    path: str
    field: str
    key_from: str  # "stored" | "none"
    auth_header: str = "X-Api-Key"
    key_prefix: str = ""


# A probe that needed the value being rotated would be asking the question
# backwards. `stored` means the service's own API key, which the runtime store
# holds separately; it is not the credential under rotation. A service whose
# version route needs a session the engine cannot create shows "no version
# probe" rather than a guess.
VERSION_PROBES: dict[str, VersionProbe] = {
    "sonarr": VersionProbe("/system/status", "version", "stored"),
    "radarr": VersionProbe("/system/status", "version", "stored"),
    "prowlarr": VersionProbe("/system/status", "version", "stored"),
    "lidarr": VersionProbe("/system/status", "version", "stored"),
    "readarr": VersionProbe("/system/status", "version", "stored"),
    "whisparr": VersionProbe("/system/status", "version", "stored"),
    # Jellyfin's public info route answers without a credential - which is why
    # it is the readiness path too, and it is the one place the version lives.
    "jellyfin": VersionProbe("/System/Info/Public", "Version", "none"),
    # Seerr's /status is its healthcheck route and answers without a key.
    "seerr": VersionProbe("/status", "version", "none"),
    # qBittorrent 5.3 accepts its API key only as `Authorization: Bearer`.
    # The route answers with plain text (`v5.3.0`), not JSON.
    "qbittorrent": VersionProbe(
        "/app/version", "", "stored",
        auth_header="Authorization", key_prefix="Bearer ",
    ),
    # qui's version route is under `/api` but not a versioned prefix, and it
    # needs qui's own key.
    "qui": VersionProbe("/api/version", "version", "stored"),
    # Grafana's health route is public and carries the running version;
    # measured on 12.1.1.
    "grafana": VersionProbe("/api/health", "version", "none"),
    # Arcane's version route is public and carries `currentVersion`;
    # measured on 2.17.0.
    "arcane": VersionProbe("/api/version", "currentVersion", "none"),
    # Gitea's version route is public and carries `version`; measured on 1.27.2.
    "gitea": VersionProbe("/version", "version", "none"),
}


@dataclass(frozen=True)
class ConnectionTest:
    """One typed URL/key pair, tested without storing either."""

    ok: bool
    detail: str
    version: str | None = None


# Routes that prove a key rather than merely a reachable URL. The version
# probes for Jellyfin and Seerr are public, so they cannot answer the question
# the wizard is asking.
_KEY_PROBES = {
    "jellyfin": ("/Auth/Keys", "ApiKey", "query"),
    "seerr": ("/auth/me", "X-API-Key", "header"),
}


def probe_service_connection(
    system: str,
    url: str,
    key: str | None,
    transport: Transport | None = None,
) -> ConnectionTest:
    """Prove that a service answers at this URL with this key.

    Nothing is written. The key is passed to the same stdlib probe a rotation
    uses, so this tests the deployment path rather than a second HTTP client.
    """
    from urllib.parse import urlsplit

    base = url.strip().rstrip("/")
    parsed = urlsplit(base)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return ConnectionTest(False, "Use a full http:// or https:// URL with a host.")
    probe = VERSION_PROBES.get(system)
    if probe is None and system not in ("profilarr", "homepage"):
        return ConnectionTest(False, f"This build has no connection test for {system}.")
    host = HostConfig(name="connection-test", urls={system: base})
    wire = transport or build_transport()
    supplied = (key or "").strip() or None

    # The two services with public version routes get a key-specific route when
    # a key was supplied; otherwise a 200 from the public route would prove
    # only that the URL exists.
    keyed = _KEY_PROBES.get(system) if supplied else None
    if keyed is not None:
        path, header, where = keyed
        try:
            status, _ = _servarr_call(
                host, system, "GET", path,
                key=supplied, auth_header=header, auth_transport=where,
                transport=wire, timeout=OBSERVE_TIMEOUT,
            )
        except (ConfigError, RotationError, TransportError) as exc:
            return ConnectionTest(False, str(exc))
        if status in (401, 403):
            return ConnectionTest(
                False, f"The service answered HTTP {status}: the API key was rejected."
            )
        if status != 200:
            return ConnectionTest(
                False, f"The service answered HTTP {status}; check the URL and version."
            )
        version, _ = _version_of(system, host, wire)
        detail = "The API key was accepted."
        if version:
            detail = f"{detail} Version {version}."
        return ConnectionTest(True, detail, version)

    if probe is not None and probe.key_from == "stored" and supplied is None:
        return ConnectionTest(False, "Enter the service API key to test this service.")
    try:
        if probe is not None:
            version, note = _version_of(
                system,
                host,
                wire,
                {system: Secret(supplied)} if supplied is not None else None,
            )
            if version:
                return ConnectionTest(True, f"Reached the service. Version {version}.", version)
            return ConnectionTest(False, f"The service did not answer as expected: {note}.")
        # profilarr and homepage have no version route this build measures.
        status, _ = _servarr_call(
            host, system, "GET", "/",
            transport=wire, timeout=OBSERVE_TIMEOUT,
        )
    except (ConfigError, RotationError, TransportError) as exc:
        return ConnectionTest(False, str(exc))
    if status >= 500:
        return ConnectionTest(False, f"The URL answered HTTP {status}.")
    if supplied is not None:
        return ConnectionTest(
            True,
            f"The URL answered HTTP {status}. This build has no key probe for {system}.",
        )
    return ConnectionTest(True, f"The URL answered HTTP {status}.")


@dataclass(frozen=True)
class HolderFacts:
    """One declared holder of a credential's value.

    `write` is the registry's strategy name, or None when this build has no
    writer - the same fact that makes the planner refuse, so the badge and the
    refusal cannot disagree.
    """

    slot: str
    write: str | None
    managed: bool
    provenance: str | None


@dataclass(frozen=True)
class ServiceObservation:
    """What one host answered about one service, or why it could not."""

    system: str
    host: str
    container: str
    container_declared: bool
    running_version: str | None
    version_note: str
    image: str | None
    image_digests: tuple[str, ...]
    image_note: str


@dataclass(frozen=True)
class ServiceFacts:
    """One service: the topology's needs, the deployment's gaps, the run.

    `holders` carry the same facts the credential view shows per holder - a
    writer or none, and the display gate with its reason - so the two screens
    cannot word one holder two ways. `provenance` is the same line for the
    service itself, which a service with no holders (Prowlarr) still needs.
    `missing` is the deployment's side of it: a URL this host needs and does
    not declare.
    """

    system: str
    host: str
    credentials: tuple[str, ...]
    holders: tuple[HolderFacts, ...]
    mint: str | None
    url: str | None
    provenance: str | None
    measured_version: str | None
    measured_image: str | None
    observation: ServiceObservation
    missing: tuple[str, ...]


@dataclass(frozen=True)
class ServiceReport:
    """Every declared service."""

    services: tuple[ServiceFacts, ...]


def _version_of(
    system: str,
    host: HostConfig,
    transport: Transport,
    service_keys: Mapping[str, Secret] | None = None,
) -> tuple[str | None, str]:
    """The running version, or the sentence saying why there is none.

    A stored service key is the only source. There is no config-file fallback:
    strict API-only means a version that cannot be read through the API is not
    read at all.
    """
    probe = VERSION_PROBES.get(system)
    if probe is None:
        return None, "this build has no version probe for it"
    key = None
    if probe.key_from == "stored":
        stored = service_keys.get(system) if service_keys else None
        if stored is None:
            return None, "no API key in the store"
        key = stored.reveal()
    try:
        status, payload = _servarr_call(
            host, system, "GET", probe.path,
            key=f"{probe.key_prefix}{key}" if key is not None else None,
            auth_header=probe.auth_header,
            transport=transport, timeout=OBSERVE_TIMEOUT,
        )
    except (ConfigError, TransportError, RotationError) as exc:
        return None, str(exc)
    if status != 200:
        return None, f"HTTP {status}"
    if not probe.field and isinstance(payload, str):
        answer = payload.strip().removeprefix("v")
    else:
        answer = payload.get(probe.field) if isinstance(payload, dict) else None
    if not isinstance(answer, str) or not answer:
        return None, f"the answer carried no usable {probe.field!r}"
    return answer, ""


def _read_docker(docker_url: str | None) -> tuple[list[dict] | None, str | None]:
    """One read-only container list for the whole report, or its refusal."""
    if not docker_url:
        return (
            None,
            "Docker discovery is off; set CREDARR_DOCKER_URL to read the "
            "running image",
        )
    try:
        return docker_containers(docker_endpoint(docker_url)), None
    except DockerApiError as exc:
        return None, str(exc)


def _image_from_rows(
    system: str, host: HostConfig, rows: list[dict] | None, error: str | None
) -> tuple[str | None, tuple[str, ...], str]:
    """The image for one declared container in an already-read list."""
    if rows is None:
        return None, (), error or "Docker discovery is off"
    container = host.containers.get(system)
    if not container:
        return None, (), f"no container is declared for {system!r} on {host.name}"
    for row in rows:
        names = row.get("Names")
        names = [
            name.strip("/") for name in names
            if isinstance(name, str) and name.strip("/")
        ] if isinstance(names, list) else []
        if container not in names and row.get("Id") != container:
            continue
        image = row.get("ImageID") or row.get("Image")
        if isinstance(image, str) and image:
            return image, (), ""
        return None, (), "the container list carried no image identity"
    return None, (), f"no running container named {container!r}"


def _image_of(
    system: str, host: HostConfig, docker_url: str | None
) -> tuple[str | None, tuple[str, ...], str]:
    """The image the declared container runs, from the read-only Docker API.

    Only `GET /containers/json` is used. It carries names and image IDs, never
    a container's environment or labels. This is read-only discovery metadata;
    no rotation acts on a container.
    """
    rows, error = _read_docker(docker_url)
    return _image_from_rows(system, host, rows, error)


def _declared(
    manifest: Manifest, *, default_host: str | None = None
) -> dict[str, set[str]]:
    """system -> the credentials that need it, and why they are listed.

    Two ways in. A consumer target names the system as a holder - the
    topology's own statement about where a value goes. And a credential whose
    *own* service this build can mint for names it as the place its value is
    minted: that is what keeps prowlarr and jellyfin visible when every holder
    of their value lives in a different service (Prowlarr's key is held by
    Sonarr's and Radarr's indexer rows and nothing else).

    The second way is gated on the mint source rather than on
    `service_for` alone, because a name that resolves to nothing the build
    knows - `qbittorrent_password` - would otherwise invent a service row.

    `default_host` scopes the answer to the deployment's default host; an
    unset consumer host resolves to it. It must be that host, not an arbitrary
    one: the manifest cannot name the default, so a non-default query would
    misread every host-less consumer. A mint-only credential has no consumer
    host and belongs to the single-host product, so it is included.
    """
    by_system: dict[str, set[str]] = {}
    for name, credential in manifest.credentials.items():
        service = service_for(credential)
        if service in MINT_SOURCES and (
            default_host is None
            or not credential.consumers
            or any(
                (consumer.host or default_host) == default_host
                for consumer in credential.consumers
            )
        ):
            by_system.setdefault(service, set()).add(name)
        for consumer in credential.consumers:
            if (
                default_host is not None
                and (consumer.host or default_host) != default_host
            ):
                continue
            by_system.setdefault(consumer.target.system, set()).add(name)
    return by_system


def declared_services(
    manifest: Manifest, *, default_host: str | None = None
) -> list[str]:
    """The services the topology names, sorted, without touching a host.

    The same rule `_declared` applies to build the Services view, so a service
    whose value is only ever held by another service - Prowlarr - is still on
    the console's menu. `default_host` scopes the answer to the configuration's
    default host; omit it to keep the original all-host view.
    """
    return sorted(_declared(manifest, default_host=default_host))


def _holders(system: str, manifest: Manifest) -> tuple[HolderFacts, ...]:
    slots = sorted(
        {
            consumer.target.slot
            for credential in manifest.credentials.values()
            for consumer in credential.consumers
            if consumer.target.system == system
        }
    )
    facts = []
    for slot in slots:
        holder = holder_for(system, slot)
        facts.append(
            HolderFacts(
                slot=slot,
                write=holder.write if holder is not None else None,
                managed=provenance.managed(system, slot),
                provenance=provenance.provenance_text(system),
            )
        )
    return tuple(facts)


def service_report(
    manifest: Manifest,
    config: Config,
    *,
    transport: Transport | None = None,
    service_keys: Mapping[str, Secret] | None = None,
    docker_url: str | None = None,
) -> ServiceReport:
    """The Services view's whole answer, with one observation per service.

    `service_keys` is the runtime store's copy of each service's own key. It is
    the only key source for the version observation; there is no config path.

    Version probes are independent and read-only, so run them with a bounded
    pool. The per-call timeout still bounds a blackholed host; one slow service
    now costs the report its own timeout rather than blocking every row behind
    it. The endpoint is a sync route, so it still holds one worker thread.
    """
    host = config.host(config.default_host)
    transport = transport or build_transport()
    declared = _declared(manifest)
    systems = sorted(declared)
    docker_rows, docker_error = _read_docker(docker_url)

    def observe_version(system: str) -> tuple[str | None, str]:
        return _version_of(system, host, transport, service_keys)

    if systems:
        workers = min(OBSERVE_CONCURRENCY, len(systems))
        with ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="credarr-observe"
        ) as pool:
            observations = dict(
                zip(systems, pool.map(observe_version, systems), strict=True)
            )
    else:
        observations = {}

    rows: list[ServiceFacts] = []
    for system in systems:
        holders = _holders(system, manifest)
        source = MINT_SOURCES.get(system)
        url = host.urls.get(system)

        missing: list[str] = []
        if (any(holder.write for holder in holders) or source is not None) and (
            url is None
        ):
            missing.append(
                f"no url is declared for {system} on {host.name}: holders "
                "cannot be written or verified"
            )
        version, version_note = observations[system]
        image, digests, image_note = _image_from_rows(
            system, host, docker_rows, docker_error
        )
        rows.append(
            ServiceFacts(
                system=system,
                host=host.name,
                credentials=tuple(sorted(declared[system])),
                holders=holders,
                mint=source.mechanism if source is not None else None,
                url=url,
                provenance=provenance.provenance_text(system),
                measured_version=provenance.measured_version(system),
                measured_image=provenance.measured_image(system),
                observation=ServiceObservation(
                    system=system,
                    host=host.name,
                    container=host.containers.get(system, ""),
                    container_declared=system in host.containers,
                    running_version=version,
                    version_note=version_note,
                    image=image,
                    image_digests=digests,
                    image_note=image_note,
                ),
                missing=tuple(missing),
            )
        )

    return ServiceReport(services=tuple(rows))
