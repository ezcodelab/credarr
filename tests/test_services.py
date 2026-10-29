"""The Services report: what is declared, what is missing, what is running.

Hermetic: a fake transport answers the host's questions, so most assertions are
about what the report derives and how it words it. The image read uses a
read-only Docker list and a stand-in for the endpoint; no Docker socket is
needed. The version route answers like a host, without a host.
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import asdict
from pathlib import Path

import credarr.services as services_module
from credarr.config import Config, HostConfig
from credarr.docker_api import DockerApiError
from credarr.model import Manifest
from credarr.redact import Secret
from credarr.services import (
    OBSERVE_CONCURRENCY,
    OBSERVE_TIMEOUT,
    VERSION_PROBES,
    ServiceFacts,
    ServiceReport,
    _image_of,
    probe_service_connection,
    service_report,
)
from credarr.targets import build_registry


def test_connection_refuses_a_bad_url_or_unknown_service_without_a_probe():
    bad = probe_service_connection("sonarr", "sonarr:8989", None)
    assert bad.ok is False
    assert "full http:// or https:// URL" in bad.detail

    unknown = probe_service_connection("not-a-service", "http://host:1", None)
    assert unknown.ok is False
    assert "no connection test" in unknown.detail

    # A keyed service without a key cannot answer the question the test asks.
    missing_key = probe_service_connection("qbittorrent", "http://qb:8080", None)
    assert missing_key.ok is False
    assert "Enter the service API key" in missing_key.detail


def test_every_servarr_family_service_has_a_version_probe():
    """The console cannot report a running version without one."""
    for service in ("sonarr", "radarr", "prowlarr", "lidarr", "readarr", "whisparr"):
        assert service in VERSION_PROBES


# Shaped like the real manifest:
#
#   prowlarr_api_key       held entirely by *other* services, so Prowlarr is
#                          named by no consumer target of its own
#   sonarr_api_key         its canonical home is its own service, with no
#                          holder target for its own key
#   seerr_api_key          an API-only holder
#   qbittorrent_password   a holder written by qui
MANIFEST = """
version: 1
credentials:
  prowlarr_api_key:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [v, prowlarr]}
    write: {mechanism: servarr_command}
    consumers:
      - target: sonarr.indexers
        count: 2
      - target: radarr.indexers
        count: 1
  sonarr_api_key:
    class: A-unv
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [v, sonarr]}
    write: {mechanism: servarr_command}
  seerr_api_key:
    class: A-unv
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [v, seerr]}
    write: {mechanism: seerr_regenerate}
    consumers:
      - target: seerr.settings_json
        count: 1
        mechanism: process_api
  qbittorrent_password:
    class: A-unv
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [v, qbt]}
    consumers:
      - target: qui.instance
        count: 1
"""

URLS = {
    "sonarr": "http://127.0.0.1:8989",
    "radarr": "http://127.0.0.1:7878",
    "prowlarr": "http://127.0.0.1:9696",
    "seerr": "http://127.0.0.1:5055",
    "qui": "http://127.0.0.1:7476",
}

# seerr and qui are deliberately left out: the image observation has no
# container to name, and that absence is a fact worth a row.
CONTAINERS = {"sonarr": "sonarr", "radarr": "radarr", "prowlarr": "prowlarr"}


class FakeTransport:
    """The host's answers, and a record of the bound each call was given."""

    def __init__(self, *, version_answers=None, key="service-key"):
        self.version_answers: dict[str, tuple[int, object]] = version_answers or {}
        self.key = key
        self.sources: list[str] = []
        self.timeouts: list[int | None] = []

    def run_python(self, code: str, *, timeout: int | None = None) -> str:
        self.sources.append(code)
        self.timeouts.append(timeout)
        url = re.search(r"url = '([^']*)'", code)
        assert url is not None, "a host call this fake does not understand"
        for fragment, answer in self.version_answers.items():
            if fragment in url.group(1):
                return "\x00" + str(answer[0]) + "\x00" + json.dumps(answer[1])
        return "\x00-1\x00URLError"


def _manifest() -> Manifest:
    return Manifest.parse(
        MANIFEST,
        known_targets=build_registry().known_targets(),
        known_backends=("ansible-vault",),
    )


def _host(
    *,
    urls: dict[str, str] | None = None,
    containers: dict[str, str] | None = None,
) -> HostConfig:
    return HostConfig(
        name="media",
        urls=dict(URLS) if urls is None else urls,
        containers=dict(CONTAINERS) if containers is None else containers,
    )


def _report(
    stack: Path,
    transport: FakeTransport,
    host: HostConfig,
    *,
    manifest: Manifest | None = None,
    service_keys: dict[str, Secret] | None = None,
    docker_url: str | None = None,
) -> ServiceReport:
    config = Config(
        version=1,
        default_host=host.name,
        hosts={host.name: host},
        manifest=stack / "credentials.yaml",
    )
    return service_report(
        manifest or _manifest(),
        config,
        transport=transport,
        service_keys=service_keys,
        docker_url=docker_url,
    )


def _rows(report: ServiceReport) -> dict[str, ServiceFacts]:
    return {row.system: row for row in report.services}


def test_a_service_is_listed_with_what_the_topology_needs_from_it(
    tmp_path: Path,
) -> None:
    rows = _rows(_report(tmp_path, FakeTransport(), _host()))
    # Prowlarr is named by nothing but the credentials whose value it mints;
    # radarr only by a holder row inside it. Both are services the stack needs.
    assert sorted(rows) == [
        "prowlarr", "qbittorrent", "qui", "radarr", "seerr", "sonarr",
    ]
    assert rows["qbittorrent"].mint == "rotate"
    assert rows["prowlarr"].credentials == ("prowlarr_api_key",)
    assert rows["prowlarr"].mint == "reset"
    assert rows["sonarr"].mint == "reset"  # its own key is minted there
    assert rows["seerr"].mint == "regenerate"  # its own key is minted there

    holders = {holder.slot: holder for holder in rows["sonarr"].holders}
    assert holders["indexers"].write == "servarr_api"
    assert holders["indexers"].managed is True  # writer + recorded version
    assert holders["indexers"].provenance == "measured against 4.0.20.3014"
    assert rows["qui"].holders[0].write == "qui_api"
    assert rows["qui"].holders[0].managed is True
    assert rows["qui"].holders[0].provenance == "measured against 1.33.0"
    # The service-level line: Prowlarr has no holders of its own, and its row
    # still says what backs a claim about it.
    assert rows["prowlarr"].provenance == "measured against 2.6.5.5623"

    # Both API-only holders need their URL, and the row reports a missing one
    # rather than converting it into a file-mount request.
    assert rows["prowlarr"].missing == ()
    assert rows["sonarr"].missing == ()
    assert rows["seerr"].missing == ()
    assert rows["qui"].missing == ()


def test_a_stored_service_key_observes_without_a_config_file(tmp_path: Path) -> None:
    """A pasted key is enough to ask for the version; no config bind needed."""
    manifest = Manifest.parse(
        """
version: 1
credentials:
  sonarr_api_key:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [v, sonarr]}
""",
        known_targets=build_registry().known_targets(),
        known_backends=("ansible-vault",),
    )
    transport = FakeTransport(
        version_answers={"127.0.0.1:8989": (200, {"version": "4.0.3"})}
    )
    report = _report(
        tmp_path,
        transport,
        _host(),
        manifest=manifest,
        service_keys={"sonarr": Secret("pasted-service-key")},
    )
    sonarr = _rows(report)["sonarr"]

    assert sonarr.observation.running_version == "4.0.3"
    assert not any("config.xml" in source for source in transport.sources)


def test_a_stale_service_key_is_not_silently_replaced(tmp_path: Path) -> None:
    """Strict API-only has no local config fallback for an observation."""
    transport = FakeTransport(
        version_answers={
            "127.0.0.1:8989": (401, {"message": "Unauthorized"}),
        }
    )
    report = _report(
        tmp_path,
        transport,
        _host(),
        service_keys={"sonarr": Secret("stale")},
    )

    sonarr = _rows(report)["sonarr"]
    assert sonarr.observation.running_version is None
    assert sonarr.observation.version_note == "HTTP 401"
    assert not any("config.xml" in source for source in transport.sources)


def test_a_holder_only_service_is_listed_without_inventing_a_mint(tmp_path: Path) -> None:
    manifest = Manifest.parse(
        """
version: 1
credentials:
  sonarr_indexer_key:
    class: B
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [v, sonarr]}
    consumers:
      - target: prowlarr.indexers
        count: 1
""",
        known_targets=build_registry().known_targets(),
        known_backends=("ansible-vault",),
    )
    rows = _rows(_report(tmp_path, FakeTransport(), _host(), manifest=manifest))

    assert rows["prowlarr"].credentials == ("sonarr_indexer_key",)
    assert rows["prowlarr"].holders[0].write == "servarr_api"
    assert rows["prowlarr"].missing == ()


def test_the_running_version_is_the_services_own_answer(tmp_path: Path) -> None:
    transport = FakeTransport(
        version_answers={
            "127.0.0.1:8989": (200, {"version": "4.0.3"}),
            "127.0.0.1:9696": (200, {"appName": "Prowlarr"}),  # answered, versionless
            "127.0.0.1:7878": (401, {"message": "Unauthorized"}),
        }
    )
    keys = {
        service: Secret("service-key")
        for service in ("sonarr", "prowlarr", "radarr")
    }
    rows = _rows(
        _report(
            tmp_path,
            transport,
            _host(),
            service_keys=keys,
        )
    )
    assert rows["sonarr"].observation.running_version == "4.0.3"
    assert rows["sonarr"].observation.version_note == ""
    assert rows["prowlarr"].observation.running_version is None
    assert rows["prowlarr"].observation.version_note == (
        "the answer carried no usable 'version'"
    )
    assert rows["radarr"].observation.version_note == "HTTP 401"
    assert rows["seerr"].observation.version_note.startswith(
        "seerr at http://127.0.0.1:5055/api/v1/status could not be reached"
    )
    assert rows["qui"].observation.version_note == "no API key in the store"
    # The version probe uses the service's own stored key, never the value
    # being rotated, and that key must not reach the report.
    assert transport.key not in json.dumps(asdict(rows["sonarr"]))


def test_a_service_reached_over_http_needs_a_url_declared(tmp_path: Path) -> None:
    """Both ways a url is needed: a holder written over the API, and the mint
    called on the service itself. qui needs neither, so it is not asked."""
    rows = _rows(
        _report(
            tmp_path,
            FakeTransport(),
            _host(urls={}),
        )
    )
    assert rows["sonarr"].url is None
    assert rows["sonarr"].missing == (
        "no url is declared for sonarr on media: holders cannot be written or "
        "verified",
    )
    assert rows["qui"].missing == (
        "no url is declared for qui on media: holders cannot be written or "
        "verified",
    )


def test_the_image_comes_from_the_optional_read_only_docker_api(
    tmp_path: Path, monkeypatch
) -> None:
    image = "sha256:" + "a" * 64
    seen: list[str] = []

    def rows(base: str) -> list[dict]:
        seen.append(base)
        return [
            {
                "Names": ["/sonarr"],
                "ImageID": image,
                "Image": "lscr.io/linuxserver/sonarr:latest",
                # Present in the Docker answer, but never read into a report.
                "Labels": {"secret": "do-not-publish"},
                "Env": ["SECRET=do-not-publish"],
            },
            {"Names": ["/other"], "ImageID": "sha256:" + "b" * 64},
        ]

    monkeypatch.setattr(services_module, "docker_endpoint", lambda raw: raw)
    monkeypatch.setattr(services_module, "docker_containers", rows)

    got = _image_of("sonarr", _host(), "http://socket-proxy:2375")
    assert got == (image, (), "")
    assert seen == ["http://socket-proxy:2375"]


def test_no_docker_endpoint_is_a_sentence_not_an_error(tmp_path: Path) -> None:
    image, digests, note = _image_of("sonarr", _host(), None)
    assert (image, digests) == (None, ())
    assert "discovery is off" in note
    assert "CREDARR_DOCKER_URL" in note


def test_an_undeclared_container_has_no_image_to_compare(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(services_module, "docker_endpoint", lambda raw: raw)
    monkeypatch.setattr(
        services_module, "docker_containers", lambda base: [{"Names": ["/seerr"]}]
    )
    image, _digests, note = _image_of("seerr", _host(), "http://socket-proxy:2375")
    assert image is None
    assert "no container is declared" in note


def test_a_missing_container_or_refused_read_is_reported(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(services_module, "docker_endpoint", lambda raw: raw)
    monkeypatch.setattr(services_module, "docker_containers", lambda base: [])
    assert _image_of("sonarr", _host(), "http://socket-proxy:2375")[2] == (
        "no running container named 'sonarr'"
    )

    def refused(base: str) -> list[dict]:
        raise DockerApiError("the Docker API refused the read (HTTP 403)")

    monkeypatch.setattr(services_module, "docker_containers", refused)
    assert _image_of("sonarr", _host(), "http://socket-proxy:2375")[2] == (
        "the Docker API refused the read (HTTP 403)"
    )


def test_the_docker_list_is_read_once_for_the_whole_report(
    tmp_path: Path, monkeypatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(services_module, "docker_endpoint", lambda raw: raw)
    monkeypatch.setattr(
        services_module,
        "docker_containers",
        lambda base: calls.append(base) or [],
    )

    report = _report(
        tmp_path,
        FakeTransport(),
        _host(),
        docker_url="http://socket-proxy:2375",
    )

    assert report.services
    assert calls == ["http://socket-proxy:2375"]


def test_every_host_call_is_bounded(tmp_path: Path) -> None:
    transport = FakeTransport()
    keys = {
        service: Secret("service-key")
        for service in ("sonarr", "prowlarr", "radarr")
    }
    _report(tmp_path, transport, _host(), service_keys=keys)
    assert transport.timeouts
    assert set(transport.timeouts) == {OBSERVE_TIMEOUT}


def test_version_probes_overlap_instead_of_waiting_row_by_row(
    tmp_path: Path,
) -> None:
    """A slow service costs its own timeout, not every row behind it.

    The report is read-only and each probe is independent; this proves the
    implementation actually fans out instead of just sorting the same serial
    calls.
    """
    class SlowTransport(FakeTransport):
        def __init__(self) -> None:
            super().__init__()
            self.active = 0
            self.high_water = 0
            self.lock = threading.Lock()

        def run_python(self, code: str, *, timeout: int | None = None) -> str:
            with self.lock:
                self.active += 1
                self.high_water = max(self.high_water, self.active)
            try:
                # The suite replaces time.sleep with a recorder; Event.wait
                # keeps this overlap real without becoming a suite-wide wait.
                threading.Event().wait(0.05)
                return super().run_python(code, timeout=timeout)
            finally:
                with self.lock:
                    self.active -= 1

    transport = SlowTransport()
    keys = {
        service: Secret("service-key")
        for service in ("sonarr", "prowlarr", "radarr", "qui")
    }
    _report(tmp_path, transport, _host(), service_keys=keys)
    assert 1 < transport.high_water <= OBSERVE_CONCURRENCY
