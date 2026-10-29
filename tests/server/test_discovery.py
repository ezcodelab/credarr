"""Docker discovery over the BFF: read-only proposals, never a write.

The fake API answers the one route discovery is allowed to call. The fixtures
carry environment and labels deliberately: the endpoint must not echo them,
because a real container's labels and environment are where secrets live.
"""

from __future__ import annotations

import contextlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from conftest import make_server, setup_admin
from credarr.config import Config, HostConfig
from credarr.model import Manifest
from credarr_server.discovery import _image_system, _port, discover


@contextlib.contextmanager
def docker_api(payload, *, status: int = 200, headers: dict | None = None):
    seen: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            seen.append(self.path)
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", seen
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def container(
    name: str,
    image: str,
    ports: list[dict] | None = None,
    mounts: list[dict] | None = None,
) -> dict:
    return {
        "Names": [f"/{name}"],
        "Image": image,
        "ImageID": f"sha256:{name}",
        "Ports": ports or [],
        "Mounts": mounts or [],
        # Discovery must ignore both of these.
        "Labels": {"secret": "LABEL-SECRET"},
        "Env": ["ENV-SECRET=do-not-return"],
    }


def test_servarr_siblings_are_discoverable() -> None:
    for name, port in (("lidarr", 8686), ("readarr", 8787), ("whisparr", 6969)):
        assert _image_system(f"lscr.io/linuxserver/{name}:latest") == name
        row = container(name, f"lscr.io/linuxserver/{name}:latest",
                        [{"PrivatePort": port, "Type": "tcp"}])
        assert _port(row, name) == port
        # The fallback default is the part that matters when a container
        # publishes no TCP port at all; the row above would pass without it.
        assert _port({}, name) == port


def test_discovery_is_off_by_default(app, tmp_path) -> None:
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        body = client.get("/api/v1/discovery").json()

    assert body["enabled"] is False
    assert body["source"] is None
    assert body["proposals"] == [] and body["diffs"] == []
    assert "CREDARR_DOCKER_URL" in body["note"]


def test_discovery_proposes_only_undeclared_services_and_never_writes(app, tmp_path) -> None:
    payload = [
        container(
            "sonarr",
            "lscr.io/linuxserver/sonarr:latest",
            [{"PrivatePort": 8989, "Type": "tcp"}],
            [{"Type": "bind", "Source": str(app.stack / "sonarr"), "Destination": "/config"}],
        ),
        container(
            "prowlarr",
            "lscr.io/linuxserver/prowlarr:latest",
            [{"PrivatePort": 9696, "Type": "tcp"}],
            [
                {
                    "Type": "bind",
                    "Source": "/mnt/tank/docker/prowlarr/config",
                    "Destination": "/config",
                }
            ],
        ),
    ]
    with docker_api(payload) as (url, seen), TestClient(
        make_server(app, tmp_path, docker_url=url)
    ) as client:
        setup_admin(client)
        before = client.get("/api/v1/topology/export").text
        response = client.get("/api/v1/discovery")
        after = client.get("/api/v1/topology/export").text

    body = response.json()
    assert body["enabled"] is True
    assert body["error"] is None
    assert body["source"] == url
    assert seen == ["/containers/json?all=0"]
    assert [proposal["system"] for proposal in body["proposals"]] == ["prowlarr"]
    (proposal,) = body["proposals"]
    assert proposal["container"] == "prowlarr"
    assert proposal["url"] == "http://prowlarr:9696"
    assert body["diffs"] == []
    # The scan is a read: the declared topology and the fixture's stored value
    # are exactly what they were before the request.
    assert after == before
    assert app.store.get_value("sonarr_api_key") is not None
    # No container environment, label, or stored value in the response.
    for secret in ("LABEL-SECRET", "ENV-SECRET"):
        assert secret not in response.text


def test_a_second_container_of_a_declared_family_is_not_a_wrong_identity(app, tmp_path) -> None:
    payload = [
        container("sonarr", "lscr.io/linuxserver/sonarr:latest"),
        container("sonarr-4k", "lscr.io/linuxserver/sonarr:latest"),
    ]
    with docker_api(payload) as (url, _seen), TestClient(
        make_server(app, tmp_path, docker_url=url)
    ) as client:
        setup_admin(client)
        body = client.get("/api/v1/discovery").json()

    assert body["diffs"] == []
    assert body["proposals"] == []


def test_discovery_reports_a_changed_container(app, tmp_path) -> None:
    payload = [
        container(
            "sonarr-v2",
            "lscr.io/linuxserver/sonarr:latest",
            [{"PrivatePort": 8989, "Type": "tcp"}],
            [{"Type": "bind", "Source": "/mnt/old/sonarr", "Destination": "/config"}],
        )
    ]
    with docker_api(payload) as (url, _seen), TestClient(
        make_server(app, tmp_path, docker_url=url)
    ) as client:
        setup_admin(client)
        body = client.get("/api/v1/discovery").json()

    asserted = {(diff["kind"], diff["observed"]) for diff in body["diffs"]}
    assert ("container", "sonarr-v2") in asserted
    assert all(kind != "mount" for kind, _ in asserted)
    assert body["proposals"] == []


def test_discovery_reports_an_image_family_change(app, tmp_path) -> None:
    payload = [
        container(
            "sonarr",
            "lscr.io/linuxserver/radarr:latest",
            [{"PrivatePort": 7878, "Type": "tcp"}],
        )
    ]
    with docker_api(payload) as (url, _seen), TestClient(
        make_server(app, tmp_path, docker_url=url)
    ) as client:
        setup_admin(client)
        body = client.get("/api/v1/discovery").json()

    (diff,) = body["diffs"]
    assert diff["kind"] == "image_family"
    assert diff["observed"] == "radarr"


def test_discovery_reports_a_self_named_url_port_change(tmp_path) -> None:
    manifest = Manifest.parse(
        "version: 1\n"
        "credentials:\n"
        "  sonarr_api_key:\n"
        "    class: A\n"
        "    max_age_days: 90\n"
        "    consumers:\n"
        "      - target: sonarr.indexers\n"
    )
    config = Config(
        version=1,
        default_host="local",
        hosts={
            "local": HostConfig(
                name="local",
                urls={"sonarr": "http://sonarr:8989"},
            )
        },
        manifest=Path("credentials.yaml"),
    )
    payload = [
        container(
            "sonarr",
            "lscr.io/linuxserver/sonarr:latest",
            [{"PrivatePort": 8990, "Type": "tcp"}],
        )
    ]
    with docker_api(payload) as (url, _seen):
        body = discover(url, manifest, config)

    (diff,) = body["diffs"]
    assert diff["kind"] == "url"
    assert diff["declared"] == "http://sonarr:8989"
    assert diff["observed"] == "http://sonarr:8990"


def test_a_service_declared_on_another_host_is_not_diffed(tmp_path) -> None:
    manifest = Manifest.parse(
        "version: 1\n"
        "credentials:\n"
        "  sonarr_api_key:\n"
        "    class: A\n"
        "    max_age_days: 90\n"
        "    consumers:\n"
        "      - target: sonarr.indexers\n"
        "        host: tower\n"
    )
    config = Config(
        version=1,
        default_host="local",
        hosts={
            "local": HostConfig(
                name="local",
            ),
            "tower": HostConfig(name="tower"),
        },
        manifest=Path("credentials.yaml"),
    )
    with docker_api(
        [
            container(
                "sonarr",
                "lscr.io/linuxserver/sonarr:latest",
                mounts=[
                    {
                        "Type": "bind",
                        "Source": "/mnt/tower/sonarr",
                        "Destination": "/config",
                    }
                ],
            )
        ]
    ) as (url, _seen):
        body = discover(url, manifest, config)

    assert body["diffs"] == []
    assert body["proposals"] == []


def test_a_broken_proxy_is_a_sentence_not_a_traceback(app, tmp_path) -> None:
    with docker_api({"message": "denied"}, status=403) as (url, _seen), TestClient(
        make_server(app, tmp_path, docker_url=url)
    ) as client:
        setup_admin(client)
        body = client.get("/api/v1/discovery").json()

    assert body["enabled"] is True
    assert body["error"] == "the Docker API refused the read (HTTP 403)"
    assert body["proposals"] == [] and body["diffs"] == []


def test_discovery_does_not_follow_a_redirect(app, tmp_path) -> None:
    with docker_api(
        {"message": "moved"},
        status=302,
        headers={"Location": "http://example.invalid/containers/json"},
    ) as (url, seen), TestClient(
        make_server(app, tmp_path, docker_url=url)
    ) as client:
        setup_admin(client)
        body = client.get("/api/v1/discovery").json()

    assert body["error"] == "the Docker API refused the read (HTTP 302)"
    assert seen == ["/containers/json?all=0"]


def test_a_non_list_answer_is_a_sentence(app, tmp_path) -> None:
    with docker_api({"message": "not a container list"}) as (url, _seen), TestClient(
        make_server(app, tmp_path, docker_url=url)
    ) as client:
        setup_admin(client)
        body = client.get("/api/v1/discovery").json()

    assert body["error"] == "the Docker API did not answer with a container list"
    assert body["proposals"] == [] and body["diffs"] == []


def test_discovery_refuses_credentials_in_the_endpoint(app, tmp_path) -> None:
    url = "http://user:pass@127.0.0.1:2375"
    with TestClient(make_server(app, tmp_path, docker_url=url)) as client:
        setup_admin(client)
        response = client.get("/api/v1/discovery")

    body = response.json()
    assert body["enabled"] is True
    assert "must not contain credentials" in body["error"]
    assert "user:pass" not in response.text


def test_discovery_refuses_an_invalid_port(app, tmp_path) -> None:
    url = "http://127.0.0.1:not-a-port"
    with TestClient(make_server(app, tmp_path, docker_url=url)) as client:
        setup_admin(client)
        body = client.get("/api/v1/discovery").json()

    assert body["enabled"] is True
    assert body["error"] == "the Docker endpoint has an invalid port"
    assert body["proposals"] == [] and body["diffs"] == []


def test_discovery_needs_auth(app, tmp_path) -> None:
    with TestClient(make_server(app, tmp_path)) as client:
        assert client.get("/api/v1/discovery").status_code == 401


@pytest.mark.parametrize(
    ("image", "expected"),
    [
        ("lscr.io/linuxserver/sonarr:latest", "sonarr"),
        ("ghcr.io/foo/radarr@sha256:abc", "radarr"),
        ("registry:5000/foo/prowlarr", "prowlarr"),
        ("registry:5000/foo/sonarr:4.0.20", "sonarr"),
        ("ghcr.io/foo/not-a-service:latest", None),
        (None, None),
    ],
)
def test_image_family_parser(image, expected) -> None:
    assert _image_system(image) == expected


def test_port_keeps_a_non_default_private_port_and_falls_back() -> None:
    assert _port({"Ports": [{"PrivatePort": 8990, "Type": "tcp"}]}, "sonarr") == 8990
    assert _port({"Ports": [{"PrivatePort": 8080, "Type": "tcp"}]}, "qbittorrent") == 8080
    assert _port({}, "sonarr") == 8989
