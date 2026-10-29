"""The shipped image, exercised only through HTTP.

These tests boot the built container on a disposable `/config` and assert what a
user sees: the console is served, the first-run setup works, a write persists,
and `/config` is owned by the configured PUID. No mocks, no fake services, no
imports from the application - if the wheel is missing a file, the entrypoint is
wrong, or `/config` is not writable, these fail and the unit suite cannot.

    make image                 # tags credarr:dev
    pytest -m integration

Skipped, with a reason, when Docker or the image is absent. CI that wants them
must build the image first.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

IMAGE = os.environ.get("CREDARR_TEST_IMAGE", "credarr:dev")
PASSWORD = "integration-password-0123456789"  # gitleaks:allow - a fixture
# Deliberately not 1000: the host user running the suite often is uid 1000, so a
# container that never chowned /config would otherwise pass the ownership check.
APP_UID = 1234


def _docker(*args: str, **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, **kwargs)


def _require_docker() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker is not installed")
    if _docker("info", "--format", "{{.ServerVersion}}").returncode != 0:
        pytest.skip("the Docker daemon is not reachable")
    if _docker("image", "inspect", IMAGE).returncode != 0:
        pytest.skip(f"image {IMAGE} is not built; run `make image`")


class Console:
    """A container plus the HTTP session a browser would use."""

    def __init__(self, container: str, port: int, config: Path) -> None:
        self.container = container
        self.base = f"http://127.0.0.1:{port}"
        self.config = config
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )

    def _call(self, method: str, path: str, body: dict | None = None,
              headers: dict[str, str] | None = None) -> tuple[int, dict | str]:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            self.base + path, data=data, method=method,
            headers={"content-type": "application/json", **(headers or {})},
        )
        try:
            with self.opener.open(request, timeout=5) as answer:
                raw = answer.read()
                status = answer.status
        except urllib.error.HTTPError as error:
            raw = error.read()
            status = error.code
        try:
            return status, json.loads(raw or b"null")
        except json.JSONDecodeError:
            return status, raw.decode("utf-8", "replace")

    def get(self, path: str) -> tuple[int, object]:
        return self._call("GET", path)

    def post(self, path: str, body: dict) -> tuple[int, object]:
        csrf = self.csrf()
        return self._call("POST", path, body, {"X-CSRF-Token": csrf})

    def csrf(self) -> str:
        _, body = self.get("/api/v1/auth/me")
        return str(body.get("csrf", "")) if isinstance(body, dict) else ""

    def stop(self) -> None:
        _docker("rm", "-f", self.container)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _wait_for_health(base: str, timeout: float = 40.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(base + "/api/v1/health", timeout=2) as answer:
                if answer.status == 200:
                    return
        except (urllib.error.URLError, OSError):
            time.sleep(0.3)
    raise AssertionError(f"the console never answered on {base}")


@pytest.fixture
def console(tmp_path: Path):
    """The built image on an empty /config, published on a random host port."""
    _require_docker()
    # Not pytest's tmp_path: the container chowns /config to PUID, which would
    # leave the host test user unable to read or remove it. This directory is
    # chowned back in teardown.
    state = Path(tempfile.mkdtemp(prefix="credarr-integration-"))
    state.chmod(0o777)
    port = _free_port()
    name = f"credarr-integration-{port}"
    started = _docker(
        "run", "-d", "--name", name,
        "-p", f"127.0.0.1:{port}:8080",
        "-v", f"{state}:/config",
        "-e", f"PUID={APP_UID}",
        "-e", f"PGID={APP_UID}",
        # Root is the documented entrypoint: it aligns /config then drops to
        # PUID/PGID. The test asserts that behaviour rather than a --user run.
        IMAGE,
    )
    if started.returncode != 0:
        shutil.rmtree(state, ignore_errors=True)
        pytest.fail(f"the image did not start: {started.stderr.strip()}")

    session = Console(name, port, state)
    try:
        _wait_for_health(session.base)
        yield session
    finally:
        session.stop()
        # Give the directory back to the invoking user so it can be removed.
        _docker(
            "run", "--rm", "--entrypoint", "chown",
            "-v", f"{state}:/config", IMAGE,
            "-R", f"{os.getuid()}:{os.getgid()}", "/config",
        )
        shutil.rmtree(state, ignore_errors=True)


def test_the_console_is_served_with_its_health_signal(console: Console) -> None:
    status, health = console.get("/api/v1/health")
    assert status == 200
    assert isinstance(health, dict) and health["status"] == "ok"

    status, page = console.get("/")
    assert status == 200
    assert isinstance(page, str) and "credarr" in page.lower()

    status, _ = console.get("/favicon.svg")
    assert status == 200, "the console's favicon ships inside the wheel"


def sign_in(console: Console) -> None:
    """Complete first-run setup the way the operator does, once."""
    status, state = console.get("/api/v1/auth/state")
    assert status == 200 and state["needs_setup"] is True
    status, answer = console.post("/api/v1/auth/setup", {"password": PASSWORD})
    assert status == 200, answer


def test_first_run_setup_signs_the_admin_in(console: Console) -> None:
    sign_in(console)

    status, me = console.get("/api/v1/auth/me")
    assert status == 200
    assert isinstance(me, dict)
    # A browser session, not a bearer key: the console's own cookie jar.
    assert me["auth"] == "session"
    assert me["csrf"], "a session always carries the CSRF token the console posts with"

    status, report = console.get("/api/v1/status")
    assert status == 200
    assert isinstance(report, dict)
    assert report["topology"]["imported"] is False, (
        "an empty store must not read as a clean topology"
    )


def test_first_boot_creates_a_private_state_directory(console: Console) -> None:
    # Asked inside the container: /config is owned by PUID, so the host test
    # user is not the one the app runs as.
    def inside(*args: str) -> str:
        return _docker("exec", console.container, *args).stdout.strip()

    assert inside("test", "-f", "/config/credarr.yaml") == ""
    assert inside("test", "-f", "/config/credentials.yaml") == ""
    assert inside("test", "-f", "/config/app.db") == ""

    mode = inside("stat", "-c", "%a", "/config/app.db")
    assert mode == "600", f"app.db mode is {mode}, not 0600"

    # The entrypoint's job, measured against a PUID that is not the host's:
    # the process that owns the state directory is the configured one.
    owner = inside("stat", "-c", "%u", "/config/app.db")
    assert owner == str(APP_UID), f"/config is owned by uid {owner}, not PUID {APP_UID}"


def test_a_write_survives_in_the_state_directory(console: Console) -> None:
    """The app user can write: a declared service comes back after a restart."""
    sign_in(console)
    status, answer = console.post(
        "/api/v1/services",
        {"name": "sonarr", "kind": "servarr", "url": "http://sonarr:8989"},
    )
    assert status == 200, answer

    _docker("restart", console.container)
    _wait_for_health(console.base)

    status, services = console.get("/api/v1/services")
    assert status == 200
    names = [row["name"] for row in services["definitions"]]
    assert "sonarr" in names, "a write that does not survive a restart is not stored"
