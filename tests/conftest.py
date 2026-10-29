"""Shared fixtures.

The important one is `stack`: the temporary directory a test uses for its
config, manifest, vault and app database. It carries no service data: strict
API-only means the engine reaches services over their APIs, never through a
fixture config directory.

`app` wraps that directory for the server suite, plus a store holding one
credential and its working copy - what the scheduler audits.

Both live here rather than in `tests/server/conftest.py`: pytest registers
every conftest.py under the module name `conftest`, so a nested one shadows
this file and breaks `from conftest import ...` in the top-level tests.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from credarr.config import Config, HostConfig
from credarr.redact import Secret
from credarr.targets import build_registry
from credarr_server.app import ServerSettings, create_app
from credarr_server.store import TopologyStore

SONARR_KEY = "95bcc02c859006271d31f6ba3a15cbdb"  # gitleaks:allow
RADARR_KEY = "cc2c8c6dbca255caf13c0799e6dc562f"  # gitleaks:allow
PROWLARR_KEY = "b32b53cb7fd1c3e7a1c9f0b2d4e6a8c1"  # gitleaks:allow
PASSWORD = "correct-horse-battery"  # gitleaks:allow - a test fixture, not a secret


@pytest.fixture
def stack(tmp_path: Path) -> Path:
    """The temporary directory a test may use for config and local state."""
    return tmp_path


SERVER_MANIFEST = """
version: 1
credentials:
  sonarr_api_key:
    class: A
    max_age_days: 90
    vault:
      backend: ansible-vault
      file: vault.yml
      path: [keys, sonarr_api_key]
    consumers:
      - target: seerr.settings_json[sonarr]
        count: 1
        mechanism: process_api
  seerr_api_key:
    class: B
    never_rotate: true
    vault:
      backend: ansible-vault
      file: vault.yml
      path: [keys, seerr_api_key]
    write:
      mechanism: seerr_regenerate
"""


@pytest.fixture
def settings_api():
    """A real HTTP Seerr settings endpoint for the API-only audit path."""
    api = SettingsAPI()
    yield api
    api.close()


@pytest.fixture
def app(tmp_path: Path, stack: Path, settings_api) -> SimpleNamespace:
    """The server suite's starting point: a store holding the runtime values
    and a real fake Seerr API that the audit can read.

    The declared vault (`vault.yml`) does not exist anywhere, so an audit that
    fell back to reading it would fail loudly rather than pass quietly.
    """
    manifest = tmp_path / "credentials.yaml"
    manifest.write_text(SERVER_MANIFEST, encoding="utf-8")
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest, build_registry())
    store.set_value("sonarr_api_key", Secret(SONARR_KEY))
    store.set_value("seerr_api_key", Secret("seerr-service-key-000000000000"))
    store.create_service(
        "seerr", kind="api", url=settings_api.url, notes="fixture"
    )
    config = Config(
        version=1,
        default_host="local",
        hosts={
            "local": HostConfig(
                name="local",
                urls={"seerr": settings_api.url},
            )
        },
        manifest=manifest,
    )
    return SimpleNamespace(
        store=store,
        config=config,
        manifest=manifest,
        stack=stack,
        settings_api=settings_api,
    )


def server_config(app, tmp_path: Path) -> Path:
    """The engine config the CLI would read, pointed at the fixture stack."""
    config_path = tmp_path / "credarr.yaml"
    config_path.write_text(
        "version: 1\n"
        "default_host: local\n"
        "hosts:\n"
        "  local:\n"
        f"    urls: {{seerr: {app.settings_api.url}}}\n"
        "    containers: {sonarr: sonarr, prowlarr: prowlarr}\n"
        f"manifest: {app.manifest}\n",
        encoding="utf-8",
    )
    return config_path


def make_server(
    app, tmp_path: Path, config_dir: Path | None = None, **overrides
) -> FastAPI:
    """A real application over the fixture stack, with the fixture's own
    `app.db` (the store the tests already seeded) unless `config_dir` points
    somewhere else.

    `web_dir` defaults to a path under the test's tmp directory, so the route
    set never depends on whether the developer ran `make web`.
    """
    overrides.setdefault("web_dir", tmp_path / "web")
    return create_app(
        ServerSettings(
            config_path=server_config(app, tmp_path),
            config_dir=config_dir or tmp_path,
            audit_interval=3600.0,
            **overrides,
        )
    )


@pytest.fixture
def server(app, tmp_path: Path) -> FastAPI:
    """The application the BFF suites drive, over the fixture stack."""
    return make_server(app, tmp_path)


def refresh_csrf(client: TestClient) -> str:
    """Read the session-bound token and make it the client's default header."""
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 200, response.text
    token = response.json()["csrf"]
    assert isinstance(token, str) and token
    client.headers["X-CSRF-Token"] = token
    return token


def setup_admin(client: TestClient) -> None:
    response = client.post("/api/v1/auth/setup", json={"password": PASSWORD})
    assert response.status_code == 200
    refresh_csrf(client)


def poll_for(predicate, what: str, timeout: float | None = None):
    """Poll until `predicate()` is truthy, then return its value.

    A fixed iteration count is a wall-clock assumption: 200 polls at 20ms is
    four seconds, which a loaded CI runner can exceed while the product is
    doing exactly the right thing. The budget is a deadline instead, and the
    fast path is unchanged.
    """
    budget = (
        timeout
        if timeout is not None
        else float(os.environ.get("CREDARR_TEST_TIMEOUT", "120"))
    )
    deadline = time.monotonic() + budget
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} (waited {budget:.0f}s)")
        time.sleep(0.02)


def wait_for_audit(client: TestClient) -> dict:
    """The loop audits on startup, in a thread; wait for the row it writes."""

    def ready() -> dict | None:
        state = client.get("/api/v1/status").json()
        return state if state["last_run"] is not None else None

    return poll_for(ready, "the first audit never landed")


class SettingsAPI:
    """Seerr's settings endpoint, with the one section the audit reads."""

    def __init__(self) -> None:
        self.value = SONARR_KEY
        self.requests: list[str] = []
        api = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                api.requests.append(self.path)
                if self.path == "/api/v1/settings/sonarr":
                    body = json.dumps([{"apiKey": api.value, "name": "Sonarr"}]).encode()
                    self.send_response(200)
                elif self.path == "/api/v1/status":
                    body = json.dumps({"version": "3.5.0"}).encode()
                    self.send_response(200)
                elif self.path in ("/auth/me", "/api/v1/auth/me"):
                    body = json.dumps({"id": 1, "displayName": "admin"}).encode()
                    self.send_response(200)
                else:
                    body = b'{"message": "not found"}'
                    self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                """Silence. A test's output is its assertions."""

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class Sink:
    """A local HTTP server that records what the notifier sends it.

    `/slow` holds the answer until the test releases it, so a test can keep a
    delivery genuinely in flight instead of racing a sleep.
    """

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.status = 200
        self.body = b"ok"
        self.arrived = threading.Event()
        self.release = threading.Event()
        self.release.set()
        sink = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length)
                sink.requests.append(
                    {
                        "path": self.path,
                        "headers": {key.lower(): value for key, value in self.headers.items()},
                        "body": body,
                    }
                )
                sink.arrived.set()
                if self.path.endswith("/slow"):
                    sink.release.wait(timeout=5)
                self.send_response(sink.status)
                self.send_header("Content-Length", str(len(sink.body)))
                self.end_headers()
                if self.path.endswith("/stream"):
                    # More body than the notifier's bound, with the rest held
                    # back until the test releases it: a full read would wait
                    # for bytes that never arrive, while a bounded read returns.
                    self.wfile.write(sink.body[:8192])
                    self.wfile.flush()
                    sink.release.wait(timeout=5)
                    return
                self.wfile.write(sink.body)

            def log_message(self, format: str, *args: object) -> None:
                """Silence. A test's output is its assertions."""

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def sink() -> Sink:
    """A notification sink on 127.0.0.1: the notifier talks to a real server,
    so what a test reads is the bytes that would have left the machine."""
    server = Sink()
    yield server
    server.close()


class FakeTransport:
    """Runs a probe in-process by executing its source with the same preamble.

    The probe genuinely runs, through the same assembly path as the executor, so a bug in
    parameter substitution or in the preamble shows up here rather than only in
    a real service process.
    """

    def __init__(self) -> None:
        self.sources: list[str] = []

    def run_python(self, code: str, *, timeout: int | None = None) -> str:
        """Returns stdout as a string, exactly as the real transports do.

        Returning a parsed dict here would let a probe that emits malformed
        output pass in tests and fail against a real host.
        """
        import io
        from contextlib import redirect_stdout

        self.sources.append(code)
        buffer = io.StringIO()
        namespace: dict = {"__name__": "__main__"}
        with redirect_stdout(buffer):
            exec(compile(code, "<probe>", "exec"), namespace)
        return buffer.getvalue()


@pytest.fixture(autouse=True)
def recorded_sleeps(monkeypatch):
    """Record sleeps instead of performing them.

    Backoff and pacing are real waits, and a suite that actually waits for them
    takes minutes. Patching the dataclass attribute does not work - defaults are
    baked into `__init__` at class creation - so the sleep call itself is
    intercepted instead. The recorded list is asserted on where pacing is the
    thing under test, which is stronger than merely not waiting.

    The readiness window is capped for the same reason, and it matters more than
    the others: a service that never answers would otherwise spin until the
    suite was killed rather than until its deadline. A wrong status or restart
    path would hang the run instead of failing it, which is the one outcome a
    test must not produce.
    Tests that exercise the timeout explicitly override this.
    """
    import credarr.executor as executor

    slept: list[float] = []
    monkeypatch.setattr(executor.time, "sleep", slept.append, raising=False)
    monkeypatch.setattr(executor, "READINESS_TIMEOUT", 0.5)
    monkeypatch.setattr(executor, "READINESS_INTERVAL", 0.01)
    monkeypatch.setattr(executor, "SEERR_READBACK_TIMEOUT", 0.5)
    monkeypatch.setattr(executor, "SEERR_READBACK_INTERVAL", 0.01)
    request = pytest.MonkeyPatch()
    # One test genuinely needs the clock to move.
    yield slept
    request.undo()
