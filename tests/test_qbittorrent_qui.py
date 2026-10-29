"""qBittorrent rotate and qui holder, against a fake service pair."""

from __future__ import annotations

from pathlib import Path

from credarr.config import HostConfig
from credarr.executor import Executor, RotationContext
from credarr.journal import Journal
from credarr.model import Manifest
from credarr.redact import Secret
from credarr.rotate import Step, StepKind, plan_rotation
from credarr.writers import holder_for

OLD = "qbt_" + "o" * 28
NEW = "qbt_" + "n" * 28
QUI_KEY = "qui-own-key"
INSTANCE = {"id": 7, "name": "qBittorrent", "host": "http://qbt:8080",
            "username": ""}

MANIFEST = """
version: 1
credentials:
  qbittorrent_api_key:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [v, qbt]}
    write: {mechanism: qbittorrent_rotate_api}
    consumers:
      - target: qui.instance[qBittorrent]
        count: 1
        mechanism: qui_api
"""


def _credential():
    manifest = Manifest.parse(
        MANIFEST,
        known_targets=("qui.instance", "sonarr.download_clients"),
        known_backends=("ansible-vault",),
    )
    return next(iter(manifest.credentials.values()))


HOST = HostConfig(
    name="media", urls={"qbittorrent": "http://127.0.0.1:8080",
          "qui": "http://127.0.0.1:7476"},
    containers={},
)


class FakePending:
    def __init__(self, values: dict[str, Secret] | None = None) -> None:
        self.values = dict(values or {})
        self.sets: list[tuple[str, str]] = []
        self.clears: list[str] = []

    def get(self, credential: str) -> Secret | None:
        return self.values.get(credential)

    def set(self, credential: str, value: Secret) -> None:
        self.values[credential] = value
        self.sets.append((credential, value.reveal()))

    def clear(self, credential: str) -> None:
        self.values.pop(credential, None)
        self.clears.append(credential)


class FakeAPI:
    def __init__(self) -> None:
        self.qbt = OLD
        self.instance = dict(INSTANCE)
        self.calls: list[tuple[str, str, str]] = []

    def __call__(self, _host, service, method, path, *, body=None,
                 key=None, auth_header="X-Api-Key", **_kwargs):
        self.calls.append((service, method, path))
        if service == "qbittorrent":
            token = key.removeprefix("Bearer ") if key else None
            if path == "/app/version":
                return (200, "v5.3.0") if token == self.qbt else (403, "")
            if path == "/app/rotateAPIKey" and method == "POST":
                if token != self.qbt:
                    return 401, None
                self.qbt = NEW
                return 200, {"apiKey": NEW}
            return 404, None
        if service == "qui":
            if key != QUI_KEY:
                return 401, None
            if path == "/api/instances" and method == "GET":
                return 200, [dict(self.instance)]
            if path == f"/api/instances/{self.instance['id']}" and method == "PUT":
                self.instance = dict(body)
                self.instance["id"] = INSTANCE["id"]
                return 200, dict(self.instance)
            if path == f"/api/instances/{self.instance['id']}/test":
                return 200, {"connected": True}
        return 404, None


def _executor(tmp_path: Path, api: FakeAPI, pending: FakePending):
    ctx = RotationContext(
        credential=_credential(),
        host=HOST,
        transport=None,  # not reached: every call is the fake
        journal=Journal(tmp_path / "j.db"),
        vault_value=OLD,
        pending=pending,
        service_keys={"qui": Secret(QUI_KEY)},
        settle_timeout=0.0,
        write_backoff=0.0,
    )
    return Executor(ctx, servarr_call=api), ctx


def test_the_plan_recognises_qbittorrents_rotate_mechanism():
    plan = plan_rotation(_credential(), HOST)

    assert plan.blocked_by == []
    assert plan.executable is True
    assert plan.revokes_before_holders is True
    assert [step.kind for step in plan.steps] == [
        StepKind.MINT, StepKind.PROPAGATE, StepKind.RECORD,
    ]


def test_the_mint_parks_the_key_before_proving_it_and_revokes_the_old_one(
    tmp_path: Path,
):
    api = FakeAPI()
    pending = FakePending()
    executor, ctx = _executor(tmp_path, api, pending)

    detail = executor._mint_qbittorrent(
        Step(StepKind.MINT, "qbittorrent", "rotate", reversible=False)
    )

    assert "rotated" in detail
    assert ctx.minted == Secret(NEW)
    assert ctx.old_key_dead is True
    assert pending.sets == [("qbittorrent_api_key", NEW)]
    assert ("qbittorrent", "POST", "/app/rotateAPIKey") in api.calls


def test_a_parked_key_resumes_without_rotating_again(tmp_path: Path):
    api = FakeAPI()
    api.qbt = NEW
    pending = FakePending({"qbittorrent_api_key": Secret(NEW)})
    executor, ctx = _executor(tmp_path, api, pending)

    detail = executor._mint_qbittorrent(
        Step(StepKind.MINT, "qbittorrent", "rotate", reversible=False)
    )

    assert detail.startswith("already-rotated")
    assert ctx.resumed is True
    assert ("qbittorrent", "POST", "/app/rotateAPIKey") not in api.calls


def test_a_dead_parked_key_does_not_fake_a_resume(tmp_path: Path):
    """A parked value from an earlier attempt is not a key the service holds."""
    api = FakeAPI()
    pending = FakePending({"qbittorrent_api_key": Secret(NEW)})
    executor, ctx = _executor(tmp_path, api, pending)

    executor._mint_qbittorrent(
        Step(StepKind.MINT, "qbittorrent", "rotate", reversible=False)
    )

    assert ("qbittorrent", "POST", "/app/rotateAPIKey") in api.calls
    assert ctx.resumed is False


def test_the_qui_holder_writes_the_key_and_tests_the_running_process(
    tmp_path: Path,
):
    api = FakeAPI()
    executor, ctx = _executor(tmp_path, api, FakePending())
    ctx.minted = Secret(NEW)
    ctx.minted_service = "qbittorrent"

    detail = executor._propagate_qui(
        Step(StepKind.PROPAGATE, "qui.instance[qBittorrent]", "PUT"),
        holder_for("qui", "instance"),
    )

    assert "connection test" in detail
    assert api.instance["apiKey"] == NEW
    assert ctx.holders[0].outcome == "confirmed"
    assert any(path.endswith("/test") for _s, _m, path in api.calls)


def test_preflight_checks_the_rotate_inputs_and_the_qui_instance(
    tmp_path: Path,
):
    api = FakeAPI()
    executor, _ctx = _executor(tmp_path, api, FakePending())
    plan = plan_rotation(_credential(), HOST)

    assert executor.preflight(plan) == []
