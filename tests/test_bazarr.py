"""Bazarr as a process-readback holder for Sonarr and Radarr keys.

Measured on 1.6.2: the settings write is a form POST, and the running process
returns the stored value under `sonarr.apikey` / `radarr.apikey`. These tests
pin the planner step, the write/readback, and the refusal shapes.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest

from conftest import FakeTransport
from credarr.audit import Auditor, Status
from credarr.config import Config, HostConfig
from credarr.errors import RotationError
from credarr.executor import Executor, RotationContext
from credarr.fingerprint import Fingerprinter
from credarr.journal import Journal
from credarr.model import Manifest
from credarr.redact import Secret
from credarr.rotate import Step, StepKind, plan_rotation
from credarr.secrets import StaticSource
from credarr.targets import build_registry
from credarr.writers import holder_for

SONARR_OLD = "a1b2c3d4e5f60718293a4b5c6d7e8f90"  # gitleaks:allow - synthetic
SONARR_NEW = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"  # gitleaks:allow - synthetic
BAZARR_KEY = "9a8b7c6d5e4f30211203f4e5d6c7b8a9"  # gitleaks:allow - synthetic

MANIFEST = """
version: 1
credentials:
  sonarr_api_key:
    class: A
    max_age_days: 90
    canonical: {service: sonarr}
    vault: {backend: ansible-vault, file: v.yml, path: [v, sonarr]}
    write: {mechanism: servarr_command}
    consumers:
      - target: bazarr.settings[sonarr]
        count: 1
        mechanism: process_api
  bazarr_api_key:
    class: B
    never_rotate: true
    canonical: {service: bazarr}
    vault: {backend: ansible-vault, file: v.yml, path: [v, bazarr]}
"""

HOST = HostConfig(
    name="media",
    urls={"sonarr": "http://127.0.0.1:8989", "bazarr": "http://127.0.0.1:6767"},
    containers={},
)

REGISTRY = build_registry()


def _manifest(text: str = MANIFEST) -> Manifest:
    return Manifest.parse(
        text, known_targets=REGISTRY.known_targets(),
        known_backends=("ansible-vault",),
    )


class FakeAPI:
    def __init__(self) -> None:
        self.settings = {
            "sonarr": {"apikey": SONARR_OLD},
            "radarr": {"apikey": "radarr-key"},
        }
        self.form: dict | None = None
        self.deny = False
        self.freeze_readback = False
        self.calls: list[tuple[str, str]] = []

    def __call__(self, _host, service, method, path, *, body=None, key=None,
                 auth_header="X-API-KEY", content_type="application/json",
                 **_kwargs):
        self.calls.append((method, path))
        if service != "bazarr":
            return 404, None
        if key != BAZARR_KEY:
            return 401, None
        if path != "/api/system/settings":
            return 404, None
        if method == "GET":
            return 200, copy.deepcopy(self.settings)
        if method == "POST":
            if content_type != "application/x-www-form-urlencoded":
                return 415, None
            self.form = dict(body or {})
            if self.deny:
                return 403, None
            if not self.freeze_readback:
                for field, value in self.form.items():
                    if field.startswith("settings-") and field.endswith("-apikey"):
                        row = field[len("settings-"):-len("-apikey")]
                        self.settings.setdefault(row, {})["apikey"] = value
            return 204, None
        return 404, None


def _context(tmp_path: Path, api: FakeAPI) -> tuple[RotationContext, Executor]:
    ctx = RotationContext(
        credential=_manifest().credentials["sonarr_api_key"],
        host=HOST,
        transport=None,
        journal=Journal(tmp_path / "j.db"),
        minted=Secret(SONARR_NEW),
        vault_value=SONARR_OLD,
        service_keys={"bazarr": Secret(BAZARR_KEY)},
        settle_timeout=0.0,
    )
    return ctx, Executor(ctx, servarr_call=api)


def _step(plan):
    return next(
        step for step in plan.steps
        if step.kind is StepKind.PROPAGATE
        and str(step.target) == "bazarr.settings[sonarr]"
    )


def test_bazarr_is_a_holder_with_a_process_readback():
    holder = holder_for("bazarr", "settings")

    assert holder is not None
    assert holder.write == "bazarr_api"
    assert holder.readback == "process_api"
    assert holder.readback_shape == "section"
    assert holder.field == "settings-{service}-apikey"


def test_a_bazarr_plan_writes_the_settings_and_reads_it_back():
    plan = plan_rotation(_manifest().credentials["sonarr_api_key"], HOST)

    assert plan.executable is True
    step = _step(plan)
    assert "Bazarr" in step.detail
    assert "running process" in step.reason


def test_bazarr_write_reaches_the_running_process(tmp_path: Path):
    api = FakeAPI()
    ctx, executor = _context(tmp_path, api)
    plan = plan_rotation(ctx.credential, HOST)

    result = executor._propagate_bazarr(
        _step(plan), holder_for("bazarr", "settings"))

    assert api.form == {"settings-sonarr-apikey": SONARR_NEW}
    assert api.settings["sonarr"]["apikey"] == SONARR_NEW
    assert ctx.holders[-1].outcome == "confirmed"
    assert "confirmed" in result


def test_a_refused_bazarr_write_is_a_failed_holder(tmp_path: Path):
    api = FakeAPI()
    api.deny = True
    ctx, executor = _context(tmp_path, api)
    plan = plan_rotation(ctx.credential, HOST)

    with pytest.raises(RotationError, match="refused"):
        executor._propagate_bazarr(
            _step(plan), holder_for("bazarr", "settings"))
    assert ctx.holders[-1].outcome == "failed"


def test_a_missing_bazarr_section_refuses_before_writing(tmp_path: Path):
    api = FakeAPI()
    del api.settings["sonarr"]
    ctx, executor = _context(tmp_path, api)
    plan = plan_rotation(ctx.credential, HOST)

    with pytest.raises(RotationError, match="no sonarr settings"):
        executor._propagate_bazarr(
            _step(plan), holder_for("bazarr", "settings"))
    assert api.form is None


def test_a_readback_that_still_holds_the_old_key_is_refused(tmp_path: Path):
    api = FakeAPI()
    api.freeze_readback = True
    ctx, executor = _context(tmp_path, api)
    plan = plan_rotation(ctx.credential, HOST)

    with pytest.raises(RotationError, match="does not report the new"):
        executor._propagate_bazarr(
            _step(plan), holder_for("bazarr", "settings"))


class SettingsTransport(FakeTransport):
    def __init__(self, body: dict) -> None:
        super().__init__()
        self.body = body

    def run_python(self, code: str, *, timeout: int | None = None) -> str:
        if "/api/system/settings" in code:
            return "\x00200\x00" + json.dumps(self.body)
        return super().run_python(code, timeout=timeout)


def _audit(monkeypatch, body: dict):
    host = HostConfig(name="media", urls={"bazarr": "http://127.0.0.1:6767"})
    config = Config(version=1, default_host="media", hosts={"media": host},
                    manifest=Path("m.yml"))
    vault = {
        "v": {
            "sonarr": SONARR_OLD,
            "bazarr": BAZARR_KEY,
        }
    }
    monkeypatch.setattr(
        "credarr.audit.build_transport", lambda: SettingsTransport(body))
    return Auditor(
        manifest=_manifest(), config=config, secrets=StaticSource(vault),
        fingerprinter=Fingerprinter(),
    ).run()


def test_the_audit_reads_bazarr_section_equal(monkeypatch):
    result = _audit(monkeypatch, {"sonarr": {"apikey": SONARR_OLD}})

    credential = next(
        row for row in result.results if row.credential.name == "sonarr_api_key")
    assert credential.status is Status.MATCH
    assert credential.consumers[0].status is Status.MATCH


def test_the_audit_reports_a_different_bazarr_value_as_drift(monkeypatch):
    result = _audit(monkeypatch, {"sonarr": {"apikey": "different-key"}})

    credential = next(
        row for row in result.results if row.credential.name == "sonarr_api_key")
    assert credential.status is Status.DRIFT
    assert credential.consumers[0].reason == "value_drift"


# --- Bazarr's own key mint -------------------------------------------------

BAZARR_PENDING = "c0ffee1234567890abcdef1234567890"  # gitleaks:allow

MINT_MANIFEST = """
version: 1
credentials:
  bazarr_api_key:
    class: A
    max_age_days: 90
    canonical: {service: bazarr}
    vault: {backend: ansible-vault, file: v.yml, path: [v, bazarr]}
    write: {mechanism: bazarr_rotate_api}
    consumers:
      - target: homepage.label
        count: 1
        mechanism: redeploy
"""


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


class FakeMintAPI:
    def __init__(self) -> None:
        self.old_live = True
        self.new_key: str | None = None
        self.posted: str | None = None
        self.events: list[str] = []
        # Statuses to answer the next settings POSTs with, in order. A
        # rejection must leave the credential and the process untouched.
        self.reject_next: list[int] = []
        self.attempts: list[str] = []
        # A write can land and still answer 406 (a proxy, a validator that
        # applies before it answers). The fake can model that to prove the
        # engine parks the applied value instead of overwriting it.
        self.apply_on_reject = False

    def __call__(self, _host, service, method, path, *, body=None, key=None,
                 content_type="application/json", **_kwargs):
        if service != "bazarr":
            return 404, None
        self.events.append(f"{method} {path}")
        if path == "/api/system/status" and method == "GET":
            if key == BAZARR_KEY:
                return (200, {}) if self.old_live else (401, None)
            if self.new_key is not None and key == self.new_key:
                return 200, {}
            return 401, None
        if path == "/api/system/settings" and method == "POST":
            if key != BAZARR_KEY or not self.old_live:
                return 401, None
            if content_type != "application/x-www-form-urlencoded":
                return 415, None
            value = (body or {}).get("settings-auth-apikey")
            if not isinstance(value, str):
                return 422, None
            self.attempts.append(value)
            if self.reject_next:
                status = self.reject_next.pop(0)
                if self.apply_on_reject:
                    self.posted = value
                    self.new_key = value
                    self.old_live = False
                return status, None
            self.posted = value
            self.new_key = value
            self.old_live = False
            return 204, None
        return 404, None


def _mint_credential():
    return Manifest.parse(
        MINT_MANIFEST, known_targets=build_registry().known_targets(),
        known_backends=("ansible-vault",),
    ).credentials["bazarr_api_key"]


def _mint_executor(tmp_path: Path, api: FakeMintAPI, pending: FakePending):
    ctx = RotationContext(
        credential=_mint_credential(),
        host=HOST,
        transport=None,
        journal=Journal(tmp_path / "j.db"),
        vault_value=BAZARR_KEY,
        pending=pending,
        settle_timeout=0.0,
    )
    return ctx, Executor(ctx, servarr_call=api)


def test_a_bazarr_own_key_plan_is_a_rotate_with_a_manual_deploy_copy():
    plan = plan_rotation(_mint_credential(), HOST)

    assert plan.blocked_by == []
    assert plan.revokes_before_holders is True
    assert [step.kind for step in plan.steps] == [
        StepKind.MINT, StepKind.MANUAL, StepKind.RECORD,
    ]


def test_the_bazarr_mint_parks_a_letter_bearing_key_before_the_write(
    tmp_path: Path,
):
    api = FakeMintAPI()
    pending = FakePending()
    ctx, executor = _mint_executor(tmp_path, api, pending)

    detail = executor._mint_bazarr(
        Step(StepKind.MINT, "bazarr", "rotate", reversible=False))

    assert "proved the old key dead" in detail
    assert pending.sets and api.posted == pending.sets[0][1]
    assert api.posted is not None and len(api.posted) == 32
    assert any(char.isalpha() for char in api.posted)
    assert ctx.minted is not None and ctx.minted.reveal() == api.posted
    assert ctx.old_key_dead is True


def test_a_pending_bazarr_key_after_the_write_resumes(tmp_path: Path):
    api = FakeMintAPI()
    api.old_live = False
    api.new_key = BAZARR_PENDING
    pending = FakePending({"bazarr_api_key": Secret(BAZARR_PENDING)})
    ctx, executor = _mint_executor(tmp_path, api, pending)

    detail = executor._mint_bazarr(
        Step(StepKind.MINT, "bazarr", "rotate", reversible=False))

    assert "already-rotated" in detail
    assert api.posted is None
    assert ctx.resumed is True


def test_a_parked_bazarr_key_is_written_when_the_old_key_is_still_live(
    tmp_path: Path,
):
    api = FakeMintAPI()
    pending = FakePending({"bazarr_api_key": Secret(BAZARR_PENDING)})
    _ctx, executor = _mint_executor(tmp_path, api, pending)

    executor._mint_bazarr(
        Step(StepKind.MINT, "bazarr", "rotate", reversible=False))

    assert api.posted == BAZARR_PENDING
    assert pending.sets == []


def test_both_bazarr_keys_live_is_refused(tmp_path: Path):
    api = FakeMintAPI()
    api.new_key = BAZARR_PENDING
    pending = FakePending({"bazarr_api_key": Secret(BAZARR_PENDING)})
    _ctx, executor = _mint_executor(tmp_path, api, pending)

    with pytest.raises(RotationError, match="both the stored key"):
        executor._mint_bazarr(
            Step(StepKind.MINT, "bazarr", "rotate", reversible=False))


def test_a_rejected_value_is_replaced_and_the_rotation_completes(
    tmp_path: Path,
):
    api = FakeMintAPI()
    api.reject_next = [406, 406]
    pending = FakePending()
    ctx, executor = _mint_executor(tmp_path, api, pending)

    detail = executor._mint_bazarr(
        Step(StepKind.MINT, "bazarr", "rotate", reversible=False))

    assert "proved the old key dead" in detail
    assert len(api.attempts) == 3
    assert len(set(api.attempts)) == 3, "a rejected value was reused"
    assert api.posted == api.attempts[-1]
    assert ctx.minted is not None and ctx.minted.reveal() == api.posted
    assert pending.values["bazarr_api_key"].reveal() == api.posted


def test_three_rejected_values_fail_closed_with_nothing_parked(
    tmp_path: Path,
):
    api = FakeMintAPI()
    api.reject_next = [406, 406, 406]
    pending = FakePending()
    ctx, executor = _mint_executor(tmp_path, api, pending)

    with pytest.raises(RotationError, match="after 3 chosen values"):
        executor._mint_bazarr(
            Step(StepKind.MINT, "bazarr", "rotate", reversible=False))

    assert len(api.attempts) == 3
    assert api.posted is None
    assert pending.values == {}
    assert ctx.minted is None


def test_an_auth_failure_is_not_retried(tmp_path: Path):
    api = FakeMintAPI()
    api.reject_next = [401]
    pending = FakePending()
    _ctx, executor = _mint_executor(tmp_path, api, pending)

    with pytest.raises(RotationError, match="HTTP 401"):
        executor._mint_bazarr(
            Step(StepKind.MINT, "bazarr", "rotate", reversible=False))

    assert len(api.attempts) == 1
    assert "bazarr_api_key" in pending.values


def test_a_chosen_key_is_always_hex_with_a_letter(tmp_path: Path):
    pending = FakePending()
    _ctx, executor = _mint_executor(tmp_path, FakeMintAPI(), pending)

    keys = {executor._bazarr_choice() for _ in range(2000)}

    for key in keys:
        assert re.fullmatch(r"[0-9a-f]{32}", key), key
        assert any(char.isalpha() for char in key), f"all-numeric: {key}"


def test_a_rejection_that_applied_the_value_is_parked_not_overwritten(
    tmp_path: Path,
):
    api = FakeMintAPI()
    api.reject_next = [406]
    api.apply_on_reject = True
    pending = FakePending()
    ctx, executor = _mint_executor(tmp_path, api, pending)

    with pytest.raises(RotationError, match="no longer authenticates"):
        executor._mint_bazarr(
            Step(StepKind.MINT, "bazarr", "rotate", reversible=False))

    assert len(api.attempts) == 1, "a landed value was overwritten"
    assert pending.values["bazarr_api_key"].reveal() == api.posted
    assert ctx.minted is None
