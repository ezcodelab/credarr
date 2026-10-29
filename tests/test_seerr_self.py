"""Seerr's own API key, rotated over its settings API, against a fake service.

The measured facts (3.5.0 @ e2f24cb):
`POST /settings/main` rejects a chosen `apiKey` (HTTP 400, readOnly in the
spec), and `POST /settings/main/regenerate` answers with the random new key
while the old one stops working immediately. The response is the only copy, so
these pin the pending-store order and the two states that must refuse: no
pending store, and a pinned `API_KEY` that returns the stored value unchanged.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from credarr.config import HostConfig
from credarr.errors import RotationError
from credarr.executor import Executor, RotationContext
from credarr.journal import Journal
from credarr.model import Manifest
from credarr.redact import Secret
from credarr.rotate import Step, StepKind, plan_rotation

OLD = "o" * 32
NEW = "n" * 32

MANIFEST = """
version: 1
credentials:
  seerr_api_key:
    class: A
    max_age_days: 90
    canonical: {service: seerr}
    vault: {backend: ansible-vault, file: v.yml, path: [v, seerr]}
    write: {mechanism: seerr_regenerate}
"""


def _credential():
    manifest = Manifest.parse(
        MANIFEST, known_targets=(), known_backends=("ansible-vault",)
    )
    return next(iter(manifest.credentials.values()))


HOST = HostConfig(
    name="media", urls={"seerr": "http://127.0.0.1:5055"},
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
    """The measured routes: /auth/me for liveness, regenerate for the mint.

    The new key is accepted only once it is parked, so a reordered
    implementation that proves it before writing it to the pending store fails
    here instead of passing on an assumption.
    """

    def __init__(self, *, pinned: bool = False) -> None:
        self.key = OLD
        self.pinned = pinned
        self.regenerates = 0
        self.pending: FakePending | None = None
        self.calls: list[tuple[str, str, str, str]] = []

    def __call__(self, _host, service, method, path, *, body=None,
                 key=None, auth_header="X-Api-Key", **_kwargs):
        self.calls.append((service, method, path, auth_header))
        if service != "seerr" or auth_header != "X-API-Key":
            return 404, None
        parked = (
            self.pending is not None
            and self.pending.get("seerr_api_key") is not None
        )
        if path == "/auth/me":
            live = key == self.key and (key != NEW or parked)
            return (200, {"id": 1}) if live else (403, {})
        if path == "/settings/main/regenerate" and method == "POST":
            if key != self.key:
                return 403, None
            self.regenerates += 1
            if not self.pinned:
                # The real route replaces the key before answering.
                self.key = NEW
            return 200, {"apiKey": self.key}
        return 404, None


def _executor(tmp_path: Path, api: FakeAPI, pending, *, vault_value=OLD):
    api.pending = pending
    ctx = RotationContext(
        credential=_credential(),
        host=HOST,
        transport=None,  # not reached: every call is the fake
        journal=Journal(tmp_path / "j.db"),
        vault_value=vault_value,
        pending=pending,
        settle_timeout=0.0,
        write_backoff=0.0,
    )
    return Executor(ctx, servarr_call=api), ctx


def _step() -> Step:
    return Step(StepKind.MINT, "seerr", "regenerate", reversible=False)


def test_the_plan_recognises_seerrs_regenerate_mechanism():
    plan = plan_rotation(_credential(), HOST)

    assert plan.blocked_by == []
    assert plan.executable is True
    assert plan.revokes_before_holders is True
    assert plan.mint_via == "regenerate"
    assert [step.kind for step in plan.steps] == [StepKind.MINT, StepKind.RECORD]
    assert plan.steps[0].detail == "POST /api/v1/settings/main/regenerate"


def test_the_conventional_name_resolves_without_a_canonical_service():
    """`seerr_api_key` must resolve like every other `<service>_api_key`."""
    manifest = Manifest.parse(
        MANIFEST.replace("    canonical: {service: seerr}\n", ""),
        known_targets=(), known_backends=("ansible-vault",),
    )
    credential = next(iter(manifest.credentials.values()))

    plan = plan_rotation(credential, HOST)

    assert plan.blocked_by == []
    assert plan.executable is True


def test_the_mint_parks_the_key_before_proving_it(tmp_path: Path):
    api = FakeAPI()
    pending = FakePending()
    executor, ctx = _executor(tmp_path, api, pending)

    detail = executor._mint_seerr(_step())

    assert "regenerated" in detail
    assert ctx.minted == Secret(NEW)
    assert ctx.old_key_dead is True
    assert pending.sets == [("seerr_api_key", NEW)]
    assert ("seerr", "POST", "/settings/main/regenerate", "X-API-Key") in api.calls
    assert {header for _s, _m, _p, header in api.calls} == {"X-API-Key"}


def test_a_parked_key_resumes_without_regenerating_again(tmp_path: Path):
    api = FakeAPI()
    api.key = NEW
    pending = FakePending({"seerr_api_key": Secret(NEW)})
    executor, ctx = _executor(tmp_path, api, pending)

    detail = executor._mint_seerr(_step())

    assert detail.startswith("already-rotated")
    assert ctx.resumed is True
    assert api.regenerates == 0
    assert pending.sets == []


def test_a_dead_parked_key_does_not_fake_a_resume(tmp_path: Path):
    """A parked value from an earlier attempt is not a key the service holds."""
    api = FakeAPI()
    pending = FakePending({"seerr_api_key": Secret(NEW)})
    executor, ctx = _executor(tmp_path, api, pending)

    executor._mint_seerr(_step())

    assert api.regenerates == 1
    assert ctx.resumed is False


def test_a_pinned_api_key_response_is_refused(tmp_path: Path):
    api = FakeAPI(pinned=True)
    pending = FakePending()
    executor, ctx = _executor(tmp_path, api, pending)

    with pytest.raises(RotationError, match="unchanged"):
        executor._mint_seerr(_step())

    assert api.key == OLD
    assert pending.sets == []
    assert ctx.minted is None


def test_the_mint_refuses_without_a_pending_store(tmp_path: Path):
    api = FakeAPI()
    executor, _ctx = _executor(tmp_path, api, None)

    with pytest.raises(RotationError, match="pending-secret"):
        executor._mint_seerr(_step())

    assert api.regenerates == 0


def test_a_dead_stored_key_with_no_pending_key_is_refused(tmp_path: Path):
    api = FakeAPI()
    api.key = NEW
    executor, _ctx = _executor(tmp_path, api, FakePending())

    with pytest.raises(RotationError, match="neither the stored key"):
        executor._mint_seerr(_step())

    assert api.regenerates == 0


def test_preflight_requires_the_pending_store_and_a_stored_value(tmp_path: Path):
    plan = plan_rotation(_credential(), HOST)

    api = FakeAPI()
    executor, _ctx = _executor(tmp_path, api, FakePending())
    assert executor.preflight(plan) == []

    executor, _ctx = _executor(tmp_path, api, None)
    problems = executor.preflight(plan)
    assert any("pending-secret" in problem for problem in problems), problems

    executor, _ctx = _executor(tmp_path, api, FakePending(), vault_value=None)
    problems = executor.preflight(plan)
    assert any("no value for this credential" in problem for problem in problems)
