"""SABnzbd reset-plus-restart mint, against a fake SABnzbd API.

The measured shape is not a simple rotate: set_apikey returns the new key, but
the running process may keep the old key until mode=restart. These tests pin
the parking order, the restart, and the resume states.
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
from credarr.targets import build_registry

OLD = "a1b2c3d4e5f60718293a4b5c6d7e8f90"  # gitleaks:allow - synthetic
NEW = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"  # gitleaks:allow - synthetic

MANIFEST = """
version: 1
credentials:
  sabnzbd_api_key:
    class: A
    max_age_days: 90
    canonical: {service: sabnzbd}
    vault: {backend: ansible-vault, file: v.yml, path: [v, sabnzbd]}
    write: {mechanism: sabnzbd_rotate_api}
    consumers:
      - target: sonarr.download_clients[SABnzbd:apiKey]
        count: 1
  sonarr_api_key:
    class: B
    never_rotate: true
    canonical: {service: sonarr}
    vault: {backend: ansible-vault, file: v.yml, path: [v, sonarr]}
"""

HOST = HostConfig(
    name="media",
    urls={"sabnzbd": "http://127.0.0.1:8080",
          "sonarr": "http://127.0.0.1:8989"},
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
        self.old_live = True
        self.new_live = False
        self.restarted = False
        self.events: list[str] = []
        self.reset = False

    def __call__(self, _host, service, method, path, *, key=None, **_kwargs):
        if service != "sabnzbd":
            return 404, None
        self.events.append(path)
        if "mode=config" in path and "set_apikey" in path:
            if key != OLD:
                return 403, None
            self.reset = True
            self.new_live = True
            return 200, {"apikey": NEW}
        if "mode=restart" in path:
            if key not in (OLD, NEW):
                return 403, None
            self.restarted = True
            self.old_live = False
            return 200, {"status": True}
        if "mode=queue" in path:
            if key == OLD:
                return (200, {}) if self.old_live else (403, None)
            if key == NEW:
                return (200, {}) if self.new_live else (403, None)
            return 403, None
        return 404, None


def _credential():
    manifest = Manifest.parse(
        MANIFEST, known_targets=build_registry().known_targets(),
        known_backends=("ansible-vault",))
    return manifest.credentials["sabnzbd_api_key"]


def _executor(tmp_path: Path, api: FakeAPI, pending: FakePending):
    ctx = RotationContext(
        credential=_credential(),
        host=HOST,
        transport=None,
        journal=Journal(tmp_path / "j.db"),
        vault_value=OLD,
        pending=pending,
        service_keys={"sonarr": Secret("sonarr-own-key")},
        settle_timeout=0.0,
        write_backoff=0.0,
    )
    return ctx, Executor(ctx, servarr_call=api)


def test_the_plan_is_a_rotate_with_no_revoke_step():
    plan = plan_rotation(_credential(), HOST)

    assert plan.blocked_by == []
    assert plan.executable is True
    assert plan.revokes_before_holders is True
    assert [step.kind for step in plan.steps] == [
        StepKind.MINT, StepKind.PROPAGATE, StepKind.RECORD,
    ]


def test_the_mint_parks_the_new_key_before_restart(tmp_path: Path):
    api = FakeAPI()
    pending = FakePending()
    ctx, executor = _executor(tmp_path, api, pending)

    detail = executor._mint_sabnzbd(
        Step(StepKind.MINT, "sabnzbd", "reset", reversible=False))

    assert "restart" in detail
    assert api.reset is True
    assert api.restarted is True
    assert pending.sets == [("sabnzbd_api_key", NEW)]
    assert ctx.minted is not None and ctx.minted.reveal() == NEW
    assert ctx.old_key_dead is True


def test_a_pending_key_after_restart_resumes_without_a_second_reset(
    tmp_path: Path,
):
    api = FakeAPI()
    api.old_live = False
    api.new_live = True
    api.restarted = True
    pending = FakePending({"sabnzbd_api_key": Secret(NEW)})
    ctx, executor = _executor(tmp_path, api, pending)

    detail = executor._mint_sabnzbd(
        Step(StepKind.MINT, "sabnzbd", "reset", reversible=False))

    assert "already-rotated" in detail
    assert api.reset is False
    assert ctx.resumed is True
    assert ctx.minted is not None and ctx.minted.reveal() == NEW


def test_a_pre_restart_pending_key_restarts_instead_of_resetting(
    tmp_path: Path,
):
    api = FakeAPI()
    api.old_live = True
    api.new_live = True
    api.restarted = False
    pending = FakePending({"sabnzbd_api_key": Secret(NEW)})
    ctx, executor = _executor(tmp_path, api, pending)

    executor._mint_sabnzbd(
        Step(StepKind.MINT, "sabnzbd", "reset", reversible=False))

    assert api.reset is False
    assert api.restarted is True
    assert ctx.old_key_dead is True


def test_neither_key_live_fails_closed(tmp_path: Path):
    api = FakeAPI()
    api.old_live = False
    api.new_live = False
    pending = FakePending()
    _ctx, executor = _executor(tmp_path, api, pending)

    with pytest.raises(RotationError, match="neither the stored key"):
        executor._mint_sabnzbd(
            Step(StepKind.MINT, "sabnzbd", "reset", reversible=False))
