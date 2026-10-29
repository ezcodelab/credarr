"""The auto-rotation gate: every reason not to mutate, before a worker exists.

The gate is a pure decision over a plan, a stored policy, the last audit rows
and an unwindowed journal answer; the worker calls it under the stack lock so
none of those inputs can move before the run. These tests drive it with no
service, so a missing case is a test failure rather than a live rotation.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from credarr.audit import Status
from credarr.config import HostConfig
from credarr.journal import PendingStep
from credarr.model import Manifest
from credarr.rotate import RotationPlan, Step, StepKind
from credarr.targets import build_registry
from credarr_server.audit_log import AuditRun, ConsumerState, CredentialState, LastState
from credarr_server.auto_rotation import (
    GateDecision,
    gate_reasons,
    manual_or_unproven_targets,
    next_due_at,
)
from credarr_server.store import AutoRotation

REGISTRY = build_registry()
HOST = HostConfig(name="local", )

MANIFEST = """
version: 1
credentials:
  sonarr_api_key:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [a, b]}
    write: {mechanism: servarr_command}
    consumers:
      - target: sonarr.indexers
        count: 2
  radarr_api_key:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [a, c]}
    write: {mechanism: servarr_command}
    consumers:
      - target: radarr.indexers
        count: 1
"""

MANUAL_MANIFEST = """
version: 1
credentials:
  sonarr_api_key:
    class: A-unv
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [a, b]}
    write: {mechanism: servarr_command}
    consumers:
      - target: homepage.label
        count: 1
        mechanism: redeploy
"""


def manifest() -> Manifest:
    return Manifest.parse(
        MANIFEST,
        known_targets=REGISTRY.known_targets(),
        known_backends=("ansible-vault",),
    )


def policy(**overrides) -> AutoRotation:
    values = {
        "credential": "sonarr_api_key",
        "enabled": True,
        "every_days": 30,
        "enabled_at": 1_000.0,
        "last_check_at": None,
        "last_outcome": None,
        "last_detail": "",
        "paused": False,
    }
    values.update(overrides)
    return AutoRotation(**values)


def plan(*, manual: bool = False, blocked: bool = False) -> RotationPlan:
    credential = manifest().credentials["sonarr_api_key"]
    result = RotationPlan(credential=credential, host=HOST)
    result.steps.append(Step(StepKind.MINT, "sonarr", "mint", False))
    if manual:
        result.steps.append(Step(StepKind.MANUAL, "sonarr.indexers", "redeploy"))
    if blocked:
        result.blocked_by.append("credential is class A-unv")
    return result


def clean_state(
    *,
    finished_at: float = 9_500.0,
    newer_failed: bool = False,
    status: Status = Status.MATCH,
    run_status: Status = Status.MATCH,
) -> LastState:
    current = manifest()
    rows = tuple(
        CredentialState(
            credential=name,
            status=status,
            detail="",
            consumers=tuple(
                ConsumerState(str(consumer.target), Status.MATCH, "")
                for consumer in credential.consumers
            ),
        )
        for name, credential in current.credentials.items()
    )
    run = AuditRun(2, 9_000.0, finished_at, 0, run_status, "")
    if newer_failed:
        failed = AuditRun(3, finished_at + 1, finished_at + 2, None, None, "boom")
        return LastState(last_run=failed, last_audit=run, credentials=rows)
    return LastState(last_run=run, last_audit=run, credentials=rows)


def manual_manifest() -> Manifest:
    return Manifest.parse(
        MANUAL_MANIFEST,
        known_targets=REGISTRY.known_targets(),
        known_backends=("ansible-vault",),
    )


def manual_plan() -> RotationPlan:
    credential = manual_manifest().credentials["sonarr_api_key"]
    result = RotationPlan(credential=credential, host=HOST)
    result.steps.append(Step(StepKind.MINT, "sonarr", "mint", False))
    result.steps.append(Step(StepKind.MANUAL, "homepage.label", "redeploy"))
    return result


def manual_state(
    *, credential_status: Status = Status.INDIRECT,
    holder_status: Status = Status.INDIRECT,
    run_status: Status = Status.INDIRECT,
) -> LastState:
    run = AuditRun(2, 9_000.0, 9_500.0, 0, run_status, "")
    return LastState(
        last_run=run,
        last_audit=run,
        credentials=(
            CredentialState(
                "sonarr_api_key",
                credential_status,
                "",
                (ConsumerState("homepage.label", holder_status, ""),),
            ),
        ),
    )


def decision(
    *,
    state: AutoRotation | None = None,
    last_state: LastState | None = None,
    plan_value: RotationPlan | None = None,
    problems: tuple[str, ...] = (),
    unfinished: tuple[PendingStep, ...] = (),
    now: float = 10_000.0,
) -> GateDecision:
    current = manifest()
    return gate_reasons(
        manifest=current,
        credential_name="sonarr_api_key",
        plan=plan_value or plan(),
        problems=problems,
        state=policy() if state is None else state,
        last_state=clean_state() if last_state is None else last_state,
        unfinished=unfinished,
        now=now,
        interval=3_600.0,
        default_host="local",
    )


def test_a_due_credential_with_a_clean_stack_passes_every_gate() -> None:
    result = decision()
    assert result.ready is True
    assert result.detail == ""


def test_auto_is_off_when_no_policy_row_exists() -> None:
    result = decision(state=policy(enabled=False))
    assert not result.ready
    assert result.reasons == ("auto-rotation is off",)


def test_a_paused_policy_needs_a_human() -> None:
    result = decision(state=policy(paused=True, last_detail="interrupted after mint"))
    assert not result.ready
    assert "interrupted after mint" in result.detail


def test_a_manual_step_is_allowed() -> None:
    """A manual copy does not stop the mint; the run notifies afterwards."""
    assert decision(plan_value=plan(manual=True)).ready


def test_a_blocked_plan_is_refused() -> None:
    result = decision(plan_value=plan(blocked=True))
    assert not result.ready
    assert result.reasons


def test_a_plan_with_no_steps_is_refused() -> None:
    empty = RotationPlan(credential=manifest().credentials["sonarr_api_key"], host=HOST)
    assert "no executable steps" in decision(plan_value=empty).detail


def test_a_preflight_problem_is_refused() -> None:
    result = decision(problems=("sonarr: the transport is not configured",))
    assert "transport is not configured" in result.detail


def test_no_audit_blocks() -> None:
    state = LastState(
        last_run=AuditRun(1, 1, 2, None, None, "failed"),
        last_audit=None,
        credentials=(),
    )
    assert "no completed audit" in decision(last_state=state).detail


def test_a_newer_failed_audit_blocks_even_after_a_clean_run() -> None:
    assert "newest audit attempt failed" in decision(
        last_state=clean_state(newer_failed=True)
    ).detail


def test_a_stale_audit_blocks() -> None:
    stale = 10_000.0 - 3_600.0 - 360.0 - 1.0
    assert "stale" in decision(last_state=clean_state(finished_at=stale)).detail


def test_a_non_match_run_blocks() -> None:
    state = clean_state()
    state = replace(
        state,
        last_run=replace(state.last_run, exit_status=Status.DRIFT),
        last_audit=replace(state.last_audit, exit_status=Status.DRIFT),
    )
    assert "not clean" in decision(last_state=state).detail


@pytest.mark.parametrize(
    "status",
    [Status.ERROR, Status.DRIFT, Status.MISSING],
)
def test_a_real_finding_blocks(status: Status) -> None:
    assert "not clean" in decision(last_state=clean_state(run_status=status)).detail


@pytest.mark.parametrize("status", [Status.INDIRECT, Status.UNVERIFIABLE])
def test_manual_aggregate_statuses_do_not_block_a_proven_stack(status: Status) -> None:
    """HOMEPAGE-style aggregates are allowed; a proven holder status is not."""
    assert decision(last_state=clean_state(run_status=status)).ready


def test_a_live_run_and_live_credentials_pass_the_gate() -> None:
    """LIVE is acceptance through an exercised holder, not equality.

    The holder rows stay MATCH here; a LIVE holder is covered separately. The
    run headline and every credential row may be LIVE, because preflight and
    old-key death remain required by the run itself.
    """
    state = clean_state(status=Status.LIVE, run_status=Status.LIVE)
    result = decision(last_state=state)
    assert result.ready, result.detail


def test_a_live_holder_is_accepted_but_never_rewritten_as_match() -> None:
    state = clean_state()
    rows = tuple(
        replace(
            row,
            consumers=(replace(row.consumers[0], status=Status.LIVE),),
        )
        if row.credential == "sonarr_api_key"
        else row
        for row in state.credentials
    )
    assert decision(last_state=replace(state, credentials=rows)).ready


def test_a_missing_or_extra_credential_blocks() -> None:
    state = clean_state()
    missing = tuple(row for row in state.credentials if row.credential != "radarr_api_key")
    assert "credential set" in decision(last_state=replace(state, credentials=missing)).detail

    extra = (*state.credentials, CredentialState("ghost", Status.MATCH, "", ()))
    assert "credential set" in decision(last_state=replace(state, credentials=extra)).detail


def test_a_missing_holder_blocks() -> None:
    state = clean_state()
    rows = tuple(
        replace(row, consumers=())
        if row.credential == "sonarr_api_key"
        else row
        for row in state.credentials
    )
    assert "holders differ" in decision(last_state=replace(state, credentials=rows)).detail


def test_an_indirect_holder_is_left_for_a_manual_step() -> None:
    """The Homepage copy is a manual step, not a reason to freeze the stack."""
    current = manual_manifest()
    credential = current.credentials["sonarr_api_key"]
    assert manual_or_unproven_targets(credential) == {"homepage.label"}
    result = gate_reasons(
        manifest=current,
        credential_name="sonarr_api_key",
        plan=manual_plan(),
        problems=(),
        state=policy(),
        last_state=manual_state(),
        unfinished=(),
        now=10_000.0,
        interval=3_600.0,
        default_host="local",
    )
    assert result.ready, result.detail


def test_a_measured_downloadclient_test_is_not_unproven() -> None:
    """The qBittorrent copy in Sonarr/Radarr is now exercised, so auto-rotation
    treats it like an indexer row with a measured test, not like a manual copy.
    An unmeasured *arr sibling remains unproven."""
    text = """
version: 1
credentials:
  qbittorrent_api_key:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [a, b]}
    write: {mechanism: qbittorrent_rotate_api}
    consumers:
      - target: sonarr.download_clients[qBittorrent:apiKey]
      - target: lidarr.download_clients[qBittorrent:apiKey]
"""
    parsed = Manifest.parse(
        text,
        known_targets=REGISTRY.known_targets(),
        known_backends=("ansible-vault",),
    )
    credential = parsed.credentials["qbittorrent_api_key"]
    assert manual_or_unproven_targets(credential) == {
        "lidarr.download_clients[qBittorrent:apiKey]"
    }


def test_a_proven_copy_that_is_unverifiable_still_blocks() -> None:
    state = clean_state()
    rows = tuple(
        replace(
            row,
            consumers=(replace(row.consumers[0], status=Status.UNVERIFIABLE),),
        )
        if row.credential == "sonarr_api_key"
        else row
        for row in state.credentials
    )
    assert "sonarr.indexers is unverifiable" in decision(
        last_state=replace(state, credentials=rows)
    ).detail


def test_an_extra_or_duplicate_holder_blocks() -> None:
    state = clean_state()
    rows = tuple(
        replace(
            row,
            consumers=(*row.consumers, ConsumerState("sonarr.indexers", Status.MATCH, "")),
        )
        if row.credential == "sonarr_api_key"
        else row
        for row in state.credentials
    )
    assert "holders differ" in decision(last_state=replace(state, credentials=rows)).detail


def test_every_non_match_credential_or_holder_status_blocks() -> None:
    state = clean_state()
    rows = tuple(
        replace(row, status=Status.DRIFT)
        if row.credential == "sonarr_api_key"
        else row
        for row in state.credentials
    )
    assert "sonarr_api_key: the last audit is drift" in decision(
        last_state=replace(state, credentials=rows)
    ).detail

    holder = tuple(
        replace(
            row,
            consumers=(replace(row.consumers[0], status=Status.MISSING),),
        )
        if row.credential == "sonarr_api_key"
        else row
        for row in state.credentials
    )
    assert "holder sonarr.indexers is missing" in decision(
        last_state=replace(state, credentials=holder)
    ).detail


def test_any_unfinished_step_blocks_regardless_of_age() -> None:
    step = PendingStep(
        attempt_id=9,
        credential="radarr_api_key",
        ordinal=1,
        kind="mint",
        target="radarr",
        detail="",
        started_at=1.0,
        seconds_ago=99_999.0,
    )
    assert "unfinished rotation steps" in decision(unfinished=(step,)).detail


def test_a_non_default_holder_host_blocks() -> None:
    current = manifest()
    changed = replace(
        current.credentials["sonarr_api_key"],
        consumers=(
            replace(
                current.credentials["sonarr_api_key"].consumers[0],
                host="remote",
            ),
        ),
    )
    current = replace(current, credentials={**current.credentials, "sonarr_api_key": changed})
    result = gate_reasons(
        manifest=current,
        credential_name="sonarr_api_key",
        plan=plan(),
        problems=(),
        state=policy(),
        last_state=clean_state(),
        unfinished=(),
        now=10_000.0,
        interval=3_600.0,
        default_host="local",
    )
    assert "single-host" in result.detail


def test_the_due_clock_uses_the_newest_success_or_enabled_at() -> None:
    state = policy(enabled_at=1_000.0)
    assert next_due_at(state, None) == 1_000.0 + 30 * 86_400.0
    assert next_due_at(state, 5_000.0) == 5_000.0 + 30 * 86_400.0
    assert next_due_at(policy(paused=True), 5_000.0) is None
    assert next_due_at(policy(enabled=False), 5_000.0) is None


def test_an_absent_no_holder_credential_does_not_freeze_the_stack() -> None:
    """A declared-but-unprovisioned name with nothing holding it is skipped.

    ABSENT must not become a stack-wide blocker for a credential with no copies;
    the per-credential loop already skips INDIRECT/no-holder rows. An ABSENT
    credential that declares holders is still a real coverage gap.
    """
    base = clean_state()
    absent = CredentialState("wave2", Status.ABSENT, "not provisioned", ())
    state = replace(
        base,
        last_run=replace(base.last_run, exit_status=Status.ABSENT),
        last_audit=replace(base.last_audit, exit_status=Status.ABSENT),
        credentials=(*base.credentials, absent),
    )
    manifest_with_empty = replace(
        manifest(),
        credentials={**manifest().credentials, "wave2": _no_holder_credential()},
    )
    result = gate_reasons(
        manifest=manifest_with_empty,
        credential_name="sonarr_api_key",
        plan=plan(),
        problems=(),
        state=policy(),
        last_state=state,
        unfinished=(),
        now=10_000.0,
        interval=3_600.0,
        default_host="local",
    )
    assert result.ready, result.detail

    held = replace(
        manifest_with_empty.credentials["wave2"],
        consumers=(manifest().credentials["sonarr_api_key"].consumers[0],),
    )
    blocked_manifest = replace(
        manifest_with_empty,
        credentials={**manifest_with_empty.credentials, "wave2": held},
    )
    blocked = gate_reasons(
        manifest=blocked_manifest,
        credential_name="sonarr_api_key",
        plan=plan(),
        problems=(),
        state=policy(),
        last_state=state,
        unfinished=(),
        now=10_000.0,
        interval=3_600.0,
        default_host="local",
    )
    assert "not match or live" in blocked.detail


def _no_holder_credential():
    from credarr.model import Credential

    return Credential(name="wave2", credential_class="B", never_rotate=True)


def test_a_manual_mint_plan_is_blocked_for_auto() -> None:
    """Auto cannot supply the key the operator rotated in the service UI."""
    manual = plan()
    manual.mint_via = "provided"

    result = decision(plan_value=manual)

    assert not result.ready
    assert "manual mint" in result.detail


def test_a_reconstructed_plan_remains_eligible_for_auto() -> None:
    """Reconstruct is the automatic no-password path; it has no manual step."""
    reconstructed = plan()
    reconstructed.mint_via = "reconstructed"

    assert decision(plan_value=reconstructed).ready
