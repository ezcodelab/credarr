"""The worker behind auto-rotation: one audit signal, no timer, no second executor.

The test stack's audit is real; only the service mutation is replaced, so these
tests pin the journal and policy transitions without touching a live holder.
"""

from __future__ import annotations

import sqlite3
import threading
import time

from conftest import SONARR_KEY
from credarr import facade
from credarr.executor import ExecutionResult
from credarr.journal import STACK_LOCK, JournalLocked
from credarr.rotate import RotationPlan, Step, StepKind
from credarr_server import auto_rotation
from credarr_server.audit_log import AuditLog
from credarr_server.auto_rotation import AutoRotator
from credarr_server.scheduler import Scheduler


def real_audit(app) -> AuditLog:
    log = AuditLog(app.store.path)
    assert Scheduler(app.store, log, app.config, interval=86_400).once() is not None
    return log


def harness(app, log: AuditLog, prepare):
    journal = facade.journal_for(app.config)
    worker = AutoRotator(
        app.store,
        app.config,
        log,
        journal,
        interval=10**9,
        prepare=prepare,
    )
    return worker, journal


def prepare_for(app):
    manifest = app.store.load_manifest()
    credential = manifest.credentials["sonarr_api_key"]
    host = app.config.host(app.config.default_host)
    plan = RotationPlan(credential=credential, host=host)
    plan.steps.append(Step(StepKind.MINT, "sonarr", "fake mint", reversible=False))

    def prepare(name: str):
        return credential, host, plan, [], 0, {}, {}

    return prepare


def test_a_due_credential_runs_only_after_a_completed_audit(app) -> None:
    log = AuditLog(app.store.path)
    called: list[str] = []

    def prepare(name: str):
        called.append(name)
        return prepare_for(app)(name)

    worker, _journal = harness(app, log, prepare)
    app.store.enable_auto_rotation("sonarr_api_key", 1, now=0)

    # No audit has been recorded, so there is no stack-wide MATCH to authorize.
    outcome = worker.run_due(now=time.time())
    assert outcome[0].outcome == "blocked"
    assert called == []
    assert app.store.auto_rotation("sonarr_api_key").paused is False
    assert worker.journal.open_attempts() == {}
    assert [event.kind for event in log.recent_events()] == ["auto_blocked"]


def test_a_clean_audit_triggers_a_due_success_and_the_journal_defers_it(
    app, monkeypatch
) -> None:
    log = real_audit(app)
    prepare = prepare_for(app)
    worker, journal = harness(app, log, prepare)
    app.store.enable_auto_rotation("sonarr_api_key", 1, now=0)

    # Build the result without depending on the executor's private helpers.
    def fake_execute(**kwargs):
        attempt = journal.begin("sonarr_api_key")
        kwargs["on_started"](attempt)
        journal.finish(attempt, "completed")
        return ExecutionResult(credential="sonarr_api_key", attempt=attempt)

    monkeypatch.setattr(auto_rotation.facade, "execute", fake_execute)
    outcome = worker.run_due(now=time.time())
    assert outcome[0].outcome == "succeeded"
    state = app.store.auto_rotation("sonarr_api_key")
    assert state is not None and state.last_outcome == "succeeded" and not state.paused
    last_success = journal.last_success("sonarr_api_key")
    assert last_success is not None
    events = log.recent_events()
    assert [event.kind for event in events[:2]] == ["auto_succeeded", "auto_started"]
    assert all(event.detail.startswith("auto:schedule: ") for event in events)
    # The outcome is stamped at completion, not at the start of the pass.
    assert events[0].at >= events[1].at
    assert SONARR_KEY not in state.last_detail
    assert all(SONARR_KEY not in event.detail for event in events)
    assert worker.run_due(now=time.time()) == []


def test_a_journal_lock_skips_without_pausing(app, monkeypatch) -> None:
    log = real_audit(app)
    worker, _journal = harness(app, log, prepare_for(app))
    app.store.enable_auto_rotation("sonarr_api_key", 1, now=0)

    def locked(**_kwargs):
        raise JournalLocked("held by console")

    monkeypatch.setattr(auto_rotation.facade, "execute", locked)
    outcome = worker.run_due(now=time.time())
    assert outcome[0].outcome == "blocked"
    assert "already running" in outcome[0].detail
    state = app.store.auto_rotation("sonarr_api_key")
    assert state is not None and state.paused is False


def test_a_console_stack_lock_skips_without_writing_policy(app, monkeypatch) -> None:
    """Auto takes the same lease as the HTTP routes.

    A console rotation or import owns the stack; the pass must skip, not plan
    against a topology that is about to change, and not write a policy outcome
    over a concurrent disable.
    """
    log = real_audit(app)
    worker, journal = harness(app, log, prepare_for(app))
    app.store.enable_auto_rotation("sonarr_api_key", 1, now=0)
    before = app.store.auto_rotation("sonarr_api_key")
    called: list[str] = []

    def execute(**kwargs):
        called.append(kwargs["credential"].name)
        return ExecutionResult(credential=kwargs["credential"].name, attempt=1)

    monkeypatch.setattr(auto_rotation.facade, "execute", execute)
    with journal.lock(STACK_LOCK, "console:import"):
        outcome = worker.run_due(now=time.time())

    assert outcome[0].outcome == "blocked"
    assert "configuration change is in progress" in outcome[0].detail
    assert called == []
    assert app.store.auto_rotation("sonarr_api_key") == before
    assert journal.open_attempts() == {}
    assert log.recent_events() == ()


def test_a_run_that_started_and_failed_pauses(app, monkeypatch) -> None:
    log = real_audit(app)
    worker, journal = harness(app, log, prepare_for(app))
    app.store.enable_auto_rotation("sonarr_api_key", 1, now=0)

    def failed(**_kwargs):
        attempt = journal.begin("sonarr_api_key")
        return ExecutionResult(
            credential="sonarr_api_key",
            attempt=attempt,
            failed="sonarr",
            detail="mint failed",
        )

    monkeypatch.setattr(auto_rotation.facade, "execute", failed)
    outcome = worker.run_due(now=time.time())
    assert outcome[0].outcome == "interrupted"
    state = app.store.auto_rotation("sonarr_api_key")
    assert state is not None and state.paused is True
    assert "review it" in state.last_detail
    assert worker.run_due(now=time.time()) == []


def test_an_exception_before_the_attempt_starts_does_not_pause(app, monkeypatch) -> None:
    log = real_audit(app)
    worker, _journal = harness(app, log, prepare_for(app))
    app.store.enable_auto_rotation("sonarr_api_key", 1, now=0)

    def broken(**_kwargs):
        raise RuntimeError("the plan was stale")

    monkeypatch.setattr(auto_rotation.facade, "execute", broken)
    outcome = worker.run_due(now=time.time())
    assert outcome[0].outcome == "blocked"
    state = app.store.auto_rotation("sonarr_api_key")
    assert state is not None and state.paused is False


def test_startup_reconciliation_pauses_an_unwindowed_unfinished_run(app) -> None:
    log = real_audit(app)
    worker, journal = harness(app, log, prepare_for(app))
    app.store.enable_auto_rotation("sonarr_api_key", 1, now=0)
    attempt = journal.begin("sonarr_api_key")
    journal.step_started(attempt, 0, "mint", "sonarr", "backup/restore")
    with sqlite3.connect(journal.path) as connection:
        connection.execute(
            "UPDATE steps SET started_at = ? WHERE attempt_id = ?",
            (time.time() - 10_000, attempt),
        )

    paused = worker.reconcile_startup()
    assert paused == ["sonarr_api_key"]
    state = app.store.auto_rotation("sonarr_api_key")
    assert state is not None and state.paused is True
    assert "did not finish" in state.last_detail


def test_a_manual_success_defers_the_auto_due_clock(app) -> None:
    """Manual, CLI and auto runs share one journal; a manual copy still counts.

    The key was rotated. Leaving the copy for a human must not make the worker
    retry the mint on the next audit, so the due clock uses `last_rotation`.
    """
    log = real_audit(app)
    worker, journal = harness(app, log, prepare_for(app))
    app.store.enable_auto_rotation("sonarr_api_key", 1, now=0)
    attempt = journal.begin("sonarr_api_key")
    journal.step_started(attempt, 0, "manual", "homepage.label", "redeploy")
    journal.step_finished(attempt, 0, "noted")
    journal.finish(attempt, "completed")

    called: list[str] = []

    def prepare(name: str):
        called.append(name)
        return prepare_for(app)(name)

    worker.prepare = prepare
    assert worker.run_due(now=time.time()) == []
    assert called == []
    assert journal.last_success("sonarr_api_key") is None
    assert journal.last_rotation("sonarr_api_key") is not None


def test_an_auto_run_with_a_manual_copy_notifies_and_stays_enabled(
    app, monkeypatch
) -> None:
    log = real_audit(app)
    worker, journal = harness(app, log, prepare_for(app))
    app.store.enable_auto_rotation("sonarr_api_key", 1, now=0)

    def manual(**_kwargs):
        attempt = journal.begin("sonarr_api_key")
        journal.step_started(attempt, 0, "manual", "homepage.label", "redeploy")
        journal.step_finished(attempt, 0, "noted")
        journal.finish(attempt, "completed")
        return ExecutionResult(
            credential="sonarr_api_key",
            attempt=attempt,
            manual=["homepage.label"],
        )

    monkeypatch.setattr(auto_rotation.facade, "execute", manual)
    outcome = worker.run_due(now=time.time())
    assert outcome[0].outcome == "manual"
    state = app.store.auto_rotation("sonarr_api_key")
    assert state is not None and state.last_outcome == "manual"
    assert state.paused is False
    assert "Homepage needs manual rotation" in state.last_detail
    assert journal.last_success("sonarr_api_key") is None
    assert journal.last_rotation("sonarr_api_key") is not None
    events = log.recent_events()
    assert events[0].kind == "auto_manual"
    assert "Homepage needs manual rotation" in events[0].detail
    assert worker.run_due(now=time.time()) == []


def test_startup_reconciliation_also_sees_an_attempt_with_no_steps(app) -> None:
    log = real_audit(app)
    worker, journal = harness(app, log, prepare_for(app))
    app.store.enable_auto_rotation("sonarr_api_key", 1, now=0)
    journal.begin("sonarr_api_key")

    assert worker.reconcile_startup() == ["sonarr_api_key"]
    assert app.store.auto_rotation("sonarr_api_key").paused is True


def test_the_worker_runs_on_a_signal_and_stops_cleanly(app, monkeypatch) -> None:
    log = real_audit(app)
    worker, journal = harness(app, log, prepare_for(app))
    app.store.enable_auto_rotation("sonarr_api_key", 1, now=0)
    ran = threading.Event()

    def fake_execute(**_kwargs):
        attempt = journal.begin("sonarr_api_key")
        journal.finish(attempt, "completed")
        ran.set()
        return ExecutionResult(credential="sonarr_api_key", attempt=attempt)

    monkeypatch.setattr(auto_rotation.facade, "execute", fake_execute)
    worker.start()
    try:
        worker.notify()
        # Generous: this runner can be several times slower than a laptop, and
        # a signal that has not arrived yet is not a failure.
        assert ran.wait(20), "the worker did not process the completed-audit signal"
    finally:
        worker.stop()
    assert worker.running is False


def test_a_disable_during_its_own_plan_stops_before_execute(app, monkeypatch) -> None:
    log = real_audit(app)
    worker, _journal = harness(app, log, prepare_for(app))
    app.store.enable_auto_rotation("sonarr_api_key", 1, now=0)
    executed: list[str] = []

    def prepare(name: str):
        app.store.disable_auto_rotation(name)
        return prepare_for(app)(name)

    def fake_execute(**kwargs):
        executed.append(kwargs["credential"].name)
        return ExecutionResult(credential=kwargs["credential"].name, attempt=1)

    worker.prepare = prepare
    monkeypatch.setattr(auto_rotation.facade, "execute", fake_execute)
    outcome = worker.run_due(now=time.time())
    assert outcome[0].outcome == "blocked"
    assert executed == []
    state = app.store.auto_rotation("sonarr_api_key")
    assert state is not None and state.enabled is False and state.last_outcome is None


def test_a_disable_during_a_pass_wins_before_the_next_credential(
    app, monkeypatch
) -> None:
    """The next candidate re-reads its policy; a pass snapshot is not authority."""
    log = real_audit(app)
    worker, _journal = harness(app, log, prepare_for(app))
    app.store.enable_auto_rotation("aaa_other", 1, now=0)
    app.store.enable_auto_rotation("sonarr_api_key", 1, now=0)
    prepared: list[str] = []
    executed: list[str] = []

    def prepare(name: str):
        prepared.append(name)
        if name == "aaa_other":
            app.store.disable_auto_rotation("sonarr_api_key")
        return prepare_for(app)(name)

    def fake_execute(**kwargs):
        executed.append("call")
        return ExecutionResult(credential="aaa_other", attempt=1)

    worker.prepare = prepare
    monkeypatch.setattr(auto_rotation, "audit_blocker", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        auto_rotation,
        "gate_reasons",
        lambda **kwargs: auto_rotation.GateDecision(()),
    )
    monkeypatch.setattr(auto_rotation.facade, "execute", fake_execute)
    outcomes = worker.run_due(now=time.time())
    assert [outcome.outcome for outcome in outcomes] == ["succeeded", "blocked"]
    assert prepared == ["aaa_other"]
    assert executed == ["call"]
    state = app.store.auto_rotation("sonarr_api_key")
    assert state is not None and state.enabled is False and state.last_outcome is None


def test_next_due_is_the_earliest_enabled_policy(app) -> None:
    log = real_audit(app)
    worker, _journal = harness(app, log, prepare_for(app))
    assert worker.next_due(0.0) is None

    app.store.enable_auto_rotation("sonarr_api_key", 1, now=1_000.0)
    assert worker.next_due(0.0) == 1_000.0 + 86_400.0
    app.store.disable_auto_rotation("sonarr_api_key")
    assert worker.next_due(0.0) is None


def test_next_due_ignores_a_stuck_past_policy_for_scheduling(app) -> None:
    log = real_audit(app)
    worker, _journal = harness(app, log, prepare_for(app))
    app.store.enable_auto_rotation("sonarr_api_key", 1, now=0.0)
    app.store.enable_auto_rotation("seerr_api_key", 1, now=100_000.0)
    now = 100_000.0
    assert worker.next_due(now) == now + 86_400.0
    assert worker.has_due(now) is True
    assert worker.has_due(0.0) is False


def test_a_paused_policy_is_not_a_due_time(app) -> None:
    log = real_audit(app)
    worker, _journal = harness(app, log, prepare_for(app))
    app.store.enable_auto_rotation("sonarr_api_key", 1, now=1_000.0)
    app.store.record_auto_rotation(
        "sonarr_api_key", "interrupted", "review", checked_at=2_000.0, paused=True
    )
    assert worker.next_due(0.0) is None
