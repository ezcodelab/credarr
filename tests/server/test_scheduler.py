"""The loop: audit, record, repeat - and a restart does not forget.

The scheduler is what keeps the ledger live. These run it against the real
fake stack: a clean run recorded as clean, drift recorded as drift, a failure
recorded without stopping the loop, and an interval loop that stops when told.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

import pytest

from credarr.audit import AuditResult, Status
from credarr.errors import ManifestError
from credarr.redact import Secret
from credarr.targets import build_registry
from credarr_server import scheduler as scheduler_module
from credarr_server.audit_log import AuditLog
from credarr_server.scheduler import Scheduler
from credarr_server.store import UnknownCredential

REGISTRY = build_registry()


def _scheduler(app, *, interval: float = 60.0) -> Scheduler:
    return Scheduler(
        app.store, AuditLog(app.store.path), app.config, interval=interval, registry=REGISTRY
    )


def _runs(database: Path) -> int:
    with sqlite3.connect(database) as connection:
        return connection.execute("SELECT COUNT(*) FROM audit_runs").fetchone()[0]


def test_a_clean_run_is_recorded(app) -> None:
    scheduler = _scheduler(app)
    result = scheduler.once()
    assert result is not None and result.exit_status is Status.MATCH
    state = scheduler.log.last_state()
    assert state is not None and state.last_run.exit_status is Status.MATCH


def test_drift_is_recorded(app) -> None:
    app.store.set_value("sonarr_api_key", Secret("0" * 32))
    scheduler = _scheduler(app)
    result = scheduler.once()
    assert result is not None and result.exit_status is Status.DRIFT
    state = scheduler.log.last_state()
    assert state is not None
    assert state.last_run.exit_status is Status.DRIFT
    assert next(
        c for c in state.credentials if c.credential == "sonarr_api_key"
    ).status is Status.DRIFT


def test_a_reportable_failure_is_recorded_and_does_not_raise(
    app, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(store) -> None:
        raise ManifestError("the store went sideways")

    monkeypatch.setattr("credarr_server.scheduler.runtime_manifest", boom)
    scheduler = _scheduler(app)
    assert scheduler.once() is None

    state = scheduler.log.last_state()
    assert state is not None
    assert state.last_run.exit_status is None
    assert state.last_run.exit_code == ManifestError.exit_code
    assert state.last_run.detail.startswith("ManifestError: the store went sideways")


def test_a_bug_is_recorded_without_an_exit_code(app, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(store) -> None:
        raise RuntimeError("nobody planned for this")

    monkeypatch.setattr("credarr_server.scheduler.runtime_manifest", boom)
    scheduler = _scheduler(app)
    assert scheduler.once() is None

    state = scheduler.log.last_state()
    assert state is not None
    assert state.last_run.exit_code is None
    assert state.last_run.detail == "RuntimeError: nobody planned for this"


def test_a_scoped_check_that_loses_its_credential_is_not_a_500(
    app, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The route checks the manifest, then the audit reads it again.

    A concurrent delete/import between those two reads is a 404, not an
    internal error from the scoped call.
    """
    scheduler = _scheduler(app)
    monkeypatch.setattr(
        scheduler_module.facade,
        "audit",
        lambda *args, **kwargs: AuditResult(),
    )
    with pytest.raises(UnknownCredential):
        scheduler.check("sonarr_api_key")


def test_a_new_scheduler_appends_to_the_recorded_history(app) -> None:
    """A restart is new objects on the same database; it must add to the
    ledger, not clobber it."""
    _scheduler(app).once()
    second = _scheduler(app)
    second.once()
    assert _runs(app.store.path) == 2
    state = second.log.last_state()
    assert state is not None and state.last_run.id == 2


def test_overlapping_runs_are_serialised(app, monkeypatch: pytest.MonkeyPatch) -> None:
    """`/audit` and the interval tick share one scheduler. Two runs in flight
    can finish in the opposite order from their ids, so the second call waits
    instead of reading the stack beside the first."""
    scheduler = _scheduler(app)
    real_audit = scheduler_module.facade.audit
    active = 0
    peak = 0
    count_lock = threading.Lock()
    start = threading.Barrier(2)

    def slow_audit(*args, **kwargs):
        nonlocal active, peak
        with count_lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.1)
            return real_audit(*args, **kwargs)
        finally:
            with count_lock:
                active -= 1

    monkeypatch.setattr(scheduler_module.facade, "audit", slow_audit)
    errors: list[BaseException] = []

    def run() -> None:
        try:
            start.wait(timeout=5)
            scheduler.once()
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=run), threading.Thread(target=run)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert not errors
    assert all(not thread.is_alive() for thread in threads)
    assert peak == 1


def test_a_scoped_check_and_full_audit_are_serialised(
    app, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A check shares the audit lock, so the two cannot hammer holders twice."""
    scheduler = _scheduler(app)
    real_audit = scheduler_module.facade.audit
    active = 0
    peak = 0
    count_lock = threading.Lock()
    start = threading.Barrier(2)

    def slow_audit(*args, **kwargs):
        nonlocal active, peak
        with count_lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.1)
            return real_audit(*args, **kwargs)
        finally:
            with count_lock:
                active -= 1

    monkeypatch.setattr(scheduler_module.facade, "audit", slow_audit)
    errors: list[BaseException] = []

    def checked() -> None:
        try:
            start.wait(timeout=5)
            scheduler.check("sonarr_api_key")
        except BaseException as exc:
            errors.append(exc)

    def full() -> None:
        try:
            start.wait(timeout=5)
            scheduler.once()
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=checked), threading.Thread(target=full)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert not errors
    assert all(not thread.is_alive() for thread in threads)
    assert peak == 1
    assert _runs(app.store.path) == 1
    checks = scheduler.log.checks("sonarr_api_key")
    assert [check.source for check in checks].count("check") == 1
    assert [check.source for check in checks].count("audit") == 1


def test_a_disabled_schedule_does_not_audit_on_startup(app) -> None:
    calls: list[float] = []
    scheduler = Scheduler(
        app.store,
        AuditLog(app.store.path),
        app.config,
        interval=60.0,
        enabled=False,
        registry=REGISTRY,
    )
    scheduler.once = lambda: calls.append(time.monotonic())
    assert scheduler._wait_seconds(time.time(), woken=False) is None

    stop = threading.Event()
    loop = threading.Thread(target=scheduler.serve, args=(stop,), daemon=True)
    loop.start()
    time.sleep(0.15)
    assert calls == []
    stop.set()
    loop.join(timeout=5)
    assert not loop.is_alive()


def test_a_disabled_schedule_still_audits_a_due_auto_rotation(app) -> None:
    calls: list[float] = []
    scheduler = Scheduler(
        app.store,
        AuditLog(app.store.path),
        app.config,
        interval=60.0,
        enabled=False,
        registry=REGISTRY,
        next_due=lambda _now: None,
        has_due=lambda _now: True,
    )
    scheduler.once = lambda: calls.append(time.monotonic())

    stop = threading.Event()
    loop = threading.Thread(target=scheduler.serve, args=(stop,), daemon=True)
    loop.start()
    deadline = time.monotonic() + 2
    while not calls and time.monotonic() < deadline:
        time.sleep(0.01)
    stop.set()
    loop.join(timeout=5)
    assert calls, "a due auto-rotation was ignored while the schedule was off"


def test_the_interval_must_be_positive(app) -> None:
    """Anything that would not actually wait is refused here as well as at the
    command line: zero and negatives audit back-to-back, and `nan` does too
    (`Event.wait(nan)` never blocks), which is the sneaky one."""
    for bad in (0, -1.0, float("nan"), float("inf")):
        with pytest.raises(ValueError, match="positive, finite"):
            _scheduler(app, interval=bad)


def test_a_database_that_cannot_be_written_is_not_swallowed(
    app, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guarantee covers run outcomes, not persistence: a loop that cannot
    record its state must fail visibly rather than look alive with a stale
    dashboard."""
    def broken(self, result, *, started_at: float) -> int:
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(AuditLog, "record", broken)
    with pytest.raises(sqlite3.OperationalError, match="disk I/O error"):
        _scheduler(app).once()


def test_serve_audits_immediately_then_waits(app) -> None:
    """The first run must not wait for the interval, and `stop` must cut the
    wait short: a 60-second interval still stops within the test."""
    scheduler = _scheduler(app, interval=60.0)
    stop = threading.Event()
    loop = threading.Thread(target=scheduler.serve, args=(stop,), daemon=True)
    loop.start()
    deadline = time.monotonic() + 5
    while _runs(app.store.path) < 1 and time.monotonic() < deadline:
        time.sleep(0.01)
    # Before `stop`, not merely by the end: the audit runs first, not on the
    # way out of the loop.
    assert _runs(app.store.path) == 1
    # And the interval is a wait, not a spin: with a 60-second interval the
    # loop must not add runs while it waits.
    time.sleep(0.2)
    assert _runs(app.store.path) == 1
    stop.set()
    loop.join(timeout=5)
    assert not loop.is_alive()
    assert _runs(app.store.path) == 1


def test_serve_ends_when_a_run_raises(
    app, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`serve` documents that an exception ends the loop; the caller owns
    what happens next. Pinned here rather than left to the reader."""
    def broken(self, result, *, started_at: float) -> int:
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(AuditLog, "record", broken)
    with pytest.raises(sqlite3.OperationalError, match="disk I/O error"):
        _scheduler(app, interval=0.01).serve(threading.Event())
    assert _runs(app.store.path) == 0


def test_serve_audits_on_its_interval_until_stopped(app) -> None:
    scheduler = _scheduler(app, interval=0.02)
    stop = threading.Event()
    loop = threading.Thread(target=scheduler.serve, args=(stop,), daemon=True)
    loop.start()
    deadline = time.monotonic() + 5
    while _runs(app.store.path) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    stop.set()
    loop.join(timeout=5)
    assert not loop.is_alive()
    assert _runs(app.store.path) >= 2


def test_only_a_completed_audit_signals_auto(
    app, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The signal is the completed-audit event, not a clock or an exception."""
    calls: list[bool] = []
    scheduler = Scheduler(
        app.store,
        AuditLog(app.store.path),
        app.config,
        interval=60.0,
        registry=REGISTRY,
        on_audit=lambda: calls.append(True),
    )
    assert scheduler.once() is not None
    assert calls == [True]

    def boom(store) -> None:
        raise ManifestError("the store went sideways")

    monkeypatch.setattr("credarr_server.scheduler.runtime_manifest", boom)
    assert scheduler.once() is None
    assert calls == [True]


def test_serve_audits_at_a_due_time_before_the_interval(app) -> None:
    """A long audit interval must not delay a scheduled rotation.

    The scheduler asks for the earliest due time after each run and wakes for
    it, so the due run gets a fresh audit immediately. The audit signal then
    lets the auto worker act.
    """
    calls: list[float] = []
    due: list[float] = []

    def next_due(now: float) -> float:
        if not due:
            due.append(now + 0.05)
        return due[0]

    scheduler = Scheduler(
        app.store,
        AuditLog(app.store.path),
        app.config,
        interval=60.0,
        registry=REGISTRY,
        next_due=next_due,
    )
    scheduler.once = lambda: calls.append(time.monotonic())

    stop = threading.Event()
    loop = threading.Thread(target=scheduler.serve, args=(stop,), daemon=True)
    loop.start()
    deadline = time.monotonic() + 2
    while len(calls) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    stop.set()
    loop.join(timeout=5)

    assert not loop.is_alive()
    assert len(calls) >= 2, calls
    assert calls[1] - calls[0] >= 0.03, calls


def test_a_wake_with_a_past_due_audits_immediately(app) -> None:
    scheduler = Scheduler(
        app.store,
        AuditLog(app.store.path),
        app.config,
        interval=60.0,
        registry=REGISTRY,
        next_due=lambda now: None,
        has_due=lambda now: True,
    )
    assert scheduler._wait_seconds(time.time(), woken=True) == 0.0


def test_a_stuck_past_due_does_not_hide_a_future_due(app) -> None:
    scheduler = Scheduler(
        app.store,
        AuditLog(app.store.path),
        app.config,
        interval=1_000.0,
        registry=REGISTRY,
        next_due=lambda now: 2_000.0,
        has_due=lambda now: True,
    )
    assert scheduler._wait_seconds(1_500.0, woken=False) == 500.0


def test_a_due_in_the_past_does_not_turn_the_loop_into_a_spin(app) -> None:
    """A blocked rotation is retried on the normal cadence, not continuously."""
    scheduler = Scheduler(
        app.store,
        AuditLog(app.store.path),
        app.config,
        interval=60.0,
        registry=REGISTRY,
        next_due=lambda _now: 0.0,
    )
    now = time.time()
    # After an audit, a due that is still past waits the normal cadence.
    assert scheduler._wait_seconds(now, woken=False) == 60.0
    # A wake (new policy/interval) re-checks immediately.
    assert scheduler._wait_seconds(now, woken=True) == 0.0


def test_set_interval_wakes_the_wait_without_a_restart(app) -> None:
    calls: list[float] = []
    scheduler = _scheduler(app, interval=60.0)
    scheduler.once = lambda: calls.append(time.monotonic())

    stop = threading.Event()
    loop = threading.Thread(target=scheduler.serve, args=(stop,), daemon=True)
    loop.start()
    deadline = time.monotonic() + 2
    while len(calls) < 1 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert len(calls) == 1
    scheduler.set_interval(0.05)
    deadline = time.monotonic() + 2
    while len(calls) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    stop.set()
    loop.join(timeout=5)

    assert not loop.is_alive()
    assert scheduler.interval == 0.05
    assert len(calls) >= 2
