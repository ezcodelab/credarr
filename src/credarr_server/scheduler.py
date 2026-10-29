"""The audit loop: check on a schedule, record what was found.

The scheduler holds no state of its own. It audits the stored topology with
the store's working copies (DECISIONS decision 2 - no vault is read at
runtime), writes the outcome to the audit log, and waits. Everything that
survives a restart is in SQLite, so a killed app comes back showing the last
audit it recorded instead of an empty dashboard.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable

from credarr import facade
from credarr.audit import AuditResult, CredentialResult
from credarr.config import Config
from credarr.targets import TargetRegistry, build_registry

from .audit_log import AuditLog
from .source import StoreSource, runtime_config, runtime_manifest
from .store import TopologyStore, UnknownCredential

# The UI/persisted setting is bounded so a typo cannot turn the loop into a
# busy-spin or hide drift for a quarter. The CLI keeps its own positive/finite
# check for tests and one-shot deployments.
MIN_AUDIT_INTERVAL_SECONDS = 60.0
MAX_AUDIT_INTERVAL_SECONDS = 7 * 24 * 60 * 60.0


class Scheduler:
    """Runs the audit on an interval, and at auto-rotation due times."""

    def __init__(
        self,
        store: TopologyStore,
        log: AuditLog,
        config: Config,
        *,
        interval: float,
        enabled: bool = True,
        registry: TargetRegistry | None = None,
        on_audit: Callable[[], None] | None = None,
        next_due: Callable[[float], float | None] | None = None,
        has_due: Callable[[float], bool] | None = None,
    ) -> None:
        if not math.isfinite(interval) or interval <= 0:
            raise ValueError("the audit interval must be a positive, finite number")
        self.store = store
        self.log = log
        self.config = config
        self.interval = interval
        self.enabled = enabled
        self.registry = registry or build_registry()
        self.on_audit = on_audit
        # A due auto-rotation is checked before the normal cadence so a long
        # audit interval cannot delay a scheduled rotation. `next_due` returns
        # the earliest due still in the future (or None); `has_due` answers
        # whether anything is already due, for an immediate audit after a wake.
        self.next_due = next_due
        self.has_due = has_due
        self._wake = threading.Event()
        # Anchored after each audit so a configuration wake does not postpone
        # the normal drift check by a whole interval.
        self._next_audit_at: float | None = None
        # The interval loop and "audit now" can call once() at the same time.
        # Two reads racing to record can finish out of order, leaving the
        # higher run id describing an older stack. One audit at a time keeps
        # the ledger's order the order the runs actually happened.
        self._run_lock = threading.Lock()

    def set_interval(self, seconds: float) -> None:
        """Change the cadence and wake the loop so it applies without a restart."""
        if not math.isfinite(seconds) or seconds <= 0:
            raise ValueError("the audit interval must be a positive, finite number")
        self.interval = seconds
        self._next_audit_at = time.time() + seconds if self.enabled else None
        self._wake.set()

    def set_enabled(self, enabled: bool) -> None:
        """Turn scheduled audits on or off without stopping the process."""
        self.enabled = enabled
        self._next_audit_at = time.time() + self.interval if enabled else None
        self._wake.set()

    def wake(self) -> None:
        """Recompute the next wait now (a policy or due time changed)."""
        self._wake.set()

    def _wait_seconds(self, now: float, *, woken: bool) -> float | None:
        audit_wait: float | None
        if self.enabled:
            audit_wait = (
                max(0.0, self._next_audit_at - now)
                if self._next_audit_at is not None
                else self.interval
            )
        else:
            # No scheduled audit. A due auto-rotation still gets its own audit;
            # otherwise wait for an explicit wake/stop.
            audit_wait = None
        if self.next_due is None:
            return audit_wait
        if woken and self.has_due is not None and self.has_due(now):
            # A policy was enabled/changed and is already due: audit now.
            return 0.0
        due = self.next_due(now)
        if due is None:
            return audit_wait
        if due <= now:
            # A due still in the past after the audit that covered it is
            # blocked; retry on the normal cadence.
            return 0.0 if woken else audit_wait
        if audit_wait is None:
            return due - now
        return min(audit_wait, due - now)

    def once(self) -> AuditResult | None:
        """Audit once and record the outcome.

        A run that cannot complete is a row, not an exception: the failure is
        part of the state the app shows and the loop keeps its schedule. A
        database that cannot be written is different - it is not a run
        outcome, and swallowing it would leave a loop alive with a dashboard
        nobody can trust, so it raises. `None` means the run never reached an
        audit; the reason is in the log.
        """
        with self._run_lock:
            return self._once()

    def check(self, credential: str) -> tuple[float, CredentialResult]:
        """Check one credential without writing a stack audit.

        The same engine path as a full audit, scoped with `only`. It shares the
        audit lock so a scoped check cannot overlap the interval run and
        double-hit rate-limited services, but it does not notify, advance the
        auto-rotation clock, or replace `last_audit`. Its result goes to the
        separate per-app check history.
        """
        with self._run_lock:
            result = facade.audit(
                runtime_config(self.config, self.store),
                runtime_manifest(self.store),
                StoreSource(self.store),
                only={credential},
            )
            if len(result.results) != 1:
                # The name can disappear between the route's manifest check and
                # this read (a concurrent delete/import). That is a 404, not a
                # 500 from a one-off scoped call.
                raise UnknownCredential(credential)
            checked_at = self.log.record_check(result.results[0])
            return checked_at, result.results[0]

    def _once(self) -> AuditResult | None:
        started_at = time.time()
        try:
            result = facade.audit(
                runtime_config(self.config, self.store),
                runtime_manifest(self.store),
                StoreSource(self.store),
            )
        except Exception as exc:
            # An exception that is not a reportable CredctlError has no exit
            # code of its own; the class name in the detail is what tells the
            # two apart.
            self.log.record_failure(
                f"{type(exc).__name__}: {exc}",
                started_at=started_at,
                exit_code=getattr(exc, "exit_code", None),
            )
            return None
        self.log.record(result, started_at=started_at)
        if self.on_audit is not None:
            self.on_audit()
        return result

    def serve(self, stop: threading.Event) -> None:
        """Audit now, then at the interval or the next auto due time.

        An exception (a store that cannot be written) ends the loop; the
        caller owns restarting it or surfacing the failure. A due time that is
        already past when a wait begins gets one audit and then the normal
        cadence: a blocked rotation must not turn into an audit spin.
        """
        def _on_stop() -> None:
            stop.wait()
            self._wake.set()

        threading.Thread(
            target=_on_stop, name="credarr-audit-stop", daemon=True
        ).start()
        while not stop.is_set():
            if self.enabled or (
                self.has_due is not None and self.has_due(time.time())
            ):
                self.once()
            self._next_audit_at = (
                time.time() + self.interval if self.enabled else None
            )
            woken = False
            while not stop.is_set():
                wait = self._wait_seconds(time.time(), woken=woken)
                if self._wake.wait(wait):
                    self._wake.clear()
                    if stop.is_set():
                        break
                    woken = True
                    continue
                break
