"""Auto-rotation policy: whether a due credential may run unattended.

This module holds the decisions, not a second executor. The worker starts the
same plan and apply path the console and CLI use. The gates are deliberately
fail-closed for real findings: a stale audit, an unrelated drift, a blocked
plan or an unfinished run stops every automatic mutation. A manual/unproven
copy is allowed and notified, because the mint can still complete.
"""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from credarr import facade
from credarr.audit import Status
from credarr.config import Config, HostConfig
from credarr.journal import STACK_LOCK, Journal, JournalLocked, PendingStep
from credarr.model import Credential, Manifest
from credarr.redact import Secret
from credarr.rotate import RotationPlan
from credarr.writers import holder_for
from credarr_server.audit_log import AuditLog, LastState
from credarr_server.source import StorePending, StoreSource
from credarr_server.store import AutoRotation, TopologyStore

DAY_SECONDS = 86_400.0
# A scheduler that just finished writing the audit is allowed a little clock
# skew; the signal is what normally makes this irrelevant.
AUDIT_GRACE_FLOOR = 60.0
AUDIT_GRACE_FRACTION = 0.1
AUDIT_GRACE_CAP = 600.0


def next_due_at(state: AutoRotation, last_rotation: float | None) -> float | None:
    """When this credential next becomes due, or None when it is not armed."""
    if not state.enabled or state.paused:
        return None
    baseline = max(last_rotation or 0.0, state.enabled_at)
    return baseline + state.every_days * DAY_SECONDS


def audit_grace(interval: float) -> float:
    return min(AUDIT_GRACE_CAP, max(AUDIT_GRACE_FLOOR, interval * AUDIT_GRACE_FRACTION))


def manual_or_unproven_targets(credential: Credential) -> set[str]:
    """Copies auto-rotation may leave for a human.

    An indirect copy is rendered at deploy time. A target with no registered
    writer, or a writer with no measured test/read-back, is either a MANUAL
    step or a `written` holder after the run. Those are the copies the gate
    ignores and the event names; a copy with a measured confirmation path is
    still required to be MATCH/LIVE.
    """
    targets: set[str] = set()
    for consumer in credential.consumers:
        if consumer.indirect:
            targets.add(str(consumer.target))
            continue
        holder = holder_for(consumer.target.system, consumer.target.slot)
        if holder is None or not (holder.test_path or holder.readback):
            targets.add(str(consumer.target))
    return targets


def audit_blocker(
    manifest: Manifest,
    state: LastState | None,
    *,
    now: float,
    interval: float,
    default_host: str,
) -> str | None:
    """Require a fresh completed audit with exact current coverage.

    LIVE is acceptance through a measured holder test, not equality. It is
    eligible only because preflight still requires the stored issuer key and
    the run still requires old-key death before exercise-only confirmation.
    Copies the run will leave to a human (indirect, no writer, or a writer
    without a measured confirmation route) contribute no status requirement;
    every proven copy must still be MATCH/LIVE. Real findings still block.
    Coverage is compared against ledger rows, not inferred from the headline.
    """
    if state is None or state.last_audit is None:
        return "no completed audit has recorded this topology"
    if state.last_run.id != state.last_audit.id:
        return "the newest audit attempt failed; the last completed run is older"
    run = state.last_audit
    if run.exit_status not in (
        Status.MATCH,
        Status.LIVE,
        Status.INDIRECT,
        Status.UNVERIFIABLE,
        Status.ABSENT,
    ):
        reason = run.exit_status.value if run.exit_status is not None else "no result"
        return f"the last completed audit is {reason}, not clean"
    if run.exit_status is Status.ABSENT:
        absent_with_holders = any(
            credential.consumers
            and any(
                row.credential == name and row.status is Status.ABSENT
                for row in state.credentials
            )
            for name, credential in manifest.credentials.items()
        )
        if absent_with_holders:
            return "the last completed audit is absent, not match or live"
    if run.finished_at < now - (interval + audit_grace(interval)):
        return "the last completed audit is stale"
    if set(manifest.credentials) != {row.credential for row in state.credentials}:
        return "the last audit does not cover the current credential set"
    for name, credential in manifest.credentials.items():
        if not credential.consumers:
            # INDIRECT is an aggregate over an empty holder set, not a
            # statement about a value nothing holds. It must not block the
            # rotation of a different credential forever.
            continue
        audited = next((row for row in state.credentials if row.credential == name), None)
        if audited is None:
            return f"{name}: the last audit has no row for this credential"
        if audited.status in (Status.ERROR, Status.DRIFT, Status.MISSING):
            return f"{name}: the last audit is {audited.status.value}, not clean"
        ignored = manual_or_unproven_targets(credential)
        declared = sorted(str(consumer.target) for consumer in credential.consumers)
        observed = sorted(consumer.target for consumer in audited.consumers)
        if declared != observed:
            return f"{name}: the declared holders differ from the last audit"
        for consumer in credential.consumers:
            if consumer.host not in (None, default_host):
                return (
                    f"{name}: holder {consumer.target} is on {consumer.host}; "
                    "auto-rotation is single-host"
                )
        for consumer in audited.consumers:
            if consumer.target in ignored:
                continue
            if consumer.status not in (Status.MATCH, Status.LIVE):
                return (
                    f"{name}: holder {consumer.target} is "
                    f"{consumer.status.value}, not match or live"
                )
    return None


@dataclass(frozen=True, slots=True)
class GateDecision:
    """The gate's answer: run, or the complete list of reasons not to."""

    reasons: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return not self.reasons

    @property
    def detail(self) -> str:
        return "; ".join(self.reasons)


def gate_reasons(
    *,
    manifest: Manifest,
    credential_name: str,
    plan: RotationPlan,
    problems: Sequence[str],
    state: AutoRotation | None,
    last_state: LastState | None,
    unfinished: Sequence[PendingStep],
    now: float,
    interval: float,
    default_host: str,
    open_attempts: Sequence[str] = (),
) -> GateDecision:
    """Every gate, evaluated without changing anything.

    Plan and preflight are read-only by construction; this function only reads
    the policy row, audit ledger and journal. The worker calls it under the
    stack lock so those inputs cannot change before the run.
    """
    if state is None or not state.enabled:
        return GateDecision(("auto-rotation is off",))
    reasons: list[str] = []
    if state.paused:
        reasons.append(
            state.last_detail or "auto-rotation is paused after an unfinished run"
        )
    if unfinished:
        names = sorted({step.credential for step in unfinished})
        reasons.append(
            "unfinished rotation steps exist for " + ", ".join(names)
        )
    if open_attempts:
        reasons.append(
            "unfinished rotation attempts exist for "
            + ", ".join(sorted(set(open_attempts)))
        )
    if plan.credential.name != credential_name:  # pragma: no cover - caller bug
        reasons.append("the plan is for a different credential")
    for blocked in plan.blocked_by:
        reasons.append(blocked)
    if plan.mint_via == "provided":
        reasons.append(
            "the manual mint needs the key rotated in the service's own UI; "
            "auto-rotation cannot supply it"
        )
    if not plan.steps:
        reasons.append("the plan has no executable steps")
    # Manual steps are allowed: the key rotation is still delivered, and the
    # run emits auto_manual so the operator can finish those copies. The plan's
    # blockers and preflight problems still stop a run that cannot mint.
    reasons.extend(problems)
    audit = audit_blocker(
        manifest,
        last_state,
        now=now,
        interval=interval,
        default_host=default_host,
    )
    if audit is not None:
        reasons.append(audit)
    return GateDecision(tuple(reasons))


PreparedRotation = tuple[
    Credential,
    HostConfig,
    RotationPlan,
    Sequence[str],
    Any,
    Mapping[str, Secret],
]


@dataclass(frozen=True, slots=True)
class AutoOutcome:
    """One due credential's answer from a pass; useful to tests and events."""

    credential: str
    outcome: str
    detail: str
    attempt: int | None = None


class AutoRotator:
    """The audit-triggered auto-rotation worker.

    It owns no timer: `notify()` is called after a completed audit, and the
    thread wakes only then. The engine's plan/execute path and journal do the
    actual work, so auto cannot pick a different mint or write path from a
    human run.
    """

    def __init__(
        self,
        store: TopologyStore,
        config: Config,
        log: AuditLog,
        journal: Journal,
        *,
        interval: float,
        prepare: Callable[[str], PreparedRotation] | None = None,
    ) -> None:
        self.store = store
        self.config = config
        self.log = log
        self.journal = journal
        self.interval = interval
        self.prepare = prepare
        self.failure: str | None = None
        self._stop = threading.Event()
        self._trigger = threading.Event()
        self._work = threading.Lock()
        self._thread = threading.Thread(
            target=self._run, name="credarr-auto-rotation", daemon=True
        )

    @property
    def running(self) -> bool:
        return self._thread.is_alive()

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        # Wake a thread waiting for the next audit so it can observe the stop.
        self._trigger.set()
        if self._thread.is_alive():
            self._thread.join(timeout=10)

    def notify(self) -> None:
        """Signal a completed audit; safe to call from the audit thread."""
        self._trigger.set()

    def _run(self) -> None:
        try:
            self.reconcile_startup()
            while not self._stop.is_set():
                self._trigger.wait()
                self._trigger.clear()
                if self._stop.is_set():
                    break
                self.run_due()
        except Exception as exc:
            self.failure = f"{type(exc).__name__}: {exc}"

    def reconcile_startup(self, *, now: float | None = None) -> list[str]:
        """Pause enabled credentials whose prior run never finished.

        This runs at process start, before the first audit. The journal query is
        deliberately unwindowed: a kill restarted after a long outage is still a
        kill, and must not become an automatic retry.
        """
        at = time.time() if now is None else now
        open_attempts = self.journal.open_attempts()
        unfinished = {step.credential for step in self.journal.unfinished()}
        paused: list[str] = []
        for name, state in self.store.auto_rotations().items():
            if not state.enabled or state.paused:
                continue
            if name not in unfinished and name not in open_attempts:
                continue
            attempt = open_attempts.get(name)
            detail = (
                f"attempt {attempt} did not finish; review it before re-enabling"
                if attempt is not None
                else "an earlier rotation did not finish; review it before re-enabling"
            )
            self._remember(
                name, "interrupted", detail, at=at, paused=True
            )
            paused.append(name)
        return paused

    def set_interval(self, seconds: float) -> None:
        """Follow the audit cadence used by the freshness gate."""
        self.interval = seconds

    def _due_times(self) -> list[float]:
        times: list[float] = []
        for name, policy in self.store.auto_rotations().items():
            if not policy.enabled or policy.paused:
                continue
            candidate = next_due_at(policy, self.journal.last_rotation(name))
            if candidate is not None:
                times.append(candidate)
        return times

    def next_due(self, now: float) -> float | None:
        """Earliest enabled due time still in the future.

        A past due is handled by `has_due`; returning it here would hide a
        different credential's future due behind a permanently blocked policy.
        """
        future = [candidate for candidate in self._due_times() if candidate > now]
        return min(future) if future else None

    def has_due(self, now: float) -> bool:
        return any(candidate <= now for candidate in self._due_times())

    def run_due(self, *, now: float | None = None) -> list[AutoOutcome]:
        """Check every enabled row and run the due ones, one at a time."""
        with self._work:
            at = time.time() if now is None else now
            outcomes: list[AutoOutcome] = []
            for name, policy in self.store.auto_rotations().items():
                if not policy.enabled or policy.paused:
                    continue
                due = next_due_at(policy, self.journal.last_rotation(name))
                if due is None or at < due:
                    continue
                outcome = self._attempt(name, now=at)
                outcomes.append(outcome)
            return outcomes

    def _remember(
        self,
        name: str,
        outcome: str,
        detail: str,
        *,
        at: float,
        paused: bool | None = None,
    ) -> None:
        """Store current state and emit only when the answer actually changed."""
        previous = self.store.auto_rotation(name)
        self.store.record_auto_rotation(
            name, outcome, detail, checked_at=at, paused=paused
        )
        changed = (
            previous is None
            or previous.last_outcome != outcome
            or previous.last_detail != detail
            or (paused is not None and previous.paused != paused)
        )
        if changed:
            # The journal names the actor; every event should be attributable
            # even when the detail is a bare gate sentence.
            self.log.record_auto_event(
                f"auto_{outcome}", name, f"auto:schedule: {detail}", at=at
            )

    def _started(self, name: str, attempt: int) -> None:
        """Called once the executor holds the lock and has opened the attempt."""
        detail = f"started attempt {attempt}"
        # A notification-ledger failure must not turn a started rotation into
        # a failed one; the run itself is already under way.
        with contextlib.suppress(Exception):
            self._remember(name, "started", detail, at=time.time())

    @staticmethod
    def _app_names(targets: Sequence[str]) -> list[str]:
        names = set()
        for target in targets:
            service = str(target).split("[", 1)[0].split(".", 1)[0].strip()
            if service:
                names.add(service.replace("_", " ").title())
        return sorted(names)

    @classmethod
    def _manual_detail(cls, result: Any) -> str:
        manual = [str(target) for target in (result.manual or [])]
        written = [
            str(holder.target)
            for holder in (result.holders or [])
            if holder.outcome == "written"
        ]
        parts = []
        manual_apps = cls._app_names(manual)
        written_apps = cls._app_names(written)
        if manual_apps:
            parts.append(
                f"{', '.join(manual_apps)} "
                f"{'needs' if len(manual_apps) == 1 else 'need'} manual rotation"
            )
        if written_apps:
            parts.append(
                f"{', '.join(written_apps)} "
                f"{'needs' if len(written_apps) == 1 else 'need'} manual verification"
            )
        return f"attempt {result.attempt}: key rotated; " + "; ".join(parts)

    def _attempt(self, name: str, *, now: float) -> AutoOutcome:
        """Keep the audited topology fixed from the first gate through RECORD."""
        try:
            with self.journal.lock(STACK_LOCK, "auto:schedule"):
                return self._attempt_serialized(name, now=now)
        except JournalLocked:
            # A console rotation or configuration write already owns the stack.
            # Do not write a policy outcome here: a concurrent disable must win.
            return AutoOutcome(
                name,
                "blocked",
                "another rotation or configuration change is in progress; skipped",
            )

    def _attempt_serialized(self, name: str, *, now: float) -> AutoOutcome:
        # Re-read per credential, not once per pass: another candidate may have
        # rotated since the previous one. Never judge freshness by pass start.
        checked = max(now, time.time())
        policy = self.store.auto_rotation(name)
        if policy is None or not policy.enabled or policy.paused:
            # A disable must win immediately, without writing a "blocked"
            # result onto the row the operator just turned off.
            return AutoOutcome(
                name, "blocked", "auto-rotation was disabled or paused during the pass"
            )
        manifest = self.store.load_manifest()
        state = self.log.last_state()
        unfinished = self.journal.unfinished()
        journal_open = self.journal.open_attempts()
        # The stack-wide audit and journal checks need no host read. Do them
        # first so a dirty stack does not make auto preflight every audit.
        static: list[str] = []
        audit = audit_blocker(
            manifest,
            state,
            now=checked,
            interval=self.interval,
            default_host=self.config.default_host,
        )
        if audit is not None:
            static.append(audit)
        if unfinished:
            names = sorted({step.credential for step in unfinished})
            static.append("unfinished rotation steps exist for " + ", ".join(names))
        if journal_open:
            static.append(
                "unfinished rotation attempts exist for "
                + ", ".join(sorted(journal_open))
            )
        if static:
            detail = "; ".join(static)
            self._remember(name, "blocked", detail, at=checked)
            return AutoOutcome(name, "blocked", detail)
        if self.prepare is None:  # pragma: no cover - wiring bug
            detail = "auto-rotation has no plan builder wired"
            self._remember(name, "blocked", detail, at=checked)
            return AutoOutcome(name, "blocked", detail)
        try:
            credential, host, plan, problems, _code, service_keys, _mint_values = (
                self.prepare(name)
            )
        except Exception as exc:
            detail = f"could not plan the rotation: {type(exc).__name__}: {exc}"
            self._remember(name, "blocked", detail, at=checked)
            return AutoOutcome(name, "blocked", detail)
        # Preflight may have taken time; re-read the audit and policy inputs so
        # a newer audit or a disable requested before the lock cannot be hidden.
        checked = max(now, time.time())
        policy = self.store.auto_rotation(name)
        if policy is None or not policy.enabled or policy.paused:
            return AutoOutcome(
                name, "blocked", "auto-rotation was disabled or paused during the plan"
            )
        fresh_manifest = self.store.load_manifest()
        fresh_state = self.log.last_state()
        fresh_unfinished = self.journal.unfinished()
        fresh_open = tuple(self.journal.open_attempts())
        decision = gate_reasons(
            manifest=fresh_manifest,
            credential_name=name,
            plan=plan,
            problems=problems,
            state=policy,
            last_state=fresh_state,
            unfinished=fresh_unfinished,
            open_attempts=fresh_open,
            now=checked,
            interval=self.interval,
            default_host=self.config.default_host,
        )
        if not decision.ready:
            self._remember(name, "blocked", decision.detail, at=checked)
            return AutoOutcome(name, "blocked", decision.detail)

        # Re-answer the two questions a concurrent human run can change: is a
        # run still unfinished, and is this credential still due after someone
        # else's successful rotation? The policy is read once more because a
        # disable is a mutation authorisation, even if no journal row moved.
        policy = self.store.auto_rotation(name)
        if policy is None or not policy.enabled or policy.paused:
            return AutoOutcome(
                name, "blocked", "auto-rotation was disabled or paused before the run"
            )
        if self.journal.open_attempts() or self.journal.unfinished():
            detail = "another rotation started or stopped during the check; skipped"
            self._remember(name, "blocked", detail, at=checked)
            return AutoOutcome(name, "blocked", detail)
        fresh_due = next_due_at(policy, self.journal.last_rotation(name))
        if fresh_due is None or checked < fresh_due:
            detail = "the due clock moved during the check; skipped"
            self._remember(name, "blocked", detail, at=checked)
            return AutoOutcome(name, "blocked", detail)

        before = self.journal.last_attempt(name)
        try:
            result = facade.execute(
                plan=plan,
                credential=credential,
                host=host,
                secrets=StoreSource(self.store),
                journal=self.journal,
                canonical=None,
                canonical_getter=lambda: self.store.get_value(name),
                actor="auto:schedule",
                take_over=False,
                service_keys=service_keys,
                pending=StorePending(self.store),
                mint_values=_mint_values,
                on_started=lambda attempt: self._started(name, attempt),
            )
        except JournalLocked as exc:
            detail = f"another rotation is already running; skipped: {exc}"
            self._remember(name, "blocked", detail, at=checked)
            return AutoOutcome(name, "blocked", detail)
        except Exception as exc:
            started = self.journal.last_attempt(name) != before
            detail = f"{type(exc).__name__}: {exc}"
            if started:
                detail = (
                    f"attempt started and did not finish: {detail}; review it, "
                    "then re-enable auto-rotation"
                )
                self._remember(
                    name, "interrupted", detail, at=time.time(), paused=True
                )
                return AutoOutcome(name, "interrupted", detail)
            self._remember(name, "blocked", detail, at=checked)
            return AutoOutcome(name, "blocked", detail)

        failed_holders = [
            holder
            for holder in (result.holders or [])
            if holder.outcome in ("failed", "not-reached")
        ]
        if result.failed or failed_holders:
            detail = result.detail or (
                f"step {result.failed} failed"
                if result.failed
                else "a holder was not reached"
            )
            detail = (
                f"attempt {result.attempt}: {detail}; review it, then re-enable "
                "auto-rotation"
            )
            self._remember(name, "interrupted", detail, at=time.time(), paused=True)
            return AutoOutcome(name, "interrupted", detail, result.attempt)
        manual = bool(result.manual) or any(
            holder.outcome == "written" for holder in (result.holders or [])
        )
        if manual:
            detail = self._manual_detail(result)
            self._remember(name, "manual", detail, at=time.time(), paused=False)
            return AutoOutcome(name, "manual", detail, result.attempt)
        if result.clean:
            detail = f"attempt {result.attempt} completed"
            self._remember(name, "succeeded", detail, at=time.time())
            return AutoOutcome(name, "succeeded", detail, result.attempt)
        detail = result.detail or "the run left work unproven"
        detail = (
            f"attempt {result.attempt}: {detail}; review it, then re-enable "
            "auto-rotation"
        )
        self._remember(name, "interrupted", detail, at=time.time(), paused=True)
        return AutoOutcome(name, "interrupted", detail, result.attempt)
