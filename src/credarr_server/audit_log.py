"""What each audit found, kept so a restart does not forget it.

The journal records rotation events; this records audit results, and the
ledger the app shows is a view over them. Each run gets one row, and each
credential and holder of that run gets one row each, keyed by name so the
history survives a credential being renamed or deleted. Scoped "Check this
app" results live in `audit_checks`, deliberately outside the stack ledger.
Nothing here holds a value or a fingerprint: statuses, and the messages the
audit already writes to be safe in a log.

Audits are read-only, so a run row is written once the run is over. A process
killed mid-audit loses only that in-flight attempt; the state recorded before
it is untouched - which is the claim being tested (kill the app, start it
again, the drift state is still there) and the reason there is no
started-without-finish state to resume, the way a rotation has one.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass, replace
from pathlib import Path

from credarr.audit import AuditResult, CredentialResult, Status
from credarr.report import exit_code_for

from .store import connect, initialise

# Action events: something was done, and nothing about a credential's equality
# was measured. Kept apart from status transitions so a reader never invents a
# "was". The auto pair is the loop's vocabulary; the rotation kinds are a
# manual attempt's.
AUTO_ROTATION_KINDS = (
    "auto_blocked",
    "auto_started",
    "auto_succeeded",
    "auto_manual",
    "auto_interrupted",
)
MANUAL_ROTATION_KINDS = (
    "rotation_refused",
    "rotation_failed",
    "rotation_manual",
    "rotation_succeeded",
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  REAL    NOT NULL,
    finished_at REAL    NOT NULL,
    exit_code   INTEGER,
    exit_status TEXT,
    detail      TEXT    NOT NULL
);

-- Rows carry the name, not a foreign key: this is history, and it has to
-- outlive the credential being renamed or deleted.
CREATE TABLE IF NOT EXISTS audit_credentials (
    run_id     INTEGER NOT NULL REFERENCES audit_runs(id) ON DELETE CASCADE,
    credential TEXT    NOT NULL,
    status     TEXT    NOT NULL,
    detail     TEXT    NOT NULL,
    reason     TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (run_id, credential)
);

-- Scoped "Check this app" results. Deliberately separate from audit_runs:
-- a one-app check must not satisfy the stack-wide freshness gate or replace
-- the stack headline. The credential name is history, not a foreign key.
CREATE TABLE IF NOT EXISTS audit_checks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    credential  TEXT    NOT NULL,
    checked_at  REAL    NOT NULL,
    status      TEXT    NOT NULL,
    detail      TEXT    NOT NULL,
    reason      TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS audit_checks_credential_time
    ON audit_checks (credential, checked_at DESC, id DESC);

-- Position is the holder's order in the run's manifest. The target is kept
-- beside it because topology changes between runs, and history must read back
-- as it was found, not through the current shape of anything.
CREATE TABLE IF NOT EXISTS audit_consumers (
    run_id     INTEGER NOT NULL REFERENCES audit_runs(id) ON DELETE CASCADE,
    credential TEXT    NOT NULL,
    position   INTEGER NOT NULL,
    target     TEXT    NOT NULL,
    status     TEXT    NOT NULL,
    detail     TEXT    NOT NULL,
    reason     TEXT    NOT NULL DEFAULT '',
    -- The live row count the holder's API listed for this copy, so the console
    -- can compare it with the declared `count` without parsing the detail.
    -- NULL when the holder was not asked or its answer could not be counted.
    observed_count INTEGER,
    PRIMARY KEY (run_id, credential, position)
);

-- The per-app history is a union of full-audit rows and scoped check rows;
-- this index keeps the full-audit side filtered to one credential.
CREATE INDEX IF NOT EXISTS audit_credentials_credential_run
    ON audit_credentials (credential, run_id);

-- One row per *change* of a credential's recorded status, written inside the
-- transaction of the run that observed it. That is what makes "delivered once"
-- a property of the schema instead of a promise a loop makes: the event exists
-- exactly when the run that saw the change exists, retries live beside it
-- (event_deliveries, owned by the notifier), and no reader has to diff runs to
-- find out what is new.
--
-- The four columns a transition carries are nullable because a `test` event -
-- a sink being proven from the console - is about no credential at all, and an
-- auto-rotation event records an action, not a status transition.
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    at              REAL    NOT NULL,
    kind            TEXT    NOT NULL,
    credential      TEXT,
    previous_status TEXT,
    status          TEXT,
    detail          TEXT    NOT NULL,
    -- NULL means every enabled service; a test names the one it probes.
    sink            TEXT
);
"""


@dataclass(frozen=True, slots=True)
class ConsumerState:
    """One holder's outcome in one run."""

    target: str
    status: Status
    detail: str
    # The stable code beside the sentence; empty for a ledger written before
    # the column existed.
    reason: str = ""
    # The live row count the holder's API listed, when it could be counted.
    observed_count: int | None = None


@dataclass(frozen=True, slots=True)
class CredentialState:
    """One credential's outcome, with its holders."""

    credential: str
    status: Status
    detail: str
    consumers: tuple[ConsumerState, ...]
    reason: str = ""


@dataclass(frozen=True, slots=True)
class AuditCheck:
    """One scoped check or one credential row from a full audit."""

    at: float
    status: Status
    detail: str
    source: str  # "check" | "audit"
    reason: str = ""


@dataclass(frozen=True, slots=True)
class AuditRun:
    """One attempt. `exit_status` is None when it failed before auditing."""

    id: int
    started_at: float
    finished_at: float
    exit_code: int | None
    exit_status: Status | None
    detail: str


@dataclass(frozen=True, slots=True)
class LastState:
    """What the app knows: the newest attempt and the newest audited states."""

    last_run: AuditRun
    last_audit: AuditRun | None
    credentials: tuple[CredentialState, ...]


@dataclass(frozen=True, slots=True)
class Event:
    """An audit transition or an auto-rotation action, as recorded.

    `credential` is None for a test event; `previous_status` and `status` are
    None for test and auto events, which are not equality measurements.
    """

    id: int
    at: float
    kind: str
    credential: str | None
    previous_status: Status | None
    status: Status | None
    detail: str
    # A test event names the one service it probes; None is a broadcast event.
    sink: str | None = None


def _previous_status(
    connection: sqlite3.Connection, credential: str, before_run: int
) -> Status | None:
    """The last recorded status for `credential`, if any run gave it one."""
    row = connection.execute(
        "SELECT status FROM audit_credentials WHERE credential = ? AND run_id < ? "
        "ORDER BY run_id DESC LIMIT 1",
        (credential, before_run),
    ).fetchone()
    return Status(row["status"]) if row else None


def _needs_explanation(status: Status) -> bool:
    """Statuses that need a holder-level sentence when the roll-up has none."""
    return status in (
        Status.ERROR,
        Status.DRIFT,
        Status.MISSING,
        Status.ABSENT,
        Status.UNVERIFIABLE,
    )


def _event_detail(result: CredentialResult) -> str:
    """The sentence an event carries.

    The credential's own detail is often empty when the finding was measured on
    a holder: the roll-up has nothing to add to what its holders said. An event
    whose body is one word is a notification nobody can act on, so the first
    holder that is not a success supplies its sentence, named by its target.
    """
    if result.detail:
        return result.detail
    for consumer in result.consumers:
        if _needs_explanation(consumer.status) and consumer.detail:
            return f"{consumer.consumer.target!s}: {consumer.detail}"
    return result.detail


def _event_reason(result: CredentialResult) -> str:
    """The code beside `_event_detail`, with the same holder fallback."""
    if result.reason:
        return result.reason
    for consumer in result.consumers:
        if _needs_explanation(consumer.status) and consumer.reason:
            return consumer.reason
    return ""


def _ledger_detail(
    connection: sqlite3.Connection, credential: str, at: float
) -> str:
    """Recover a holder sentence for an event written before this fix.

    Older event rows can carry an empty detail even though the matching
    `audit_consumers` row has the reason. The event and its run share the same
    `finished_at`, so read-time fallback can repair history without rewriting
    the ledger.
    """
    row = connection.execute(
        "SELECT NULLIF(c.detail, '') AS detail, "
        "  (SELECT co.target || ': ' || co.detail "
        "     FROM audit_consumers co "
        "    WHERE co.run_id = c.run_id AND co.credential = c.credential "
        "      AND co.status IN ('error', 'drift', 'missing', 'absent', 'unverifiable') "
        "      AND co.detail <> '' "
        "    ORDER BY co.position LIMIT 1) AS holder_detail "
        "FROM audit_credentials c "
        "JOIN audit_runs r ON r.id = c.run_id "
        "WHERE c.credential = ? AND r.finished_at = ? "
        "ORDER BY c.run_id DESC LIMIT 1",
        (credential, at),
    ).fetchone()
    if row is None:
        return ""
    return row["detail"] or row["holder_detail"] or ""


def _transition(previous: Status | None, current: Status) -> str | None:
    """The event kind for a status change, or None when there is nothing to say.

    Edges, not levels: a credential that was already drifting last run is not
    news this run, and a first recorded status is a baseline - it says what the
    operator just imported, not that anything changed. `drift` covers every
    problem status (`is_problem`), because the payload carries which one it is
    and a receiver can filter on that; `unverifiable` and its way back are told
    apart from drift because "cannot tell" is the state that hides drift, not
    drift itself.
    """
    if previous is None or previous is current:
        return None
    if current is Status.LIVE:
        # Liveness is not equality. Any transition into live is not a recovery
        # event; the audit row carries the weaker status, and a later readable
        # audit emits recovered only when it compares a match.
        return None
    if current.is_problem:
        return "drift"
    if current is Status.UNVERIFIABLE:
        return "unverifiable"
    if previous.is_problem or previous is Status.UNVERIFIABLE:
        return "recovered"
    return None


class AuditLog:
    """The audit history: one row per run, credential and holder."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        initialise(self.path, SCHEMA)
        # `CREATE TABLE IF NOT EXISTS` will not add a column to a table that
        # already exists, so a ledger written before these columns had none.
        # Guarded, like the journal's ownership-token migration.
        with connect(self.path) as connection:
            for table in ("audit_credentials", "audit_consumers", "audit_checks"):
                columns = {
                    row["name"]
                    for row in connection.execute(f"PRAGMA table_info({table})")
                }
                if "reason" not in columns:
                    connection.execute(
                        f"ALTER TABLE {table} ADD COLUMN reason TEXT NOT NULL DEFAULT ''"
                    )
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(audit_consumers)")
            }
            if "observed_count" not in columns:
                connection.execute(
                    "ALTER TABLE audit_consumers ADD COLUMN observed_count INTEGER"
                )
            event_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(events)")
            }
            if "sink" not in event_columns:
                connection.execute("ALTER TABLE events ADD COLUMN sink TEXT")

    def record(self, result: AuditResult, *, started_at: float) -> int:
        """Write one completed audit and return its run id.

        The exit code is `report.exit_code_for`, the same function the CLI
        uses, so the ledger and `credarr audit` cannot disagree about what
        exit 1 meant.

        A credential whose status differs from the last run's also writes an
        `event`, in this same transaction. That is deliberate: the event is
        derived from the run, so it cannot be lost by a crash after the run was
        recorded, cannot be written twice by two readers racing, and cannot
        disagree with the rows beside it.
        """
        finished_at = time.time()
        with connect(self.path) as connection:
            connection.execute("BEGIN")
            try:
                cursor = connection.execute(
                    "INSERT INTO audit_runs (started_at, finished_at, exit_code, "
                    "exit_status, detail) VALUES (?, ?, ?, ?, '')",
                    (started_at, finished_at, exit_code_for(result), result.exit_status.value),
                )
                run_id = cursor.lastrowid
                for credential_result in result.results:
                    name = credential_result.credential.name
                    # Read the previous status before writing this run's row, so
                    # "previous" cannot mean the row about to be inserted.
                    previous = _previous_status(connection, name, run_id)
                    connection.execute(
                        "INSERT INTO audit_credentials (run_id, credential, status, "
                        "detail, reason) VALUES (?, ?, ?, ?, ?)",
                        (
                            run_id,
                            name,
                            credential_result.status.value,
                            credential_result.detail,
                            _event_reason(credential_result),
                        ),
                    )
                    kind = _transition(previous, credential_result.status)
                    if kind is not None:
                        connection.execute(
                            "INSERT INTO events (at, kind, credential, previous_status, "
                            "status, detail) VALUES (?, ?, ?, ?, ?, ?)",
                            (
                                finished_at,
                                kind,
                                name,
                                previous.value if previous else None,
                                credential_result.status.value,
                                _event_detail(credential_result),
                            ),
                        )
                    for position, consumer_result in enumerate(credential_result.consumers):
                        connection.execute(
                            "INSERT INTO audit_consumers (run_id, credential, position, "
                            "target, status, detail, reason, observed_count) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                run_id,
                                name,
                                position,
                                str(consumer_result.consumer.target),
                                consumer_result.status.value,
                                consumer_result.detail,
                                consumer_result.reason,
                                consumer_result.observed_count,
                            ),
                        )
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        return run_id

    def record_failure(
        self, detail: str, *, started_at: float, exit_code: int | None = None
    ) -> int:
        """Write an attempt that never reached an audit, and return its id.

        `exit_code` is the failure's own when it has one; a failure without a
        code is a bug, and its detail starts with the class name so it can be
        told apart from a reportable error.
        """
        with connect(self.path) as connection:
            cursor = connection.execute(
                "INSERT INTO audit_runs (started_at, finished_at, exit_code, "
                "exit_status, detail) VALUES (?, ?, ?, NULL, ?)",
                (started_at, time.time(), exit_code, detail),
            )
        return cursor.lastrowid

    def record_check(
        self, result: CredentialResult, *, at: float | None = None
    ) -> float:
        """Record one scoped app check, outside the stack audit ledger.

        A check is a measurement with a time, not a completed stack audit. It
        must never become `last_audit`: auto-rotation's freshness gate requires
        exact stack coverage, and the Apps headline is dated by the last full
        run. The sentence is scrubbed by the engine before it reaches here.
        """
        checked_at = time.time() if at is None else at
        with connect(self.path) as connection:
            connection.execute(
                "INSERT INTO audit_checks "
                "(credential, checked_at, status, detail, reason) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    result.credential.name,
                    checked_at,
                    result.status.value,
                    _event_detail(result),
                    _event_reason(result),
                ),
            )
        return checked_at

    def checks(
        self, credential: str, *, limit: int = 20
    ) -> tuple[AuditCheck, ...]:
        """This credential's check history, newest first.

        A full audit measured every declared credential, so its row is history
        too. Both sources are filtered by credential and the response is
        capped; the work is proportional to this app's history, not every
        app's. A full audit's credential detail is often empty because the
        reason lives on a holder row, so the first non-success holder's
        sentence stands in, as it does for a scoped check.
        """
        with connect(self.path) as connection:
            rows = connection.execute(
                "SELECT * FROM ("
                "  SELECT checked_at AS at, status, detail, reason, 'check' AS source "
                "  FROM audit_checks WHERE credential = ? "
                "  ORDER BY checked_at DESC LIMIT ?"
                ") "
                "UNION ALL "
                "SELECT * FROM ("
                "  SELECT r.finished_at AS at, c.status, "
                "  COALESCE("
                "    NULLIF(c.detail, ''), "
                "    NULLIF(("
                "      SELECT co.target || ': ' || co.detail FROM audit_consumers co "
                "      WHERE co.run_id = c.run_id AND co.credential = c.credential "
                "        AND co.status IN ('error', 'drift', 'missing', 'absent', 'unverifiable') "
                "        AND co.detail <> '' "
                "      ORDER BY co.position LIMIT 1"
                "    ), ''), "
                "    ''"
                "  ) AS detail, "
                "  COALESCE("
                "    NULLIF(c.reason, ''), "
                "    NULLIF(("
                "      SELECT co.reason FROM audit_consumers co "
                "      WHERE co.run_id = c.run_id AND co.credential = c.credential "
                "        AND co.status IN ('error', 'drift', 'missing', 'absent', 'unverifiable') "
                "        AND co.reason <> '' "
                "      ORDER BY co.position LIMIT 1"
                "    ), ''), "
                "    ''"
                "  ) AS reason, "
                "  'audit' AS source "
                "  FROM audit_credentials c "
                "  JOIN audit_runs r ON r.id = c.run_id "
                "  WHERE c.credential = ? AND r.exit_status IS NOT NULL "
                "  ORDER BY r.id DESC LIMIT ?"
                ") "
                "ORDER BY at DESC LIMIT ?",
                (credential, limit, credential, limit, limit),
            ).fetchall()
        return tuple(
            AuditCheck(
                at=float(row["at"]),
                status=Status(row["status"]),
                detail=row["detail"],
                source=row["source"],
                reason=row["reason"],
            )
            for row in rows
        )

    def last_state(self) -> LastState | None:
        """The newest attempt, the newest completed audit, and its states.

        The two runs differ when the newest attempt failed before it could
        read the stack: a caller must be able to show "the last audit failed"
        without replacing the last known states with nothing.
        """
        with connect(self.path) as connection:
            last_run_row = connection.execute(
                "SELECT * FROM audit_runs ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if last_run_row is None:
                return None
            last_audit_row = connection.execute(
                "SELECT * FROM audit_runs WHERE exit_status IS NOT NULL "
                "ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if last_audit_row is None:
                return LastState(last_run=_run(last_run_row), last_audit=None, credentials=())
            run_id = last_audit_row["id"]
            credential_rows = connection.execute(
                "SELECT * FROM audit_credentials WHERE run_id = ? ORDER BY credential",
                (run_id,),
            ).fetchall()
            consumer_rows = connection.execute(
                "SELECT * FROM audit_consumers WHERE run_id = ? ORDER BY credential, position",
                (run_id,),
            ).fetchall()

        by_credential: dict[str, list[sqlite3.Row]] = {}
        for row in consumer_rows:
            by_credential.setdefault(row["credential"], []).append(row)
        return LastState(
            last_run=_run(last_run_row),
            last_audit=_run(last_audit_row),
            credentials=tuple(
                CredentialState(
                    credential=row["credential"],
                    status=Status(row["status"]),
                    detail=row["detail"],
                    reason=row["reason"],
                    consumers=tuple(
                        ConsumerState(
                            target=consumer["target"],
                            status=Status(consumer["status"]),
                            detail=consumer["detail"],
                            reason=consumer["reason"],
                            observed_count=consumer["observed_count"],
                        )
                        for consumer in by_credential.get(row["credential"], [])
                    ),
                )
                for row in credential_rows
            ),
        )

    def record_auto_event(
        self, kind: str, credential: str, detail: str, *, at: float | None = None
    ) -> Event:
        """One auto-rotation fact, without a fake status transition.

        These events share delivery rows and sinks with audit transitions, but
        they are not measurements of a credential's equality: `previous_status`
        and `status` stay NULL so a receiver never reads an invented "was".
        """
        return self._record_action(
            kind,
            credential,
            detail,
            at=at,
            allowed=AUTO_ROTATION_KINDS,
            what="auto-rotation",
        )

    def record_rotation_event(
        self, kind: str, credential: str, detail: str, *, at: float | None = None
    ) -> Event:
        """One manual rotation attempt, in the auto events' action shape.

        A refusal, a failed preflight and a finished run all belong in the
        Activity trail: the operator's click is the only record of why nothing
        happened, and "nothing happened" is exactly what a status transition
        never shows. `previous_status`/`status` stay NULL because an attempt is
        not a measurement. Whether the event notifies is the delivery path's
        decision (`notifier.SILENT_KINDS`), not this table's.
        """
        return self._record_action(
            kind,
            credential,
            detail,
            at=at,
            allowed=MANUAL_ROTATION_KINDS,
            what="manual rotation",
        )

    def _record_action(
        self,
        kind: str,
        credential: str,
        detail: str,
        *,
        at: float | None,
        allowed: tuple[str, ...],
        what: str,
    ) -> Event:
        """The one insert behind both action flavours."""
        if kind not in allowed:
            raise ValueError(f"not a {what} event: {kind}")
        when = time.time() if at is None else at
        with connect(self.path) as connection:
            cursor = connection.execute(
                "INSERT INTO events (at, kind, credential, previous_status, status, detail) "
                "VALUES (?, ?, ?, NULL, NULL, ?)",
                (when, kind, credential, detail),
            )
        return Event(
            id=cursor.lastrowid,
            at=when,
            kind=kind,
            credential=credential,
            previous_status=None,
            status=None,
            detail=detail,
        )

    def recent_events(self, limit: int = 50) -> tuple[Event, ...]:
        """The newest recorded changes, newest first: what the Events view shows."""
        with connect(self.path) as connection:
            rows = connection.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            events = []
            for row in rows:
                event = event_from_row(row)
                if (
                    not event.detail
                    and event.credential is not None
                    and event.status is not None
                    and _needs_explanation(event.status)
                ):
                    recovered = _ledger_detail(
                        connection, event.credential, event.at
                    )
                    if recovered:
                        event = replace(event, detail=recovered)
                events.append(event)
        return tuple(events)

    def record_test_event(self, sink: str) -> Event:
        """One event no run produced, addressed to exactly one service.

        It shares the table and therefore the delivery path with real
        transitions, and is marked `test`, so no reader can mistake it for a
        measurement of the stack. The recipient is part of the row: a probe of
        one sink must never be replayed to every other configured sink.
        """
        at = time.time()
        detail = "a test notification from the console"
        with connect(self.path) as connection:
            cursor = connection.execute(
                "INSERT INTO events (at, kind, credential, previous_status, status, "
                "detail, sink) VALUES (?, 'test', NULL, NULL, NULL, ?, ?)",
                (at, detail, sink),
            )
        return Event(
            id=cursor.lastrowid,
            at=at,
            kind="test",
            credential=None,
            previous_status=None,
            status=None,
            detail=detail,
            sink=sink,
        )


def event_from_row(row: sqlite3.Row) -> Event:
    """One `events` row as the dataclass. Public because the notifier reads the
    same rows through its own queries and must not grow a second constructor."""
    return Event(
        id=row["id"],
        at=row["at"],
        kind=row["kind"],
        credential=row["credential"],
        previous_status=Status(row["previous_status"]) if row["previous_status"] else None,
        status=Status(row["status"]) if row["status"] else None,
        detail=row["detail"],
        sink=row["sink"],
    )


def _run(row: sqlite3.Row) -> AuditRun:
    return AuditRun(
        id=row["id"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        exit_code=row["exit_code"],
        exit_status=Status(row["exit_status"]) if row["exit_status"] is not None else None,
        detail=row["detail"],
    )
