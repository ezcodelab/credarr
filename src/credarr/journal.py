"""Durable state for rotation: who is doing what, and what was left half-done.

This exists for a reason that only shows up over HTTP, which is why it is built
now rather than when the dashboard needs it.

On a command line, a rotation that dies leaves a mess on someone's terminal and
they can see it. The same rotation interrupted on a server leaves a mess in
three services and no visible trace - the request timed out, the operator does
not know whether it finished, and the next run happily rotates a credential
whose consumers are already inconsistent. The damage is not the failure, it is
not knowing which failure it was.

So two things are recorded, both before anything irreversible happens:

- **A lock.** One rotation per credential at a time, across processes. Without
  it, a dashboard with two tabs open can rotate the same key twice
  concurrently, and the second run's "already rotated" state is meaningless.
- **A journal.** Each step is written as *started* before it runs and *finished*
  after. A step with a start and no finish is an interrupted rotation, and the
  next run says so instead of guessing.

The lock is advisory and time-bounded rather than a true mutex: a process that
is killed -9 cannot release it. A lock older than `stale_after` is recoverable,
because refusing to ever rotate again after a crash is worse than the small
chance of two overlapping runs on a credential nobody was watching.
"""

from __future__ import annotations

import contextlib
import os
import secrets
import socket
import sqlite3
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from .errors import RotationError

# Serialises the one-time initialisation of a brand-new SQLite database.
#
# `PRAGMA journal_mode = WAL` takes an exclusive lock for the duration of the
# mode change and fails immediately with "database is locked" if any other
# connection holds a read or write lock at that moment.  The busy timeout in
# `sqlite3.connect` does not apply here, so eight threads opening a new
# database at once would reliably produce errors rather than queueing.  The
# lock is per-path, keyed by the resolved initialisation: the first thread
# through creates the schema while the rest wait, and every later connection
# finds the database already initialised and skips the critical section.
# Public because the server's store opens its own database the same way.
_init_locks: dict[str, threading.Lock] = {}
_init_locks_guard = threading.Lock()

# The server serialises topology/value writes and whole rotations with this
# lock. It cannot collide with a manifest credential (NAME_RE forbids the
# leading underscores), and the per-credential lease still guards recovery.
STACK_LOCK = "__stack_configuration__"


def init_lock_for(path: Path) -> threading.Lock:
    key = str(path)
    with _init_locks_guard:
        if key not in _init_locks:
            _init_locks[key] = threading.Lock()
        return _init_locks[key]

SCHEMA = """
CREATE TABLE IF NOT EXISTS attempts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    credential    TEXT    NOT NULL,
    started_at    REAL    NOT NULL,
    finished_at   REAL,
    outcome       TEXT
);

CREATE TABLE IF NOT EXISTS steps (
    attempt_id    INTEGER NOT NULL REFERENCES attempts(id),
    ordinal       INTEGER NOT NULL,
    kind          TEXT    NOT NULL,
    target        TEXT    NOT NULL,
    detail        TEXT,
    started_at    REAL    NOT NULL,
    finished_at   REAL,
    outcome       TEXT,
    PRIMARY KEY (attempt_id, ordinal)
);

CREATE TABLE IF NOT EXISTS locks (
    credential    TEXT PRIMARY KEY,
    pid           INTEGER NOT NULL,
    host          TEXT    NOT NULL,
    acquired_at   REAL    NOT NULL,
    token         TEXT    NOT NULL DEFAULT '',
    actor         TEXT
);

-- A journal written before ownership tokens existed leaves token empty. The
-- placeholder is applied once, lazily, by _connect rather than here: this
-- script runs on every connection and must not issue a write each time. It
-- cannot collide with a real token - a token is 32 hex characters and this is
-- not - so such a lock is reclaimed rather than adopted.

CREATE INDEX IF NOT EXISTS steps_pending ON steps (attempt_id) WHERE finished_at IS NULL;

CREATE TABLE IF NOT EXISTS holders (
    attempt_id    INTEGER NOT NULL REFERENCES attempts(id),
    target        TEXT    NOT NULL,
    label         TEXT    NOT NULL,
    outcome       TEXT    NOT NULL,
    detail        TEXT,
    recorded_at   REAL    NOT NULL,
    PRIMARY KEY (attempt_id, target, label)
);
"""


@dataclass(frozen=True, slots=True)
class PendingStep:
    """A step that started and never finished. The shape of a crash."""

    attempt_id: int
    credential: str
    ordinal: int
    kind: str
    target: str
    detail: str
    started_at: float
    seconds_ago: float


def _pending(row: sqlite3.Row) -> PendingStep:
    """One row of the pending query, as the shape every caller reads."""
    return PendingStep(
        attempt_id=row["attempt_id"],
        credential=row["credential"],
        ordinal=row["ordinal"],
        kind=row["kind"],
        target=row["target"],
        detail=row["detail"] or "",
        started_at=row["started_at"],
        seconds_ago=time.time() - row["started_at"],
    )


class JournalLocked(RotationError):
    """Another rotation of this credential is already running."""


class Journal:
    """SQLite-backed rotation state.

    Deliberately not a history database. Audit history is a feature someone will
    ask for; crash detection is a correctness requirement, and only the second
    one justifies writing anything to disk before touching a credential.
    """

    def __init__(self, path: Path | str, *, stale_after: float = 900.0) -> None:
        # Coerced rather than trusted: a caller passing a string is ordinary,
        # not a mistake, and it should not become an AttributeError at the first
        # directory creation.
        self.path = Path(path)
        self.stale_after = stale_after

    @contextlib.contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            with init_lock_for(self.path):
                connection.execute("PRAGMA journal_mode = WAL")
                connection.executescript(SCHEMA)
            # CREATE TABLE IF NOT EXISTS will not add a column to a table that
            # already exists, so a journal written before ownership tokens had
            # none and every query against it raised OperationalError. Found by
            # running a dry run that actually preflights, rather than by a test.
            columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(locks)")
            }
            if "token" not in columns:
                connection.execute(
                    "ALTER TABLE locks ADD COLUMN token TEXT NOT NULL DEFAULT ''"
                )
            if "actor" not in columns:
                connection.execute("ALTER TABLE locks ADD COLUMN actor TEXT")
            # One-time migration, guarded so the common case writes nothing.
            if connection.execute(
                "SELECT 1 FROM locks WHERE token = '' LIMIT 1"
            ).fetchone():
                connection.execute(
                    "UPDATE locks SET token = 'legacy-' || credential "
                    "WHERE token = ''"
                )
            yield connection
        finally:
            connection.close()

    # -- locking ------------------------------------------------------------

    def try_acquire(self, credential: str, actor: str | None = None) -> str | None:
        """Take the lock if it is free. Returns an ownership token, or None.

        Non-blocking, because this is also how a UI asks "can this be rotated
        right now?" without committing to doing it. A caller that wants the
        blocking behaviour uses lock(), which is built on this.

        The token is what makes ownership unambiguous. pid and host alone are
        an identity that can be coincidentally reproduced - two containers can
        both be pid 1 on the same hostname - and a coincidental match would let
        one process renew or release another's lock. The token cannot be
        guessed, is different on every acquisition, and is stored alongside so
        a stale holder's token stops matching the moment it is replaced.

        `actor` is the caller's own statement of who is rotating, for display -
        "rotation in progress by X". It is deliberately not derived from pid or
        hostname, which are already recorded and are not identity: inventing one
        would show a confident wrong answer. It is never checked and never
        grants anything; ownership is provable only by the token. Absent stays
        absent rather than becoming a placeholder that reads like a name.
        """
        now = time.time()
        token = secrets.token_hex(16)
        with self._connect() as db:
            # IMMEDIATE takes the write lock up front. Without it the check, the
            # reclaim and the insert are three separate statements, and two
            # processes both finding the lock stale would each delete and
            # insert - both returning a token and both believing they hold it.
            db.execute("BEGIN IMMEDIATE")
            try:
                existing = db.execute(
                    "SELECT acquired_at FROM locks WHERE credential = ?", (credential,)
                ).fetchone()
                if (existing is not None
                        and now - existing["acquired_at"] <= self.stale_after):
                    db.execute("COMMIT")
                    return None
                if existing is not None:
                    # Reclaim. Refusing to ever rotate again after a crash is a
                    # worse failure than a rare overlap nobody was watching.
                    # Deliberately unconditional: reclaiming a stale lock must
                    # work whoever held it, which is why it is the one place a
                    # token is not required.
                    db.execute("DELETE FROM locks WHERE credential = ?", (credential,))
                db.execute(
                    "INSERT INTO locks (credential, pid, host, acquired_at, token, "
                    "actor) VALUES (?, ?, ?, ?, ?, ?)",
                    (credential, os.getpid(), socket.gethostname(), now, token, actor),
                )
            except Exception:
                db.execute("ROLLBACK")
                raise
            db.execute("COMMIT")
            return token

    def release(self, credential: str, token: str) -> None:
        """Release the lock, but only if this token still owns it.

        The ownership test and the deletion are one conditional DELETE, so
        there is no window between checking and removing in which a reclaim can
        swap the lock underneath. A process whose lock was reclaimed comes back,
        finishes, and releases on the way out; its token no longer matches, so
        it deletes nothing and cannot unlock the process that replaced it.
        """
        with self._connect() as db:
            db.execute(
                "DELETE FROM locks WHERE credential = ? AND token = ?",
                (credential, token),
            )

    def renew(self, credential: str, token: str) -> bool:
        """Extend the lease if this process still holds it.

        Returns False once the lock has been reclaimed, which is the signal to
        stop writing. A process that is merely slow keeps its lock because it
        keeps saying so; one that is wedged cannot, and is correctly fenced out.
        """
        with self._connect() as db:
            # One conditional UPDATE: a stale token cannot extend a
            # replacement's lease any more than it can release its lock.
            cursor = db.execute(
                "UPDATE locks SET acquired_at = ? WHERE credential = ? AND token = ?",
                (time.time(), credential, token),
            )
            return cursor.rowcount > 0

    def holds(self, credential: str, token: str) -> bool:
        """Whether this token still owns the lock. Read-only.

        Separate from renew because the check in front of a write should not
        itself extend the lease - that is the heartbeat's job, and conflating
        them makes a read of ownership look like a keep-alive.
        """
        with self._connect() as db:
            return db.execute(
                "SELECT 1 FROM locks WHERE credential = ? AND token = ?",
                (credential, token),
            ).fetchone() is not None

    def assert_held(self, credential: str, token: str) -> None:
        """Raise unless this process still holds the lock.

        The fence. It cannot make a write atomic with the check, but it means a
        process that was reclaimed stops before its next write rather than
        carrying on to the end and reporting success for work that was overtaken.
        """
        if not self.holds(credential, token):
            raise JournalLocked(
                f"{credential}: this process no longer holds the lock",
                hint="it was reclaimed as stale while this run was still going, "
                "so another rotation has taken over. Stopping rather than "
                "writing to services it no longer owns.",
            )

    @contextlib.contextmanager
    def lock(self, credential: str, actor: str | None = None) -> Iterator[str]:
        """Hold an exclusive rotation lock for one credential.

        Yields once the lock is held, and releases it on the way out - including
        when the body raises, which is the case that matters, since a failed
        rotation is precisely when a stale lock would be worst.

        The lease is renewed in the background for as long as the body runs. A
        fixed timeout alone cannot tell a dead process from a slow one, and
        reclaiming a merely-slow holder is how two runs end up writing the same
        holders at once.
        """
        token = self.try_acquire(credential, actor)
        if token is None:
            held = self.held(credential)
            age = time.time() - held["acquired_at"] if held else 0
            raise JournalLocked(
                f"{credential} is already being rotated "
                f"(pid {held['pid']} on {held['host']}, {int(age)}s ago)"
                if held
                else f"{credential} is already being rotated",
                hint="if that process is gone, the lock goes stale after "
                f"{int(self.stale_after)}s, or remove {self.path}",
            )

        stop = threading.Event()
        # Three renewals per lease: frequent enough that a live holder is never
        # seen as stale, rare enough to be noise.
        interval = max(self.stale_after / 3, 0.05)

        def _renew() -> None:
            while not stop.wait(interval):
                if not self.renew(credential, token):
                    return

        heartbeat = threading.Thread(target=_renew, daemon=True)
        heartbeat.start()
        try:
            yield token
        finally:
            stop.set()
            heartbeat.join(timeout=interval)
            self.release(credential, token)

    def held(self, credential: str) -> sqlite3.Row | None:
        with self._connect() as db:
            return db.execute(
                "SELECT pid, host, acquired_at, token, actor "
                "FROM locks WHERE credential = ?",
                (credential,),
            ).fetchone()

    # -- attempts -----------------------------------------------------------

    def begin(self, credential: str) -> int:
        """Record that a rotation is starting. Returns the attempt id.

        Called before the first step, so an interrupted rotation is visible even
        if it died before doing anything.
        """
        with self._connect() as db:
            cursor = db.execute(
                "INSERT INTO attempts (credential, started_at) VALUES (?, ?)",
                (credential, time.time()),
            )
            return int(cursor.lastrowid or 0)

    def step_started(self, attempt: int, ordinal: int, kind: str,
                     target: str, detail: str) -> None:
        """Record a step as beginning.

        Written *before* the step runs. That ordering is the whole point: a
        record with no matching finish means the process died inside the step,
        which is exactly the case an operator needs to be told about.
        """
        with self._connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO steps "
                "(attempt_id, ordinal, kind, target, detail, started_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (attempt, ordinal, kind, target, detail, time.time()),
            )

    def step_finished(self, attempt: int, ordinal: int, outcome: str) -> None:
        with self._connect() as db:
            db.execute(
                "UPDATE steps SET finished_at = ?, outcome = ? "
                "WHERE attempt_id = ? AND ordinal = ?",
                (time.time(), outcome, attempt, ordinal),
            )

    def attempt_outcome(self, attempt: int) -> str | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT outcome FROM attempts WHERE id = ?", (attempt,)
            ).fetchone()
        return row["outcome"] if row else None

    def steps(self, attempt: int) -> list[dict]:
        """What an attempt actually did, in order. Used to explain a rotation
        after the fact without exposing any value."""
        with self._connect() as db:
            rows = db.execute(
                "SELECT ordinal, kind, target, detail, finished_at, outcome "
                "FROM steps WHERE attempt_id = ? ORDER BY ordinal",
                (attempt,),
            ).fetchall()
        return [dict(r) for r in rows]

    def record_holder(self, attempt: int, target: str, label: str,
                      outcome: str, detail: str = "") -> None:
        """Record what happened to one holder.

        The database is the authority on what a holder currently holds, but it
        lives on the machine being changed. This is the controller's record of
        what it *did*, which is what an operator needs after a crash: the answer
        to "which of the sixteen did we already write" cannot come from the
        thing that may be half-changed.
        """
        with self._connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO holders "
                "(attempt_id, target, label, outcome, detail, recorded_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (attempt, target, label, outcome, detail, time.time()),
            )

    def holders(self, attempt: int) -> list[dict]:
        """What this run did to each holder, as of the last write.

        Promoted through the run: a holder first recorded as `written` and later
        as `confirmed` appears once, with the final state.
        """
        with self._connect() as db:
            rows = db.execute(
                "SELECT target, label, outcome, detail FROM holders "
                "WHERE attempt_id = ? ORDER BY target, label",
                (attempt,),
            ).fetchall()
        return [dict(r) for r in rows]

    def last_attempt(self, credential: str) -> int | None:
        """The newest attempt id for a credential, or None if it has none."""
        with self._connect() as db:
            row = db.execute(
                "SELECT id FROM attempts WHERE credential = ? ORDER BY id DESC LIMIT 1",
                (credential,),
            ).fetchone()
        return int(row["id"]) if row else None

    def finish(self, attempt: int, outcome: str) -> None:
        with self._connect() as db:
            db.execute(
                "UPDATE attempts SET finished_at = ?, outcome = ? WHERE id = ?",
                (time.time(), outcome, attempt),
            )

    def open_attempts(self) -> dict[str, int]:
        """Attempts begun but never finished, mapped to their ids.

        A kill can land after the last step finished and before `finish` wrote
        the attempt outcome. The step rows would all look complete, so an
        unattended start must treat the open attempt itself as unfinished too.
        """
        with self._connect() as db:
            rows = db.execute(
                "SELECT credential, MAX(id) AS id FROM attempts "
                "WHERE finished_at IS NULL GROUP BY credential"
            ).fetchall()
        return {row["credential"]: int(row["id"]) for row in rows}

    def last_success(self, credential: str) -> float | None:
        """When this credential was last rotated *successfully*, or None.

        This is the strict "nothing is left to do" answer: the attempt must be
        finished and `completed`, every step must be finished, there must be no
        manual step (its work is still outstanding), and no step may carry a
        failure/abandonment outcome. Auto-rotation uses `last_rotation` instead,
        because an outstanding manual copy must not make the due clock repeat
        the mint on every audit.
        """
        with self._connect() as db:
            row = db.execute(
                "SELECT a.finished_at FROM attempts a "
                "WHERE a.credential = ? AND a.outcome = 'completed' "
                "  AND a.finished_at IS NOT NULL "
                "  AND NOT EXISTS ("
                "    SELECT 1 FROM steps s WHERE s.attempt_id = a.id AND ("
                "      s.finished_at IS NULL OR s.kind = 'manual' "
                "      OR s.outcome LIKE 'failed%' OR s.outcome LIKE 'abandoned%'"
                "    )"
                "  ) "
                "  AND NOT EXISTS ("
                "    SELECT 1 FROM holders h WHERE h.attempt_id = a.id "
                "      AND h.outcome IN ('failed', 'not-reached', 'written')"
                "  ) "
                "ORDER BY a.id DESC LIMIT 1",
                (credential,),
            ).fetchone()
        return float(row["finished_at"]) if row else None

    def last_rotation(self, credential: str) -> float | None:
        """When this credential last completed a rotation, manual work included.

        `last_success` is the strict "nothing left to do" answer. Auto-rotation
        needs a different one: when the mint completed and every step that
        could run did run, an outstanding manual copy must not make the worker
        retry on the next audit. A holder written but not read back is the same
        case - the key changed, the copy is unproven, and the operator has been
        told. Failed/abandoned/unfinished steps still do not count.
        """
        with self._connect() as db:
            row = db.execute(
                "SELECT a.finished_at FROM attempts a "
                "WHERE a.credential = ? AND a.outcome = 'completed' "
                "  AND a.finished_at IS NOT NULL "
                "  AND NOT EXISTS ("
                "    SELECT 1 FROM steps s WHERE s.attempt_id = a.id AND ("
                "      s.finished_at IS NULL "
                "      OR s.outcome LIKE 'failed%' OR s.outcome LIKE 'abandoned%'"
                "    )"
                "  ) "
                "  AND NOT EXISTS ("
                "    SELECT 1 FROM holders h WHERE h.attempt_id = a.id "
                "      AND h.outcome IN ('failed', 'not-reached')"
                "  ) "
                "ORDER BY a.id DESC LIMIT 1",
                (credential,),
            ).fetchone()
        return float(row["finished_at"]) if row else None

    def last_rotations(self) -> dict[str, float]:
        """When each credential last completed a rotation, in one read.

        Same predicate as `last_rotation`, grouped instead of asked once per
        credential. The credentials list uses this on every shell refresh; a
        per-name query made that list N round trips for one screen.
        """
        with self._connect() as db:
            rows = db.execute(
                "WITH eligible AS ("
                "  SELECT a.id, a.credential, a.finished_at "
                "  FROM attempts a "
                "  WHERE a.finished_at IS NOT NULL AND a.outcome = 'completed' "
                "    AND NOT EXISTS ("
                "      SELECT 1 FROM steps s WHERE s.attempt_id = a.id AND ("
                "        s.finished_at IS NULL "
                "        OR s.outcome LIKE 'failed%' OR s.outcome LIKE 'abandoned%'"
                "      )"
                "    ) "
                "    AND NOT EXISTS ("
                "      SELECT 1 FROM holders h WHERE h.attempt_id = a.id "
                "        AND h.outcome IN ('failed', 'not-reached')"
                "    )"
                ") "
                "SELECT e.credential, e.finished_at "
                "FROM eligible e "
                "JOIN ("
                "  SELECT credential, MAX(id) AS id FROM eligible GROUP BY credential"
                ") latest ON latest.id = e.id"
            ).fetchall()
        return {
            row["credential"]: float(row["finished_at"])
            for row in rows
        }

    def unfinished(self) -> list[PendingStep]:
        """Every started-but-unfinished step, with no liveness window.

        `pending()` answers "is a live worker stuck?" and therefore hides old
        steps; an unattended run needs the stricter question "is there any
        unfinished record at all?". This query is that question.
        """
        with self._connect() as db:
            rows = db.execute(
                "SELECT s.attempt_id, a.credential, s.ordinal, s.kind, s.target, "
                "       s.detail, s.started_at "
                "FROM steps s JOIN attempts a ON a.id = s.attempt_id "
                "WHERE s.finished_at IS NULL "
                "ORDER BY s.started_at",
            ).fetchall()
        return [_pending(row) for row in rows]

    @staticmethod
    def _close_reclaimed_attempts(
        db: sqlite3.Connection,
        credential: str,
        outcome: str,
    ) -> None:
        """Finish attempts whose steps no longer leave them open.

        A kill can land after ``begin`` and before the first step, or after the
        last step and before ``finish``. Those attempts have no pending step to
        close, but they are still unfinished records. This is called only after
        the caller owns the credential's lock, so an attempt with no unfinished
        step cannot belong to a live run.
        """
        db.execute(
            "UPDATE attempts SET finished_at = ?, outcome = ? "
            "WHERE credential = ? AND finished_at IS NULL "
            "  AND NOT EXISTS ("
            "    SELECT 1 FROM steps s WHERE s.attempt_id = attempts.id "
            "    AND s.finished_at IS NULL)",
            (time.time(), outcome, credential),
        )

    def reclaim_stale(self, credential: str) -> list[PendingStep]:
        """Close out this credential's steps abandoned by a dead run, and report them.

        Age alone never authorises a new rotation. What authorises it is the
        state observed afterwards: the mint step re-derives from the service's
        live key, the backup artifact and the pending store whether a restore
        already happened, so a reclaimed run resumes the earlier mint instead of
        making a second one. This only stops the abandoned steps from blocking
        forever, and it closes them explicitly rather than letting them quietly
        age out of a query.

        One credential's steps, not the journal's: "reclaimed by a later
        attempt" is a statement about *this* credential's history, and a run of
        another credential writing it onto these rows would both invent an
        attempt that never happened and close the record of a run that is alive
        but slow. Another credential's stale steps are invisible everywhere
        already (`pending` excludes them) and its own next run reclaims them.

        Returns the reclaimed steps so the caller can say what it took over.
        """
        cutoff = time.time() - self.stale_after
        with self._connect() as db:
            rows = db.execute(
                "SELECT s.attempt_id, a.credential, s.ordinal, s.kind, s.target, "
                "       s.detail, s.started_at "
                "FROM steps s JOIN attempts a ON a.id = s.attempt_id "
                "WHERE s.finished_at IS NULL AND s.started_at <= ? "
                "  AND a.credential = ? "
                "ORDER BY s.started_at",
                (cutoff, credential),
            ).fetchall()
            db.execute(
                "UPDATE steps SET finished_at = ?, outcome = 'abandoned: run "
                "presumed dead, reclaimed by a later attempt' "
                "WHERE finished_at IS NULL AND started_at <= ? "
                "  AND attempt_id IN (SELECT id FROM attempts WHERE credential = ?)",
                (time.time(), cutoff, credential),
            )
            self._close_reclaimed_attempts(
                db,
                credential,
                "abandoned: run presumed dead, reclaimed by a later attempt",
            )
        return [_pending(r) for r in rows]

    def take_over(self, credential: str, actor: str | None) -> list[PendingStep]:
        """Close a credential's unfinished steps now, because a human said so.

        `pending()` excludes steps older than `stale_after`, so without this the
        only way past a fresh crash is to wait out that window. An operator who
        knows the run is dead - the console offers exactly this - closes them
        early, and the row says who decided, because "reclaimed by a later
        attempt" would be a claim about a run that never happened.

        This closes the record, not the rotation: what makes a takeover safe is
        that the mint re-derives from the service's own state and the vault, and
        never gets here without the lock.
        """
        who = actor or "an unnamed caller"
        with self._connect() as db:
            rows = db.execute(
                "SELECT s.attempt_id, a.credential, s.ordinal, s.kind, s.target, "
                "       s.detail, s.started_at "
                "FROM steps s JOIN attempts a ON a.id = s.attempt_id "
                "WHERE s.finished_at IS NULL AND a.credential = ? "
                "ORDER BY s.started_at",
                (credential,),
            ).fetchall()
            db.execute(
                "UPDATE steps SET finished_at = ?, outcome = ? "
                "WHERE finished_at IS NULL AND attempt_id IN "
                "      (SELECT id FROM attempts WHERE credential = ?)",
                (time.time(), f"abandoned: taken over by {who}", credential),
            )
            self._close_reclaimed_attempts(
                db, credential, f"abandoned: taken over by {who}"
            )
        return [_pending(r) for r in rows]

    def pending(self) -> list[PendingStep]:
        """Steps that started and never finished and are still recent enough to
        matter, oldest first.

        This is the query a dashboard shows on load and an operator runs before
        retrying anything.

        Steps older than `stale_after` are excluded for the same reason the lock
        reclaims them: the run that owned them is presumed dead, and a step
        left behind by a killed process would otherwise block every future
        rotation with no way to clear it. The preflight turns a non-empty result
        into a refusal, so the age rule is what keeps a crash from permanently
        wedging the credential. It is a liveness rule only - see
        `reclaim_stale` and `take_over` for what authorises the new run.
        """
        now = time.time()
        with self._connect() as db:
            rows = db.execute(
                "SELECT s.attempt_id, a.credential, s.ordinal, s.kind, s.target, "
                "       s.detail, s.started_at "
                "FROM steps s JOIN attempts a ON a.id = s.attempt_id "
                "WHERE s.finished_at IS NULL AND s.started_at > ? "
                "ORDER BY s.started_at",
                (now - self.stale_after,),
            ).fetchall()
        return [_pending(r) for r in rows]
