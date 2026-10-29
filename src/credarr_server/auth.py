"""The single admin: one password, sessions, hashed keys.

The app serves one operator, so the model is the smallest honest one: a
password (argon2id, from the reference library), a durable five-failure
lockout, browser sessions whose raw token exists only in the cookie, and API
keys for automation, stored as the SHA-256 of a 256-bit random value and shown
once, at creation.

A session row holds a hash of the token, a CSRF token, and the two expiries the
server enforces: an idle window that slides on activity and an absolute window
that cannot. Nothing in these tables is a service credential, and nothing in
them can be turned back into one.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError

from .store import connect, initialise

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- The hash of an issued key, never the key. The prefix is what the UI lists so
-- an operator can tell two keys apart while neither is recoverable.
CREATE TABLE IF NOT EXISTS app_api_keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash     TEXT    NOT NULL UNIQUE,
    prefix       TEXT    NOT NULL,
    created_at   REAL    NOT NULL,
    last_used_at REAL
);

-- Browser sessions. The token is the cookie; only its hash is stored. A row
-- is live while it is neither revoked nor past either expiry. `device` is a
-- sanitized label, never an address: there is no need to retain one.
CREATE TABLE IF NOT EXISTS app_sessions (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash          TEXT    NOT NULL UNIQUE,
    subject             TEXT    NOT NULL,
    csrf_token          TEXT    NOT NULL,
    created_at          REAL    NOT NULL,
    last_seen_at        REAL    NOT NULL,
    idle_expires_at     REAL    NOT NULL,
    absolute_expires_at REAL    NOT NULL,
    revoked_at          REAL,
    device              TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS app_sessions_live
    ON app_sessions (subject, revoked_at, absolute_expires_at);

-- Failed sign-ins are counted against the one admin account, not the
-- caller-supplied name: otherwise an attacker could create a row per guess.
CREATE TABLE IF NOT EXISTS login_failures (
    subject         TEXT PRIMARY KEY,
    failures        INTEGER NOT NULL,
    last_failure_at REAL    NOT NULL,
    locked_until    REAL    NOT NULL DEFAULT 0
);
"""

# The app's own policy, and the only claim about password strength it makes:
# length. Twelve characters is a floor, not an opinion about how a password
# should be built. Servarr accepts a non-empty password; copying that would
# weaken the console that holds every service key, so the minimum stays here.
MIN_PASSWORD_LENGTH = 12
MAX_LOGIN_FAILURES = 5
LOGIN_FAILURE_WINDOW = 15 * 60
LOGIN_LOCKOUT_SECONDS = 5 * 60

# A credential console is worth stealing. Thirty minutes of idle time keeps an
# active operator signed in, and a twelve-hour ceiling means a copied cookie
# stops working the same day even if it is used continuously.
SESSION_IDLE_SECONDS = 30 * 60
SESSION_ABSOLUTE_SECONDS = 12 * 60 * 60
SESSION_RENEW_FRACTION = 0.5

# `last_used_at` is informative, not an audit event. Writing it on every API
# request turns a read-only automation call into a SQLite write; Profilarr
# throttles the same field to a minute, so this keeps the UI useful without
# making every poll a transaction.
LAST_USED_THROTTLE_SECONDS = 60.0

PASSWORD_SETTING = "admin_password"  # noqa: S105 - a settings row name, not a password

KEY_PREFIX = "credarr_"
_DISPLAY_CHARS = 8
_DEVICE_LIMIT = 120


class SetupAlreadyDone(Exception):
    """An admin password exists; setup is a one-time act."""


class WrongPassword(Exception):
    """The current password did not match; a change was refused."""


class InvalidCredentials(Exception):
    """The password did not match; the caller answers generically."""


class LoginLocked(Exception):
    """Too many recent failures; the account is temporarily closed."""

    def __init__(self, seconds: int) -> None:
        self.seconds = max(1, seconds)
        super().__init__(f"too many failed sign-in attempts; try again in {self.seconds}s")


@dataclass(frozen=True, slots=True)
class ApiKey:
    """One automation key as the UI may see it: never the key itself."""

    id: int
    prefix: str
    created_at: float
    last_used_at: float | None


@dataclass(frozen=True, slots=True)
class Session:
    """One live browser session. The token and its hash never leave storage."""

    id: int
    subject: str
    csrf_token: str
    created_at: float
    last_seen_at: float
    idle_expires_at: float
    absolute_expires_at: float
    device: str


@dataclass(frozen=True, slots=True)
class IssuedSession:
    """The raw cookie value and the row it authenticates, returned once."""

    token: str
    session: Session


@dataclass(frozen=True, slots=True)
class SessionLookup:
    """An authenticated request's session, and whether its cookie was renewed."""

    session: Session
    renewed: bool


class AdminAuth:
    """The password, the browser sessions and the API keys, in one database."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        initialise(self.path, SCHEMA)
        self._hasher = PasswordHasher()
        # One process owns /config, so this is the exact lockout bound; the
        # database keeps the durable state across restarts.
        self._login_lock = threading.Lock()
        self._last_used: dict[int, float] = {}

    def needs_setup(self) -> bool:
        """True until an admin password exists."""
        with connect(self.path) as connection:
            row = connection.execute(
                "SELECT 1 FROM settings WHERE key = ?", (PASSWORD_SETTING,)
            ).fetchone()
        return row is None

    def set_password(self, password: str) -> None:
        """Set the admin password, once.

        `INSERT OR IGNORE` makes the check and the write one statement, so two
        first-run requests cannot both win.
        """
        if len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"the password must be at least {MIN_PASSWORD_LENGTH} characters")
        if not self.needs_setup():
            raise SetupAlreadyDone
        digest = self._hasher.hash(password.encode("utf-8"))
        with connect(self.path) as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
                (PASSWORD_SETTING, digest),
            )
            if cursor.rowcount == 0:
                raise SetupAlreadyDone

    def verify_password(self, password: str) -> bool:
        """Argon2's own answer; without an admin, nothing matches."""
        with connect(self.path) as connection:
            row = connection.execute(
                "SELECT value FROM settings WHERE key = ?", (PASSWORD_SETTING,)
            ).fetchone()
        if row is None:
            return False
        try:
            self._hasher.verify(row["value"], password.encode("utf-8"))
        except VerificationError:
            return False
        return True

    def login(self, password: str, *, now: float | None = None) -> None:
        """Authenticate the one admin, with a durable failure lockout.

        The lock is keyed to the single account. A generic result is the
        caller's responsibility; this method only distinguishes locked from
        invalid. A successful login clears the failure window.
        """
        at = time.time() if now is None else now
        with self._login_lock:
            remaining = self._lockout_remaining(at)
            if remaining > 0:
                raise LoginLocked(remaining)
            if not self.verify_password(password):
                self._record_failure(at)
                raise InvalidCredentials
            self._clear_failures()

    def _lockout_remaining(self, now: float) -> int:
        with connect(self.path) as connection:
            row = connection.execute(
                "SELECT locked_until FROM login_failures WHERE subject = 'admin'"
            ).fetchone()
        if row is None:
            return 0
        return max(0, int(float(row["locked_until"]) - now + 0.999))

    def _record_failure(self, now: float) -> None:
        with connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT failures, last_failure_at, locked_until "
                    "FROM login_failures WHERE subject = 'admin'"
                ).fetchone()
                if (
                    row is None
                    or now - float(row["last_failure_at"]) > LOGIN_FAILURE_WINDOW
                    or (
                        float(row["locked_until"]) > 0
                        and float(row["locked_until"]) <= now
                    )
                ):
                    failures = 1
                else:
                    failures = int(row["failures"]) + 1
                locked_until = (
                    now + LOGIN_LOCKOUT_SECONDS
                    if failures >= MAX_LOGIN_FAILURES
                    else 0.0
                )
                connection.execute(
                    "INSERT INTO login_failures "
                    "(subject, failures, last_failure_at, locked_until) "
                    "VALUES ('admin', ?, ?, ?) "
                    "ON CONFLICT(subject) DO UPDATE SET "
                    "failures = excluded.failures, "
                    "last_failure_at = excluded.last_failure_at, "
                    "locked_until = excluded.locked_until",
                    (failures, now, locked_until),
                )
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    def _clear_failures(self) -> None:
        with connect(self.path) as connection:
            connection.execute(
                "DELETE FROM login_failures WHERE subject = 'admin'"
            )

    def change_password(self, current: str, new: str) -> None:
        """Replace the password and revoke every browser session.

        The caller creates a fresh session after this, so the operator who
        changed it is not signed out; any other tab is.
        """
        if not self.verify_password(current):
            raise WrongPassword
        if len(new) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"the password must be at least {MIN_PASSWORD_LENGTH} characters")
        digest = self._hasher.hash(new.encode("utf-8"))
        now = time.time()
        with connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "UPDATE settings SET value = ? WHERE key = ?",
                    (digest, PASSWORD_SETTING),
                )
                connection.execute(
                    "UPDATE app_sessions SET revoked_at = ? "
                    "WHERE subject = 'admin' AND revoked_at IS NULL",
                    (now,),
                )
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    def create_session(self, device: str = "", *, now: float | None = None) -> IssuedSession:
        """Issue a new opaque session; the raw token is returned exactly once."""
        issued_at = time.time() if now is None else now
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        idle_expires = issued_at + SESSION_IDLE_SECONDS
        absolute_expires = issued_at + SESSION_ABSOLUTE_SECONDS
        label = _device_label(device)
        with connect(self.path) as connection:
            cursor = connection.execute(
                "INSERT INTO app_sessions "
                "(token_hash, subject, csrf_token, created_at, last_seen_at, "
                " idle_expires_at, absolute_expires_at, device) "
                "VALUES (?, 'admin', ?, ?, ?, ?, ?, ?)",
                (
                    _session_hash(token),
                    csrf,
                    issued_at,
                    issued_at,
                    idle_expires,
                    absolute_expires,
                    label,
                ),
            )
        return IssuedSession(
            token=token,
            session=Session(
                id=cursor.lastrowid,
                subject="admin",
                csrf_token=csrf,
                created_at=issued_at,
                last_seen_at=issued_at,
                idle_expires_at=idle_expires,
                absolute_expires_at=absolute_expires,
                device=label,
            ),
        )

    def authenticate_session(
        self, token: str, *, now: float | None = None
    ) -> SessionLookup | None:
        """Check a cookie and slide the idle window when it is half spent.

        Both expiries are enforced here, not by the browser's `Max-Age`. An
        expired row is marked revoked so a replay cannot extend it later.
        Concurrent requests may renew the same idle window; the token does not
        rotate, so they cannot invalidate each other.
        """
        if not token:
            return None
        seen_at = time.time() if now is None else now
        digest = _session_hash(token)
        with connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT * FROM app_sessions WHERE token_hash = ?", (digest,)
                ).fetchone()
                if row is None or row["revoked_at"] is not None:
                    connection.execute("COMMIT")
                    return None
                absolute_expires = row["absolute_expires_at"]
                if seen_at >= absolute_expires or seen_at >= row["idle_expires_at"]:
                    connection.execute(
                        "UPDATE app_sessions SET revoked_at = ? "
                        "WHERE id = ? AND revoked_at IS NULL",
                        (seen_at, row["id"]),
                    )
                    connection.execute("COMMIT")
                    return None
                remaining = row["idle_expires_at"] - seen_at
                renewed = remaining < SESSION_IDLE_SECONDS * SESSION_RENEW_FRACTION
                idle_expires = row["idle_expires_at"]
                if renewed:
                    idle_expires = min(seen_at + SESSION_IDLE_SECONDS, absolute_expires)
                cursor = connection.execute(
                    "UPDATE app_sessions SET last_seen_at = ?, idle_expires_at = ? "
                    "WHERE id = ? AND revoked_at IS NULL",
                    (seen_at, idle_expires, row["id"]),
                )
                if cursor.rowcount == 0:
                    connection.execute("COMMIT")
                    return None
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        return SessionLookup(
            session=Session(
                id=row["id"],
                subject=row["subject"],
                csrf_token=row["csrf_token"],
                created_at=row["created_at"],
                last_seen_at=seen_at,
                idle_expires_at=idle_expires,
                absolute_expires_at=absolute_expires,
                device=row["device"],
            ),
            renewed=renewed,
        )

    def revoke_session(
        self, session_id: int, *, subject: str = "admin", now: float | None = None
    ) -> bool:
        """Revoke one session; True when a live row was there."""
        revoked_at = time.time() if now is None else now
        with connect(self.path) as connection:
            cursor = connection.execute(
                "UPDATE app_sessions SET revoked_at = ? "
                "WHERE id = ? AND subject = ? AND revoked_at IS NULL",
                (revoked_at, session_id, subject),
            )
        return cursor.rowcount == 1

    def revoke_token(self, token: str, *, now: float | None = None) -> bool:
        """Revoke the session a cookie names, if it is still live."""
        if not token:
            return False
        revoked_at = time.time() if now is None else now
        with connect(self.path) as connection:
            cursor = connection.execute(
                "UPDATE app_sessions SET revoked_at = ? "
                "WHERE token_hash = ? AND revoked_at IS NULL",
                (revoked_at, _session_hash(token)),
            )
        return cursor.rowcount == 1

    def revoke_all_sessions(
        self,
        *,
        subject: str = "admin",
        keep: int | None = None,
        now: float | None = None,
    ) -> int:
        """Revoke every live session for the subject, optionally keeping one."""
        revoked_at = time.time() if now is None else now
        statement = (
            "UPDATE app_sessions SET revoked_at = ? "
            "WHERE subject = ? AND revoked_at IS NULL"
        )
        values: list[float | str | int] = [revoked_at, subject]
        if keep is not None:
            statement += " AND id != ?"
            values.append(keep)
        with connect(self.path) as connection:
            cursor = connection.execute(statement, values)
        return cursor.rowcount

    def list_sessions(
        self, *, subject: str = "admin", now: float | None = None
    ) -> tuple[Session, ...]:
        """Every live session for the subject, newest activity first."""
        seen_at = time.time() if now is None else now
        with connect(self.path) as connection:
            rows = connection.execute(
                "SELECT * FROM app_sessions "
                "WHERE subject = ? AND revoked_at IS NULL "
                "AND idle_expires_at > ? AND absolute_expires_at > ? "
                "ORDER BY last_seen_at DESC, id DESC",
                (subject, seen_at, seen_at),
            ).fetchall()
        return tuple(_session_from_row(row) for row in rows)

    def create_key(self) -> tuple[int, str]:
        """Issue a key and return `(id, key)`; this is the only clear copy."""
        key = KEY_PREFIX + secrets.token_urlsafe(32)
        with connect(self.path) as connection:
            cursor = connection.execute(
                "INSERT INTO app_api_keys (key_hash, prefix, created_at) VALUES (?, ?, ?)",
                (_key_hash(key), key[: len(KEY_PREFIX) + _DISPLAY_CHARS], time.time()),
            )
        return cursor.lastrowid, key

    def list_keys(self) -> tuple[ApiKey, ...]:
        with connect(self.path) as connection:
            rows = connection.execute(
                "SELECT id, prefix, created_at, last_used_at FROM app_api_keys ORDER BY id"
            ).fetchall()
        return tuple(
            ApiKey(
                id=row["id"],
                prefix=row["prefix"],
                created_at=row["created_at"],
                last_used_at=row["last_used_at"],
            )
            for row in rows
        )

    def revoke_key(self, key_id: int) -> bool:
        """Delete a key; True when one was there to delete."""
        with connect(self.path) as connection:
            cursor = connection.execute("DELETE FROM app_api_keys WHERE id = ?", (key_id,))
        return cursor.rowcount == 1

    def verify_key(self, presented: str) -> int | None:
        """The key's id when it authenticates, or None; records the use.

        The lookup is the hash: a 256-bit random value has nothing to guess, so
        the unique index is an adequate comparison and constant time is a
        second boundary rather than the first. `last_used_at` is informative;
        it is throttled, and a backwards clock can delay its next write until
        the clock catches up. That is not an authentication decision.
        """
        digest = _key_hash(presented)
        with connect(self.path) as connection:
            row = connection.execute(
                "SELECT id, key_hash FROM app_api_keys WHERE key_hash = ?", (digest,)
            ).fetchone()
            if row is None or not hmac.compare_digest(row["key_hash"], digest):
                return None
            now = time.time()
            last = self._last_used.get(row["id"])
            if last is None or now - last >= LAST_USED_THROTTLE_SECONDS:
                connection.execute(
                    "UPDATE app_api_keys SET last_used_at = ? WHERE id = ?",
                    (now, row["id"]),
                )
                self._last_used[row["id"]] = now
        return row["id"]


def _session_from_row(row: sqlite3.Row) -> Session:
    return Session(
        id=row["id"],
        subject=row["subject"],
        csrf_token=row["csrf_token"],
        created_at=row["created_at"],
        last_seen_at=row["last_seen_at"],
        idle_expires_at=row["idle_expires_at"],
        absolute_expires_at=row["absolute_expires_at"],
        device=row["device"],
    )


def _device_label(user_agent: str) -> str:
    """A short, printable label for the session list; never an address."""
    text = "".join(char for char in str(user_agent or "") if char.isprintable()).strip()
    return text[:_DEVICE_LIMIT] or "Unknown browser"


def _session_hash(token: str) -> str:
    """SHA-256: the token is 256 random bits, so there is nothing to stretch."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _key_hash(key: str) -> str:
    """SHA-256, not argon2: slow hashing protects guessable secrets, and a
    256-bit random key has no guessable space to protect."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()
