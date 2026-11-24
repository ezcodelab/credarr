"""Durable delivery jobs for the agents that deploy a changed value.

A value change commits its version, generation and outbox row in one
transaction. This module turns that outbox into per-target jobs after the
commit, leases one job at a time to an enrolled agent, and records the agent's
per-service result. It never holds a value: a job names the credential, the
value version and the generation; the agent reads the shared vault tree.

State machine:

    queued -> leased -> running -> delivered
                        |  \\-> retry_wait -> queued
                        \\-----> failed
    queued/retry_wait -> cancelled

A partial service result is never terminal success: it becomes `retry_wait`
and a later attempt re-runs the whole declared service set. A job that exhausts
its attempts becomes `failed` and emits `sync_failed`. Expired leases are
returned to `retry_wait` by the maintenance tick, and a replayed result for a
job that is no longer leased by that agent is refused.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from credarr.redact import scrub

from . import event_schema
from .database import connect, initialise

SYNC_STATES = ("queued", "leased", "running", "retry_wait", "delivered", "failed", "cancelled")
ACTIVE_STATES = ("queued", "leased", "running", "retry_wait")
TERMINAL_STATES = ("delivered", "failed", "cancelled")
AGENT_STATES = ("enrolled", "active", "offline", "revoked", "disabled")
WORKFLOWS = ("compose", "env")

MAX_ATTEMPTS = 5
LEASE_SECONDS = 60.0
BACKOFF_BASE_SECONDS = 30.0
BACKOFF_CAP_SECONDS = 3600.0

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    id                      TEXT PRIMARY KEY,
    name                    TEXT NOT NULL UNIQUE,
    status                  TEXT NOT NULL
                            CHECK (status IN
                              ('enrolled','active','offline','revoked','disabled')),
    capabilities            TEXT NOT NULL DEFAULT '[]',
    certificate_fingerprint TEXT UNIQUE,
    certificate_expires_at  REAL,
    rootful                 INTEGER NOT NULL DEFAULT 0,
    rootful_ack             INTEGER NOT NULL DEFAULT 0,
    last_seen_at            REAL,
    disabled_reason         TEXT NOT NULL DEFAULT '',
    created_at              REAL NOT NULL,
    updated_at              REAL NOT NULL
);

-- A one-time enrollment token: only its hash is stored, and it is unusable
-- after the first success or its short expiry.
CREATE TABLE IF NOT EXISTS agent_enrollments (
    id           TEXT PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE,
    agent_name   TEXT NOT NULL,
    capabilities TEXT NOT NULL DEFAULT '[]',
    expires_at   REAL NOT NULL,
    used_at      REAL,
    created_at   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sync_targets (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    agent_id     TEXT NOT NULL,
    stack_path   TEXT NOT NULL,
    project_name TEXT NOT NULL,
    services     TEXT NOT NULL,
    workflow     TEXT NOT NULL DEFAULT 'compose'
                 CHECK (workflow IN ('compose','env')),
    env_file     TEXT,
    values_json  TEXT NOT NULL DEFAULT '{}',
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sync_jobs (
    id              TEXT PRIMARY KEY,
    credential      TEXT NOT NULL,
    target_id       TEXT NOT NULL,
    value_version   TEXT NOT NULL,
    generation_id   INTEGER NOT NULL,
    state           TEXT NOT NULL
                    CHECK (state IN
                      ('queued','leased','running','retry_wait','delivered',
                       'failed','cancelled')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    max_attempts    INTEGER NOT NULL DEFAULT 5,
    next_attempt_at REAL,
    lease_until     REAL,
    agent_id        TEXT,
    created_at      REAL NOT NULL,
    updated_at      REAL NOT NULL,
    started_at      REAL,
    finished_at     REAL,
    last_error      TEXT NOT NULL DEFAULT '',
    result          TEXT NOT NULL DEFAULT '{}'
);

CREATE UNIQUE INDEX IF NOT EXISTS sync_jobs_one_active
    ON sync_jobs (credential, target_id)
    WHERE state IN ('queued','leased','running','retry_wait');

CREATE INDEX IF NOT EXISTS sync_jobs_agent_state
    ON sync_jobs (agent_id, state, next_attempt_at);
"""


class SyncError(Exception):
    """A sync operation was refused; the message is safe to show."""


class PolicyViolation(SyncError):
    """An agent asked for work outside its bound capabilities or allowlist."""


@dataclass(frozen=True, slots=True)
class SyncTarget:
    id: str
    name: str
    agent_id: str
    stack_path: str
    project_name: str
    services: tuple[str, ...]
    workflow: str
    enabled: bool
    created_at: float
    updated_at: float
    env_file: str | None = None
    values: dict[str, str] = field(default_factory=dict)

    def as_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "agent_id": self.agent_id,
            "stack_path": self.stack_path,
            "project_name": self.project_name,
            "services": list(self.services),
            "workflow": self.workflow,
            "env_file": self.env_file,
            "values": dict(self.values),
            "enabled": self.enabled,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True, slots=True)
class Agent:
    id: str
    name: str
    status: str
    capabilities: tuple[str, ...]
    certificate_fingerprint: str | None
    certificate_expires_at: float | None
    rootful: bool
    rootful_ack: bool
    last_seen_at: float | None
    disabled_reason: str
    created_at: float
    updated_at: float

    def as_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status,
            "capabilities": list(self.capabilities),
            "certificate_fingerprint": self.certificate_fingerprint,
            "certificate_expires_at": self.certificate_expires_at,
            "rootful": self.rootful,
            "rootful_ack": self.rootful_ack,
            "last_seen_at": self.last_seen_at,
            "disabled_reason": self.disabled_reason,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True, slots=True)
class SyncJob:
    id: str
    credential: str
    target_id: str
    value_version: str
    generation_id: int
    state: str
    attempts: int
    max_attempts: int
    next_attempt_at: float | None
    lease_until: float | None
    agent_id: str | None
    created_at: float
    updated_at: float
    started_at: float | None
    finished_at: float | None
    last_error: str
    result: dict[str, Any]

    def as_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "credential": self.credential,
            "target_id": self.target_id,
            "value_version": self.value_version,
            "generation_id": self.generation_id,
            "state": self.state,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "next_attempt_at": self.next_attempt_at,
            "lease_until": self.lease_until,
            "agent_id": self.agent_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "last_error": self.last_error,
            "result": self.result,
        }


def _target(row: Any) -> SyncTarget:
    try:
        services = tuple(json.loads(row["services"]))
    except (TypeError, ValueError):
        services = ()
    try:
        values = json.loads(row["values_json"] or "{}")
    except (TypeError, ValueError):
        values = {}
    return SyncTarget(
        id=row["id"],
        name=row["name"],
        agent_id=row["agent_id"],
        stack_path=row["stack_path"],
        project_name=row["project_name"],
        services=services,
        workflow=row["workflow"],
        enabled=bool(row["enabled"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        env_file=row["env_file"],
        values=values if isinstance(values, dict) else {},
    )


def _agent(row: Any) -> Agent:
    try:
        capabilities = tuple(json.loads(row["capabilities"]))
    except (TypeError, ValueError):
        capabilities = ()
    return Agent(
        id=row["id"],
        name=row["name"],
        status=row["status"],
        capabilities=capabilities,
        certificate_fingerprint=row["certificate_fingerprint"],
        certificate_expires_at=row["certificate_expires_at"],
        rootful=bool(row["rootful"]),
        rootful_ack=bool(row["rootful_ack"]),
        last_seen_at=row["last_seen_at"],
        disabled_reason=row["disabled_reason"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _job(row: Any) -> SyncJob:
    try:
        result = json.loads(row["result"] or "{}")
    except (TypeError, ValueError):
        result = {}
    return SyncJob(
        id=row["id"],
        credential=row["credential"],
        target_id=row["target_id"],
        value_version=row["value_version"],
        generation_id=row["generation_id"],
        state=row["state"],
        attempts=row["attempts"],
        max_attempts=row["max_attempts"],
        next_attempt_at=row["next_attempt_at"],
        lease_until=row["lease_until"],
        agent_id=row["agent_id"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        last_error=row["last_error"],
        result=result if isinstance(result, dict) else {},
    )


def _event(
    connection: Any,
    kind: str,
    credential: str | None,
    detail: str,
    data: dict[str, Any] | None = None,
    *,
    at: float | None = None,
) -> None:
    connection.execute(
        "INSERT INTO events "
        "(at, kind, credential, previous_status, status, detail, origin, data) "
        "VALUES (?, ?, ?, NULL, NULL, ?, 'auto', ?)",
        (time.time() if at is None else at, kind, credential, detail, event_schema.encode(data)),
    )


def backoff(attempts: int) -> float:
    return min(BACKOFF_BASE_SECONDS * (2 ** max(attempts - 1, 0)), BACKOFF_CAP_SECONDS)


class SyncStore:
    """Targets, agents, jobs and the outbox dispatcher."""

    def __init__(
        self,
        database: Path | str,
        *,
        tree_configured: bool = False,
        max_attempts: int = MAX_ATTEMPTS,
    ) -> None:
        self.path = Path(database)
        self.tree_configured = tree_configured
        self.max_attempts = max(1, max_attempts)
        initialise(self.path, SCHEMA)
        self._migrate_targets()

    def _migrate_targets(self) -> None:
        """Rebuild the target table for the env workflow on an older store.

        SQLite cannot alter a CHECK constraint in place, and an existing
        database was created with `workflow IN ('compose')`. The rows are
        copied; the two new columns get their declared defaults.
        """
        with connect(self.path) as connection:
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(sync_targets)")
            }
            if "env_file" in columns:
                return
            from credarr.transaction import transaction

            start = SCHEMA.index("CREATE TABLE IF NOT EXISTS sync_targets")
            end = SCHEMA.index("CREATE TABLE IF NOT EXISTS sync_jobs")
            targets_schema = SCHEMA[start:end]
            with transaction(connection):
                connection.execute("ALTER TABLE sync_targets RENAME TO sync_targets_old")
                connection.execute(targets_schema)
                connection.execute(
                    "INSERT INTO sync_targets "
                    "(id, name, agent_id, stack_path, project_name, services, workflow, "
                    " env_file, values_json, enabled, created_at, updated_at) "
                    "SELECT id, name, agent_id, stack_path, project_name, services, "
                    "       'compose', NULL, '{}', enabled, created_at, updated_at "
                    "FROM sync_targets_old"
                )
                connection.execute("DROP TABLE sync_targets_old")

    # -- targets -----------------------------------------------------------

    def targets(self) -> tuple[SyncTarget, ...]:
        with connect(self.path) as connection:
            rows = connection.execute("SELECT * FROM sync_targets ORDER BY name").fetchall()
        return tuple(_target(row) for row in rows)

    def target(self, identifier: str) -> SyncTarget | None:
        with connect(self.path) as connection:
            row = connection.execute(
                "SELECT * FROM sync_targets WHERE id = ? OR name = ?",
                (identifier, identifier),
            ).fetchone()
        return _target(row) if row else None

    def save_target(
        self,
        *,
        name: str,
        agent_id: str,
        stack_path: str,
        project_name: str,
        services: tuple[str, ...],
        workflow: str = "compose",
        enabled: bool = True,
        env_file: str | None = None,
        values: dict[str, str] | None = None,
        identifier: str | None = None,
    ) -> SyncTarget:
        """Create or replace one target, validating the agent and identity."""
        if not self.tree_configured:
            raise SyncError(
                "no shared vault tree is configured; set CREDARR_VAULT_TREE "
                "before creating a sync target"
            )
        if workflow not in WORKFLOWS:
            raise SyncError(f"unknown workflow {workflow!r}")
        values = dict(values or {})
        if workflow == "env":
            if not env_file or env_file.startswith("/") or ".." in env_file.split("/"):
                raise SyncError(
                    "an env target needs a relative env file path without '..'"
                )
            if not values:
                raise SyncError("an env target needs at least one env-key mapping")
            for key, credential in values.items():
                if not key or not key[0].isalpha() or not all(
                    character.isalnum() or character == "_" for character in key
                ):
                    raise SyncError(f"invalid environment key {key!r}")
                if not credential or any(
                    character not in "abcdefghijklmnopqrstuvwxyz0123456789_-"
                    for character in credential
                ):
                    raise SyncError(f"invalid credential name {credential!r}")
        elif env_file or values:
            raise SyncError("env_file and values are only for the env workflow")
        if not services:
            raise SyncError("a target needs at least one service")
        if not stack_path.startswith("/") or "/../" in stack_path or stack_path.endswith("/.."):
            raise SyncError("the stack path must be absolute, without '..'")
        if not project_name or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789_-"
            for character in project_name
        ):
            raise SyncError("the project name is lowercase letters, digits, '_' or '-'")
        if any(
            not service or any(
                character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
                for character in service
            )
            for service in services
        ):
            raise SyncError("a service name has an unsupported character")
        agent = self.agent(agent_id)
        if agent is None:
            raise SyncError("no such agent")
        if agent.status == "revoked":
            raise SyncError("that agent is revoked")
        now = time.time()
        identifier = identifier or secrets.token_hex(12)
        with connect(self.path) as connection:
            existing = connection.execute(
                "SELECT id FROM sync_targets WHERE name = ?", (name,)
            ).fetchone()
            if existing is not None and existing["id"] != identifier:
                raise SyncError(f"a target named {name!r} already exists")
            connection.execute(
                "INSERT INTO sync_targets "
                "(id, name, agent_id, stack_path, project_name, services, workflow, "
                " env_file, values_json, enabled, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET name = excluded.name, "
                "agent_id = excluded.agent_id, stack_path = excluded.stack_path, "
                "project_name = excluded.project_name, services = excluded.services, "
                "workflow = excluded.workflow, env_file = excluded.env_file, "
                "values_json = excluded.values_json, enabled = excluded.enabled, "
                "updated_at = excluded.updated_at",
                (
                    identifier,
                    name,
                    agent.id,
                    stack_path,
                    project_name,
                    json.dumps(sorted(set(services))),
                    workflow,
                    env_file,
                    json.dumps(values, sort_keys=True),
                    1 if enabled else 0,
                    now,
                    now,
                ),
            )
        target = self.target(identifier)
        if target is None:  # pragma: no cover - the row was just written
            raise SyncError("the target vanished after it was written")
        if target.enabled:
            self.backfill_target(target.id)
        return target

    def backfill_target(self, target_id: str, *, now: float | None = None) -> int:
        """Give a new target the current version of every stored credential.

        A target created after the last rotation has no outbox row of its own;
        without this it would wait for the next value change. The job still
        carries the real CURRENT version, so the agent's tree preflight is the
        same check as any other delivery.
        """
        at = time.time() if now is None else now
        created = 0
        with connect(self.path) as connection:
            from credarr.transaction import transaction

            with transaction(connection):
                rows = connection.execute(
                    "SELECT sv.credential, sv.id AS version_id, g.id AS generation_id "
                    "FROM secret_versions sv "
                    "JOIN (SELECT credential, MAX(id) AS id FROM vault_generations "
                    "      GROUP BY credential) g ON g.credential = sv.credential "
                    "WHERE sv.stage = 'CURRENT' "
                    "AND NOT EXISTS (SELECT 1 FROM secret_lifecycle l "
                    "                WHERE l.credential = sv.credential)"
                ).fetchall()
                for row in rows:
                    active = connection.execute(
                        "SELECT 1 FROM sync_jobs WHERE credential = ? AND target_id = ? "
                        "AND state IN ('queued','leased','running','retry_wait')",
                        (row["credential"], target_id),
                    ).fetchone()
                    if active is not None:
                        continue
                    connection.execute(
                        "INSERT INTO sync_jobs "
                        "(id, credential, target_id, value_version, generation_id, "
                        " state, attempts, max_attempts, next_attempt_at, created_at, "
                        " updated_at) "
                        "VALUES (?, ?, ?, ?, ?, 'queued', 0, ?, ?, ?, ?)",
                        (
                            secrets.token_hex(12),
                            row["credential"],
                            target_id,
                            row["version_id"],
                            row["generation_id"],
                            self.max_attempts,
                            at,
                            at,
                            at,
                        ),
                    )
                    created += 1
        return created

    def delete_target(self, identifier: str) -> bool:
        with connect(self.path) as connection:
            cursor = connection.execute(
                "DELETE FROM sync_targets WHERE id = ? OR name = ?",
                (identifier, identifier),
            )
            connection.execute(
                "UPDATE sync_jobs SET state = 'cancelled', finished_at = ?, "
                "updated_at = ? WHERE target_id = ? AND state IN "
                "('queued','leased','running','retry_wait')",
                (time.time(), time.time(), identifier),
            )
        return cursor.rowcount > 0

    # -- agents ------------------------------------------------------------

    def agents(self) -> tuple[Agent, ...]:
        with connect(self.path) as connection:
            rows = connection.execute("SELECT * FROM agents ORDER BY name").fetchall()
        return tuple(_agent(row) for row in rows)

    def agent(self, identifier: str) -> Agent | None:
        with connect(self.path) as connection:
            row = connection.execute(
                "SELECT * FROM agents WHERE id = ? OR name = ?",
                (identifier, identifier),
            ).fetchone()
        return _agent(row) if row else None

    def create_enrollment(
        self, name: str, capabilities: tuple[str, ...], ttl: float = 600.0
    ) -> tuple[str, Agent]:
        """Create a one-time token and return it exactly once, with its agent row."""
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode()).hexdigest()
        now = time.time()
        identifier = secrets.token_hex(12)
        with connect(self.path) as connection:
            existing = connection.execute(
                "SELECT id FROM agents WHERE name = ?", (name,)
            ).fetchone()
            if existing is not None:
                raise SyncError(f"an agent named {name!r} already exists; revoke it first")
            connection.execute(
                "INSERT INTO agents "
                "(id, name, status, capabilities, created_at, updated_at) "
                "VALUES (?, ?, 'enrolled', ?, ?, ?)",
                (identifier, name, json.dumps(sorted(set(capabilities))), now, now),
            )
            connection.execute(
                "INSERT INTO agent_enrollments "
                "(id, token_hash, agent_name, capabilities, expires_at, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    secrets.token_hex(12),
                    digest,
                    name,
                    json.dumps(sorted(set(capabilities))),
                    now + ttl,
                    now,
                ),
            )
        agent = self.agent(identifier)
        assert agent is not None
        return token, agent

    def consume_enrollment(
        self, token: str, *, fingerprint: str, expires_at: float, rootful: bool, ack: bool
    ) -> Agent:
        digest = hashlib.sha256(token.encode()).hexdigest()
        now = time.time()
        with connect(self.path) as connection:
            row = connection.execute(
                "SELECT * FROM agent_enrollments WHERE token_hash = ?",
                (digest,),
            ).fetchone()
            if row is None or row["used_at"] is not None:
                raise SyncError("that enrollment token is not valid")
            if row["expires_at"] < now:
                raise SyncError("that enrollment token has expired")
            if rootful and not ack:
                raise SyncError("a rootful agent requires an explicit acknowledgment")
            connection.execute(
                "UPDATE agent_enrollments SET used_at = ? WHERE id = ?",
                (now, row["id"]),
            )
            connection.execute(
                "UPDATE agents SET status = 'active', certificate_fingerprint = ?, "
                "certificate_expires_at = ?, rootful = ?, rootful_ack = ?, "
                "last_seen_at = ?, updated_at = ? WHERE name = ?",
                (
                    fingerprint,
                    expires_at,
                    1 if rootful else 0,
                    1 if ack else 0,
                    now,
                    now,
                    row["agent_name"],
                ),
            )
        agent = self.agent(row["agent_name"])
        assert agent is not None
        return agent

    def authenticate(self, fingerprint: str) -> Agent | None:
        with connect(self.path) as connection:
            row = connection.execute(
                "SELECT * FROM agents WHERE certificate_fingerprint = ?",
                (fingerprint,),
            ).fetchone()
        if row is None:
            return None
        agent = _agent(row)
        if agent.status not in ("active", "offline"):
            return None
        if agent.certificate_expires_at is not None and agent.certificate_expires_at < time.time():
            return None
        return agent

    def renew_certificate(
        self, agent_id: str, *, fingerprint: str, expires_at: float
    ) -> Agent:
        now = time.time()
        with connect(self.path) as connection:
            connection.execute(
                "UPDATE agents SET certificate_fingerprint = ?, "
                "certificate_expires_at = ?, updated_at = ? WHERE id = ?",
                (fingerprint, expires_at, now, agent_id),
            )
        agent = self.agent(agent_id)
        if agent is None:
            raise SyncError("no such agent")
        return agent

    def touch(self, agent_id: str, *, at: float | None = None) -> None:
        when = time.time() if at is None else at
        with connect(self.path) as connection:
            connection.execute(
                "UPDATE agents SET last_seen_at = ?, updated_at = ?, "
                "status = CASE WHEN status = 'offline' THEN 'active' ELSE status END "
                "WHERE id = ?",
                (when, when, agent_id),
            )

    def revoke(self, identifier: str, *, reason: str = "revoked by the operator") -> bool:
        now = time.time()
        with connect(self.path) as connection:
            row = connection.execute(
                "SELECT id FROM agents WHERE id = ? OR name = ?",
                (identifier, identifier),
            ).fetchone()
            if row is None:
                return False
            connection.execute(
                "UPDATE agents SET status = 'revoked', disabled_reason = ?, "
                "updated_at = ? WHERE id = ?",
                (reason, now, row["id"]),
            )
            connection.execute(
                "UPDATE sync_jobs SET state = 'cancelled', finished_at = ?, "
                "updated_at = ? WHERE agent_id = ? AND state IN "
                "('queued','leased','running','retry_wait')",
                (now, now, row["id"]),
            )
        return True

    def disable(self, identifier: str, reason: str, *, event: bool = True) -> bool:
        now = time.time()
        with connect(self.path) as connection:
            row = connection.execute(
                "SELECT id FROM agents WHERE id = ? OR name = ?",
                (identifier, identifier),
            ).fetchone()
            if row is None:
                return False
            connection.execute(
                "UPDATE agents SET status = 'disabled', disabled_reason = ?, "
                "updated_at = ? WHERE id = ?",
                (reason, now, row["id"]),
            )
            connection.execute(
                "UPDATE sync_jobs SET state = 'cancelled', finished_at = ?, "
                "updated_at = ?, last_error = ? WHERE agent_id = ? AND state IN "
                "('queued','leased','running','retry_wait')",
                (now, now, f"the agent is disabled: {reason}", row["id"]),
            )
            if event:
                _event(
                    connection,
                    "agent_policy_violation",
                    None,
                    f"agent disabled: {reason}",
                    {"agent": row["id"]},
                )
        return True

    # -- dispatch ----------------------------------------------------------

    def dispatch(self, *, now: float | None = None) -> int:
        """Turn committed outbox rows into jobs, newest value winning.

        One group per credential: the newest committed version is the only one
        worth deploying. Older rows are closed as superseded. A target with an
        active job is skipped, and its outbox row stays pending for the tick
        after that job is terminal.
        """
        if not self.tree_configured:
            return 0
        at = time.time() if now is None else now
        with connect(self.path) as connection:
            rows = connection.execute(
                "SELECT o.*, g.credential FROM sync_outbox o "
                "JOIN vault_generations g ON g.id = o.generation_id "
                "WHERE o.dispatched_at IS NULL ORDER BY o.credential, o.id"
            ).fetchall()
            if not rows:
                return 0
            newest: dict[str, Any] = {}
            for row in rows:
                newest[row["credential"]] = row
            created = 0
            for credential, row in newest.items():
                live = connection.execute(
                    "SELECT 1 FROM secret_lifecycle WHERE credential = ?",
                    (credential,),
                ).fetchone()
                if live is not None:
                    connection.execute(
                        "UPDATE sync_outbox SET dispatched_at = ? WHERE id = ?",
                        (at, row["id"]),
                    )
                    continue
                targets = connection.execute(
                    "SELECT t.* FROM sync_targets t JOIN agents a ON a.id = t.agent_id "
                    "WHERE t.enabled = 1 AND a.status = 'active'",
                ).fetchall()
                blocked = False
                for target_row in targets:
                    active = connection.execute(
                        "SELECT state, value_version FROM sync_jobs "
                        "WHERE credential = ? AND target_id = ? "
                        "AND state IN ('queued','leased','running','retry_wait')",
                        (credential, target_row["id"]),
                    ).fetchone()
                    if active is not None:
                        if active["value_version"] != row["version_id"]:
                            # The target is still delivering an older version;
                            # keep this outbox row pending so the newer value
                            # gets a job after the current one is terminal.
                            blocked = True
                        continue
                    connection.execute(
                        "INSERT INTO sync_jobs "
                        "(id, credential, target_id, value_version, generation_id, "
                        " state, attempts, max_attempts, next_attempt_at, created_at, "
                        " updated_at) "
                        "VALUES (?, ?, ?, ?, ?, 'queued', 0, ?, ?, ?, ?)",
                        (
                            secrets.token_hex(12),
                            credential,
                            target_row["id"],
                            row["version_id"],
                            row["generation_id"],
                            self.max_attempts,
                            at,
                            at,
                            at,
                        ),
                    )
                    created += 1
                if not blocked:
                    connection.execute(
                        "UPDATE sync_outbox SET dispatched_at = ? WHERE credential = ? "
                        "AND id <= ?",
                        (at, credential, row["id"]),
                    )
        return created

    # -- jobs --------------------------------------------------------------

    def jobs(self, *, credential: str | None = None, limit: int = 100) -> tuple[SyncJob, ...]:
        with connect(self.path) as connection:
            if credential is None:
                rows = connection.execute(
                    "SELECT * FROM sync_jobs ORDER BY created_at DESC LIMIT ?", (limit,)
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM sync_jobs WHERE credential = ? "
                    "ORDER BY created_at DESC LIMIT ?",
                    (credential, limit),
                ).fetchall()
        return tuple(_job(row) for row in rows)

    def projection(self, credential: str) -> dict[str, Any]:
        """The delivery status the console shows, separate from the audit verdict."""
        jobs = self.jobs(credential=credential, limit=50)
        if not jobs:
            return {"state": "none", "jobs": []}
        if any(job.state in ("queued", "leased", "running") for job in jobs):
            state = "in_progress"
        elif any(job.state == "retry_wait" for job in jobs):
            state = "pending"
        elif any(job.state == "failed" for job in jobs):
            state = "failed"
        elif any(job.state == "delivered" for job in jobs):
            state = "delivered"
        else:
            state = "cancelled"
        return {"state": state, "jobs": [job.as_json() for job in jobs]}

    def lease(
        self, agent: Agent, *, now: float | None = None
    ) -> tuple[SyncJob, SyncTarget] | None:
        """Lease one eligible job, or return None when the agent is idle."""
        at = time.time() if now is None else now
        violation: str | None = None
        with connect(self.path) as connection:
            from credarr.transaction import transaction

            with transaction(connection):
                candidates = connection.execute(
                    "SELECT j.*, t.* FROM sync_jobs j JOIN sync_targets t "
                    "ON t.id = j.target_id "
                    "WHERE t.agent_id = ? AND t.enabled = 1 "
                    "AND (j.state = 'queued' "
                    "     OR (j.state = 'retry_wait' AND j.next_attempt_at <= ?)) "
                    "ORDER BY j.created_at, j.id LIMIT 20",
                    (agent.id, at),
                ).fetchall()
                chosen = None
                for row in candidates:
                    target_row = connection.execute(
                        "SELECT * FROM sync_targets WHERE id = ?",
                        (row["target_id"],),
                    ).fetchone()
                    target = _target(target_row)
                    capability = f"{target.workflow}:{target.stack_path}"
                    if (
                        target.workflow not in agent.capabilities
                        and capability not in agent.capabilities
                    ):
                        connection.execute(
                            "UPDATE sync_jobs SET state = 'failed', finished_at = ?, "
                            "updated_at = ?, last_error = ? WHERE id = ?",
                            (at, at, "the agent is not bound to this workflow or path", row["id"]),
                        )
                        violation = (
                            "a job was outside the agent's bound capabilities"
                        )
                        _event(
                            connection,
                            "agent_policy_violation",
                            row["credential"],
                            "a job was refused: it is outside the agent's bound capabilities",
                            {"agent": agent.id, "job": row["id"]},
                        )
                        continue
                    chosen = row
                    break
                if chosen is not None:
                    connection.execute(
                        "UPDATE sync_jobs SET state = 'leased', agent_id = ?, "
                        "attempts = attempts + 1, lease_until = ?, "
                        "started_at = COALESCE(started_at, ?), updated_at = ? "
                        "WHERE id = ?",
                        (agent.id, at + LEASE_SECONDS, at, at, chosen["id"]),
                    )
                    job_row = connection.execute(
                        "SELECT * FROM sync_jobs WHERE id = ?", (chosen["id"],)
                    ).fetchone()
                    target_row = connection.execute(
                        "SELECT * FROM sync_targets WHERE id = ?", (chosen["target_id"],)
                    ).fetchone()
        if violation is not None:
            self.disable(agent.id, violation)
        if chosen is None:
            return None
        return _job(job_row), _target(target_row)

    def begin(self, job_id: str, agent: Agent, *, now: float | None = None) -> SyncJob:
        at = time.time() if now is None else now
        with connect(self.path) as connection:
            cursor = connection.execute(
                "UPDATE sync_jobs SET state = 'running', updated_at = ? "
                "WHERE id = ? AND agent_id = ? AND state = 'leased'",
                (at, job_id, agent.id),
            )
            if cursor.rowcount == 0:
                raise SyncError("that job is not leased by this agent")
        job = self.job(job_id)
        assert job is not None
        return job

    def job(self, job_id: str) -> SyncJob | None:
        with connect(self.path) as connection:
            row = connection.execute(
                "SELECT * FROM sync_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return _job(row) if row else None

    def report(
        self,
        job_id: str,
        agent: Agent,
        *,
        services: dict[str, bool],
        detail: str = "",
        now: float | None = None,
    ) -> SyncJob:
        """Record an agent's per-service outcome and apply the retry contract."""
        at = time.time() if now is None else now
        detail = scrub((detail or "").strip())[:500]
        with connect(self.path) as connection:
            from credarr.transaction import transaction

            with transaction(connection):
                row = connection.execute(
                    "SELECT j.*, t.services FROM sync_jobs j JOIN sync_targets t "
                    "ON t.id = j.target_id WHERE j.id = ?",
                    (job_id,),
                ).fetchone()
                if row is None:
                    raise SyncError("no such job")
                if row["agent_id"] != agent.id:
                    raise SyncError("that job is not assigned to this agent")
                if row["state"] not in ("leased", "running"):
                    raise SyncError("that job is no longer in flight")
                expected = set(json.loads(row["services"]))
                if set(services) != expected:
                    raise SyncError("the result must name exactly the declared services")
                if any(type(value) is not bool for value in services.values()):
                    raise SyncError("a service outcome is a boolean, never a log line")
                partial = not all(services.values())
                attempts = row["attempts"]
                if partial:
                    if attempts >= row["max_attempts"]:
                        state = "failed"
                        finished = at
                        next_at = None
                        kind = "sync_failed"
                        message = "delivery failed after the attempt budget"
                    else:
                        state = "retry_wait"
                        finished = None
                        next_at = at + backoff(attempts)
                        kind = "sync_partial"
                        message = "partial delivery; the full service set will be retried"
                    connection.execute(
                        "UPDATE sync_jobs SET state = ?, next_attempt_at = ?, "
                        "finished_at = ?, updated_at = ?, last_error = ?, result = ? "
                        "WHERE id = ?",
                        (
                            state,
                            next_at,
                            finished,
                            at,
                            detail or message,
                            json.dumps(
                                {"services": services, "detail": detail or message},
                                sort_keys=True,
                            ),
                            job_id,
                        ),
                    )
                else:
                    connection.execute(
                        "UPDATE sync_jobs SET state = 'delivered', finished_at = ?, "
                        "updated_at = ?, last_error = '', result = ? WHERE id = ?",
                        (
                            at,
                            at,
                            json.dumps({"services": services, "detail": detail}, sort_keys=True),
                            job_id,
                        ),
                    )
                    kind = "sync_delivered"
                    message = "every declared service accepted the deploy"
                _event(
                    connection,
                    kind,
                    row["credential"],
                    message,
                    {"job": job_id, "target": row["target_id"], "version": row["value_version"]},
                    at=at,
                )
                updated = connection.execute(
                    "SELECT * FROM sync_jobs WHERE id = ?", (job_id,)
                ).fetchone()
        return _job(updated)

    def cancel(self, job_id: str, *, actor: str = "admin") -> SyncJob | None:
        now = time.time()
        with connect(self.path) as connection:
            connection.execute(
                "UPDATE sync_jobs SET state = 'cancelled', finished_at = ?, "
                "updated_at = ?, last_error = ? WHERE id = ? AND state IN "
                "('queued','leased','running','retry_wait')",
                (now, now, f"cancelled by {actor}", job_id),
            )
            row = connection.execute(
                "SELECT * FROM sync_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return _job(row) if row else None

    def cancel_credential(self, credential: str) -> int:
        now = time.time()
        with connect(self.path) as connection:
            cursor = connection.execute(
                "UPDATE sync_jobs SET state = 'cancelled', finished_at = ?, "
                "updated_at = ?, last_error = 'the credential is soft-deleted' "
                "WHERE credential = ? AND state IN "
                "('queued','leased','running','retry_wait')",
                (now, now, credential),
            )
        return cursor.rowcount

    def tick(self, *, now: float | None = None) -> dict[str, int]:
        """Expire leases, fail exhausted jobs, and keep the outbox moving."""
        at = time.time() if now is None else now
        expired = 0
        failed = 0
        with connect(self.path) as connection:
            from credarr.transaction import transaction

            with transaction(connection):
                rows = connection.execute(
                    "SELECT * FROM sync_jobs WHERE state IN ('leased','running') "
                    "AND lease_until IS NOT NULL AND lease_until < ?",
                    (at,),
                ).fetchall()
                for row in rows:
                    expired += 1
                    if row["attempts"] >= row["max_attempts"]:
                        failed += 1
                        connection.execute(
                            "UPDATE sync_jobs SET state = 'failed', finished_at = ?, "
                            "updated_at = ?, last_error = ? WHERE id = ?",
                            (
                                at,
                                at,
                                "the agent lease expired and the attempt budget is spent",
                                row["id"],
                            ),
                        )
                        _event(
                            connection,
                            "sync_failed",
                            row["credential"],
                            "delivery failed: the agent lease expired after the attempt budget",
                            {"job": row["id"], "target": row["target_id"]},
                            at=at,
                        )
                    else:
                        connection.execute(
                            "UPDATE sync_jobs SET state = 'retry_wait', "
                            "next_attempt_at = ?, lease_until = NULL, updated_at = ?, "
                            "last_error = ? WHERE id = ?",
                            (
                                at + backoff(row["attempts"]),
                                at,
                                "the agent lease expired",
                                row["id"],
                            ),
                        )
                stale = connection.execute(
                    "SELECT id, name FROM agents WHERE status = 'active' "
                    "AND last_seen_at IS NOT NULL AND last_seen_at < ?",
                    (at - 300.0,),
                ).fetchall()
                for row in stale:
                    connection.execute(
                        "UPDATE agents SET status = 'offline', updated_at = ? WHERE id = ?",
                        (at, row["id"]),
                    )
                    _event(
                        connection,
                        "agent_offline",
                        None,
                        f"agent {row['name']} has not checked in for five minutes",
                        {"agent": row["id"]},
                        at=at,
                    )
        self.dispatch(now=at)
        return {"expired": expired, "failed": failed, "offline": len(stale)}

    def retry(self, job_id: str, *, actor: str = "admin") -> SyncJob | None:
        now = time.time()
        with connect(self.path) as connection:
            connection.execute(
                "UPDATE sync_jobs SET state = 'queued', attempts = 0, "
                "next_attempt_at = ?, lease_until = NULL, finished_at = NULL, "
                "updated_at = ?, last_error = ? WHERE id = ? AND state IN "
                "('failed','cancelled','retry_wait')",
                (now, now, f"retried by {actor}", job_id),
            )
            row = connection.execute(
                "SELECT * FROM sync_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return _job(row) if row else None

    def status(self) -> dict[str, Any]:
        with connect(self.path) as connection:
            jobs = {
                state: connection.execute(
                    "SELECT COUNT(*) FROM sync_jobs WHERE state = ?", (state,)
                ).fetchone()[0]
                for state in SYNC_STATES
            }
            outbox = connection.execute(
                "SELECT COUNT(*) FROM sync_outbox WHERE dispatched_at IS NULL"
            ).fetchone()[0]
            agents = connection.execute(
                "SELECT status, COUNT(*) FROM agents GROUP BY status"
            ).fetchall()
        return {
            "tree_configured": self.tree_configured,
            "outbox_pending": int(outbox),
            "jobs": jobs,
            "agents": {row[0]: row[1] for row in agents},
        }


class SyncLoop:
    """The delivery scheduler: dispatch committed outbox rows and expire leases."""

    def __init__(self, sync: SyncStore, *, interval: float = 5.0) -> None:
        import threading

        self.sync = sync
        self.interval = interval
        self.failure: str | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="credarr-sync", daemon=True)

    @property
    def running(self) -> bool:
        return self._thread.is_alive()

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=10)

    def _run(self) -> None:
        try:
            while not self._stop.is_set():
                self.sync.dispatch()
                self.sync.tick()
                self._stop.wait(self.interval)
        except Exception as exc:
            self.failure = f"{type(exc).__name__}: {exc}"
