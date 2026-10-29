"""The topology store: the manifest as rows, and the rows back as a manifest.

The manifest file stays the source of truth for what exists. This is its
working copy, so the app can change topology - add a holder, retarget a
consumer - without hand-editing YAML, and write it back out through the same
emitter the command line uses. The round trip is therefore the contract:
import then export must return the manifest that went in, or the store is a
lossy copy of a file the operator has to keep repairing by hand.

Import runs the same strict parse the audit uses (`facade.read_manifest`,
registry included), so a target this build cannot read is an error here, not
a row that later audits as clean. Export runs `emit_manifest`, so the text
the app writes is the text the CLI would have written for the same model.

SQLite in WAL mode (DECISIONS: `/config/app.db`). The public API is import,
load and export; the HTTP layer never sees SQL.

It also holds the app's working copy of each credential's value
(`working_copies`), which is the canonical the runtime audit compares
against: DECISIONS decision 2 - SQLite is the source of record and a vault is
an import/export format. The declared vault reference stays beside it as
provenance and is not read at runtime.
"""

from __future__ import annotations

import contextlib
import json
import math
import os
import sqlite3
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from credarr.emitter import emit_manifest
from credarr.facade import read_manifest
from credarr.journal import init_lock_for
from credarr.model import MANIFEST_VERSION, Consumer, Credential, Manifest, Target, VaultRef
from credarr.redact import Secret
from credarr.secrets import BACKENDS
from credarr.targets import TargetRegistry

SCHEMA = """
CREATE TABLE IF NOT EXISTS credentials (
    name             TEXT    PRIMARY KEY,
    position         INTEGER NOT NULL,
    description      TEXT    NOT NULL,
    credential_class TEXT    NOT NULL,
    max_age_days     INTEGER,
    never_rotate     INTEGER NOT NULL,
    provisioned      INTEGER NOT NULL,
    vault_backend    TEXT,
    vault_file       TEXT,
    vault_path       TEXT,
    canonical        TEXT    NOT NULL,
    write            TEXT    NOT NULL
);

-- Position is the manifest's declaration order, kept so an export reads like
-- the file it came from. The server stores rows; a re-imported file should
-- diff against its source, not reshuffle on every save.
CREATE TABLE IF NOT EXISTS holders (
    credential TEXT    NOT NULL REFERENCES credentials(name) ON DELETE CASCADE,
    position   INTEGER NOT NULL,
    target     TEXT    NOT NULL,
    count      INTEGER NOT NULL,
    mechanism  TEXT    NOT NULL,
    host       TEXT,
    note       TEXT    NOT NULL,
    PRIMARY KEY (credential, position)
);

-- The app's working copy of each credential's value. Deliberately no foreign
-- key: a topology re-import replaces every credential row and a value must
-- outlive that; `import_manifest` prunes values whose credential is gone.
CREATE TABLE IF NOT EXISTS working_copies (
    credential TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at REAL NOT NULL
);

-- A chosen value parked between the API-only mint's restore and RECORD.
-- Deliberately separate from working_copies: until every holder is confirmed
-- this is not the canonical value, and a crash after the service restart must
-- leave something a resumed run can prove against the live service. No foreign
-- key, for the same reason working_copies has none; `_replace` prunes names the
-- topology no longer declares.
CREATE TABLE IF NOT EXISTS pending_secrets (
    credential TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    created_at REAL NOT NULL
);

-- Deployment policy, not topology: it deliberately has no foreign key, so a
-- re-import can prune it by name without touching a surviving opt-in. No
-- value, fingerprint or secret belongs in this table.
CREATE TABLE IF NOT EXISTS auto_rotation (
    credential     TEXT PRIMARY KEY,
    enabled        INTEGER NOT NULL DEFAULT 0,
    every_days     INTEGER NOT NULL,
    enabled_at     REAL    NOT NULL,
    last_check_at  REAL,
    last_outcome   TEXT,
    last_detail    TEXT    NOT NULL DEFAULT '',
    paused         INTEGER NOT NULL DEFAULT 0
);

-- Deployment facts the console edits: a service's base URL. These used to live
-- only in credarr.yaml. The store is now their source of record; the config is
-- read once to seed this table for existing installs.
CREATE TABLE IF NOT EXISTS services (
    name     TEXT    PRIMARY KEY,
    position INTEGER NOT NULL,
    kind     TEXT    NOT NULL DEFAULT '',
    url      TEXT,
    notes    TEXT    NOT NULL DEFAULT ''
);

-- One marker per migration that must run only once. Without it, deleting every
-- service would be undone by a restart re-seeding from credarr.yaml.
CREATE TABLE IF NOT EXISTS store_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

SERVICES_SEEDED = "services_seeded"
AUDIT_INTERVAL_KEY = "audit_interval_seconds"
AUDIT_ENABLED_KEY = "audit_enabled"


class UnknownCredential(Exception):
    """A working copy was offered for a credential the store does not have."""


class CredentialExists(Exception):
    """A create was asked for a name the topology already declares."""


class ServiceExists(Exception):
    """A create was asked for a service name that is already defined."""


@dataclass(frozen=True, slots=True)
class Service:
    """One service's editable deployment facts."""

    name: str
    kind: str
    url: str | None
    notes: str
    position: int


@dataclass(frozen=True, slots=True)
class ImportSummary:
    """What one import actually changed."""

    mode: str
    credentials: int
    holders: int
    added: int = 0
    updated: int = 0
    removed: int = 0
    pruned: bool = False


@dataclass(frozen=True, slots=True)
class AutoRotation:
    """One credential's auto-rotation policy, as stored in `app.db`.

    The due clock is intentionally not a column: the journal already records
    every completed rotation, including manual, CLI and manual-copy runs, so a
    second copy here could disagree with it.
    """

    credential: str
    enabled: bool
    every_days: int
    enabled_at: float
    last_check_at: float | None
    last_outcome: str | None
    last_detail: str
    paused: bool


def _database_files(path: Path) -> tuple[Path, ...]:
    """The database and the sidecars SQLite keeps beside it.

    SQLite gives a sidecar the database's mode when it creates it, so a
    sidecar left over from before this rule keeps its old mode and keeps
    receiving plaintext pages - it has to be tightened too.
    """
    return (
        path,
        *(path.with_name(path.name + suffix) for suffix in ("-wal", "-shm", "-journal")),
    )


def initialise(path: Path, schema: str) -> None:
    """Create the database file and its tables: WAL on, mode 0600.

    Under the same lock the journal uses, so two stores built in one process
    do not race the schema. That lock is in-process; two *processes* starting
    on one fresh file can still race the WAL pragma, which the app does not do
    today (one process) and the packaging slice owns making a rule.

    The file and its sidecars are chmodded 0600 on every start because they
    hold every working copy in plaintext. The chmod is best-effort: a file the
    process does not own (a root-made bind mount) is still writable, and
    refusing to boot over a hardening step is worse than the mode the
    deployment chose.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    # Create the file private before SQLite opens it. A default 0644 window is
    # enough for another local user to read every working copy. O_EXCL keeps a
    # concurrent creator from making this open follow a path swapped underneath.
    with contextlib.suppress(FileExistsError):
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(descriptor)
    with init_lock_for(path):
        for database_file in _database_files(path):
            with contextlib.suppress(OSError):
                database_file.chmod(0o600)
        connection = sqlite3.connect(path, timeout=15)
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(schema)
            _drop_retired_columns(connection)
            # WAL and shared-memory files are created by the pragma/schema.
            for database_file in _database_files(path):
                with contextlib.suppress(OSError):
                    database_file.chmod(0o600)
        finally:
            connection.close()


def _drop_retired_columns(connection: sqlite3.Connection) -> None:
    """Drop columns strict API-only removed, on an existing database.

    SQLite has no portable "drop if exists". A new database never has these
    columns; an old one keeps the data until this runs. The values are
    deployment facts or display-only descriptions, never credential values.

    shortcut: DROP COLUMN needs SQLite 3.35+ (2021). The app already requires a
    current Python; rebuild the table if an older SQLite ever matters.
    """
    for table, column in (("holders", "storage"), ("services", "path")):
        columns = {
            row[1] for row in connection.execute(f"PRAGMA table_info({table})")
        }
        if column in columns:
            connection.execute(f"ALTER TABLE {table} DROP COLUMN {column}")


@contextlib.contextmanager
def connect(path: Path) -> Iterator[sqlite3.Connection]:
    """One connection for one call, closed on the way out."""
    connection = sqlite3.connect(path, timeout=15, isolation_level=None)
    connection.row_factory = sqlite3.Row
    try:
        # Per connection, not per database: SQLite defaults foreign keys off.
        connection.execute("PRAGMA foreign_keys = ON")
        yield connection
    finally:
        connection.close()


class TopologyStore:
    """The manifest's working copy, behind an import/load/export API."""

    def __init__(self, path: Path | str) -> None:
        # Coerced rather than trusted, like the journal: a caller passing a
        # string is ordinary, not a mistake.
        self.path = Path(path)
        initialise(self.path, SCHEMA)
        # A crash between RECORD and the pending delete leaves a value that is
        # already canonical. It is safe, but it is still a second copy of a
        # credential, so it is pruned before anyone can ask for it.
        self.prune_pending()

    def import_manifest(
        self,
        path: Path,
        registry: TargetRegistry,
        *,
        mode: str = "replace",
        prune: bool = False,
    ) -> ImportSummary:
        """Import the manifest at `path`, replacing or merging.

        Replace is the historical contract: the file is the declared state.
        Merge is the console's additive path and never deletes a name the file
        omits unless `prune` is set.
        """
        return self.import_model(
            read_manifest(path, registry), mode=mode, prune=prune
        )

    def import_text(
        self,
        text: str,
        registry: TargetRegistry,
        *,
        origin: Path,
        mode: str = "replace",
        prune: bool = False,
    ) -> ImportSummary:
        """Import manifest text - the console's paste.

        The same strict parse as the file import, against the same registry, so
        the console cannot accept a manifest the CLI would refuse. `origin` is
        the path the text would have had: relative vault files resolve against
        its directory exactly as they would for the configured manifest, so a
        pasted topology declares the refs the CLI would read.
        """
        return self.import_model(
            Manifest.parse(
                text,
                origin=origin,
                known_targets=registry.known_targets(),
                known_backends=BACKENDS,
            ),
            mode=mode,
            prune=prune,
        )

    def import_model(
        self, manifest: Manifest, *, mode: str = "replace", prune: bool = False
    ) -> ImportSummary:
        """Import an already-parsed manifest, in one transaction."""
        if mode not in ("replace", "merge"):
            raise ValueError("mode must be 'replace' or 'merge'")
        if mode == "replace":
            return self._replace(manifest)
        return self._merge(manifest, prune=prune)

    def _replace(self, manifest: Manifest) -> ImportSummary:
        """Swap in `manifest`, pruning values for names it no longer declares."""
        with connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                previous = connection.execute(
                    "SELECT COUNT(*) FROM credentials"
                ).fetchone()[0]
                connection.execute("DELETE FROM holders")
                connection.execute("DELETE FROM credentials")
                for position, (name, credential) in enumerate(manifest.credentials.items()):
                    _insert_credential(connection, position, name, credential)
                # A working copy survives a re-import for a credential the file
                # still declares; one the file no longer declares loses its
                # value, because a secret kept for a name nothing references is
                # a secret kept for no reason.
                connection.execute(
                    "DELETE FROM working_copies WHERE credential NOT IN "
                    "(SELECT name FROM credentials)"
                )
                connection.execute(
                    "DELETE FROM pending_secrets WHERE credential NOT IN "
                    "(SELECT name FROM credentials)"
                )
                # Policy for a name the manifest no longer declares is dead
                # state. A surviving name keeps its row, including enabled,
                # interval and pause, until an operator changes it.
                connection.execute(
                    "DELETE FROM auto_rotation WHERE credential NOT IN "
                    "(SELECT name FROM credentials)"
                )
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        return _summary("replace", manifest, added=len(manifest.credentials), removed=previous)

    def _merge(self, manifest: Manifest, *, prune: bool) -> ImportSummary:
        """Upsert by name; only `prune` removes names the file omits.

        A matching credential's holders are replaced: the file is authoritative
        for that name. Auto-rotation policy survives every matching name,
        including a disabled or paused row, because it is deployment policy and
        not part of the manifest.
        """
        added = updated = removed = 0
        with connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing = {
                    row["name"]: row["position"]
                    for row in connection.execute(
                        "SELECT name, position FROM credentials"
                    )
                }
                position = max(existing.values(), default=-1) + 1
                for name, credential in manifest.credentials.items():
                    if name in existing:
                        at = existing[name]
                        updated += 1
                    else:
                        at = position
                        position += 1
                        added += 1
                    _write_credential(connection, at, name, credential)
                if prune:
                    for row in connection.execute("SELECT name FROM credentials").fetchall():
                        if row["name"] not in manifest.credentials:
                            connection.execute(
                                "DELETE FROM credentials WHERE name = ?", (row["name"],)
                            )
                            removed += 1
                    _prune_orphans(connection)
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        return _summary(
            "merge",
            manifest,
            added=added,
            updated=updated,
            removed=removed,
            pruned=prune,
        )

    def load_manifest(self) -> Manifest:
        """The stored topology as a model, in import order."""
        with connect(self.path) as connection:
            credential_rows = connection.execute(
                "SELECT * FROM credentials ORDER BY position"
            ).fetchall()
            holder_rows = connection.execute(
                "SELECT * FROM holders ORDER BY credential, position"
            ).fetchall()
        by_credential: dict[str, list[sqlite3.Row]] = {}
        for row in holder_rows:
            by_credential.setdefault(row["credential"], []).append(row)
        credentials: dict[str, Credential] = {}
        for row in credential_rows:
            name = row["name"]
            credentials[name] = _credential_from_row(row, by_credential.get(name, []))
        # The parser only accepts this version, so the store cannot be holding
        # a different one - imports of anything else were refused up front.
        return Manifest(version=MANIFEST_VERSION, credentials=credentials)

    def export_text(self) -> str:
        """The stored topology as manifest YAML, through the engine's emitter."""
        return emit_manifest(self.load_manifest())

    def services(self) -> tuple[Service, ...]:
        """Every editable service definition, in console order."""
        with connect(self.path) as connection:
            rows = connection.execute(
                "SELECT * FROM services ORDER BY position, name"
            ).fetchall()
        return tuple(_service_from_row(row) for row in rows)

    def service(self, name: str) -> Service | None:
        with connect(self.path) as connection:
            row = connection.execute(
                "SELECT * FROM services WHERE name = ?", (name,)
            ).fetchone()
        return _service_from_row(row) if row else None

    def seed_services(self, entries: Sequence[Service]) -> int:
        """Copy deployment facts from `credarr.yaml` once, on first boot.

        `store_meta` makes this a migration, not a default: an operator who
        deletes every service must not have the file quietly put them back.
        """
        with connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                if connection.execute(
                    "SELECT 1 FROM store_meta WHERE key = ?", (SERVICES_SEEDED,)
                ).fetchone():
                    connection.execute("COMMIT")
                    return 0
                inserted = 0
                for position, entry in enumerate(entries):
                    cursor = connection.execute(
                        "INSERT OR IGNORE INTO services "
                        "(name, position, kind, url, notes) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (
                            entry.name,
                            position,
                            entry.kind,
                            entry.url,
                            entry.notes,
                        ),
                    )
                    inserted += cursor.rowcount
                connection.execute(
                    "INSERT OR REPLACE INTO store_meta (key, value) VALUES (?, ?)",
                    (SERVICES_SEEDED, str(time.time())),
                )
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        return inserted

    def create_service(
        self,
        name: str,
        *,
        kind: str,
        url: str | None,
        notes: str,
    ) -> Service:
        with connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                position = connection.execute(
                    "SELECT COALESCE(MAX(position), -1) + 1 FROM services"
                ).fetchone()[0]
                cursor = connection.execute(
                    "INSERT OR IGNORE INTO services "
                    "(name, position, kind, url, notes) VALUES (?, ?, ?, ?, ?)",
                    (name, position, kind, url, notes),
                )
                if cursor.rowcount == 0:
                    raise ServiceExists(name)
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        state = self.service(name)
        assert state is not None
        return state

    def update_service(
        self,
        name: str,
        *,
        kind: str,
        url: str | None,
        notes: str,
    ) -> Service | None:
        with connect(self.path) as connection:
            cursor = connection.execute(
                "UPDATE services SET kind = ?, url = ?, notes = ? "
                "WHERE name = ?",
                (kind, url, notes, name),
            )
            if cursor.rowcount == 0:
                return None
        return self.service(name)

    def update_service_destination(
        self,
        name: str,
        *,
        kind: str,
        url: str | None,
        notes: str,
        credential: str,
        value: Secret,
    ) -> Service | None:
        """Move a service URL and re-store its key as one transaction.

        A URL change without a fresh key is the destination-change hazard:
        the old key belongs to the old server. The caller has already required
        the value; committing both here means a crash cannot leave the URL
        changed while the new key is only in a request body.
        """
        with connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = connection.execute(
                    "UPDATE services SET kind = ?, url = ?, notes = ? "
                    "WHERE name = ?",
                    (kind, url, notes, name),
                )
                if cursor.rowcount == 0:
                    connection.execute("ROLLBACK")
                    return None
                stored = connection.execute(
                    "INSERT INTO working_copies (credential, value, updated_at) "
                    "SELECT ?, ?, ? WHERE EXISTS "
                    "(SELECT 1 FROM credentials WHERE name = ?) "
                    "ON CONFLICT(credential) DO UPDATE SET value = excluded.value, "
                    "updated_at = excluded.updated_at",
                    (credential, value.reveal(), time.time(), credential),
                )
                if stored.rowcount == 0:
                    raise UnknownCredential(credential)
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        return self.service(name)

    def delete_service(self, name: str) -> bool:
        with connect(self.path) as connection:
            cursor = connection.execute("DELETE FROM services WHERE name = ?", (name,))
        return cursor.rowcount > 0

    def create_credential(self, credential: Credential) -> None:
        """Add one validated credential after the existing declaration order."""
        with connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                if connection.execute(
                    "SELECT 1 FROM credentials WHERE name = ?", (credential.name,)
                ).fetchone():
                    raise CredentialExists(credential.name)
                position = connection.execute(
                    "SELECT COALESCE(MAX(position), -1) + 1 FROM credentials"
                ).fetchone()[0]
                _write_credential(connection, position, credential.name, credential)
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    def update_credential(self, name: str, credential: Credential) -> bool:
        """Replace one credential's metadata and holders, keeping its order."""
        with connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT position FROM credentials WHERE name = ?", (name,)
                ).fetchone()
                if row is None:
                    connection.execute("ROLLBACK")
                    return False
                _write_credential(connection, row["position"], name, credential)
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        return True

    def delete_credential(self, name: str) -> bool:
        """Delete a credential and every policy/value row that names it."""
        with connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = connection.execute(
                    "DELETE FROM credentials WHERE name = ?", (name,)
                )
                if cursor.rowcount:
                    _prune_orphans(connection)
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        return cursor.rowcount > 0

    def clear_value(self, name: str) -> bool:
        """Drop the app's working copy, never the service's live value."""
        with connect(self.path) as connection:
            cursor = connection.execute(
                "DELETE FROM working_copies WHERE credential = ?", (name,)
            )
        return cursor.rowcount > 0

    def set_value(self, name: str, value: Secret) -> None:
        """Store the app's working copy of `name`'s value.

        Takes a `Secret`, like every other write path in the engine: a bare
        string in a signature is a bare string in a log. One statement, so a
        concurrent topology change cannot slip between the check and the
        write.
        """
        with connect(self.path) as connection:
            cursor = connection.execute(
                "INSERT INTO working_copies (credential, value, updated_at) "
                "SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM credentials WHERE name = ?) "
                "ON CONFLICT(credential) DO UPDATE SET value = excluded.value, "
                "updated_at = excluded.updated_at",
                (name, value.reveal(), time.time(), name),
            )
            if cursor.rowcount == 0:
                raise UnknownCredential(name)

    def get_value(self, name: str) -> Secret | None:
        """The stored working copy, or None when the app holds none."""
        with connect(self.path) as connection:
            row = connection.execute(
                "SELECT value FROM working_copies WHERE credential = ?", (name,)
            ).fetchone()
        return Secret(row["value"]) if row else None

    def set_pending(self, name: str, value: Secret) -> None:
        """Park the value an API-only mint chose before it mutates a service.

        Same UnknownCredential refusal as `set_value`: a pending secret for a
        name no topology declares is a secret kept for no reason.
        """
        with connect(self.path) as connection:
            cursor = connection.execute(
                "INSERT INTO pending_secrets (credential, value, created_at) "
                "SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM credentials WHERE name = ?) "
                "ON CONFLICT(credential) DO UPDATE SET value = excluded.value, "
                "created_at = excluded.created_at",
                (name, value.reveal(), time.time(), name),
            )
            if cursor.rowcount == 0:
                raise UnknownCredential(name)

    def get_pending(self, name: str) -> Secret | None:
        with connect(self.path) as connection:
            row = connection.execute(
                "SELECT value FROM pending_secrets WHERE credential = ?", (name,)
            ).fetchone()
        return Secret(row["value"]) if row else None

    def clear_pending(self, name: str) -> None:
        with connect(self.path) as connection:
            connection.execute(
                "DELETE FROM pending_secrets WHERE credential = ?", (name,)
            )

    def prune_pending(self) -> None:
        """Drop pending values that are orphaned or already recorded.

        A crash can land after RECORD's working-copy write but before the
        explicit clear. The value is then canonical and the extra copy is no
        longer needed. Only an exact match is pruned: a pending value that
        differs is the recovery state an unfinished mint depends on.
        """
        with connect(self.path) as connection:
            connection.execute(
                "DELETE FROM pending_secrets WHERE credential NOT IN "
                "(SELECT name FROM credentials)"
            )
            connection.execute(
                "DELETE FROM pending_secrets WHERE credential IN "
                "(SELECT credential FROM working_copies w "
                " WHERE w.value = pending_secrets.value)"
            )

    def working_copy_times(self) -> dict[str, float]:
        """When each stored value was last written, keyed by credential.

        Which names are in the map is "the app holds a value for this" (a
        credential without one is unverifiable, not drift, so the console says
        "no value stored yet" rather than borrowing the engine's wording for a
        different cause). The time is what makes a recorded audit status honest:
        a run that finished before a value was pasted measured a different
        canonical, so the read path uses it to date the statuses it shows.
        """
        with connect(self.path) as connection:
            rows = connection.execute(
                "SELECT credential, updated_at FROM working_copies"
            ).fetchall()
        return {row["credential"]: row["updated_at"] for row in rows}

    def audit_interval(self) -> float | None:
        """The operator's persisted audit cadence, or None before the first save."""
        with connect(self.path) as connection:
            row = connection.execute(
                "SELECT value FROM store_meta WHERE key = ?", (AUDIT_INTERVAL_KEY,)
            ).fetchone()
        if row is None:
            return None
        try:
            value = float(row["value"])
        except (TypeError, ValueError):
            return None
        return value if math.isfinite(value) and value > 0 else None

    def set_audit_interval(self, seconds: float) -> None:
        """Persist the cadence; the API validates the usable range."""
        with connect(self.path) as connection:
            connection.execute(
                "INSERT INTO store_meta (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (AUDIT_INTERVAL_KEY, str(seconds)),
            )

    def audit_enabled(self) -> bool | None:
        """The persisted schedule switch, or None before the first save."""
        with connect(self.path) as connection:
            row = connection.execute(
                "SELECT value FROM store_meta WHERE key = ?", (AUDIT_ENABLED_KEY,)
            ).fetchone()
        if row is None:
            return None
        return row["value"] not in ("0", "false", "False")

    def set_audit_enabled(self, enabled: bool) -> None:
        """Persist the schedule switch."""
        with connect(self.path) as connection:
            connection.execute(
                "INSERT INTO store_meta (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (AUDIT_ENABLED_KEY, "1" if enabled else "0"),
            )

    def auto_rotations(self) -> dict[str, AutoRotation]:
        """Every stored auto-rotation policy, keyed by credential."""
        with connect(self.path) as connection:
            rows = connection.execute(
                "SELECT * FROM auto_rotation ORDER BY credential"
            ).fetchall()
        return {row["credential"]: _auto_from_row(row) for row in rows}

    def auto_rotation(self, name: str) -> AutoRotation | None:
        """One policy, or None when this credential has never been enabled."""
        with connect(self.path) as connection:
            row = connection.execute(
                "SELECT * FROM auto_rotation WHERE credential = ?", (name,)
            ).fetchone()
        return _auto_from_row(row) if row else None

    def enable_auto_rotation(
        self, name: str, every_days: int, *, now: float | None = None
    ) -> AutoRotation:
        """Turn auto-rotation on (or re-enable after a pause).

        Always resets `enabled_at` and clears the pause: enabling is an explicit
        new starting point, so it cannot fire from an old schedule in the same
        request. The API owns the typed confirmation and interval bounds; this
        method owns the durable state transition.
        """
        if not 1 <= every_days <= 365:
            raise ValueError("every_days must be between 1 and 365")
        at = time.time() if now is None else now
        with connect(self.path) as connection:
            connection.execute(
                "INSERT INTO auto_rotation "
                "(credential, enabled, every_days, enabled_at, last_check_at, "
                " last_outcome, last_detail, paused) "
                "VALUES (?, 1, ?, ?, NULL, NULL, '', 0) "
                "ON CONFLICT(credential) DO UPDATE SET "
                "enabled = 1, every_days = excluded.every_days, "
                "enabled_at = excluded.enabled_at, last_check_at = NULL, "
                "last_outcome = NULL, last_detail = '', paused = 0",
                (name, every_days, at),
            )
        state = self.auto_rotation(name)
        assert state is not None
        return state

    def set_auto_rotation_interval(self, name: str, every_days: int) -> AutoRotation:
        """Change an enabled policy's cadence without touching its baseline.

        The due clock is derived from the last completed rotation, so changing
        the interval recalculates the next due time and nothing else. The pause
        state and last outcome are preserved; only a fresh enable is a new
        starting point.
        """
        if not 1 <= every_days <= 365:
            raise ValueError("every_days must be between 1 and 365")
        with connect(self.path) as connection:
            connection.execute(
                "UPDATE auto_rotation SET every_days = ? WHERE credential = ?",
                (every_days, name),
            )
        state = self.auto_rotation(name)
        assert state is not None
        return state

    def disable_auto_rotation(self, name: str) -> AutoRotation | None:
        """Turn policy off without deleting what is known about it.

        A later enable is a fresh baseline anyway; keeping the row lets the
        console show the last outcome instead of pretending the credential was
        never configured.
        """
        with connect(self.path) as connection:
            connection.execute(
                "UPDATE auto_rotation SET enabled = 0, paused = 0 "
                "WHERE credential = ?",
                (name,),
            )
        return self.auto_rotation(name)

    def record_auto_rotation(
        self,
        name: str,
        outcome: str,
        detail: str,
        *,
        checked_at: float | None = None,
        paused: bool | None = None,
    ) -> None:
        """Remember the last check/run result; current state, not a history row."""
        at = time.time() if checked_at is None else checked_at
        with connect(self.path) as connection:
            if paused is None:
                connection.execute(
                    "UPDATE auto_rotation SET last_check_at = ?, last_outcome = ?, "
                    "last_detail = ? WHERE credential = ?",
                    (at, outcome, detail, name),
                )
            else:
                connection.execute(
                    "UPDATE auto_rotation SET last_check_at = ?, last_outcome = ?, "
                    "last_detail = ?, paused = ? WHERE credential = ?",
                    (at, outcome, detail, int(paused), name),
                )


def _auto_from_row(row: sqlite3.Row) -> AutoRotation:
    return AutoRotation(
        credential=row["credential"],
        enabled=bool(row["enabled"]),
        every_days=row["every_days"],
        enabled_at=row["enabled_at"],
        last_check_at=row["last_check_at"],
        last_outcome=row["last_outcome"],
        last_detail=row["last_detail"],
        paused=bool(row["paused"]),
    )


def _summary(
    mode: str,
    manifest: Manifest,
    *,
    added: int = 0,
    updated: int = 0,
    removed: int = 0,
    pruned: bool = False,
) -> ImportSummary:
    return ImportSummary(
        mode=mode,
        credentials=len(manifest.credentials),
        holders=sum(len(credential.consumers) for credential in manifest.credentials.values()),
        added=added,
        updated=updated,
        removed=removed,
        pruned=pruned,
    )


def _service_from_row(row: sqlite3.Row) -> Service:
    return Service(
        name=row["name"],
        kind=row["kind"],
        url=row["url"],
        notes=row["notes"],
        position=row["position"],
    )


def _prune_orphans(connection: sqlite3.Connection) -> None:
    """Delete value and policy rows no credential declares any more."""
    connection.execute(
        "DELETE FROM working_copies "
        "WHERE credential NOT IN (SELECT name FROM credentials)"
    )
    connection.execute(
        "DELETE FROM pending_secrets "
        "WHERE credential NOT IN (SELECT name FROM credentials)"
    )
    connection.execute(
        "DELETE FROM auto_rotation "
        "WHERE credential NOT IN (SELECT name FROM credentials)"
    )


def _insert_credential(
    connection: sqlite3.Connection, position: int, name: str, credential: Credential
) -> None:
    _write_credential(connection, position, name, credential)


def _write_credential(
    connection: sqlite3.Connection, position: int, name: str, credential: Credential
) -> None:
    """Upsert one credential and replace its holder rows."""
    vault = credential.vault
    connection.execute(
        "INSERT INTO credentials (name, position, description, credential_class, "
        "max_age_days, never_rotate, provisioned, vault_backend, vault_file, "
        "vault_path, canonical, write) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(name) DO UPDATE SET position = excluded.position, "
        "description = excluded.description, "
        "credential_class = excluded.credential_class, "
        "max_age_days = excluded.max_age_days, "
        "never_rotate = excluded.never_rotate, "
        "provisioned = excluded.provisioned, "
        "vault_backend = excluded.vault_backend, "
        "vault_file = excluded.vault_file, "
        "vault_path = excluded.vault_path, "
        "canonical = excluded.canonical, write = excluded.write",
        (
            name,
            position,
            credential.description,
            credential.credential_class,
            credential.max_age_days,
            int(credential.never_rotate),
            int(credential.provisioned),
            vault.backend if vault else None,
            vault.file if vault else None,
            json.dumps(list(vault.path)) if vault else None,
            # String-keyed plain data, checked at parse time; JSON keeps its
            # order, so an export writes `canonical` back as it was written.
            json.dumps(dict(credential.canonical)),
            json.dumps(dict(credential.write)),
        ),
    )
    connection.execute("DELETE FROM holders WHERE credential = ?", (name,))
    for index, consumer in enumerate(credential.consumers):
        connection.execute(
            "INSERT INTO holders (credential, position, target, count, mechanism, "
            "host, note) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                name,
                index,
                str(consumer.target),
                consumer.count,
                consumer.mechanism,
                consumer.host,
                consumer.note,
            ),
        )


def _credential_from_row(row: sqlite3.Row, holders: list[sqlite3.Row]) -> Credential:
    vault = None
    if row["vault_backend"] is not None:
        vault = VaultRef(
            backend=row["vault_backend"],
            file=row["vault_file"],
            path=tuple(json.loads(row["vault_path"])),
        )
    where = f"store: credential {row['name']!r}"
    return Credential(
        name=row["name"],
        description=row["description"],
        credential_class=row["credential_class"],
        max_age_days=row["max_age_days"],
        never_rotate=bool(row["never_rotate"]),
        vault=vault,
        consumers=tuple(
            Consumer(
                target=Target.parse(holder["target"], where=where),
                count=holder["count"],
                mechanism=holder["mechanism"],
                host=holder["host"],
                note=holder["note"],
            )
            for holder in holders
        ),
        provisioned=bool(row["provisioned"]),
        canonical=json.loads(row["canonical"]),
        write=json.loads(row["write"]),
    )
