"""The versioned encrypted value store.

Every value is a `secret_versions` row sealed with AES-256-GCM under a fresh
data key wrapped by a file KEK. AAD binds credential, version, stage and
attempt id, so a ciphertext moved to another row or stage fails authentication.

Non-negotiable rules: one CURRENT row per credential, at most one PENDING; a
stage transition re-encrypts under the new AAD; finish writes the version flip,
generation, outbox and one `secret.current_changed` event in one transaction;
a missing KEK refuses every value operation while metadata reads continue; a
soft-deleted credential is unusable until restored, and only an explicit purge
removes ciphertext.

The file KEK protects a stolen database or backup, not a compromised BFF
process. `docs/SECURITY.md` states that boundary.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import secrets
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from credarr.paths import fsync_directory
from credarr.redact import Secret

from . import event_schema
from .database import connect, initialise

KEK_VERSION = 1
KEK_FILENAME = "kek.json"
KEK_BYTES = 32
DEK_BYTES = 32
NONCE_BYTES = 12
KEK_MODE = 0o600

CURRENT = "CURRENT"
PREVIOUS = "PREVIOUS"
PENDING = "PENDING"
ABANDONED = "ABANDONED"
DELETED = "DELETED"
STAGES = (PENDING, CURRENT, PREVIOUS, ABANDONED, DELETED)

UNKNOWN = "unknown"
VERIFIED = "verified"
UNVERIFIED = "unverified"
FAILED = "failed"
VERIFICATIONS = (UNKNOWN, VERIFIED, UNVERIFIED, FAILED)

DEFAULT_RETENTION_DAYS = 30
RETENTION_FLOOR_DAYS = 1
DEFAULT_RECOVERY_DAYS = 7

VAULT_INITIALISED = "vault_initialised"
_EVENT_TABLE_READY = "vault_events_ready"

SECRET_CURRENT_CHANGED = "secret.current_changed"  # noqa: S105 - an event kind
SECRET_ADOPTED = "secret.adopted"  # noqa: S105 - an event kind
SECRET_REVEALED = "secret.revealed"  # noqa: S105 - an event kind
SECRET_DELETED = "secret.deleted"  # noqa: S105 - an event kind
SECRET_RESTORED = "secret.restored"  # noqa: S105 - an event kind
SECRET_PURGED = "secret.purged"  # noqa: S105 - an event kind
SECRET_CLEARED = "secret.cleared"  # noqa: S105 - an event kind

SECRET_KINDS = frozenset(
    {
        SECRET_CURRENT_CHANGED,
        SECRET_ADOPTED,
        SECRET_REVEALED,
        SECRET_DELETED,
        SECRET_RESTORED,
        SECRET_PURGED,
        SECRET_CLEARED,
    }
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS store_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- One encrypted value at one stage. `id` is part of the AAD, not a surrogate:
-- a row copied to another id cannot be opened under the new id.
CREATE TABLE IF NOT EXISTS secret_versions (
    id           TEXT    PRIMARY KEY,
    credential   TEXT    NOT NULL,
    stage        TEXT    NOT NULL
                 CHECK (stage IN ('PENDING','CURRENT','PREVIOUS','ABANDONED','DELETED')),
    attempt_id   TEXT,
    verification TEXT    NOT NULL
                 CHECK (verification IN ('unknown','verified','unverified','failed')),
    ciphertext   BLOB    NOT NULL,
    nonce        BLOB    NOT NULL,
    wrapped_dek  BLOB    NOT NULL,
    dek_nonce    BLOB    NOT NULL,
    kek_id       TEXT    NOT NULL,
    created_at   REAL    NOT NULL,
    updated_at   REAL    NOT NULL,
    tombstoned_at REAL,
    purge_after  REAL,
    actor        TEXT    NOT NULL DEFAULT '',
    origin       TEXT    NOT NULL DEFAULT 'user'
);

CREATE UNIQUE INDEX IF NOT EXISTS secret_versions_one_current
    ON secret_versions (credential) WHERE stage = 'CURRENT';
CREATE UNIQUE INDEX IF NOT EXISTS secret_versions_one_pending
    ON secret_versions (credential) WHERE stage = 'PENDING';
CREATE INDEX IF NOT EXISTS secret_versions_credential
    ON secret_versions (credential, stage, created_at);

-- Tombstone state is separate from stages so restore does not have to guess
-- which version was current before the delete. NULL deleted_at means live.
CREATE TABLE IF NOT EXISTS secret_lifecycle (
    credential  TEXT PRIMARY KEY,
    deleted_at  REAL NOT NULL,
    purge_after REAL NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    actor       TEXT NOT NULL DEFAULT ''
);

-- The app's parked mint value, encrypted under the same KEK. It is not a
-- version: until RECORD succeeds it is a candidate, not the canonical value.
CREATE TABLE IF NOT EXISTS pending_secrets_encrypted (
    credential TEXT PRIMARY KEY,
    ciphertext BLOB NOT NULL,
    nonce      BLOB NOT NULL,
    wrapped_dek BLOB NOT NULL,
    dek_nonce  BLOB NOT NULL,
    kek_id     TEXT NOT NULL,
    created_at REAL NOT NULL
);

-- One non-secret row per committed value change. `id` is the monotonic vault
-- generation the agent preflight can compare without a value.
CREATE TABLE IF NOT EXISTS vault_generations (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    credential TEXT    NOT NULL,
    version_id TEXT    NOT NULL,
    kind       TEXT    NOT NULL,
    at         REAL    NOT NULL,
    actor      TEXT    NOT NULL DEFAULT '',
    origin     TEXT    NOT NULL DEFAULT 'user'
);

CREATE INDEX IF NOT EXISTS vault_generations_credential
    ON vault_generations (credential, id);

-- Work is inserted in the same transaction as the version flip. A dispatcher
-- materialises jobs after commit, so no agent can observe a version that the
-- transaction did not commit.
CREATE TABLE IF NOT EXISTS sync_outbox (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    credential    TEXT    NOT NULL,
    version_id    TEXT    NOT NULL,
    generation_id INTEGER NOT NULL,
    created_at    REAL    NOT NULL,
    dispatched_at REAL
);

CREATE INDEX IF NOT EXISTS sync_outbox_pending
    ON sync_outbox (id) WHERE dispatched_at IS NULL;
"""


class VaultError(Exception):
    """A value operation was refused; the message is safe to show."""

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.hint = hint

    def render(self) -> str:
        return f"{self}\nhint: {self.hint}" if self.hint else str(self)


class KekUnavailable(VaultError):
    """The KEK is missing or unreadable. Every value operation is refused."""


class CredentialTombstoned(VaultError):
    """The credential is soft-deleted and cannot reveal, rotate or adopt."""


class VersionConflict(VaultError):
    """The caller expected a different CURRENT version than the store holds."""


class VersionNotFound(VaultError):
    """No version exists at the requested stage."""

    def __init__(self, credential: str, stage: str) -> None:
        super().__init__(f"{credential} has no {stage.lower()} version")
        self.credential = credential
        self.stage = stage


@dataclass(frozen=True, slots=True)
class SecretVersion:
    """One encrypted version, without its plaintext."""

    id: str
    credential: str
    stage: str
    attempt_id: str | None
    verification: str
    created_at: float
    updated_at: float
    actor: str
    origin: str

    def as_json(self) -> dict[str, Any]:
        return {
            "version": self.id,
            "stage": self.stage,
            "verification": self.verification,
            "created_at": self.created_at,
            "attempt_id": self.attempt_id,
        }


@dataclass(frozen=True, slots=True)
class RevealedValue:
    """A value returned by the one audited reveal path."""

    credential: str
    version: str
    stage: str
    verification: str
    value: Secret = field(repr=False)


def _aad(credential: str, version: str, stage: str, attempt_id: str | None) -> bytes:
    """Length-prefixed AAD: a delimiter cannot be smuggled in a field."""
    fields = (
        b"credarr-secret-v1",
        credential.encode("utf-8"),
        version.encode("utf-8"),
        stage.encode("utf-8"),
        (attempt_id or "").encode("utf-8"),
    )
    return b"".join(struct.pack(">I", len(part)) + part for part in fields)


def _wrap_aad(credential: str, version: str, stage: str, attempt_id: str | None) -> bytes:
    return b"credarr-dek-wrap-v1\0" + _aad(credential, version, stage, attempt_id)


def _pending_aad(credential: str) -> bytes:
    return _aad(credential, "pending", PENDING, None)


def _tree_aad(credential: str, version: str, stage: str) -> bytes:
    return b"credarr-tree-v1\0" + _aad(credential, version, stage, None)


def _key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:16]


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _read_private(path: Path, what: str) -> bytes:
    try:
        mode = path.stat().st_mode & 0o777
    except OSError as exc:
        raise KekUnavailable(
            f"{what} {path} is unreadable: {exc.strerror}",
            hint="restore it from an encrypted backup; a missing KEK means the "
            "stored values cannot be recovered",
        ) from None
    if mode & 0o077:
        raise KekUnavailable(
            f"{what} {path} is mode {mode:04o}; it must not be readable by "
            "another user",
            hint=f"chmod 600 {path}",
        )
    try:
        return path.read_bytes()
    except OSError as exc:
        raise KekUnavailable(
            f"{what} {path} is unreadable: {exc.strerror}",
            hint="restore it from an encrypted backup",
        ) from None


def _write_private(path: Path, payload: bytes) -> None:
    """Create or replace one private file, durably."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, KEK_MODE)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        fsync_directory(path.parent)
    except BaseException:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise


class KekRing:
    """The local KEK keyring: one active key plus retired keys.

    Retired keys stay until an operator removes them. A value's wrapped DEK
    names the key that wrapped it, so a keyring with history can always open
    the database. Rotation adds a key, rewraps every DEK to the new one, then
    makes it active; each step leaves the previous state readable.
    """

    def __init__(self, path: Path) -> None:
        self.path = path

    def exists(self) -> bool:
        return self.path.is_file()

    @classmethod
    def create(cls, path: Path) -> KekRing:
        key = secrets.token_bytes(KEK_BYTES)
        identifier = _key_id(key)
        document = {
            "version": KEK_VERSION,
            "active": identifier,
            "keys": {identifier: _b64(key)},
        }
        _write_private(path, json.dumps(document, sort_keys=True).encode("utf-8"))
        return cls(path)

    def load(self) -> tuple[dict[str, bytes], str]:
        raw = _read_private(self.path, "the KEK file")
        try:
            document = json.loads(raw)
        except (TypeError, ValueError):
            raise KekUnavailable(
                f"the KEK file {self.path} is not valid JSON",
                hint="restore the last good KEK from an encrypted backup",
            ) from None
        if not isinstance(document, dict) or document.get("version") != KEK_VERSION:
            raise KekUnavailable(
                f"the KEK file {self.path} has an unsupported format",
                hint="restore it from a backup written by this build",
            )
        keys = document.get("keys")
        if not isinstance(keys, dict) or not keys:
            raise KekUnavailable(f"the KEK file {self.path} contains no keys")
        decoded: dict[str, bytes] = {}
        for identifier, encoded in keys.items():
            try:
                key = base64.b64decode(str(encoded), validate=True)
            except (ValueError, TypeError):
                raise KekUnavailable(
                    f"the KEK file {self.path} contains a malformed key"
                ) from None
            if len(key) != KEK_BYTES:
                raise KekUnavailable(
                    f"the KEK file {self.path} contains a key with the wrong length"
                )
            decoded[str(identifier)] = key
        active = str(document.get("active") or "")
        if active not in decoded:
            raise KekUnavailable(
                f"the KEK file {self.path} names an active key it does not contain"
            )
        return decoded, active

    def add(self, keys: dict[str, bytes], active: str) -> tuple[str, bytes]:
        """Persist a new key without making it active, and return it."""
        key = secrets.token_bytes(KEK_BYTES)
        identifier = _key_id(key)
        while identifier in keys:
            key = secrets.token_bytes(KEK_BYTES)
            identifier = _key_id(key)
        updated = dict(keys)
        updated[identifier] = key
        self.write(updated, active)
        return identifier, key

    def activate(self, keys: dict[str, bytes], identifier: str) -> None:
        if identifier not in keys:
            raise KekUnavailable("cannot activate a key the keyring does not hold")
        self.write(keys, identifier)

    def write(self, keys: dict[str, bytes], active: str) -> None:
        document = {
            "version": KEK_VERSION,
            "active": active,
            "keys": {name: _b64(key) for name, key in sorted(keys.items())},
        }
        _write_private(self.path, json.dumps(document, sort_keys=True).encode("utf-8"))


def _seal(
    ring_keys: dict[str, bytes],
    active: str,
    credential: str,
    version: str,
    stage: str,
    attempt_id: str | None,
    value: str,
) -> dict[str, bytes | str]:
    """Encrypt one value under a fresh DEK, wrapped by the active KEK."""
    dek = secrets.token_bytes(DEK_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    aad = _aad(credential, version, stage, attempt_id)
    ciphertext = AESGCM(dek).encrypt(nonce, value.encode("utf-8"), aad)
    dek_nonce = secrets.token_bytes(NONCE_BYTES)
    wrapped = AESGCM(ring_keys[active]).encrypt(
        dek_nonce, dek, _wrap_aad(credential, version, stage, attempt_id)
    )
    return {
        "ciphertext": ciphertext,
        "nonce": nonce,
        "wrapped_dek": wrapped,
        "dek_nonce": dek_nonce,
        "kek_id": active,
    }


def _open_version(keys: dict[str, bytes], row: Any) -> str:
    identifier = row["kek_id"]
    key = keys.get(identifier)
    if key is None:
        raise KekUnavailable(
            f"the KEK keyring does not hold key {identifier}",
            hint="restore the KEK file that was active when this value was written",
        )
    try:
        dek = AESGCM(key).decrypt(
            row["dek_nonce"],
            row["wrapped_dek"],
            _wrap_aad(
                row["credential"], row["id"], row["stage"], row["attempt_id"]
            ),
        )
        plaintext = AESGCM(dek).decrypt(
            row["nonce"],
            row["ciphertext"],
            _aad(row["credential"], row["id"], row["stage"], row["attempt_id"]),
        )
    except InvalidTag:
        raise VaultError(
            "the stored value failed authentication; the ciphertext or its "
            "bound metadata was changed"
        ) from None
    return plaintext.decode("utf-8")


class VaultTree:
    """The shared, encrypted working tree an agent reads.

    The BFF writes one sealed value file per credential and a non-secret
    generation marker after the database commit. The agent needs the separate
    key file, which is deliberately outside the tree: a fresh clone of the
    tree alone cannot read a value. This is a delivery mirror of the app's
    canonical store, not a second source of truth.
    """

    def __init__(self, root: Path, key_path: Path) -> None:
        self.root = root
        self.key_path = key_path
        self.values = root / "values"
        self.markers = root / "generations"

    @property
    def configured(self) -> bool:
        return self.root.is_dir() or self.root.parent.is_dir()

    def _key(self) -> bytes:
        if not self.key_path.is_file():
            if self.root.exists() and any(self.values.glob("*.bin")):
                raise KekUnavailable(
                    f"the vault-tree key {self.key_path} is missing while "
                    "sealed values exist",
                    hint="restore the vault-tree key from the agent deployment",
                )
            _write_private(self.key_path, secrets.token_bytes(KEK_BYTES))
        raw = _read_private(self.key_path, "the vault-tree key")
        if len(raw) != KEK_BYTES:
            raise KekUnavailable(
                f"the vault-tree key {self.key_path} has the wrong length"
            )
        return raw

    def _name(self, credential: str) -> str:
        return hashlib.sha256(credential.encode("utf-8")).hexdigest()

    def write_value(
        self, credential: str, version: str, stage: str, value: str, at: float
    ) -> None:
        key = self._key()
        payload = json.dumps(
            {
                "version": 1,
                "credential": credential,
                "value_version": version,
                "stage": stage,
                "at": at,
                "value": value,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        nonce = secrets.token_bytes(NONCE_BYTES)
        sealed = AESGCM(key).encrypt(nonce, payload, _tree_aad(credential, version, stage))
        self.values.mkdir(parents=True, exist_ok=True)
        _write_private(self.values / f"{self._name(credential)}.bin", nonce + sealed)

    def write_marker(
        self, credential: str, version: str, stage: str, generation: int, at: float
    ) -> None:
        self.markers.mkdir(parents=True, exist_ok=True)
        marker = {
            "version": 1,
            "credential": credential,
            "value_version": version,
            "stage": stage,
            "generation": generation,
            "at": at,
        }
        _write_private(
            self.markers / f"{self._name(credential)}.json",
            json.dumps(marker, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )

    def forget(self, credential: str) -> None:
        """Remove the delivery copies after a clear or purge."""
        for path in (
            self.values / f"{self._name(credential)}.bin",
            self.markers / f"{self._name(credential)}.json",
        ):
            with contextlib.suppress(OSError):
                path.unlink()

    def read_marker(self, credential: str) -> dict[str, Any] | None:
        path = self.markers / f"{self._name(credential)}.json"
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            raise VaultError(
                f"the shared vault generation marker for {credential} is unreadable"
            ) from None

    def verify(self, credential: str, value_version: str) -> str:
        """Prove the marker and the sealed value agree before a deploy.

        A generation behind the job, a missing marker, or an unreadable value
        is fail-closed: the agent performs no Docker action.
        """
        marker = self.read_marker(credential)
        if marker is None:
            raise VaultError(
                f"no generation marker for {credential}; the shared vault is behind"
            )
        if marker.get("credential") != credential:
            raise VaultError(f"the generation marker for {credential} names another credential")
        if marker.get("value_version") != value_version:
            raise VaultError(
                f"the shared vault is at {marker.get('value_version', 'an older generation')} "
                f"for {credential}, not the job's {value_version}; refusing to deploy"
            )
        key = self._key()
        path = self.values / f"{self._name(credential)}.bin"
        try:
            sealed = path.read_bytes()
        except OSError as exc:
            raise VaultError(
                f"the shared value for {credential} is unreadable: {exc.strerror}"
            ) from None
        if len(sealed) <= NONCE_BYTES:
            raise VaultError(f"the shared value for {credential} is truncated")
        try:
            payload = json.loads(
                AESGCM(key).decrypt(
                    sealed[:NONCE_BYTES],
                    sealed[NONCE_BYTES:],
                    _tree_aad(credential, value_version, marker.get("stage", CURRENT)),
                )
            )
        except (InvalidTag, ValueError, TypeError):
            raise VaultError(
                f"the shared value for {credential} failed authentication"
            ) from None
        if payload.get("value_version") != value_version:
            raise VaultError(
                f"the shared value file for {credential} does not carry the job's version"
            )
        return str(payload.get("value", ""))


class VaultStore:
    """Encrypted versions, lifecycle, generations and the sync outbox."""

    def __init__(
        self,
        database: Path | str,
        *,
        kek_path: Path | None = None,
        tree: VaultTree | None = None,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        recovery_days: int = DEFAULT_RECOVERY_DAYS,
    ) -> None:
        self.path = Path(database)
        self.kek_path = Path(kek_path) if kek_path else self.path.with_name(KEK_FILENAME)
        self.ring = KekRing(self.kek_path)
        self.tree = tree
        self.retention_seconds = max(retention_days, RETENTION_FLOOR_DAYS) * 86400.0
        self.recovery_seconds = max(recovery_days, RETENTION_FLOOR_DAYS) * 86400.0
        self.kek_error: str | None = None
        self._keys: dict[str, bytes] = {}
        self._active = ""
        initialise(self.path, SCHEMA)
        with connect(self.path) as connection:
            connection.executescript(event_schema.SCHEMA)
        self._ensure_events()
        self._load_or_bootstrap()
        if self.kek_error is None:
            self._migrate_legacy()
            if self.tree is not None:
                self.publish_existing()

    def publish_existing(self) -> int:
        """Seed the shared tree from committed CURRENT values after a restart.

        A tree mounted after the last rotation would otherwise have no file for
        a value the agent is asked to deploy. The marker is written from the
        committed generation, so the same preflight applies as after a commit.
        """
        self._require_kek()
        published = 0
        with connect(self.path) as connection:
            rows = connection.execute(
                "SELECT sv.*, (SELECT MAX(id) FROM vault_generations g "
                "              WHERE g.credential = sv.credential) AS generation "
                "FROM secret_versions sv WHERE sv.stage = ?",
                (CURRENT,),
            ).fetchall()
        for row in rows:
            try:
                plaintext = _open_version(self._keys, row)
            except VaultError:
                continue
            self.tree.write_value(
                row["credential"], row["id"], row["stage"], plaintext, row["updated_at"]
            )
            if row["generation"] is not None:
                self.tree.write_marker(
                    row["credential"],
                    row["id"],
                    row["stage"],
                    int(row["generation"]),
                    row["updated_at"],
                )
            published += 1
        return published

    # -- KEK ---------------------------------------------------------------

    def _ensure_events(self) -> None:
        with connect(self.path) as connection:
            event_schema.ensure(connection)

    def _has_marker(self) -> bool:
        with connect(self.path) as connection:
            return (
                connection.execute(
                    "SELECT 1 FROM store_meta WHERE key = ?", (VAULT_INITIALISED,)
                ).fetchone()
                is not None
            )

    def _raw_data_count(self) -> int:
        with connect(self.path) as connection:
            versions = connection.execute(
                "SELECT COUNT(*) FROM secret_versions"
            ).fetchone()[0]
            working = connection.execute(
                "SELECT COUNT(*) FROM working_copies"
            ).fetchone()[0] if self._table(connection, "working_copies") else 0
            pending = connection.execute(
                "SELECT COUNT(*) FROM pending_secrets"
            ).fetchone()[0] if self._table(connection, "pending_secrets") else 0
        return int(versions) + int(working) + int(pending)

    @staticmethod
    def _table(connection: Any, name: str) -> bool:
        return (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                (name,),
            ).fetchone()
            is not None
        )

    def _load_or_bootstrap(self) -> None:
        if self.ring.exists():
            try:
                self._keys, self._active = self.ring.load()
            except KekUnavailable as exc:
                self.kek_error = str(exc)
            return
        if self._has_marker() or self._raw_data_count() > 0:
            self.kek_error = (
                f"the KEK file {self.kek_path} is missing; stored values cannot "
                "be decrypted"
            )
            return
        self.ring.create(self.kek_path)
        self._keys, self._active = self.ring.load()
        with connect(self.path) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO store_meta (key, value) VALUES (?, ?)",
                (VAULT_INITIALISED, str(time.time())),
            )

    def _require_kek(self) -> None:
        if self.kek_error is not None:
            raise KekUnavailable(
                self.kek_error,
                hint="restore the KEK from the encrypted backup; losing it makes "
                "every stored value unrecoverable",
            ) from None

    def key_status(self) -> dict[str, Any]:
        """Non-secret facts about the keyring, for the console and the drill."""
        status: dict[str, Any] = {
            "path": str(self.kek_path),
            "present": self.ring.exists(),
            "available": self.kek_error is None,
            "error": self.kek_error,
            "active": self._active if self.kek_error is None else None,
            "keys": sorted(self._keys) if self.kek_error is None else [],
        }
        if self.kek_error is None:
            with connect(self.path) as connection:
                status["versions"] = connection.execute(
                    "SELECT COUNT(*) FROM secret_versions"
                ).fetchone()[0]
                status["unwrapped"] = connection.execute(
                    "SELECT COUNT(*) FROM secret_versions WHERE kek_id != ?",
                    (self._active,),
                ).fetchone()[0]
        return status

    # -- reads -------------------------------------------------------------

    def _lifecycle(self, connection: Any, credential: str) -> Any:
        return connection.execute(
            "SELECT * FROM secret_lifecycle WHERE credential = ?", (credential,)
        ).fetchone()

    def _assert_live(self, connection: Any, credential: str) -> None:
        row = self._lifecycle(connection, credential)
        if row is not None:
            raise CredentialTombstoned(
                f"{credential} is soft-deleted until "
                f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(row['purge_after']))}; "
                "restore it first"
            )

    def is_tombstoned(self, credential: str) -> bool:
        with connect(self.path) as connection:
            return self._lifecycle(connection, credential) is not None

    def tombstoned_names(self) -> set[str]:
        with connect(self.path) as connection:
            rows = connection.execute(
                "SELECT credential FROM secret_lifecycle"
            ).fetchall()
        return {row["credential"] for row in rows}

    def lifecycle(self, credential: str) -> dict[str, Any] | None:
        with connect(self.path) as connection:
            row = self._lifecycle(connection, credential)
        if row is None:
            return None
        return {
            "deleted_at": row["deleted_at"],
            "purge_after": row["purge_after"],
            "reason": row["reason"],
            "actor": row["actor"],
        }

    def versions(self, credential: str) -> tuple[SecretVersion, ...]:
        with connect(self.path) as connection:
            rows = connection.execute(
                "SELECT * FROM secret_versions WHERE credential = ? "
                "ORDER BY created_at DESC, id",
                (credential,),
            ).fetchall()
        return tuple(_version_from_row(row) for row in rows)

    def current_version(self, credential: str) -> SecretVersion | None:
        with connect(self.path) as connection:
            row = connection.execute(
                "SELECT * FROM secret_versions WHERE credential = ? AND stage = ?",
                (credential, CURRENT),
            ).fetchone()
        return _version_from_row(row) if row else None

    def get_current(self, credential: str) -> Secret | None:
        self._require_kek()
        with connect(self.path) as connection:
            self._assert_live(connection, credential)
            row = connection.execute(
                "SELECT * FROM secret_versions WHERE credential = ? AND stage = ?",
                (credential, CURRENT),
            ).fetchone()
        return Secret(_open_version(self._keys, row)) if row else None

    def get_pending(self, credential: str) -> Secret | None:
        self._require_kek()
        with connect(self.path) as connection:
            row = connection.execute(
                "SELECT * FROM pending_secrets_encrypted WHERE credential = ?",
                (credential,),
            ).fetchone()
        if row is None:
            return None
        try:
            dek = AESGCM(self._keys[row["kek_id"]]).decrypt(
                row["dek_nonce"], row["wrapped_dek"], _pending_aad(credential)
            )
            plaintext = AESGCM(dek).decrypt(
                row["nonce"], row["ciphertext"], _pending_aad(credential)
            )
        except KeyError:
            raise KekUnavailable(
                f"the KEK keyring does not hold key {row['kek_id']}"
            ) from None
        except InvalidTag:
            raise VaultError("the pending value failed authentication") from None
        return Secret(plaintext.decode("utf-8"))

    def reveal(self, credential: str, stage: str = CURRENT) -> RevealedValue:
        if stage not in (CURRENT, PREVIOUS):
            raise VaultError("only CURRENT and PREVIOUS versions can be revealed")
        self._require_kek()
        with connect(self.path) as connection:
            self._assert_live(connection, credential)
            row = connection.execute(
                "SELECT * FROM secret_versions WHERE credential = ? AND stage = ?",
                (credential, stage),
            ).fetchone()
        if row is None:
            raise VersionNotFound(credential, stage)
        version = _version_from_row(row)
        return RevealedValue(
            credential=credential,
            version=version.id,
            stage=version.stage,
            verification=version.verification,
            value=Secret(_open_version(self._keys, row)),
        )

    def record_reveal(
        self, revealed: RevealedValue, *, actor: str, origin: str
    ) -> None:
        """Audit one reveal: who, which version, stage and time. Never the value."""
        now = time.time()
        with connect(self.path) as connection:
            connection.execute(
                "INSERT INTO events "
                "(at, kind, credential, previous_status, status, detail, origin, data) "
                "VALUES (?, ?, ?, NULL, NULL, ?, ?, ?)",
                (
                    now,
                    SECRET_REVEALED,
                    revealed.credential,
                    f"revealed {revealed.stage.lower()} version {revealed.version[:12]}",
                    origin,
                    event_schema.encode(
                        {
                            "version": revealed.version,
                            "stage": revealed.stage,
                            "actor": actor,
                        }
                    ),
                ),
            )

    def working_copy_times(self) -> dict[str, float]:
        with connect(self.path) as connection:
            rows = connection.execute(
                "SELECT credential, MAX(updated_at) AS updated_at "
                "FROM secret_versions WHERE stage = ? GROUP BY credential",
                (CURRENT,),
            ).fetchall()
        return {row["credential"]: row["updated_at"] for row in rows}

    # -- writes ------------------------------------------------------------

    def set_current(
        self,
        credential: str,
        value: Secret,
        *,
        actor: str,
        origin: str,
        verification: str = UNKNOWN,
        attempt_id: str | None = None,
        expected_version: str | None = None,
        event_kind: str = SECRET_CURRENT_CHANGED,
        extra_event: str | None = None,
        tree_publish: bool = True,
    ) -> SecretVersion:
        """Commit one new CURRENT value under the full barrier.

        The sealed tree file is written before the database transaction so the
        agent can never observe a committed version whose value is absent. The
        tree marker is written only after COMMIT, so a crash between the two
        leaves the marker behind the database and the agent fails closed.
        """
        if verification not in VERIFICATIONS:
            raise VaultError(f"unknown verification status {verification!r}")
        self._require_kek()
        now = time.time()
        version_id = secrets.token_hex(16)
        sealed = _seal(
            self._keys, self._active, credential, version_id, CURRENT, attempt_id,
            value.reveal(),
        )
        # Refuse the obvious conflicts before touching the shared tree, so a
        # tombstoned credential or a stale expected version does not replace a
        # value the agent may still be deploying. The transaction rechecks.
        with connect(self.path) as connection:
            self._assert_live(connection, credential)
            if expected_version is not None:
                current = connection.execute(
                    "SELECT id FROM secret_versions WHERE credential = ? AND stage = ?",
                    (credential, CURRENT),
                ).fetchone()
                if current is None or current["id"] != expected_version:
                    raise VersionConflict(
                        f"{credential} changed while this operation was running; "
                        "read the current version and retry"
                    )
        if tree_publish and self.tree is not None:
            self.tree.write_value(credential, version_id, CURRENT, value.reveal(), now)

        with connect(self.path) as connection:
            from credarr.transaction import transaction

            with transaction(connection):
                self._assert_live(connection, credential)
                current = connection.execute(
                    "SELECT * FROM secret_versions WHERE credential = ? AND stage = ?",
                    (credential, CURRENT),
                ).fetchone()
                if expected_version is not None and (
                    current is None or current["id"] != expected_version
                ):
                    raise VersionConflict(
                        f"{credential} changed while this operation was running; "
                        "read the current version and retry"
                    )
                previous_id = current["id"] if current else None
                if current is not None:
                    self._stage_previous(connection, current, now, actor, origin)
                connection.execute(
                    "INSERT INTO secret_versions "
                    "(id, credential, stage, attempt_id, verification, ciphertext, "
                    " nonce, wrapped_dek, dek_nonce, kek_id, created_at, updated_at, "
                    " actor, origin) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        version_id,
                        credential,
                        CURRENT,
                        attempt_id,
                        verification,
                        sealed["ciphertext"],
                        sealed["nonce"],
                        sealed["wrapped_dek"],
                        sealed["dek_nonce"],
                        sealed["kek_id"],
                        now,
                        now,
                        actor,
                        origin,
                    ),
                )
                connection.execute(
                    "UPDATE secret_versions SET stage = ?, purge_after = ?, "
                    "updated_at = ? WHERE credential = ? AND stage = ?",
                    (ABANDONED, now + self.retention_seconds, now, credential, PENDING),
                )
                generation = self._record_change(
                    connection,
                    credential,
                    version_id,
                    event_kind,
                    actor,
                    origin,
                    now,
                    previous_id,
                    attempt_id,
                    verification,
                    extra_event,
                )
        if tree_publish and self.tree is not None:
            with contextlib.suppress(VaultError, OSError):
                self.tree.write_marker(credential, version_id, CURRENT, generation, now)
        return SecretVersion(
            id=version_id,
            credential=credential,
            stage=CURRENT,
            attempt_id=attempt_id,
            verification=verification,
            created_at=now,
            updated_at=now,
            actor=actor,
            origin=origin,
        )

    def _stage_previous(
        self, connection: Any, current: Any, now: float, actor: str, origin: str
    ) -> None:
        """Re-encrypt the outgoing CURRENT as PREVIOUS under a new DEK/AAD."""
        plaintext = _open_version(self._keys, current)
        sealed = _seal(
            self._keys,
            self._active,
            current["credential"],
            current["id"],
            PREVIOUS,
            current["attempt_id"],
            plaintext,
        )
        connection.execute(
            "UPDATE secret_versions SET stage = ?, ciphertext = ?, nonce = ?, "
            "wrapped_dek = ?, dek_nonce = ?, kek_id = ?, updated_at = ?, "
            "actor = ?, origin = ? WHERE id = ?",
            (
                PREVIOUS,
                sealed["ciphertext"],
                sealed["nonce"],
                sealed["wrapped_dek"],
                sealed["dek_nonce"],
                sealed["kek_id"],
                now,
                actor,
                origin,
                current["id"],
            ),
        )
        connection.execute(
            "UPDATE secret_versions SET stage = ?, purge_after = ?, updated_at = ? "
            "WHERE credential = ? AND stage = ? AND id != ?",
            (ABANDONED, now + self.retention_seconds, now, current["credential"],
             PREVIOUS, current["id"]),
        )

    def _record_change(
        self,
        connection: Any,
        credential: str,
        version_id: str,
        event_kind: str,
        actor: str,
        origin: str,
        now: float,
        previous_id: str | None,
        attempt_id: str | None,
        verification: str,
        extra_event: str | None = None,
    ) -> int:
        cursor = connection.execute(
            "INSERT INTO vault_generations "
            "(credential, version_id, kind, at, actor, origin) VALUES (?, ?, ?, ?, ?, ?)",
            (credential, version_id, event_kind, now, actor, origin),
        )
        generation = int(cursor.lastrowid)
        connection.execute(
            "INSERT INTO sync_outbox "
            "(credential, version_id, generation_id, created_at) VALUES (?, ?, ?, ?)",
            (credential, version_id, generation, now),
        )
        data = {
            "version": version_id,
            "previous_version": previous_id,
            "verification": verification,
            "generation": generation,
        }
        if attempt_id:
            data["attempt_id"] = attempt_id
        connection.execute(
            "INSERT INTO events "
            "(at, kind, credential, previous_status, status, detail, origin, data) "
            "VALUES (?, ?, ?, NULL, NULL, ?, ?, ?)",
            (
                now,
                event_kind,
                credential,
                f"current value changed to version {version_id[:12]}",
                origin,
                event_schema.encode(data),
            ),
        )
        if extra_event is not None:
            connection.execute(
                "INSERT INTO events "
                "(at, kind, credential, previous_status, status, detail, origin, data) "
                "VALUES (?, ?, ?, NULL, NULL, ?, ?, ?)",
                (
                    now,
                    extra_event,
                    credential,
                    f"value adopted as {verification}",
                    origin,
                    event_schema.encode(data),
                ),
            )
        return generation

    def set_pending(self, credential: str, value: Secret) -> None:
        self._require_kek()
        now = time.time()
        dek = secrets.token_bytes(DEK_BYTES)
        nonce = secrets.token_bytes(NONCE_BYTES)
        sealed = AESGCM(dek).encrypt(
            nonce, value.reveal().encode("utf-8"), _pending_aad(credential)
        )
        dek_nonce = secrets.token_bytes(NONCE_BYTES)
        wrapped = AESGCM(self._keys[self._active]).encrypt(
            dek_nonce, dek, _pending_aad(credential)
        )
        with connect(self.path) as connection:
            self._assert_live(connection, credential)
            connection.execute(
                "INSERT INTO pending_secrets_encrypted "
                "(credential, ciphertext, nonce, wrapped_dek, dek_nonce, kek_id, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(credential) DO UPDATE SET ciphertext = excluded.ciphertext, "
                "nonce = excluded.nonce, wrapped_dek = excluded.wrapped_dek, "
                "dek_nonce = excluded.dek_nonce, kek_id = excluded.kek_id, "
                "created_at = excluded.created_at",
                (credential, sealed, nonce, wrapped, dek_nonce, self._active, now),
            )

    def clear_pending(self, credential: str) -> None:
        with connect(self.path) as connection:
            connection.execute(
                "DELETE FROM pending_secrets_encrypted WHERE credential = ?",
                (credential,),
            )

    def tombstone(
        self, credential: str, *, actor: str, origin: str, reason: str = ""
    ) -> dict[str, Any]:
        now = time.time()
        purge_after = now + self.recovery_seconds
        with connect(self.path) as connection:
            from credarr.transaction import transaction

            with transaction(connection):
                self._assert_live(connection, credential)
                connection.execute(
                    "INSERT INTO secret_lifecycle "
                    "(credential, deleted_at, purge_after, reason, actor) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (credential, now, purge_after, reason, actor),
                )
                connection.execute(
                    "INSERT INTO events "
                    "(at, kind, credential, previous_status, status, detail, origin, data) "
                    "VALUES (?, ?, ?, NULL, NULL, ?, ?, ?)",
                    (
                        now,
                        SECRET_DELETED,
                        credential,
                        "credential soft-deleted; values are unusable until restored",
                        origin,
                        event_schema.encode({"purge_after": purge_after}),
                    ),
                )
        return {"deleted_at": now, "purge_after": purge_after, "reason": reason}

    def restore(self, credential: str, *, actor: str, origin: str) -> bool:
        with connect(self.path) as connection:
            from credarr.transaction import transaction

            with transaction(connection):
                row = self._lifecycle(connection, credential)
                if row is None:
                    return False
                connection.execute(
                    "DELETE FROM secret_lifecycle WHERE credential = ?", (credential,)
                )
                connection.execute(
                    "INSERT INTO events "
                    "(at, kind, credential, previous_status, status, detail, origin, data) "
                    "VALUES (?, ?, ?, NULL, NULL, ?, ?, ?)",
                    (
                        time.time(),
                        SECRET_RESTORED,
                        credential,
                        "credential restored; its current version is usable again",
                        origin,
                        event_schema.encode({}),
                    ),
                )
        return True

    def clear_values(
        self, credential: str, *, actor: str, origin: str
    ) -> int:
        """Forget a credential's value history without tombstoning the name.

        This is the existing "forget the app's copy" operation: the next audit
        reports it unverifiable, and no lifecycle row blocks a later paste. It
        is still audited and still removes ciphertext.
        """
        with connect(self.path) as connection:
            from credarr.transaction import transaction

            with transaction(connection):
                self._assert_live(connection, credential)
                removed = connection.execute(
                    "DELETE FROM secret_versions WHERE credential = ?", (credential,)
                ).rowcount
                connection.execute(
                    "DELETE FROM pending_secrets_encrypted WHERE credential = ?",
                    (credential,),
                )
                connection.execute(
                    "DELETE FROM sync_outbox WHERE credential = ?", (credential,)
                )
                connection.execute(
                    "INSERT INTO events "
                    "(at, kind, credential, previous_status, status, detail, origin, data) "
                    "VALUES (?, ?, ?, NULL, NULL, ?, ?, ?)",
                    (
                        time.time(),
                        SECRET_CLEARED,
                        credential,
                        "stored value cleared; the credential is unverifiable "
                        "until a value is stored again",
                        origin,
                        event_schema.encode({"versions_removed": removed}),
                    ),
                )
        if removed:
            self._scrub()
        if self.tree is not None:
            self.tree.forget(credential)
        return int(removed)

    def drop_connection(self, connection: Any, credential: str) -> None:
        """Remove every trace of a name the topology no longer declares."""
        connection.execute(
            "DELETE FROM secret_versions WHERE credential = ?", (credential,)
        )
        connection.execute(
            "DELETE FROM pending_secrets_encrypted WHERE credential = ?", (credential,)
        )
        connection.execute(
            "DELETE FROM secret_lifecycle WHERE credential = ?", (credential,)
        )
        connection.execute(
            "DELETE FROM sync_outbox WHERE credential = ?", (credential,)
        )

    def prune_connection(self, connection: Any) -> None:
        """Drop values for names a topology import no longer declares."""
        if not self._table(connection, "credentials"):
            return
        connection.execute(
            "DELETE FROM secret_versions WHERE credential NOT IN "
            "(SELECT name FROM credentials)"
        )
        connection.execute(
            "DELETE FROM pending_secrets_encrypted WHERE credential NOT IN "
            "(SELECT name FROM credentials)"
        )
        connection.execute(
            "DELETE FROM secret_lifecycle WHERE credential NOT IN "
            "(SELECT name FROM credentials)"
        )
        connection.execute(
            "DELETE FROM sync_outbox WHERE credential NOT IN "
            "(SELECT name FROM credentials)"
        )

    def prune_pending(self) -> None:
        """Drop a parked value that already became CURRENT or lost its name."""
        with connect(self.path) as connection:
            rows = connection.execute(
                "SELECT credential FROM pending_secrets_encrypted"
            ).fetchall()
        for row in rows:
            name = row["credential"]
            try:
                pending = self.get_pending(name)
                current = self.get_current(name)
            except (KekUnavailable, CredentialTombstoned):
                continue
            if pending is None:
                continue
            if current is not None and current == pending:
                self.clear_pending(name)

    def purge_credential(self, credential: str, *, actor: str = "admin") -> int:
        """Remove every ciphertext, pending value and lifecycle row for good."""
        with connect(self.path) as connection:
            from credarr.transaction import transaction

            with transaction(connection):
                row = self._lifecycle(connection, credential)
                if row is None:
                    raise VaultError(
                        f"{credential} is not soft-deleted; soft-delete it before "
                        "an explicit purge"
                    )
                removed = connection.execute(
                    "DELETE FROM secret_versions WHERE credential = ?", (credential,)
                ).rowcount
                connection.execute(
                    "DELETE FROM pending_secrets_encrypted WHERE credential = ?",
                    (credential,),
                )
                connection.execute(
                    "DELETE FROM secret_lifecycle WHERE credential = ?", (credential,)
                )
                connection.execute(
                    "DELETE FROM sync_outbox WHERE credential = ?", (credential,)
                )
                connection.execute(
                    "INSERT INTO events "
                    "(at, kind, credential, previous_status, status, detail, origin, data) "
                    "VALUES (?, ?, ?, NULL, NULL, ?, ?, ?)",
                    (
                        time.time(),
                        SECRET_PURGED,
                        credential,
                        "credential purged; ciphertext and pending value removed",
                        "user",
                        event_schema.encode({"versions_removed": removed}),
                    ),
                )
        self._scrub()
        if self.tree is not None:
            self.tree.forget(credential)
        return int(removed)

    def maintenance(self, now: float | None = None) -> dict[str, int]:
        """Purge retention-expired versions and soft-deleted credentials."""
        at = time.time() if now is None else now
        purged_versions = 0
        purged_credentials: list[str] = []
        with connect(self.path) as connection:
            from credarr.transaction import transaction

            with transaction(connection):
                purged_versions = connection.execute(
                    "DELETE FROM secret_versions WHERE purge_after IS NOT NULL "
                    "AND purge_after <= ?",
                    (at,),
                ).rowcount
                rows = connection.execute(
                    "SELECT credential FROM secret_lifecycle WHERE purge_after <= ?",
                    (at,),
                ).fetchall()
                for row in rows:
                    name = row["credential"]
                    connection.execute(
                        "DELETE FROM secret_versions WHERE credential = ?", (name,)
                    )
                    connection.execute(
                        "DELETE FROM pending_secrets_encrypted WHERE credential = ?",
                        (name,),
                    )
                    connection.execute(
                        "DELETE FROM secret_lifecycle WHERE credential = ?", (name,)
                    )
                    connection.execute(
                        "DELETE FROM sync_outbox WHERE credential = ?", (name,)
                    )
                    purged_credentials.append(name)
        if purged_versions or purged_credentials:
            self._scrub()
            if self.tree is not None:
                for name in purged_credentials:
                    self.tree.forget(name)
        return {
            "versions": int(purged_versions),
            "credentials": len(purged_credentials),
        }

    def _scrub(self) -> None:
        """Overwrite free pages after deleting ciphertext, then truncate WAL."""
        with connect(self.path) as connection:
            with contextlib.suppress(Exception):
                connection.execute("PRAGMA secure_delete = ON")
            with contextlib.suppress(Exception):
                connection.execute("VACUUM")
            with contextlib.suppress(Exception):
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    # -- outbox ------------------------------------------------------------

    def pending_outbox(self, limit: int = 100) -> tuple[dict[str, Any], ...]:
        with connect(self.path) as connection:
            rows = connection.execute(
                "SELECT * FROM sync_outbox WHERE dispatched_at IS NULL "
                "ORDER BY id LIMIT ?",
                (limit,),
            ).fetchall()
        return tuple(dict(row) for row in rows)

    def mark_dispatched(self, ids: list[int], now: float | None = None) -> None:
        if not ids:
            return
        at = time.time() if now is None else now
        with connect(self.path) as connection:
            connection.executemany(
                "UPDATE sync_outbox SET dispatched_at = ? WHERE id = ?",
                [(at, identifier) for identifier in ids],
            )

    # -- rotation of the KEK ----------------------------------------------

    def rotate_kek(self) -> str:
        """Rewrap every DEK under a new KEK, leaving old keys readable."""
        self._require_kek()
        keys = dict(self._keys)
        active = self._active
        new_id, _new_key = self.ring.add(keys, active)
        keys, active = self.ring.load()
        with connect(self.path) as connection:
            from credarr.transaction import transaction

            with transaction(connection):
                for row in connection.execute("SELECT * FROM secret_versions").fetchall():
                    plaintext = _open_version(keys, row)
                    sealed = _seal(
                        keys,
                        new_id,
                        row["credential"],
                        row["id"],
                        row["stage"],
                        row["attempt_id"],
                        plaintext,
                    )
                    connection.execute(
                        "UPDATE secret_versions SET ciphertext = ?, nonce = ?, "
                        "wrapped_dek = ?, dek_nonce = ?, kek_id = ? WHERE id = ?",
                        (
                            sealed["ciphertext"],
                            sealed["nonce"],
                            sealed["wrapped_dek"],
                            sealed["dek_nonce"],
                            sealed["kek_id"],
                            row["id"],
                        ),
                    )
                for row in connection.execute(
                    "SELECT * FROM pending_secrets_encrypted"
                ).fetchall():
                    dek = AESGCM(keys[row["kek_id"]]).decrypt(
                        row["dek_nonce"], row["wrapped_dek"], _pending_aad(row["credential"])
                    )
                    dek_nonce = secrets.token_bytes(NONCE_BYTES)
                    wrapped = AESGCM(keys[new_id]).encrypt(
                        dek_nonce, dek, _pending_aad(row["credential"])
                    )
                    connection.execute(
                        "UPDATE pending_secrets_encrypted SET wrapped_dek = ?, "
                        "dek_nonce = ?, kek_id = ? WHERE credential = ?",
                        (wrapped, dek_nonce, new_id, row["credential"]),
                    )
        self.ring.activate(keys, new_id)
        self._keys, self._active = keys, new_id
        return new_id

    # -- migration ---------------------------------------------------------

    def _migrate_legacy(self) -> None:
        """Move plaintext working copies and pending values into the vault."""
        with connect(self.path) as connection:
            has_working = self._table(connection, "working_copies")
            has_pending = self._table(connection, "pending_secrets")
            working = (
                connection.execute("SELECT * FROM working_copies").fetchall()
                if has_working
                else []
            )
            pending = (
                connection.execute("SELECT * FROM pending_secrets").fetchall()
                if has_pending
                else []
            )
        if not working and not pending:
            return
        migrated = 0
        for row in working:
            name = row["credential"]
            if self.current_version(name) is None:
                self.set_current(
                    name,
                    Secret(row["value"]),
                    actor="migration",
                    origin="auto",
                    verification=UNKNOWN,
                    event_kind=SECRET_CURRENT_CHANGED,
                    tree_publish=False,
                )
                migrated += 1
        for row in pending:
            if self.get_pending(row["credential"]) is None:
                self.set_pending(row["credential"], Secret(row["value"]))
        with connect(self.path) as connection:
            from credarr.transaction import transaction

            with transaction(connection):
                if has_working:
                    connection.execute("DELETE FROM working_copies")
                if has_pending:
                    connection.execute("DELETE FROM pending_secrets")
        if working or pending:
            self._scrub()
            with connect(self.path) as connection:
                connection.execute(
                    "INSERT INTO events "
                    "(at, kind, credential, previous_status, status, detail, origin, data) "
                    "VALUES (?, 'vault.migrated', NULL, NULL, NULL, ?, 'auto', ?)",
                    (
                        time.time(),
                        f"migrated {len(working)} stored values and "
                        f"{len(pending)} pending values into encrypted versions",
                        event_schema.encode(
                            {"working_copies": len(working), "pending": len(pending)}
                        ),
                    ),
                )
        if migrated:
            self.maintenance()


class VaultMaintenanceLoop:
    """The hourly retention sweep: abandoned versions and expired tombstones."""

    def __init__(self, vault: VaultStore, *, interval: float = 3600.0) -> None:
        import threading

        self.vault = vault
        self.interval = interval
        self.failure: str | None = None
        self.last_result: dict[str, int] | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="credarr-vault-maintenance", daemon=True
        )

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
                self.last_result = self.vault.maintenance()
                self._stop.wait(self.interval)
        except Exception as exc:
            self.failure = f"{type(exc).__name__}: {exc}"


def _version_from_row(row: Any) -> SecretVersion:
    return SecretVersion(
        id=row["id"],
        credential=row["credential"],
        stage=row["stage"],
        attempt_id=row["attempt_id"],
        verification=row["verification"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        actor=row["actor"],
        origin=row["origin"],
    )
