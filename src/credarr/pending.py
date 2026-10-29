"""The chosen value an API-only mint must not lose.

A Servarr cannot return a reset key, so the mint reads `config.xml` out of a
temporary backup over the API: choose the new key here, persist it, then write
it into the service's config through a config-only restore and restart. The
persisted value is the difference between a crash after the restart (the service
is on the new key, credarr still holds the old one in its store) and a rotation
nobody can finish from the service's own answers.

It is a separate table/file from the canonical store because it is not canonical
yet: RECORD is still the only step that moves the vault/store value. The value
lives beside the journal, is written before the first mutation, and is removed
at RECORD. It is plaintext at rest exactly like the working copy; the file is
0600 and the app database already is.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Protocol

from .redact import Secret


class PendingSecrets(Protocol):
    """Where a backup/restore mint parks the value it chose but has not recorded."""

    def get(self, credential: str) -> Secret | None: ...

    def set(self, credential: str, value: Secret) -> None: ...

    def clear(self, credential: str) -> None: ...


SCHEMA = """
CREATE TABLE IF NOT EXISTS pending_secrets (
    credential TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    created_at REAL NOT NULL
);
"""


def _sidecars(path: Path) -> tuple[Path, ...]:
    return (
        path,
        *(path.with_name(path.name + suffix) for suffix in ("-wal", "-shm", "-journal")),
    )


class FilePending:
    """The CLI's pending store, beside the rotation journal.

    The CLI's canonical copy is a vault, not the server's app database. The
    pending value needs the same crash durability, so it gets its own small
    SQLite file in the state directory the journal already owns.

    A dry run never writes, so construction is lazy: the file appears only when
    an API-only mint actually starts.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    @contextlib.contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Create it private before SQLite opens it; a default 0644 window is
        # enough for another local user to read a credential.
        if not self.path.exists():
            descriptor = os.open(
                self.path, os.O_CREAT | os.O_RDWR, 0o600
            )
            os.close(descriptor)
        connection = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(SCHEMA)
            # The sidecars are created by the pragma/schema, so chmod after.
            # Repeated every time, because the file holds a credential until
            # RECORD and an old copy may have the wrong mode.
            for database_file in _sidecars(self.path):
                with contextlib.suppress(OSError):
                    database_file.chmod(0o600)
            yield connection
        finally:
            connection.close()

    def get(self, credential: str) -> Secret | None:
        if not self.path.exists():
            return None
        with self._connect() as connection:
            row = connection.execute(
                "SELECT value FROM pending_secrets WHERE credential = ?",
                (credential,),
            ).fetchone()
        return Secret(row[0]) if row else None

    def set(self, credential: str, value: Secret) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO pending_secrets (credential, value, created_at) "
                "VALUES (?, ?, ?) ON CONFLICT(credential) DO UPDATE SET "
                "value = excluded.value, created_at = excluded.created_at",
                (credential, value.reveal(), time.time()),
            )

    def clear(self, credential: str) -> None:
        if not self.path.exists():
            return
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM pending_secrets WHERE credential = ?", (credential,)
            )
