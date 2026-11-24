"""One database file, one way to open it.

Every table in `/config/app.db` shares the same WAL mode, the same private file
mode, the same row factory and the same foreign-key pragma. Keeping those in
one module is what stops a new subsystem from opening a second, subtly
different connection - the kind that forgets `foreign_keys = ON` and leaves
deleted topology behind.

`TopologyStore` still exposes `connect` and `initialise` for its callers; this
module is where they live, not a second contract.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
from collections.abc import Iterator
from pathlib import Path

from credarr.journal import init_lock_for


def database_files(path: Path) -> tuple[Path, ...]:
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
    hold every encrypted value and its metadata. The chmod is best-effort: a
    file the process does not own (a root-made bind mount) is still writable,
    and refusing to boot over a hardening step is worse than the mode the
    deployment chose.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    # Create the file private before SQLite opens it. A default 0644 window is
    # enough for another local user to read every row. O_EXCL keeps a
    # concurrent creator from making this open follow a path swapped underneath.
    with contextlib.suppress(FileExistsError):
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(descriptor)
    with init_lock_for(path):
        for database_file in database_files(path):
            with contextlib.suppress(OSError):
                database_file.chmod(0o600)
        connection = sqlite3.connect(path, timeout=15)
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(schema)
            # WAL and shared-memory files are created by the pragma/schema.
            for database_file in database_files(path):
                with contextlib.suppress(OSError):
                    database_file.chmod(0o600)
        finally:
            connection.close()


@contextlib.contextmanager
def connect(path: Path) -> Iterator[sqlite3.Connection]:
    """One connection for one call, closed on the way out."""
    connection = sqlite3.connect(path, timeout=15, isolation_level=None)
    connection.row_factory = sqlite3.Row
    try:
        # Per connection, not per database: SQLite defaults foreign keys off.
        connection.execute("PRAGMA foreign_keys = ON")
        # Deleted rows are overwritten rather than left in free pages. The
        # encrypted store deletes rows on retention expiry, and a page from a
        # removed ciphertext should not stay readable.
        connection.execute("PRAGMA secure_delete = ON")
        yield connection
    finally:
        connection.close()
