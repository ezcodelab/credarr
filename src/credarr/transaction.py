"""One way to open a write transaction.

SQLite is opened with `isolation_level=None` everywhere, so every write spells
out its own `BEGIN ... COMMIT/ROLLBACK`. Doing that by hand fifteen times
produced fifteen chances to disagree, and one did: a copy caught `Exception`
where the transaction needed `BaseException`, so Ctrl-C skipped the rollback
and left the resolution of the write to connection close.

`BEGIN IMMEDIATE` takes the write lock at entry. Every block here reads
something and then writes based on it - a lock to reclaim, a row to update, a
counter to increment - and a deferred transaction would upgrade after that
read, which in WAL mode can fail at the upgrade instead of at entry. The lock
is taken up front so a busy database is a wait, not a half-run block.

The rollback runs for `BaseException`: an interrupt, a `SystemExit`, and an
error all leave the same clean state. A raise still propagates, because
swallowing the reason a step died is how a rotation lies about being finished.
"""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Iterator


@contextlib.contextmanager
def transaction(connection: sqlite3.Connection) -> Iterator[None]:
    """Run the block as one write transaction, committing or rolling it back."""
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        connection.execute("ROLLBACK")
        raise
    else:
        connection.execute("COMMIT")
