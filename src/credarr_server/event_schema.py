"""The durable event ledger: one table every producer and reader shares.

Events are the product's public record that something changed. They carry
identities, verdict codes, timestamps and a scrubbed sentence - never a value,
a value fragment, or a fingerprint. The shape lives here rather than in the
audit log because credential lifecycle and sync producers write the same table;
a second definition is how a column silently diverges.

`origin` says who caused the event (`cli`, `user`, `auto`, `hook`). Sinks
exclude `hook` by default so a hook that reacts to an event cannot feed its
own reaction back into the delivery loop. `data` is a small JSON object for
kind-specific identifiers; its keys are pinned by the notifier payload tests.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    at              REAL    NOT NULL,
    kind            TEXT    NOT NULL,
    credential      TEXT,
    previous_status TEXT,
    status          TEXT,
    detail          TEXT    NOT NULL,
    sink            TEXT,
    origin          TEXT    NOT NULL DEFAULT 'auto',
    data            TEXT    NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS events_credential_id ON events (credential, id);
CREATE INDEX IF NOT EXISTS events_kind_id ON events (kind, id);
"""

_COLUMNS = (
    ("origin", "TEXT NOT NULL DEFAULT 'auto'"),
    ("data", "TEXT NOT NULL DEFAULT '{}'"),
)


def ensure(connection: sqlite3.Connection) -> None:
    """Add the lifecycle columns to a ledger written by an earlier build."""
    columns = {row[1] for row in connection.execute("PRAGMA table_info(events)")}
    for name, definition in _COLUMNS:
        if name not in columns:
            connection.execute(f"ALTER TABLE events ADD COLUMN {name} {definition}")


def encode(data: dict[str, Any] | None) -> str:
    """A bounded JSON object: identifiers and booleans, never a value."""
    if not data:
        return "{}"
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def decode(text: str | None) -> dict[str, Any]:
    if not text:
        return {}
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}
