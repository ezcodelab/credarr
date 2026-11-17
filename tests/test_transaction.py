"""One transaction helper: rollback on BaseException, not just Exception.

Every write in this tree used to spell out `BEGIN IMMEDIATE` / `COMMIT` /
`ROLLBACK` by hand, fifteen times, and the copies disagreed about what an
interruption is: the journal's lock acquisition caught `Exception`, so a
Ctrl-C during the insert skipped its rollback. These tests pin both halves of
the helper - the rollback that always happens, and the source scan that keeps
the next hand-rolled copy out.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest

from credarr.transaction import transaction

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
HELPER = SRC / "credarr" / "transaction.py"

# A transaction statement handed to sqlite, wherever it is spelled out.
# `executescript` takes a whole SQL document; lowercase is still the same
# statement; a string prefix (`f"..."`) must not hide it from the scan.
STATEMENT = re.compile(
    r"""\.(?:execute|executescript)\(\s*[frbu]{0,2}(['"])\s*(BEGIN|COMMIT|ROLLBACK)\b""",
    re.IGNORECASE,
)


def database() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("CREATE TABLE rows (value TEXT)")
    return connection


def values(connection: sqlite3.Connection) -> list[str]:
    return [
        row["value"]
        for row in connection.execute("SELECT value FROM rows ORDER BY value")
    ]


def test_a_normal_exit_commits() -> None:
    connection = database()
    with transaction(connection):
        connection.execute("INSERT INTO rows VALUES ('kept')")
    assert values(connection) == ["kept"]
    assert connection.in_transaction is False


def test_an_exception_rolls_back_and_propagates() -> None:
    connection = database()
    with pytest.raises(ValueError), transaction(connection):
        connection.execute("INSERT INTO rows VALUES ('dropped')")
        raise ValueError("the step failed")
    assert values(connection) == []
    assert connection.in_transaction is False


def test_a_keyboard_interrupt_rolls_back_and_propagates() -> None:
    """BaseException, not Exception: Ctrl-C is the case the old copies missed."""
    connection = database()
    with pytest.raises(KeyboardInterrupt), transaction(connection):
        connection.execute("INSERT INTO rows VALUES ('dropped')")
        raise KeyboardInterrupt
    assert values(connection) == []
    assert connection.in_transaction is False


def test_the_write_lock_is_taken_at_entry(tmp_path: Path) -> None:
    """A deferred BEGIN would leave this second writer free to start."""
    path = tmp_path / "transaction.db"
    first = sqlite3.connect(path, timeout=0, isolation_level=None)
    second = sqlite3.connect(path, timeout=0, isolation_level=None)
    try:
        with transaction(first), pytest.raises(sqlite3.OperationalError):
            second.execute("BEGIN IMMEDIATE")
    finally:
        first.close()
        second.close()


def statements(source: str) -> list[str]:
    """The transaction keywords a source string spells out, in order."""
    return [match.group(2).upper() for match in STATEMENT.finditer(source)]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ('.execute("BEGIN IMMEDIATE")', ["BEGIN"]),
        (".executescript('BEGIN')", ["BEGIN"]),
        ('.execute("begin immediate")', ["BEGIN"]),
        ('.execute(f"ROLLBACK")', ["ROLLBACK"]),
        ('.execute("  commit  ")', ["COMMIT"]),
        ('.execute("SELECT 1")', []),
        ('.execute("BEGINNING")', []),
    ],
)
def test_the_scan_catches_every_spelling(source: str, expected: list[str]) -> None:
    """The scan is the ratchet: prove it on the spellings a hand copy uses."""
    assert statements(source) == expected


def test_transaction_statements_live_in_one_place() -> None:
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        if path == HELPER or "__pycache__" in path.parts:
            continue
        for keyword in statements(path.read_text(encoding="utf-8")):
            offenders.append(f"{path.relative_to(ROOT)}:{keyword}")
    assert not offenders, (
        "hand-rolled transactions (use credarr.transaction.transaction): "
        + repr(offenders)
    )
