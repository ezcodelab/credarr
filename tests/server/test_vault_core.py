"""The encrypted version store in isolation: AAD, KEK failure and retention.

This is the first layer of the lifecycle work. It exercises `VaultStore`
directly, before the topology store or the API is wired to it, so a crypto
regression fails here even if every caller is unchanged.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from credarr.redact import Secret
from credarr_server.vault import (
    ABANDONED,
    CURRENT,
    PREVIOUS,
    CredentialTombstoned,
    KekUnavailable,
    VaultStore,
)


def _db(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def test_a_value_is_encrypted_and_bound_to_its_aad(tmp_path: Path) -> None:
    vault = VaultStore(tmp_path / "app.db")
    vault.set_current(
        "sonarr_api_key",
        Secret("value-0123456789"),
        actor="test",
        origin="user",
    )
    assert vault.reveal("sonarr_api_key").value.reveal() == "value-0123456789"
    with _db(tmp_path / "app.db") as connection:
        row = connection.execute(
            "SELECT * FROM secret_versions WHERE stage = 'CURRENT'"
        ).fetchone()
        assert b"value-0123456789" not in (tmp_path / "app.db").read_bytes()
        connection.execute(
            "UPDATE secret_versions SET stage = 'PREVIOUS' WHERE id = ?", (row["id"],)
        )
    with pytest.raises(Exception, match="failed authentication"):
        vault.reveal("sonarr_api_key", PREVIOUS)


def test_a_stage_transition_is_a_new_ciphertext(tmp_path: Path) -> None:
    vault = VaultStore(tmp_path / "app.db")
    vault.set_current("key", Secret("first"), actor="test", origin="user")
    with _db(tmp_path / "app.db") as connection:
        first = connection.execute(
            "SELECT * FROM secret_versions WHERE stage = 'CURRENT'"
        ).fetchone()
    vault.set_current("key", Secret("second"), actor="test", origin="user")
    with _db(tmp_path / "app.db") as connection:
        previous = connection.execute(
            "SELECT * FROM secret_versions WHERE id = ?", (first["id"],)
        ).fetchone()
    assert previous["stage"] == PREVIOUS
    assert previous["ciphertext"] != first["ciphertext"]
    assert previous["wrapped_dek"] != first["wrapped_dek"]
    assert vault.reveal("key", PREVIOUS).value.reveal() == "first"
    assert vault.reveal("key").value.reveal() == "second"


def test_a_missing_kek_refuses_value_operations(tmp_path: Path) -> None:
    vault = VaultStore(tmp_path / "app.db")
    vault.set_current("key", Secret("value"), actor="test", origin="user")
    (tmp_path / "kek.json").unlink()
    reopened = VaultStore(tmp_path / "app.db")
    with pytest.raises(KekUnavailable, match="missing"):
        reopened.reveal("key")
    with pytest.raises(KekUnavailable, match="missing"):
        reopened.set_current("key", Secret("blocked"), actor="test", origin="user")
    assert reopened.current_version("key").stage == CURRENT


def test_soft_delete_refuses_reads_and_restore_returns_them(tmp_path: Path) -> None:
    vault = VaultStore(tmp_path / "app.db")
    vault.set_current("key", Secret("value"), actor="test", origin="user")
    vault.tombstone("key", actor="test", origin="user")
    with pytest.raises(CredentialTombstoned):
        vault.reveal("key")
    assert vault.restore("key", actor="test", origin="user") is True
    assert vault.reveal("key").value.reveal() == "value"


def test_kek_rotation_rewraps_every_version(tmp_path: Path) -> None:
    vault = VaultStore(tmp_path / "app.db")
    vault.set_current("key", Secret("first"), actor="test", origin="user")
    vault.set_current("key", Secret("second"), actor="test", origin="user")
    old = vault.key_status()["active"]
    new = vault.rotate_kek()
    assert new != old
    assert vault.reveal("key").value.reveal() == "second"
    assert vault.key_status()["unwrapped"] == 0
    assert old in vault.key_status()["keys"]


def test_retention_purges_abandoned_versions_not_previous(tmp_path: Path) -> None:
    vault = VaultStore(tmp_path / "app.db")
    for value in ("first", "second", "third"):
        vault.set_current("key", Secret(value), actor="test", origin="user")
    vault.maintenance(now=10**12)
    with _db(tmp_path / "app.db") as connection:
        stages = [
            row["stage"]
            for row in connection.execute("SELECT stage FROM secret_versions")
        ]
    assert ABANDONED not in stages
    assert set(stages) == {CURRENT, PREVIOUS}
