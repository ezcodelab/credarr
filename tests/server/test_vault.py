"""The encrypted version store, its barriers and its refusals.

These tests drive the real SQLite file and the real HTTP surface. They pin the
properties that would be silent data loss if they drifted: AAD binds a value to
its row, a missing KEK refuses every value operation, a stage transition is a
new ciphertext, and one committed change produces one event and one outbox row.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from conftest import make_server, setup_admin
from credarr.redact import Secret
from credarr.targets import build_registry
from credarr_server.store import TopologyStore
from credarr_server.vault import (
    ABANDONED,
    CURRENT,
    PREVIOUS,
    CredentialTombstoned,
    KekUnavailable,
    VaultStore,
    VaultTree,
)

REGISTRY = build_registry()
MANIFEST = """version: 1
credentials:
  sonarr_api_key:
    class: A
    max_age_days: 90
    consumers:
      - target: seerr.settings_json[sonarr]
        count: 1
        mechanism: process_api
"""


def _store(tmp_path: Path) -> TopologyStore:
    manifest = tmp_path / "credentials.yaml"
    manifest.write_text(MANIFEST, encoding="utf-8")
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest, REGISTRY)
    return store


def _db(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def test_a_missing_kek_refuses_value_operations_and_reads_metadata(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    store.set_value("sonarr_api_key", Secret("the-current-value"))
    (tmp_path / "kek.json").unlink()

    reopened = TopologyStore(tmp_path / "app.db")
    with pytest.raises(KekUnavailable, match="missing"):
        reopened.get_value("sonarr_api_key")
    with pytest.raises(KekUnavailable, match="missing"):
        reopened.set_value("sonarr_api_key", Secret("another"))
    # Metadata is how an operator sees what is waiting for the missing key.
    assert set(reopened.working_copy_times()) == {"sonarr_api_key"}
    assert reopened.vault.current_version("sonarr_api_key") is not None
    assert reopened.vault.key_status()["available"] is False


def test_aad_binds_the_ciphertext_to_its_row_and_stage(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.set_value("sonarr_api_key", Secret("value-bound-to-current"))
    with _db(tmp_path / "app.db") as connection:
        row = connection.execute(
            "SELECT * FROM secret_versions WHERE stage = 'CURRENT'"
        ).fetchone()
        connection.execute(
            "UPDATE secret_versions SET stage = 'PREVIOUS' WHERE id = ?", (row["id"],)
        )
    with pytest.raises(Exception, match="failed authentication"):
        store.vault.reveal("sonarr_api_key", PREVIOUS)


def test_a_stage_transition_is_a_new_ciphertext_under_new_aad(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.set_value("sonarr_api_key", Secret("first-value"))
    with _db(tmp_path / "app.db") as connection:
        first = connection.execute(
            "SELECT * FROM secret_versions WHERE stage = 'CURRENT'"
        ).fetchone()
    store.set_value("sonarr_api_key", Secret("second-value"))
    with _db(tmp_path / "app.db") as connection:
        previous = connection.execute(
            "SELECT * FROM secret_versions WHERE id = ?", (first["id"],)
        ).fetchone()
    assert previous["stage"] == PREVIOUS
    assert previous["ciphertext"] != first["ciphertext"]
    assert previous["wrapped_dek"] != first["wrapped_dek"]
    assert store.vault.reveal("sonarr_api_key", PREVIOUS).value.reveal() == "first-value"
    assert store.get_value("sonarr_api_key").reveal() == "second-value"


def test_one_commit_emits_one_current_event_and_one_outbox_row(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.set_value("sonarr_api_key", Secret("first-value"))
    store.set_value("sonarr_api_key", Secret("second-value"))
    with _db(tmp_path / "app.db") as connection:
        events = connection.execute(
            "SELECT * FROM events WHERE kind = 'secret.current_changed' ORDER BY id"
        ).fetchall()
        outbox = connection.execute(
            "SELECT * FROM sync_outbox ORDER BY id"
        ).fetchall()
        jobs = connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'sync_jobs'"
        ).fetchone()[0]
    assert len(events) == 2
    assert len(outbox) == 2
    assert [json.loads(row["data"])["version"] for row in events] == [
        outbox[0]["version_id"],
        outbox[1]["version_id"],
    ]
    assert all(row["dispatched_at"] is None for row in outbox)
    # No dispatcher has run, so no job exists yet; the outbox is the only
    # work row and it was written in the version transaction.
    assert jobs == 0


def test_soft_delete_refuses_value_reads_and_restore_returns_it(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.set_value("sonarr_api_key", Secret("still-there"))
    state = store.vault.tombstone(
        "sonarr_api_key", actor="admin", origin="user", reason="test"
    )
    assert state["purge_after"] > state["deleted_at"]
    with pytest.raises(CredentialTombstoned):
        store.get_value("sonarr_api_key")
    with pytest.raises(CredentialTombstoned):
        store.set_value("sonarr_api_key", Secret("blocked"))
    assert store.vault.restore("sonarr_api_key", actor="admin", origin="user") is True
    assert store.get_value("sonarr_api_key").reveal() == "still-there"


def test_reveal_is_audited_and_returns_no_store_headers(app, tmp_path) -> None:
    pasted = "reveal-me-0123456789"
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        assert client.put(
            "/api/v1/credentials/sonarr_api_key/value", json={"value": pasted}
        ).status_code == 200
        response = client.post(
            "/api/v1/credentials/sonarr_api_key/reveal", json={"stage": "CURRENT"}
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["value"] == pasted
        assert body["expires_in"] == 30
        assert response.headers["cache-control"].startswith("no-store")
        events = client.get("/api/v1/events").json()["events"]
    assert events[0]["kind"] == "secret.revealed"
    assert events[0]["credential"] == "sonarr_api_key"
    assert pasted not in json.dumps(events)


def test_the_strategy_view_does_not_claim_a_blocked_plan_is_rotatable(
    app, tmp_path
) -> None:
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        answer = client.get("/api/v1/credentials/sonarr_api_key/strategy")
    assert answer.status_code == 200, answer.text
    document = answer.json()
    assert document["credential"] == "sonarr_api_key"
    assert document["provenance"] == "measured"
    assert document["claimable"] is False
    assert document["blockers"]


def test_a_missing_kek_is_a_503_sentence_not_a_bare_500(app, tmp_path) -> None:
    (tmp_path / "kek.json").unlink()
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        response = client.post("/api/v1/credentials/sonarr_api_key/plan")
    assert response.status_code == 503
    assert "KEK" in response.json()["detail"]


def test_a_second_reveal_is_rate_limited(app, tmp_path) -> None:
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        first = client.post(
            "/api/v1/credentials/sonarr_api_key/reveal", json={"stage": "CURRENT"}
        )
        second = client.post(
            "/api/v1/credentials/sonarr_api_key/reveal", json={"stage": "CURRENT"}
        )
    assert first.status_code == 200
    assert second.status_code == 429


def test_kek_rotation_rewraps_every_version(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.set_value("sonarr_api_key", Secret("first-value"))
    store.set_value("sonarr_api_key", Secret("second-value"))
    old = store.vault.key_status()["active"]
    new = store.vault.rotate_kek()
    assert new != old
    assert store.get_value("sonarr_api_key").reveal() == "second-value"
    status = store.vault.key_status()
    assert status["active"] == new
    assert status["unwrapped"] == 0
    # The old key is retained for the values an older backup may still hold;
    # what changed is that no current row needs it.
    assert old in status["keys"]


def test_retention_purges_abandoned_versions_but_not_current(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.set_value("sonarr_api_key", Secret("first-value"))
    store.set_value("sonarr_api_key", Secret("second-value"))
    store.set_value("sonarr_api_key", Secret("third-value"))
    with _db(tmp_path / "app.db") as connection:
        # The two older versions are ABANDONED with a future purge_after.
        rows = connection.execute(
            "SELECT stage, purge_after FROM secret_versions ORDER BY created_at"
        ).fetchall()
    assert {row["stage"] for row in rows} == {ABANDONED, PREVIOUS, CURRENT}
    store.vault.maintenance(now=10**12)
    with _db(tmp_path / "app.db") as connection:
        remaining = connection.execute(
            "SELECT stage FROM secret_versions ORDER BY stage"
        ).fetchall()
    # PREVIOUS stays revealable; the unlabeled old version is the one that is
    # bounded by retention.
    assert sorted(row["stage"] for row in remaining) == [CURRENT, PREVIOUS]


def test_the_shared_tree_is_written_before_the_transaction_and_marked_after(
    tmp_path: Path,
) -> None:
    tree = VaultTree(tmp_path / "tree", tmp_path / "tree.key")
    store = _store(tmp_path)
    store.vault.tree = tree
    store.set_value("sonarr_api_key", Secret("tree-value-0123456789"))
    version = store.vault.current_version("sonarr_api_key")
    assert version is not None
    assert tree.verify("sonarr_api_key", version.id) == "tree-value-0123456789"
    marker = tree.read_marker("sonarr_api_key")
    assert marker is not None and marker["value_version"] == version.id

    # A crash after the sealed value is written and before the transaction
    # commits leaves the tree ahead of the marker; the agent refuses it.
    original = VaultStore._record_change

    def explode(*args, **kwargs):
        raise RuntimeError("the commit failed")

    VaultStore._record_change = explode
    try:
        with pytest.raises(RuntimeError, match="commit failed"):
            store.set_value("sonarr_api_key", Secret("uncommitted-value"))
    finally:
        VaultStore._record_change = original
    assert store.vault.current_version("sonarr_api_key").id == version.id
    assert tree.read_marker("sonarr_api_key")["value_version"] == version.id


def test_a_legacy_plaintext_working_copy_is_migrated_and_scrubbed(
    tmp_path: Path,
) -> None:
    database = tmp_path / "app.db"
    store = TopologyStore(database)
    manifest = tmp_path / "credentials.yaml"
    manifest.write_text(MANIFEST, encoding="utf-8")
    store.import_manifest(manifest, REGISTRY)
    # Simulate a database written by the previous build: the vault tables
    # exist, but the canonical row is still in `working_copies`.
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO working_copies (credential, value, updated_at) "
            "VALUES ('sonarr_api_key', 'legacy-plaintext-value', 1.0)"
        )
    reopened = TopologyStore(database)
    assert reopened.get_value("sonarr_api_key").reveal() == "legacy-plaintext-value"
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM working_copies"
        ).fetchone()[0] == 0
    assert b"legacy-plaintext-value" not in database.read_bytes()
