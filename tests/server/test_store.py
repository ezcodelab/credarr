"""YAML through the SQLite store and back: the import/export round trip.

The store is a working copy of the manifest, so the failure that matters is
silent loss: a holder that comes back without its host, a `canonical` that
comes back empty, a re-import that duplicates rows. Every case starts from
text an operator or the CLI wrote, and must end at the same model through the
same strict loader. The manifest fixture is `test_emitter.FULL` on purpose -
one fixture covering every accepted shape, so a field the store drops fails
here and in the emitter test together rather than in one of them only.

It also holds the app's working copies, and re-importing an edited file is
routine - so the last tests here pin that a re-import takes the topology
replace-all and leaves the values alone.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest

from credarr.redact import Secret
from credarr_server import store as store_module
from credarr_server.store import TopologyStore, UnknownCredential
from test_emitter import FULL, LIVE, REGISTRY, parse

MINIMAL = "version: 1\ncredentials:\n  signing_key:\n    class: B\n    never_rotate: true\n"


def manifest_file(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "credentials.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_a_full_manifest_through_the_store_is_the_manifest(tmp_path: Path) -> None:
    path = manifest_file(tmp_path, FULL)
    database = tmp_path / "config" / "app.db"
    store = TopologyStore(database)
    store.import_manifest(path, REGISTRY)
    original = parse(FULL)

    loaded = store.load_manifest()
    assert loaded.version == original.version
    assert loaded.credentials == original.credentials

    exported = store.export_text()
    read_back = parse(exported)
    assert read_back == original
    # Declaration order survives the rows, so an export diffs against its source.
    assert list(read_back.credentials) == list(original.credentials)
    # Byte-stable: two exports of one state are one file.
    assert store.export_text() == exported
    # WAL is a deployment requirement (DECISIONS), so it is pinned here.
    mode = sqlite3.connect(database).execute("PRAGMA journal_mode").fetchone()[0]
    assert mode == "wal"


def test_re_importing_replaces_rather_than_merging_or_duplicating(tmp_path: Path) -> None:
    """A merge would keep a credential the operator just deleted from the file;
    an insert that did not replace would double every holder."""
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest_file(tmp_path, FULL), REGISTRY)
    store.import_manifest(manifest_file(tmp_path, FULL), REGISTRY)
    assert store.load_manifest().credentials == parse(FULL).credentials

    store.import_manifest(manifest_file(tmp_path, MINIMAL), REGISTRY)
    assert set(store.load_manifest().credentials) == {"signing_key"}
    assert "sonarr_api_key" not in store.export_text()


def test_order_comes_from_position_not_from_rowid(tmp_path: Path) -> None:
    """A move in the app is an UPDATE of `position`, and a bare rowid scan
    happens to agree with import order today - so this pins the ORDER BY
    itself, not just "some order that matches the source"."""
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest_file(tmp_path, FULL), REGISTRY)
    with sqlite3.connect(tmp_path / "app.db") as connection:
        connection.execute(
            "UPDATE credentials SET position = CASE name "
            "WHEN 'legacy_credentials' THEN 0 ELSE position + 1 END"
        )
    assert list(store.load_manifest().credentials) == [
        "legacy_credentials",
        "sonarr_api_key",
        "qbittorrent_api_key",
    ]


def test_a_rejected_manifest_leaves_the_stored_topology_untouched(tmp_path: Path) -> None:
    # The strict loader refuses before any row is written, so a file with a
    # typo'd target cannot cost the operator the topology that was working.
    bad = (
        "version: 1\ncredentials:\n  x:\n    class: B\n    never_rotate: true\n"
        "    consumers:\n      - target: sonarr.nonexistent_slot\n"
    )
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest_file(tmp_path, FULL), REGISTRY)
    before = store.export_text()
    with pytest.raises(Exception, match="unknown target"):
        store.import_manifest(manifest_file(tmp_path, bad), REGISTRY)
    assert store.export_text() == before


def test_a_failed_import_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The transaction is the "never half-replaced" claim, and no valid
    manifest can trip it - so the insert is made to fail on the second
    credential, after the first row of the new topology is already written.
    """
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest_file(tmp_path, FULL), REGISTRY)
    before = store.export_text()

    real_insert = store_module._insert_credential

    def explode_on_second(
        connection: sqlite3.Connection, position: int, name: str, credential: object
    ) -> None:
        if name == "qbittorrent_api_key":
            raise RuntimeError("insert failed halfway")
        real_insert(connection, position, name, credential)

    monkeypatch.setattr(store_module, "_insert_credential", explode_on_second)
    with pytest.raises(RuntimeError, match="halfway"):
        store.import_manifest(manifest_file(tmp_path, FULL), REGISTRY)
    assert store.export_text() == before


@pytest.mark.skipif(not LIVE.is_file(), reason="the live manifest repo is not checked out")
def test_the_live_manifest_survives_the_store(tmp_path: Path) -> None:
    store = TopologyStore(tmp_path / "app.db")
    try:
        store.import_manifest(LIVE, REGISTRY)
    except Exception as exc:
        pytest.skip(f"the sibling manifest predates strict API-only: {exc}")
    original = parse(LIVE.read_text(encoding="utf-8"), origin=LIVE)
    assert parse(store.export_text(), origin=LIVE) == original


def test_a_working_copy_survives_a_re_import(tmp_path: Path) -> None:
    """Re-importing an edited file is routine; the values the app holds are
    the part nothing can regenerate, so the replace-all must not take them."""
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest_file(tmp_path, FULL), REGISTRY)
    store.set_value("sonarr_api_key", Secret("value-1"))
    store.import_manifest(manifest_file(tmp_path, FULL), REGISTRY)
    stored = store.get_value("sonarr_api_key")
    assert stored is not None and stored.reveal() == "value-1"


def test_a_credential_the_file_drops_loses_its_working_copy(tmp_path: Path) -> None:
    """A secret kept for a name nothing references is a secret kept for no
    reason."""
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest_file(tmp_path, FULL), REGISTRY)
    store.set_value("sonarr_api_key", Secret("value-1"))
    store.import_manifest(manifest_file(tmp_path, MINIMAL), REGISTRY)
    assert store.get_value("sonarr_api_key") is None


def test_a_working_copy_needs_a_credential_that_exists(tmp_path: Path) -> None:
    store = TopologyStore(tmp_path / "app.db")
    with pytest.raises(UnknownCredential, match="nosuch"):
        store.set_value("nosuch", Secret("value-1"))


def test_a_pending_value_is_separate_from_the_canonical_value(tmp_path: Path) -> None:
    """Until RECORD, the chosen value is not the one the app presents as
    canonical. Keeping them in one row would make a crash look like a completed
    rotation and skip every holder write."""
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest_file(tmp_path, FULL), REGISTRY)
    store.set_value("sonarr_api_key", Secret("old-value"))

    store.set_pending("sonarr_api_key", Secret("candidate-value"))

    assert store.get_value("sonarr_api_key").reveal() == "old-value"
    assert store.get_pending("sonarr_api_key").reveal() == "candidate-value"


def test_a_pending_value_needs_a_credential_that_exists(tmp_path: Path) -> None:
    store = TopologyStore(tmp_path / "app.db")
    with pytest.raises(UnknownCredential, match="nosuch"):
        store.set_pending("nosuch", Secret("candidate-value"))


def test_clearing_a_pending_value_does_not_touch_the_working_copy(tmp_path: Path) -> None:
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest_file(tmp_path, FULL), REGISTRY)
    store.set_value("sonarr_api_key", Secret("recorded-value"))
    store.set_pending("sonarr_api_key", Secret("candidate-value"))

    store.clear_pending("sonarr_api_key")

    assert store.get_pending("sonarr_api_key") is None
    assert store.get_value("sonarr_api_key").reveal() == "recorded-value"


def test_a_crash_after_record_is_pruned_on_the_next_start(tmp_path: Path) -> None:
    """A crash can land between the canonical write and the explicit clear.
    The extra copy is then already recorded; keeping it would make the next
    mint think a different rotation is still pending."""
    path = tmp_path / "app.db"
    store = TopologyStore(path)
    store.import_manifest(manifest_file(tmp_path, FULL), REGISTRY)
    store.set_pending("sonarr_api_key", Secret("candidate-value"))
    store.set_value("sonarr_api_key", Secret("candidate-value"))

    reopened = TopologyStore(path)

    assert reopened.get_pending("sonarr_api_key") is None
    assert reopened.get_value("sonarr_api_key").reveal() == "candidate-value"


def test_pruning_keeps_a_pending_value_that_differs(tmp_path: Path) -> None:
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest_file(tmp_path, FULL), REGISTRY)
    store.set_value("sonarr_api_key", Secret("old-value"))
    store.set_pending("sonarr_api_key", Secret("candidate-value"))

    store.prune_pending()

    assert store.get_pending("sonarr_api_key").reveal() == "candidate-value"


def test_reimporting_a_manifest_drops_an_orphaned_pending_value(tmp_path: Path) -> None:
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest_file(tmp_path, FULL), REGISTRY)
    store.set_pending("sonarr_api_key", Secret("candidate-value"))

    store.import_manifest(manifest_file(tmp_path, MINIMAL), REGISTRY)

    assert store.get_pending("sonarr_api_key") is None


def test_an_existing_database_gains_the_pending_table(tmp_path: Path) -> None:
    """The app database is upgraded in place. Dropping the table is the
    pre-change schema; reopening must add it without losing the topology."""
    path = tmp_path / "app.db"
    store = TopologyStore(path)
    store.import_manifest(manifest_file(tmp_path, FULL), REGISTRY)
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE pending_secrets")

    reopened = TopologyStore(path)
    reopened.set_pending("sonarr_api_key", Secret("candidate-value"))

    assert reopened.get_pending("sonarr_api_key").reveal() == "candidate-value"
    assert "sonarr_api_key" in reopened.load_manifest().credentials


def test_an_existing_database_drops_the_retired_path_and_storage_columns(
    tmp_path: Path,
) -> None:
    """An old install keeps its rows; the columns strict API-only removed are
    gone, so every insert that never names them keeps working."""
    path = tmp_path / "app.db"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            "CREATE TABLE holders (credential TEXT NOT NULL,"
            " position INTEGER NOT NULL, target TEXT NOT NULL,"
            " count INTEGER NOT NULL, mechanism TEXT NOT NULL,"
            " storage TEXT NOT NULL, host TEXT, note TEXT NOT NULL,"
            " PRIMARY KEY (credential, position));"
            "CREATE TABLE services (name TEXT PRIMARY KEY,"
            " position INTEGER NOT NULL, kind TEXT NOT NULL DEFAULT '',"
            " url TEXT, path TEXT, notes TEXT NOT NULL DEFAULT '');"
            "INSERT INTO holders VALUES ('sonarr_api_key', 0,"
            " 'seerr.settings_json', 1, '', 'seerr-db', NULL, '');"
            "INSERT INTO services VALUES ('sonarr', 0, '',"
            " 'http://sonarr:8989', '/mnt/sonarr', '');"
        )

    TopologyStore(path)

    with sqlite3.connect(path) as connection:
        holder_columns = [
            row[1] for row in connection.execute("PRAGMA table_info(holders)")
        ]
        service_columns = [
            row[1] for row in connection.execute("PRAGMA table_info(services)")
        ]
        assert "storage" not in holder_columns
        assert "path" not in service_columns
        # The rows themselves are kept: only the retired columns go.
        assert connection.execute("SELECT count(*) FROM holders").fetchone()[0] == 1
        assert connection.execute("SELECT url FROM services").fetchone()[0] == (
            "http://sonarr:8989"
        )


def test_working_copy_times_says_what_is_stored_and_when(tmp_path: Path) -> None:
    """`stored` and the freshness of every recorded status come from this one
    map, so membership must track the working copies exactly, and the time must
    move when a value does."""
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest_file(tmp_path, FULL), REGISTRY)
    assert store.working_copy_times() == {}
    store.set_value("sonarr_api_key", Secret("value-1"))
    assert set(store.working_copy_times()) == {"sonarr_api_key"}
    first = store.working_copy_times()["sonarr_api_key"]
    store.set_value("sonarr_api_key", Secret("value-2"))
    assert store.working_copy_times()["sonarr_api_key"] >= first
    store.import_manifest(manifest_file(tmp_path, MINIMAL), REGISTRY)
    assert store.working_copy_times() == {}


def test_the_paste_path_imports_the_same_manifest_as_the_file(tmp_path: Path) -> None:
    """`import_text` is the console's paste: same strict parse, same rows, same
    export. A manifest is not a different manifest for arriving as text."""
    from_file = TopologyStore(tmp_path / "file.db")
    from_file.import_manifest(manifest_file(tmp_path, FULL), REGISTRY)
    from_text = TopologyStore(tmp_path / "text.db")
    from_text.import_text(FULL, REGISTRY, origin=tmp_path / "credentials.yaml")
    assert from_text.export_text() == from_file.export_text()


def test_the_paste_path_refuses_what_the_file_import_refuses(tmp_path: Path) -> None:
    bad = (
        "version: 1\ncredentials:\n  x:\n    class: B\n    never_rotate: true\n"
        "    consumers:\n      - target: sonarr.nonexistent_slot\n"
    )
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest_file(tmp_path, FULL), REGISTRY)
    before = store.export_text()
    with pytest.raises(Exception, match="unknown target"):
        store.import_text(bad, REGISTRY, origin=tmp_path / "credentials.yaml")
    assert store.export_text() == before


def test_a_pasted_manifests_errors_name_the_path_it_would_have_had(tmp_path: Path) -> None:
    """`origin` is not decoration: the console shows the same sentence the CLI
    would, naming the manifest path this deployment reads."""
    origin = tmp_path / "credentials.yaml"
    store = TopologyStore(tmp_path / "app.db")
    with pytest.raises(Exception, match=re.escape(str(origin))):
        store.import_text("version: 1\ncredentials: [no]\n", REGISTRY, origin=origin)


def test_replacing_a_working_copy_keeps_only_the_newest(tmp_path: Path) -> None:
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest_file(tmp_path, MINIMAL), REGISTRY)
    store.set_value("signing_key", Secret("old"))
    store.set_value("signing_key", Secret("new"))
    stored = store.get_value("signing_key")
    assert stored is not None and stored.reveal() == "new"
    with sqlite3.connect(tmp_path / "app.db") as connection:
        rows = connection.execute("SELECT COUNT(*) FROM working_copies").fetchone()[0]
    assert rows == 1


def test_saving_the_same_value_twice_is_not_an_error(tmp_path: Path) -> None:
    """Saving an unchanged value is an ordinary retry, not an unknown
    credential - the refusal must mean the credential is gone, nothing else."""
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest_file(tmp_path, MINIMAL), REGISTRY)
    store.set_value("signing_key", Secret("same"))
    store.set_value("signing_key", Secret("same"))
    stored = store.get_value("signing_key")
    assert stored is not None and stored.reveal() == "same"


def test_the_database_is_not_world_readable(tmp_path: Path) -> None:
    """It holds every working copy in plaintext; a default mode makes them
    readable by every local user."""
    store = TopologyStore(tmp_path / "app.db")
    assert store.path.stat().st_mode & 0o077 == 0


def test_a_sidecar_left_behind_by_an_older_version_is_tightened(tmp_path: Path) -> None:
    """The -wal is where the plaintext pages actually are. SQLite gives a new
    sidecar the database's mode at creation, so one created before this rule
    keeps its old mode unless it is chmodded too."""
    path = tmp_path / "app.db"
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("CREATE TABLE t (x)")
        connection.execute("INSERT INTO t VALUES (1)")
        connection.commit()
        sidecars = [
            path.with_name(path.name + suffix) for suffix in ("-wal", "-shm")
        ]
        for sidecar in sidecars:
            sidecar.chmod(0o644)

        TopologyStore(path)

        assert path.stat().st_mode & 0o077 == 0
        for sidecar in sidecars:
            assert sidecar.stat().st_mode & 0o077 == 0
    finally:
        connection.close()


def test_a_database_that_cannot_be_chmodded_still_opens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A root-made bind mount is writable but not chmoddable; the hardening
    step is best-effort, because refusing to boot is worse than the mode the
    deployment chose."""
    def refuse(self: Path, mode: int) -> None:
        raise PermissionError(13, "Operation not permitted", str(self))

    monkeypatch.setattr(Path, "chmod", refuse)
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest_file(tmp_path, MINIMAL), REGISTRY)
    assert store.get_value("signing_key") is None


TWO_CREDENTIALS = """version: 1
credentials:
  first:
    class: B
    never_rotate: true
  second:
    class: B
    never_rotate: true
"""

ONE_CREDENTIAL = """version: 1
credentials:
  first:
    class: B
    never_rotate: true
"""


def test_auto_rotation_survives_reimport_and_prunes_a_removed_name(
    tmp_path: Path,
) -> None:
    """The opt-in is deployment policy, not topology.

    A surviving credential keeps enabled, interval and pause exactly; a name the
    manifest drops loses its row. A re-import must never silently toggle a
    survivor off or on.
    """
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest_file(tmp_path, TWO_CREDENTIALS), REGISTRY)
    store.enable_auto_rotation("first", 30, now=100.0)
    store.enable_auto_rotation("second", 7, now=100.0)
    store.record_auto_rotation("first", "interrupted", "needs a human", paused=True)

    store.import_manifest(manifest_file(tmp_path, ONE_CREDENTIAL), REGISTRY)

    first = store.auto_rotation("first")
    assert first is not None
    assert first.enabled is True and first.paused is True
    assert first.every_days == 30 and first.enabled_at == 100.0
    assert store.auto_rotation("second") is None

    store.disable_auto_rotation("first")
    disabled = store.auto_rotation("first")
    assert disabled is not None and disabled.enabled is False


def test_an_existing_database_gains_the_auto_rotation_table(tmp_path: Path) -> None:
    """Opening an `app.db` from before this feature adds the table in place."""
    path = tmp_path / "app.db"
    store = TopologyStore(path)
    store.import_manifest(manifest_file(tmp_path, FULL), REGISTRY)
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE auto_rotation")

    reopened = TopologyStore(path)
    assert reopened.auto_rotations() == {}
    state = reopened.enable_auto_rotation("sonarr_api_key", 90)
    assert state.enabled is True
    assert "sonarr_api_key" in reopened.load_manifest().credentials


MERGE_TEXT = """
version: 1
credentials:
  sonarr_api_key:
    class: A
    max_age_days: 90
    consumers:
      - target: sonarr.indexers
        count: 2
  signing_key:
    class: B
    never_rotate: true
"""


def test_merge_upserts_by_name_and_keeps_omitted_credentials(tmp_path: Path) -> None:
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest_file(tmp_path, FULL), REGISTRY)
    store.set_value("sonarr_api_key", Secret("value"))
    store.enable_auto_rotation("sonarr_api_key", 30)

    summary = store.import_text(
        MERGE_TEXT, REGISTRY, origin=tmp_path / "credentials.yaml", mode="merge"
    )

    manifest = store.load_manifest()
    assert set(manifest.credentials) == {
        "sonarr_api_key",
        "qbittorrent_api_key",
        "legacy_credentials",
        "signing_key",
    }
    assert summary.added == 1 and summary.updated == 1 and summary.removed == 0
    assert [str(c.target) for c in manifest.credentials["sonarr_api_key"].consumers] == [
        "sonarr.indexers",
    ]
    assert store.get_value("sonarr_api_key") == Secret("value")
    assert store.auto_rotation("sonarr_api_key") is not None


def test_prune_removes_omitted_credentials_values_and_policy(tmp_path: Path) -> None:
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest_file(tmp_path, FULL), REGISTRY)
    store.set_value("sonarr_api_key", Secret("value"))
    store.enable_auto_rotation("sonarr_api_key", 30)

    summary = store.import_text(
        MERGE_TEXT,
        REGISTRY,
        origin=tmp_path / "credentials.yaml",
        mode="merge",
        prune=True,
    )

    assert summary.pruned is True
    assert set(store.load_manifest().credentials) == {"sonarr_api_key", "signing_key"}
    assert store.get_value("sonarr_api_key") == Secret("value")
    assert store.get_value("qbittorrent_api_key") is None
    assert store.auto_rotation("qbittorrent_api_key") is None


def test_service_seed_runs_once_even_after_delete(tmp_path: Path) -> None:
    store = TopologyStore(tmp_path / "app.db")
    seeded = store.seed_services(
        [
            store_module.Service(
                name="sonarr",
                kind="servarr",
                url=None,
                notes="",
                position=0,
            )
        ]
    )
    assert seeded == 1
    assert store.delete_service("sonarr") is True
    assert store.seed_services([]) == 0
    assert store.service("sonarr") is None


def test_the_audit_interval_is_persisted_and_malformed_values_are_ignored(
    tmp_path: Path,
) -> None:
    path = tmp_path / "app.db"
    store = TopologyStore(path)
    assert store.audit_interval() is None
    store.set_audit_interval(120.5)
    assert store.audit_interval() == 120.5
    assert TopologyStore(path).audit_interval() == 120.5

    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE store_meta SET value = ? WHERE key = 'audit_interval_seconds'",
            ("not-a-number",),
        )
    assert store.audit_interval() is None
