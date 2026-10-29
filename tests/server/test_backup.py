"""Backups: the file is a secret, and a restored app audits the same stack.

The drill is the point. Take a backup of a server that has a stored value, a
recorded drift, an event and a configured sink; wipe the data directory;
restore; boot the app again; sign in with the same password and get the same
verdicts. A backup nobody has restored is a hope, not a backup.
"""

from __future__ import annotations

import io
import json
import tarfile

import pytest
from fastapi.testclient import TestClient

from conftest import (
    PASSWORD,
    SONARR_KEY,
    make_server,
    refresh_csrf,
    server_config,
    setup_admin,
    wait_for_audit,
)
from credarr.redact import Secret
from credarr_server.app import ServerSettings, create_app
from credarr_server.audit_log import AuditLog
from credarr_server.backup import (
    CONFIG_PREFIX,
    DATABASE_NAME,
    MANIFEST_NAME,
    BackupError,
    _snapshot,
    encrypt,
    main,
    restore_backup,
    write_backup,
)
from credarr_server.notifier import Notifier

PASSPHRASE = "correct horse battery staple"


def test_the_backup_entry_point_disables_core_dumps_before_reading(
    monkeypatch,
) -> None:
    import credarr_server.backup as backup

    calls: list[str] = []
    monkeypatch.setattr(backup, "disable_core_dumps", lambda: calls.append("called"))
    with pytest.raises(SystemExit):
        backup.main([])
    assert calls == ["called"]


def _sealed_archive(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return encrypt(buffer.getvalue(), PASSPHRASE)


@pytest.mark.parametrize(
    "config_name",
    ["../creds.yaml", "/etc/passwd", "sub/creds.yaml", "..", ".", "", 7],
    ids=["parent", "absolute", "nested", "double-dot", "dot", "empty", "not-a-string"],
)
def test_a_backup_cannot_name_a_config_path_outside_the_data_directory(
    app, tmp_path, config_name
) -> None:
    """The archive's config name is data, not a path. Extraction is by exact
    member, and the name itself must be a bare file name."""
    database = _snapshot(app.store.path)
    entries = {
        DATABASE_NAME: database,
        MANIFEST_NAME: json.dumps(
            {"format": 1, "config_name": config_name}
        ).encode(),
    }
    payload = _sealed_archive(entries)
    archive = tmp_path / "hostile.credarr"
    archive.write_bytes(payload)
    destination = tmp_path / "restore-target"
    destination.mkdir()

    with pytest.raises(BackupError, match="unusable config file"):
        restore_backup(
            path=archive,
            config_dir=destination,
            config_path=None,
            passphrase=PASSPHRASE,
        )

    assert list(destination.iterdir()) == []


def test_a_backup_missing_a_member_writes_nothing(app, tmp_path) -> None:
    payload = _sealed_archive(
        {
            MANIFEST_NAME: json.dumps(
                {"format": 1, "config_name": "credarr.yaml"}
            ).encode()
        }
    )
    archive = tmp_path / "incomplete.credarr"
    archive.write_bytes(payload)
    destination = tmp_path / "restore-target"
    destination.mkdir()

    with pytest.raises(BackupError, match=r"no app\.db"):
        restore_backup(
            path=archive,
            config_dir=destination,
            config_path=None,
            passphrase=PASSPHRASE,
        )
    assert list(destination.iterdir()) == []


def test_a_path_shaped_member_is_never_extracted(app, tmp_path) -> None:
    """An extra traversal-shaped member is ignored; only the three exact names
    are read, and the restored config keeps its declared bare name."""
    database = _snapshot(app.store.path)
    config = b"version: 1\n"
    entries = {
        DATABASE_NAME: database,
        CONFIG_PREFIX + "credarr.yaml": config,
        MANIFEST_NAME: json.dumps(
            {"format": 1, "config_name": "credarr.yaml"}
        ).encode(),
        "../../etc/credarr.yaml": b"not extracted",
        CONFIG_PREFIX + "../credarr.yaml": b"not extracted either",
    }
    archive = tmp_path / "extra-members.credarr"
    archive.write_bytes(_sealed_archive(entries))
    destination = tmp_path / "restore-target"
    destination.mkdir()

    written = restore_backup(
        path=archive,
        config_dir=destination,
        config_path=None,
        passphrase=PASSPHRASE,
    )

    assert set(written) == {
        destination / DATABASE_NAME,
        destination / "credarr.yaml",
    }
    assert (destination / "credarr.yaml").read_bytes() == config
    assert not (tmp_path / "etc").exists()
    assert sorted(path.name for path in destination.iterdir()) == [
        "app.db",
        "credarr.yaml",
    ]

def _backed_up(app, tmp_path) -> tuple[object, object]:
    """Write a backup of the fixture app exactly as the server has it."""
    config_path = server_config(app, tmp_path)
    out = tmp_path / "backup.credarr"
    write_backup(
        config_path=config_path,
        config_dir=tmp_path,
        out=out,
        passphrase=PASSPHRASE,
    )
    return config_path, out


def _restore(out, tmp_path, name: str = "restored"):
    directory = tmp_path / name
    directory.mkdir()
    written = restore_backup(
        path=out,
        config_dir=directory,
        config_path=None,
        passphrase=PASSPHRASE,
    )
    return directory, written


def _shape(document: dict) -> list[tuple]:
    """What a restart must preserve: the verdicts, not the run's id."""
    return [
        (
            row["name"],
            row["stored"],
            row["status"],
            [consumer["status"] for consumer in row["consumers"]],
        )
        for row in document["credentials"]
    ]


def test_a_restored_app_audits_the_same_stack_and_keeps_its_secrets(app, tmp_path) -> None:
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        wait_for_audit(client)
        Notifier(app.store.path).save_service(
            "ntfy",
            "ntfy",
            url="https://ntfy.example",
            topic="credarr",
            token="ntfy-token",
        )
        app.store.set_value("sonarr_api_key", Secret("0" * 32))
        assert client.post("/api/v1/audit").status_code == 200
        before = client.get("/api/v1/credentials").json()
        before_status = client.get("/api/v1/status").json()

    _, out = _backed_up(app, tmp_path)
    restored_dir, written = _restore(out, tmp_path)
    assert written == [restored_dir / "app.db", restored_dir / "credarr.yaml"]

    # The sink's secret and the admin's digest came out of the encrypted file.
    assert Notifier(restored_dir / "app.db").views()["ntfy"].token_configured is True
    assert [event.kind for event in AuditLog(restored_dir / "app.db").recent_events()] == [
        "drift"
    ]

    restored = create_app(
        ServerSettings(
            config_path=restored_dir / "credarr.yaml",
            config_dir=restored_dir,
            web_dir=tmp_path / "web",
        )
    )
    with TestClient(restored) as client:
        # The password set up before the backup is the password after it.
        assert (
            client.post("/api/v1/auth/login", json={"password": PASSWORD}).status_code
            == 200
        )
        refresh_csrf(client)
        assert client.post("/api/v1/audit").status_code == 200
        after = client.get("/api/v1/credentials").json()
        after_status = client.get("/api/v1/status").json()

    assert after_status["topology"]["imported"] is True
    assert (
        after_status["last_audit"]["exit_status"]
        == before_status["last_audit"]["exit_status"]
    )
    assert _shape(after) == _shape(before)


def test_the_backup_on_disk_is_encrypted(app, tmp_path) -> None:
    Notifier(app.store.path).save_service(
        "ntfy",
        "ntfy",
        url="https://ntfy.example",
        topic="credarr",
        token="ntfy-token",
    )
    _, out = _backed_up(app, tmp_path)

    raw = out.read_bytes()
    assert b"SQLite format 3" not in raw
    assert SONARR_KEY.encode() not in raw
    assert b"ntfy-token" not in raw
    assert b"ntfy.example" not in raw
    assert PASSPHRASE.encode() not in raw
    assert out.stat().st_mode & 0o777 == 0o600


def test_a_wrong_passphrase_or_a_damaged_file_writes_nothing(app, tmp_path) -> None:
    _, out = _backed_up(app, tmp_path)
    restored_dir = tmp_path / "restored"
    restored_dir.mkdir()

    raw = out.read_bytes()
    damaged = tmp_path / "damaged.credarr"
    damaged.write_bytes(raw[:-1] + bytes([raw[-1] ^ 0xFF]))
    truncated = tmp_path / "truncated.credarr"
    # Shorter than magic + version + salt + nonce: refused before decrypting.
    truncated.write_bytes(raw[:20])
    foreign = tmp_path / "foreign.credarr"
    foreign.write_bytes(b"this is not one")

    for path, passphrase, message in (
        (out, "a different passphrase", "passphrase is wrong"),
        (damaged, PASSPHRASE, "passphrase is wrong"),
        (truncated, PASSPHRASE, "truncated"),
        (foreign, PASSPHRASE, "not a credarr backup"),
    ):
        with pytest.raises(BackupError, match=message):
            restore_backup(
                path=path,
                config_dir=restored_dir,
                config_path=None,
                passphrase=passphrase,
            )
        assert list(restored_dir.iterdir()) == []


def test_a_restore_refuses_when_a_wal_says_a_server_may_be_running(app, tmp_path) -> None:
    _, out = _backed_up(app, tmp_path)
    restored_dir = tmp_path / "restored"
    restored_dir.mkdir()
    (restored_dir / "app.db-wal").write_bytes(b"")

    with pytest.raises(BackupError, match=r"app\.db-wal is beside"):
        restore_backup(
            path=out,
            config_dir=restored_dir,
            config_path=None,
            passphrase=PASSPHRASE,
        )
    assert not (restored_dir / "app.db").exists()


def test_a_restore_refuses_when_a_journal_says_a_server_may_be_running(
    app, tmp_path
) -> None:
    _, out = _backed_up(app, tmp_path)
    restored_dir = tmp_path / "restored"
    restored_dir.mkdir()
    (restored_dir / "app.db-journal").write_bytes(b"")

    with pytest.raises(BackupError, match=r"app\.db-journal"):
        restore_backup(
            path=out,
            config_dir=restored_dir,
            config_path=None,
            passphrase=PASSPHRASE,
        )
    assert not (restored_dir / "app.db").exists()
    assert not (restored_dir / "credarr.yaml").exists()


def test_a_failed_restore_restores_the_files_it_had_already_replaced(
    app, tmp_path, monkeypatch
) -> None:
    """The config is published before the database. If the database publish
    fails, the config must go back, or a failed restore leaves the app pointing
    at an archive it does not hold."""
    import credarr_server.backup as backup

    _, out = _backed_up(app, tmp_path)
    restored_dir = tmp_path / "restored"
    restored_dir.mkdir()
    database = restored_dir / "app.db"
    config = restored_dir / "credarr.yaml"
    database.write_bytes(b"the old database")
    config.write_text("old: config\n", encoding="utf-8")

    publish = backup._publish

    def fail_database(source, destination) -> None:
        if destination.name == "app.db":
            raise OSError("simulated publish failure")
        publish(source, destination)

    monkeypatch.setattr(backup, "_publish", fail_database)
    with pytest.raises(OSError, match="simulated publish failure"):
        restore_backup(
            path=out,
            config_dir=restored_dir,
            config_path=None,
            passphrase=PASSPHRASE,
        )

    assert database.read_bytes() == b"the old database"
    assert config.read_text(encoding="utf-8") == "old: config\n"
    assert not (restored_dir / "app.db.pre-restore").exists()
    assert list(restored_dir.glob(".restore-*")) == []


def test_a_restore_rolls_back_a_database_it_already_published(
    app, tmp_path, monkeypatch
) -> None:
    """The failure after the rename is the one that needs the kept copy. It
    must put both files back and leave no `pre-restore` link behind."""
    import credarr_server.backup as backup

    _, out = _backed_up(app, tmp_path)
    restored_dir = tmp_path / "restored"
    restored_dir.mkdir()
    database = restored_dir / "app.db"
    config = restored_dir / "credarr.yaml"
    database.write_bytes(b"the old database")
    config.write_text("old: config\n", encoding="utf-8")

    fsync = backup._fsync_directory
    failed = False

    def fail_once(path) -> None:
        nonlocal failed
        if not failed and path == restored_dir:
            failed = True
            raise OSError("simulated fsync failure")
        fsync(path)

    monkeypatch.setattr(backup, "_fsync_directory", fail_once)
    with pytest.raises(OSError, match="simulated fsync failure"):
        restore_backup(
            path=out,
            config_dir=restored_dir,
            config_path=None,
            passphrase=PASSPHRASE,
        )

    assert database.read_bytes() == b"the old database"
    assert config.read_text(encoding="utf-8") == "old: config\n"
    assert not (restored_dir / "app.db.pre-restore").exists()
    assert list(restored_dir.glob(".restore-*")) == []


def test_a_restore_keeps_the_database_it_replaced(app, tmp_path) -> None:
    _, out = _backed_up(app, tmp_path)
    restored_dir = tmp_path / "restored"
    restored_dir.mkdir()
    (restored_dir / "app.db").write_bytes(b"the previous database")

    restore_backup(
        path=out,
        config_dir=restored_dir,
        config_path=None,
        passphrase=PASSPHRASE,
    )

    assert (restored_dir / "app.db.pre-restore").read_bytes() == b"the previous database"
    assert (restored_dir / "app.db").read_bytes().startswith(b"SQLite format 3\x00")


def test_a_second_restore_refuses_to_eat_the_kept_database(app, tmp_path) -> None:
    _, out = _backed_up(app, tmp_path)
    restored_dir = tmp_path / "restored"
    restored_dir.mkdir()
    (restored_dir / "app.db").write_bytes(b"the original")

    restore_backup(
        path=out,
        config_dir=restored_dir,
        config_path=None,
        passphrase=PASSPHRASE,
    )
    kept = restored_dir / "app.db.pre-restore"
    assert kept.read_bytes() == b"the original"

    with pytest.raises(BackupError, match=r"already exists"):
        restore_backup(
            path=out,
            config_dir=restored_dir,
            config_path=None,
            passphrase=PASSPHRASE,
        )
    assert kept.read_bytes() == b"the original"


def test_a_backup_refuses_to_overwrite_and_refuses_a_short_passphrase(app, tmp_path) -> None:
    config_path = server_config(app, tmp_path)
    out = tmp_path / "backup.credarr"
    with pytest.raises(BackupError, match="at least 12"):
        write_backup(
            config_path=config_path,
            config_dir=tmp_path,
            out=out,
            passphrase="short",
        )
    assert not out.exists()

    write_backup(
        config_path=config_path,
        config_dir=tmp_path,
        out=out,
        passphrase=PASSPHRASE,
    )
    with pytest.raises(BackupError, match="already exists"):
        write_backup(
            config_path=config_path,
            config_dir=tmp_path,
            out=out,
            passphrase=PASSPHRASE,
        )


def test_a_passphrase_file_readable_by_others_is_refused(app, tmp_path) -> None:
    config_path = server_config(app, tmp_path)
    passphrase_file = tmp_path / "passphrase"
    passphrase_file.write_text(PASSPHRASE + "\n", encoding="utf-8")
    passphrase_file.chmod(0o644)
    out = tmp_path / "backup.credarr"
    assert (
        main(
            [
                "--config",
                str(config_path),
                "--config-dir",
                str(tmp_path),
                "--out",
                str(out),
                "--passphrase-file",
                str(passphrase_file),
            ]
        )
        == 3
    )
    assert not out.exists()


def test_the_cli_takes_the_passphrase_from_a_file_and_never_from_argv(
    app, tmp_path, capsys
) -> None:
    config_path = server_config(app, tmp_path)
    passphrase_file = tmp_path / "passphrase"
    passphrase_file.write_text(PASSPHRASE + "\n", encoding="utf-8")
    passphrase_file.chmod(0o600)
    out = tmp_path / "cli-backup"
    assert (
        main(
            [
                "--config",
                str(config_path),
                "--config-dir",
                str(tmp_path),
                "--out",
                str(out),
                "--passphrase-file",
                str(passphrase_file),
            ]
        )
        == 0
    )
    printed = capsys.readouterr().out
    assert out.is_file()
    assert PASSPHRASE not in printed
    assert "secret" in printed

    restored_dir = tmp_path / "restored"
    restored_dir.mkdir()
    without_yes = [
        "--config-dir",
        str(restored_dir),
        "--restore",
        str(out),
        "--passphrase-file",
        str(passphrase_file),
    ]
    assert main(without_yes) == 2
    assert list(restored_dir.iterdir()) == []
    assert main([*without_yes, "--yes"]) == 0
    assert (restored_dir / "app.db").is_file()
    assert (restored_dir / "credarr.yaml").is_file()

    with pytest.raises(SystemExit) as refusal:
        main(
            [
                "--config-dir",
                str(restored_dir),
                "--out",
                str(tmp_path / "x"),
                "--passphrase",
                "x",
            ]
        )
    assert refusal.value.code == 2
    with pytest.raises(SystemExit) as both:
        main(
            [
                "--config-dir",
                str(restored_dir),
                "--out",
                str(tmp_path / "x"),
                "--restore",
                str(out),
            ]
        )
    assert both.value.code == 2

    wrong = tmp_path / "wrong"
    wrong.write_text("a different passphrase\n", encoding="utf-8")
    wrong.chmod(0o600)
    another = tmp_path / "another"
    another.mkdir()
    assert (
        main(
            [
                "--config-dir",
                str(another),
                "--restore",
                str(out),
                "--yes",
                "--passphrase-file",
                str(wrong),
            ]
        )
        == 3
    )
    assert not (another / "app.db").exists()
    assert not (another / "credarr.yaml").exists()
    assert "passphrase is wrong" in capsys.readouterr().err
