"""The mount check: decision 8's filesystems, by their mount-table types.

The check is a table lookup, so it is tested with a table. What the tests pin
is the part the product promises: a network mount is found even when the path
is below it, the longest match wins, a missing table is no finding, and the
server refuses with the operator's way out named.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import make_server, server_config
from credarr.errors import CredctlError
from credarr_server import mounts
from credarr_server.app import ServerSettings, create_app
from credarr_server.app import main as server_main

MOUNTINFO = """\
22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw
55 22 0:47 / /mnt/nas rw,relatime shared:2 - nfs4 nas:/export rw
77 22 0:50 / /mnt/user rw,relatime shared:3 - shfs shfs rw
88 22 0:51 / /mnt/user/appdata rw,relatime shared:4 - shfs shfs rw
99 22 0:52 / /mnt/back\\040up rw,relatime shared:5 - cifs //nas/backup rw
"""


def test_the_mount_table_is_parsed_and_escaped_points_are_unescaped() -> None:
    table = mounts.parse_mounts(MOUNTINFO)
    assert mounts.Mount(Path("/"), "ext4") in table
    assert mounts.Mount(Path("/mnt/back up"), "cifs") in table


def test_a_network_mount_is_found_by_the_longest_prefix() -> None:
    table = mounts.parse_mounts(MOUNTINFO)
    assert mounts.network_mount(Path("/mnt/nas/config"), table) == mounts.Mount(
        Path("/mnt/nas"), "nfs4"
    )
    assert mounts.network_mount(Path("/mnt/user/appdata/credarr"), table) == mounts.Mount(
        Path("/mnt/user/appdata"), "shfs"
    )
    assert mounts.network_mount(Path("/srv/credarr"), table) is None


def test_a_system_without_a_mount_table_is_no_finding(monkeypatch, tmp_path) -> None:
    """A hidden `/proc` is "cannot tell", not a refusal dressed as a check."""
    monkeypatch.setattr(mounts, "read_mounts", lambda: None)
    assert mounts.network_mount(tmp_path) is None


def test_the_server_refuses_a_data_directory_on_a_network_mount(
    app, tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(mounts, "read_mounts", lambda: [mounts.Mount(Path("/"), "nfs4")])
    with pytest.raises(CredctlError, match="is on nfs4"):
        create_app(
            ServerSettings(
                config_path=server_config(app, tmp_path),
                config_dir=tmp_path,
            )
        )


def test_the_override_warns_instead_of_refusing(app, tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(mounts, "read_mounts", lambda: [mounts.Mount(Path("/"), "shfs")])
    create_app(
        ServerSettings(
            config_path=server_config(app, tmp_path),
            config_dir=tmp_path,
            allow_network_config=True,
        )
    )
    warning = capsys.readouterr().err
    assert "warning:" in warning
    assert "shfs" in warning


def test_a_local_directory_is_not_a_finding(app, tmp_path) -> None:
    """The suite's own data directory is the control: no refusal, no warning."""
    make_server(app, tmp_path)


def test_run_once_refuses_a_network_data_directory(app, tmp_path, monkeypatch, capsys) -> None:
    """Cron mode writes to the same `app.db`, so it gets the same check."""
    monkeypatch.setattr(mounts, "read_mounts", lambda: [mounts.Mount(Path("/"), "nfs4")])
    assert (
        server_main(
            [
                "--once",
                "--config",
                str(server_config(app, tmp_path)),
                "--config-dir",
                str(tmp_path),
            ]
        )
        == 3
    )
    assert "is on nfs4" in capsys.readouterr().err


def test_the_journal_directory_is_checked_itself(app, tmp_path, monkeypatch) -> None:
    """A mount placed exactly at `state/` is the one the lock would void on."""
    config_path = server_config(app, tmp_path)
    journal = app.manifest.parent / "state"
    monkeypatch.setattr(
        mounts,
        "read_mounts",
        lambda: [
            mounts.Mount(app.manifest.parent, "ext4"),
            mounts.Mount(journal, "nfs4"),
        ],
    )
    with pytest.raises(CredctlError, match=r"rotation journal .* is on nfs4"):
        create_app(ServerSettings(config_path=config_path, config_dir=tmp_path))


def test_first_run_does_not_write_a_config_on_a_network_mount(
    tmp_path, monkeypatch
) -> None:
    """Bootstrap happens after the mount rule, not before it."""
    monkeypatch.setattr(
        mounts, "read_mounts", lambda: [mounts.Mount(Path("/"), "nfs4")]
    )
    config_path = tmp_path / "credarr.yaml"
    with pytest.raises(CredctlError, match="nfs4"):
        create_app(
            ServerSettings(config_path=config_path, config_dir=tmp_path)
        )
    assert not config_path.exists()
    assert not (tmp_path / "credentials.yaml").exists()
