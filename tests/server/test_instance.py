"""One app process per config directory.

The lock is what makes that a rule rather than a sentence in the README. These
tests hold it from a separate process and drive the real entry points, so they
prove the wiring and the cross-process exclusion.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import stat
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from credarr import cli
from credarr.errors import ConfigError
from credarr.instance import LOCK_NAME, InstanceLock
from credarr_server.app import main as server_main
from credarr_server.backup import main as backup_main


@contextlib.contextmanager
def another_process_holding(config_dir: Path) -> Iterator[None]:
    code = (
        "import sys, time\n"
        "from pathlib import Path\n"
        "from credarr.instance import InstanceLock\n"
        "with InstanceLock(Path(sys.argv[1])):\n"
        "    print('ready', flush=True)\n"
        "    time.sleep(60)\n"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", code, str(config_dir)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        line = process.stdout.readline().strip()
        if line != "ready":
            raise AssertionError(
                f"lock holder did not start: {line!r} {process.stderr.read()!r}"
            )
        yield
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def test_a_second_server_process_is_refused_before_it_opens_the_database(
    tmp_path, capsys,
) -> None:
    with another_process_holding(tmp_path):
        code = server_main(
            [
                "--once",
                "--config",
                str(tmp_path / "missing.yaml"),
                "--config-dir",
                str(tmp_path),
            ]
        )

    assert code == 3
    error = capsys.readouterr().err
    assert "another credarr process holds this config directory" in error
    assert "one process per /config is required" in error


def test_both_backup_directions_take_the_same_lock(tmp_path, capsys) -> None:
    with another_process_holding(tmp_path):
        out = backup_main(
            ["--config-dir", str(tmp_path), "--out", str(tmp_path / "x.backup")]
        )
        restore = backup_main(
            [
                "--config-dir",
                str(tmp_path),
                "--restore",
                str(tmp_path / "missing.backup"),
                "--yes",
            ]
        )

    assert (out, restore) == (3, 3)
    error = capsys.readouterr().err
    assert error.count("another credarr process holds this config directory") == 2


def test_cli_apply_refuses_while_the_server_owns_the_config(
    tmp_path, capsys, monkeypatch,
) -> None:
    monkeypatch.delenv("CREDARR_CONFIG_DIR", raising=False)
    monkeypatch.setattr(cli, "DEFAULT_CONFIG_DIR", tmp_path)
    with another_process_holding(tmp_path):
        code = cli.main(
            [
                "--config",
                str(tmp_path / "elsewhere" / "missing.yaml"),
                "rotate",
                "sample",
                "--apply",
                "--yes",
            ]
        )

    assert code == 3
    assert "another credarr process holds this config directory" in capsys.readouterr().err


def test_cli_lock_dir_prefers_the_default_data_dir(
    tmp_path, monkeypatch,
) -> None:
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setattr(cli, "DEFAULT_CONFIG_DIR", data)
    monkeypatch.delenv("CREDARR_CONFIG_DIR", raising=False)
    args = argparse.Namespace(
        config=tmp_path / "elsewhere" / "credarr.yaml",
        config_dir=None,
    )

    assert cli._lock_dir(args) == data

    data.rmdir()
    assert cli._lock_dir(args) == args.config.resolve().parent


def test_cli_dry_run_is_not_blocked_by_the_server_lock(
    tmp_path, capsys, monkeypatch,
) -> None:
    monkeypatch.delenv("CREDARR_CONFIG_DIR", raising=False)
    with another_process_holding(tmp_path):
        code = cli.main(
            [
                "--config",
                str(tmp_path / "missing.yaml"),
                "rotate",
                "sample",
                "--dry-run",
            ]
        )

    assert code == 3
    error = capsys.readouterr().err
    assert "another credarr process" not in error
    assert "cannot read config" in error


def test_the_lock_is_private_and_names_the_holder(tmp_path) -> None:
    with InstanceLock(tmp_path):
        path = tmp_path / LOCK_NAME
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert f"pid={os.getpid()}" in path.read_text()


def test_a_stale_lock_file_does_not_block_the_next_owner(tmp_path) -> None:
    (tmp_path / LOCK_NAME).write_text("pid=999999 started=0\n")

    with InstanceLock(tmp_path):
        pass


def test_the_lock_refuses_a_symlink_without_truncating_its_target(tmp_path) -> None:
    target = tmp_path / "target"
    target.write_text("keep this")
    (tmp_path / LOCK_NAME).symlink_to(target)

    with pytest.raises(ConfigError, match="cannot open the instance lock"):
        InstanceLock(tmp_path).acquire()

    assert target.read_text() == "keep this"


def test_a_missing_config_directory_names_the_lock_path(tmp_path) -> None:
    with pytest.raises(ConfigError, match="cannot open the instance lock"):
        InstanceLock(tmp_path / "missing").acquire()
