"""The agent image's defaults are environment-driven.

The container has no command block. `credarr-agent` must default to `run` and
take its required paths from the environment, while the command line keeps
working for a host install and for one-time enrollment.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from credarr.errors import ExitCode
from credarr_agent import cli


def _env(monkeypatch, **values: str) -> None:
    for name in (
        "CREDARR_AGENT_SERVER",
        "CREDARR_AGENT_STATE",
        "CREDARR_AGENT_VAULT_ROOT",
        "CREDARR_AGENT_VAULT_KEY",
        "CREDARR_AGENT_CA",
        "CREDARR_AGENT_ALLOWED_ROOT",
        "CREDARR_AGENT_ROOTFUL",
        "CREDARR_AGENT_ACK_ROOTFUL",
        "CREDARR_AGENT_POLL_SECONDS",
        "CREDARR_AGENT_ENROLL_NAME",
        "CREDARR_AGENT_ENROLL_TOKEN_FILE",
        "CREDARR_AGENT_CAPABILITY",
    ):
        monkeypatch.delenv(name, raising=False)
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def test_the_container_defaults_to_run_from_environment(monkeypatch, tmp_path: Path) -> None:
    _env(
        monkeypatch,
        CREDARR_AGENT_SERVER="https://credarr:8443",
        CREDARR_AGENT_STATE=str(tmp_path / "state"),
        CREDARR_AGENT_VAULT_ROOT=str(tmp_path / "vault"),
        CREDARR_AGENT_VAULT_KEY=str(tmp_path / "vault.key"),
        CREDARR_AGENT_CA=str(tmp_path / "ca.crt"),
        CREDARR_AGENT_ALLOWED_ROOT="/stacks,/srv/stacks",
        CREDARR_AGENT_ROOTFUL="1",
        CREDARR_AGENT_ACK_ROOTFUL="true",
        CREDARR_AGENT_POLL_SECONDS="9",
    )
    captured = {}

    def fake_run(config, *, once=False):
        captured["config"] = config
        captured["once"] = once
        return 0

    monkeypatch.setattr(cli, "run", fake_run)
    assert cli.main([]) == 0
    config = captured["config"]
    assert config.server == "https://credarr:8443"
    assert config.allowed_roots == (Path("/stacks"), Path("/srv/stacks"))
    assert config.rootful is True
    assert config.ack_rootful is True
    assert config.poll_seconds == 9
    assert captured["once"] is False


def test_missing_required_environment_is_a_config_error(monkeypatch, capsys) -> None:
    _env(monkeypatch)
    monkeypatch.setattr(cli, "run", lambda config, once=False: 0)
    assert cli.main([]) == int(ExitCode.CONFIG)
    err = capsys.readouterr().err
    assert "CREDARR_AGENT_SERVER" in err
    assert "CREDARR_AGENT_VAULT_ROOT" in err


def test_flags_and_the_run_subcommand_still_work(monkeypatch, tmp_path: Path) -> None:
    _env(monkeypatch, CREDARR_AGENT_ALLOWED_ROOT="/env")
    captured = {}

    def fake_run(config, *, once=False):
        captured["config"] = config
        captured["once"] = once
        return 0

    monkeypatch.setattr(cli, "run", fake_run)
    assert (
        cli.main(
            [
                "--server",
                "https://credarr:9443",
                "--vault-root",
                str(tmp_path / "vault"),
                "--vault-key",
                str(tmp_path / "vault.key"),
                "--ca",
                str(tmp_path / "ca.crt"),
                "--allowed-root",
                "/flag",
                "run",
                "--once",
            ]
        )
        == 0
    )
    assert captured["config"].server == "https://credarr:9443"
    assert captured["config"].allowed_roots == (Path("/flag"),)
    assert captured["once"] is True


def test_help_still_exits_zero(monkeypatch) -> None:
    _env(monkeypatch)
    with pytest.raises(SystemExit) as exc:
        cli._parser().parse_args(["--help"])
    assert exc.value.code == 0
