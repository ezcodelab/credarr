"""The agent's generic env workflow: declared keys, atomic replacement, compose."""

from __future__ import annotations

from pathlib import Path

import pytest

from credarr_agent.client import AgentClient, AgentConfig, AgentError, Workflow, run


def _config(tmp_path: Path) -> AgentConfig:
    state = tmp_path / "state"
    state.mkdir()
    return AgentConfig(
        server="https://127.0.0.1:8443",
        state_dir=state,
        vault_root=tmp_path / "vault",
        vault_key=tmp_path / "vault.key",
        allowed_roots=(tmp_path,),
        ca_path=tmp_path / "ca.crt",
        cert_path=state / "agent.crt",
        key_path=state / "agent.key",
    )


def test_the_agent_refuses_an_empty_ca(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.ca_path.write_bytes(b"")
    with pytest.raises(AgentError, match="missing or empty"):
        AgentClient(config)


def test_the_agent_refuses_an_empty_vault_key(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.cert_path.write_bytes(b"certificate")
    config.key_path.write_bytes(b"key")
    config.vault_key.write_bytes(b"")
    with pytest.raises(AgentError, match="vault tree key"):
        run(config)


def test_preflight_observes_rootful_without_a_user_acknowledgment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Completed:
        returncode = 0

        def __init__(self, stdout: str) -> None:
            self.stdout = stdout

    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        return Completed(seen["stdout"])

    monkeypatch.setattr("credarr_agent.client.subprocess.run", fake_run)
    workflow = Workflow(_config(tmp_path))
    seen["stdout"] = '["name=seccomp,profile=builtin"]'
    assert workflow.preflight() is True
    seen["stdout"] = '["name=rootless"]'
    assert workflow.preflight() is False
    assert seen["argv"][:3] == ["docker", "info", "--format"]


def test_env_updates_only_declared_keys_and_recreates_services(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stack = tmp_path / "homepage"
    stack.mkdir()
    (stack / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    target_env = stack / ".env"
    target_env.write_text(
        "# keep this\nOTHER=one\nHOMEPAGE_VAR_SONARR_API_KEY=old\n"
        "HOMEPAGE_VAR_SONARR_API_KEY=stale\n",
        encoding="utf-8",
    )
    calls: list[list[str]] = []

    class Completed:
        returncode = 0

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return Completed()

    monkeypatch.setattr("credarr_agent.client.subprocess.run", fake_run)
    workflow = Workflow(_config(tmp_path))
    results = workflow.write_env(
        {
            "stack_path": str(stack),
            "project_name": "homepage",
            "services": ["homepage"],
            "workflow": "env",
            "env_file": ".env",
            "values": {
                "HOMEPAGE_VAR_SONARR_API_KEY": "sonarr_api_key",
                "HOMEPAGE_VAR_RADARR_API_KEY": "radarr_api_key",
            },
        },
        "sonarr_api_key",
        "new-value-0123456789",
    )
    assert results == {"homepage": True}
    text = target_env.read_text(encoding="utf-8")
    assert "# keep this" in text
    assert "OTHER=one" in text
    assert text.count("HOMEPAGE_VAR_SONARR_API_KEY=") == 1
    assert "HOMEPAGE_VAR_SONARR_API_KEY=new-value-0123456789" in text
    assert "HOMEPAGE_VAR_RADARR_API_KEY" not in text
    assert target_env.stat().st_mode & 0o777 == 0o600
    assert calls and calls[0][-1] == "homepage"


def test_probe_validates_compose_and_env_without_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stack = tmp_path / "homepage"
    stack.mkdir()
    (stack / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (stack / ".env").write_text("HOMEPAGE_VAR_SONARR_API_KEY=old\n", encoding="utf-8")
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return type("Done", (), {"returncode": 0})()

    monkeypatch.setattr("credarr_agent.client.subprocess.run", fake_run)
    workflow = Workflow(_config(tmp_path))
    results = workflow.probe(
        {
            "stack_path": str(stack),
            "project_name": "homepage",
            "services": ["homepage"],
            "workflow": "env",
            "env_file": ".env",
            "values": {"HOMEPAGE_VAR_SONARR_API_KEY": "sonarr_api_key"},
        }
    )
    assert results == {"homepage": True}
    assert calls and calls[0][-2:] == ["config", "--quiet"]
    assert (stack / ".env").read_text(encoding="utf-8") == (
        "HOMEPAGE_VAR_SONARR_API_KEY=old\n"
    )


def test_env_refuses_an_unmapped_credential_or_path_escape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stack = tmp_path / "homepage"
    stack.mkdir()
    (stack / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (stack / ".env").write_text("OTHER=one\n", encoding="utf-8")
    monkeypatch.setattr(
        "credarr_agent.client.subprocess.run",
        lambda *args, **kwargs: type("Done", (), {"returncode": 0})(),
    )
    workflow = Workflow(_config(tmp_path))
    target = {
        "stack_path": str(stack),
        "project_name": "homepage",
        "services": ["homepage"],
        "workflow": "env",
        "env_file": ".env",
        "values": {"HOMEPAGE_VAR_SONARR_API_KEY": "sonarr_api_key"},
    }
    with pytest.raises(AgentError, match="no key for this credential"):
        workflow.write_env(target, "radarr_api_key", "value")
    escaped = dict(target)
    escaped["env_file"] = "../outside"
    with pytest.raises(AgentError, match="relative path"):
        workflow.write_env(escaped, "sonarr_api_key", "value")
