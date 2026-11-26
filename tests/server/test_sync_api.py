"""The operator's sync surface over HTTP.

The store tests cover the state machine; these cover the boundary: a target
cannot be created without the shared tree, an enrollment token is returned once,
a committed value reaches the outbox, and the JSON never carries a value.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from conftest import make_server, setup_admin
from credarr_server.agent_control import AgentControlPlane


def _server(app, tmp_path, **overrides):
    tree = tmp_path / "tree"
    tree.mkdir()
    return make_server(
        app, tmp_path, vault_tree=tree, vault_tree_key=tree / "vault-tree.key", **overrides
    )


def _active_agent(server):
    token, agent = server.state.sync.create_enrollment("edge", ("compose",))
    server.state.sync.consume_enrollment(
        token,
        fingerprint="fp-edge",
        expires_at=10**12,
    )
    return agent


def test_the_ca_download_requires_an_admin_session(app, tmp_path) -> None:
    server = _server(app, tmp_path)
    with TestClient(server) as client:
        assert client.get("/api/v1/agents/ca").status_code == 401
        setup_admin(client)
        assert client.get("/api/v1/agents/ca").status_code in (200, 404)


def test_a_configured_tree_has_its_key_before_the_first_value(app, tmp_path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    key = tree / "vault-tree.key"
    server = make_server(app, tmp_path, vault_tree=tree, vault_tree_key=key)
    with TestClient(server) as client:
        setup_admin(client)
    assert key.is_file()
    assert len(key.read_bytes()) == 32


def test_a_target_needs_a_tree_and_an_agent(app, tmp_path) -> None:
    server = make_server(app, tmp_path)
    with TestClient(server) as client:
        setup_admin(client)
        refused = client.post(
            "/api/v1/sync/targets",
            json={
                "name": "media",
                "agent_id": "nope",
                "stack_path": "/srv/media",
                "project_name": "media",
                "services": ["sonarr"],
            },
        )
        assert refused.status_code == 400
        assert "vault tree" in refused.json()["detail"]


def test_targets_and_enrollment_are_wired_to_the_outbox(app, tmp_path) -> None:
    server = _server(app, tmp_path)
    with TestClient(server) as client:
        setup_admin(client)
        agent = _active_agent(server)
        created = client.post(
            "/api/v1/sync/targets",
            json={
                "name": "media",
                "agent_id": agent.id,
                "stack_path": "/srv/media",
                "project_name": "media",
                "services": ["sonarr", "seerr"],
                "workflow": "compose",
            },
        )
        assert created.status_code == 200, created.text
        pasted = "tree-value-0123456789"
        assert client.put(
            "/api/v1/credentials/sonarr_api_key/value", json={"value": pasted}
        ).status_code == 200
        targets = client.get("/api/v1/sync/targets").json()["targets"]
        agents = client.get("/api/v1/agents").json()
        # The dispatcher is a loop; one tick makes the committed outbox visible.
        server.state.sync.dispatch()
        jobs = client.get("/api/v1/sync/jobs").json()["jobs"]
    # The target backfills every CURRENT value it did not know about, then the
    # paste adds one more. Both are real jobs for this target.
    assert {job["credential"] for job in jobs} == {
        "seerr_api_key",
        "sonarr_api_key",
    }
    assert all(job["state"] in ("queued", "leased", "running") for job in jobs)
    assert targets[0]["services"] == ["seerr", "sonarr"]
    assert agents["agents"][0]["name"] == "edge"
    assert pasted not in str(jobs) and pasted not in str(targets)


def test_an_env_target_is_created_with_its_declared_mapping(app, tmp_path) -> None:
    server = _server(app, tmp_path)
    with TestClient(server) as client:
        setup_admin(client)
        agent = _active_agent(server)
        created = client.post(
            "/api/v1/sync/targets",
            json={
                "name": "homepage",
                "agent_id": agent.id,
                "stack_path": "/stacks/homepage",
                "project_name": "homepage",
                "services": ["homepage"],
                "workflow": "env",
                "env_file": ".env",
                "values": {
                    "HOMEPAGE_VAR_SONARR_API_KEY": "sonarr_api_key",
                },
            },
        )
        assert created.status_code == 200, created.text
        target = created.json()["target"]
        listed = client.get("/api/v1/sync/targets").json()["targets"]
    assert target["workflow"] == "env"
    assert target["env_file"] == ".env"
    assert target["values"] == {"HOMEPAGE_VAR_SONARR_API_KEY": "sonarr_api_key"}
    assert listed[0]["values"] == target["values"]


def test_the_console_reports_the_listener_and_serves_the_agent_ca(app, tmp_path) -> None:
    server = _server(app, tmp_path, agent_port=9443, agent_hostname="credarr.test")
    plane = AgentControlPlane(
        server.state.sync,
        tmp_path,
        host="127.0.0.1",
        port=0,
        hostname="credarr.test",
    )
    plane.start()
    server.state.agent_plane = plane
    server.state.api_context.agent_plane = plane
    try:
        with TestClient(server) as client:
            setup_admin(client)
            answer = client.get("/api/v1/agents").json()
            listed = answer["control_plane"]
            assert listed["enabled"] is True
            assert listed["port"] == plane.port
            assert listed["hostname"] == "credarr.test"
            assert listed["url"] == f"https://credarr.test:{plane.port}"
            assert listed["ca"] is True
            ca = client.get("/api/v1/agents/ca")
            assert ca.status_code == 200
            assert ca.headers["content-type"].startswith("application/x-pem-file")
            assert "BEGIN CERTIFICATE" in ca.text
    finally:
        plane.stop()


def test_a_disabled_listener_still_reports_its_startup_configuration(app, tmp_path) -> None:
    server = _server(app, tmp_path, agent_port=0, agent_hostname="credarr.test")
    with TestClient(server) as client:
        setup_admin(client)
        listed = client.get("/api/v1/agents").json()["control_plane"]
        missing = client.get("/api/v1/agents/ca")
    assert listed["enabled"] is False
    assert listed["port"] == 0
    assert listed["hostname"] == "credarr.test"
    assert listed["url"] is None
    assert missing.status_code == 404


def test_an_enrollment_token_is_returned_once_and_never_listed(app, tmp_path) -> None:
    server = _server(app, tmp_path)
    with TestClient(server) as client:
        setup_admin(client)
        answer = client.post(
            "/api/v1/agents/enrollment",
            json={"name": "edge", "capabilities": ["compose"]},
        )
        assert answer.status_code == 200, answer.text
        token = answer.json()["token"]
        assert token
        again = client.post(
            "/api/v1/agents/enrollment",
            json={"name": "edge", "capabilities": ["compose"]},
        )
        listed = client.get("/api/v1/agents").text
    assert again.status_code == 409
    assert token not in listed
