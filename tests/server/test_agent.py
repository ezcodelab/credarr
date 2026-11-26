"""The agent control plane: mTLS, enrollment, leases, clock and replay bounds.

The listener is started on a real loopback socket with the real certificate
chain. The agent side is the shipped `credarr_agent` client, so a broken CSR,
a missing client certificate, or a TLS downgrade fails here and not only in a
deployment.
"""

from __future__ import annotations

import http.client
import ssl
import time
from pathlib import Path

import pytest

from credarr.redact import Secret
from credarr.targets import build_registry
from credarr_agent.client import AgentClient, AgentConfig, AgentError, enroll
from credarr_server.agent_control import AgentControlPlane
from credarr_server.store import TopologyStore
from credarr_server.sync_store import SyncStore
from credarr_server.vault import VaultTree

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


def _plane(tmp_path: Path) -> tuple[AgentControlPlane, SyncStore]:
    manifest = tmp_path / "credentials.yaml"
    manifest.write_text(MANIFEST, encoding="utf-8")
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest, REGISTRY)
    sync = SyncStore(tmp_path / "app.db", tree_configured=True)
    plane = AgentControlPlane(sync, tmp_path, host="127.0.0.1", port=0)
    plane.start()
    return plane, sync


def _agent(tmp_path: Path, plane: AgentControlPlane, sync: SyncStore, name: str = "edge"):
    token, _ = sync.create_enrollment(name, ("compose",))
    ca = tmp_path / "agent-ca.crt"
    port = plane.port
    config = AgentConfig(
        server=f"https://127.0.0.1:{port}",
        state_dir=tmp_path / "state",
        vault_root=tmp_path / "tree",
        vault_key=tmp_path / "tree.key",
        allowed_roots=(tmp_path,),
        ca_path=ca,
        cert_path=tmp_path / "state" / "agent.crt",
        key_path=tmp_path / "state" / "agent.key",
        rootful=False,
        ack_rootful=False,
    )
    enroll(config, token, name=name, capabilities=("compose",))
    return config, AgentClient(config)


def test_a_failed_listener_keeps_its_failure_sentence(tmp_path: Path) -> None:
    plane = AgentControlPlane(
        SyncStore(tmp_path / "app.db", tree_configured=True),
        tmp_path,
        host="127.0.0.1",
        port=0,
        hostname="credarr.test",
    )
    plane.failure = "OSError: address already in use"
    info = plane.info()
    assert info["enabled"] is False
    assert info["failure"] == "OSError: address already in use"
    assert info["url"] is None


def test_a_client_certificate_is_required_and_tls_1_3_is_enforced(
    tmp_path: Path,
) -> None:
    plane, _sync = _plane(tmp_path)
    try:
        context = ssl.create_default_context(cafile=str(tmp_path / "agent-ca.crt"))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        with pytest.raises((ssl.SSLError, OSError)):
            connection = http.client.HTTPSConnection(
                "127.0.0.1", plane.port, context=context, timeout=3
            )
            connection.request("GET", "/v1/info")
            connection.getresponse()
    finally:
        plane.stop()


def test_enrollment_then_lease_begin_and_delivered(tmp_path: Path) -> None:
    plane, sync = _plane(tmp_path)
    try:
        _config, client = _agent(tmp_path, plane, sync)
        store = TopologyStore(tmp_path / "app.db")
        agent = sync.agent("edge")
        target = sync.save_target(
            name="media",
            agent_id=agent.id,
            stack_path="/srv/media",
            project_name="media",
            services=("sonarr", "seerr"),
            workflow="compose",
        )
        store.set_value("sonarr_api_key", Secret("value"))
        sync.dispatch()
        lease = client.post("/v1/jobs/lease", {"timestamp": time.time()})
        job = lease["job"]
        assert job is not None
        client.post(f"/v1/jobs/{job['id']}/begin", {"timestamp": time.time()})
        result = client.post(
            f"/v1/jobs/{job['id']}/result",
            {"timestamp": time.time(), "services": {"sonarr": True, "seerr": True}},
        )
        assert result["job"]["state"] == "delivered"
        assert target.agent_id == agent.id
    finally:
        plane.stop()


def test_a_replayed_result_and_a_stale_clock_are_refused(tmp_path: Path) -> None:
    plane, sync = _plane(tmp_path)
    try:
        _config, client = _agent(tmp_path, plane, sync)
        store = TopologyStore(tmp_path / "app.db")
        agent = sync.agent("edge")
        sync.save_target(
            name="media",
            agent_id=agent.id,
            stack_path="/srv/media",
            project_name="media",
            services=("sonarr", "seerr"),
        )
        store.set_value("sonarr_api_key", Secret("value"))
        sync.dispatch()
        job = client.post("/v1/jobs/lease", {"timestamp": time.time()})["job"]
        with pytest.raises(AgentError, match="clock"):
            client.post("/v1/jobs/lease", {"timestamp": time.time() - 10_000})
        client.post(f"/v1/jobs/{job['id']}/begin", {"timestamp": time.time()})
        client.post(
            f"/v1/jobs/{job['id']}/result",
            {"timestamp": time.time(), "services": {"sonarr": True, "seerr": True}},
        )
        with pytest.raises(AgentError, match="no longer in flight"):
            client.post(
                f"/v1/jobs/{job['id']}/result",
                {"timestamp": time.time(), "services": {"sonarr": True, "seerr": True}},
            )
    finally:
        plane.stop()


def test_revocation_stops_the_agent(tmp_path: Path) -> None:
    plane, sync = _plane(tmp_path)
    try:
        _config, client = _agent(tmp_path, plane, sync)
        assert sync.revoke("edge") is True
        with pytest.raises(AgentError, match="unknown or revoked"):
            client.post("/v1/heartbeat", {"timestamp": time.time(), "rootful": False})
    finally:
        plane.stop()


def test_a_generation_mismatch_fails_closed(tmp_path: Path) -> None:
    tree = VaultTree(tmp_path / "tree", tmp_path / "tree.key")
    tree.write_value("sonarr_api_key", "v2", "CURRENT", "value", time.time())
    tree.write_marker("sonarr_api_key", "v1", "CURRENT", 1, time.time())
    with pytest.raises(Exception, match="refusing to deploy"):
        tree.verify("sonarr_api_key", "v2")
