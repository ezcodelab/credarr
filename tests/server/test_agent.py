"""The agent control plane: mTLS, enrollment, leases, clock and replay bounds.

The listener is started on a real loopback socket with the real certificate
chain. The agent side is the shipped `credarr_agent` client, so a broken CSR,
a missing client certificate, or a TLS downgrade fails here and not only in a
deployment.
"""

from __future__ import annotations

import datetime
import http.client
import ssl
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from credarr.redact import Secret
from credarr.targets import build_registry
from credarr_agent.client import AgentClient, AgentConfig, AgentError, enroll
from credarr_server.agent_control import (
    CA_CERT,
    CA_KEY,
    SERVER_CERT,
    SERVER_KEY,
    AgentControlError,
    AgentControlPlane,
    _load_or_create_ca,
    _server_certificate,
)
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


def _plane(
    tmp_path: Path,
    *,
    hostname: str | None = None,
    sans: tuple[str, ...] = (),
) -> tuple[AgentControlPlane, SyncStore]:
    manifest = tmp_path / "credentials.yaml"
    manifest.write_text(MANIFEST, encoding="utf-8")
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest, REGISTRY)
    sync = SyncStore(tmp_path / "app.db", tree_configured=True)
    plane = AgentControlPlane(
        sync,
        tmp_path,
        host="127.0.0.1",
        port=0,
        hostname=hostname,
        sans=sans,
    )
    plane.start()
    return plane, sync


def _expired_ca(directory: Path) -> None:
    directory.mkdir(exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=10))
        .not_valid_after(now - datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    (directory / CA_KEY).write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (directory / CA_CERT).write_bytes(cert.public_bytes(serialization.Encoding.PEM))


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
    )
    enroll(config, token, name=name, capabilities=("compose",))
    return config, AgentClient(config)


def test_first_start_creates_a_ca_and_listener_certificate(tmp_path: Path) -> None:
    plane, _sync = _plane(tmp_path)
    try:
        assert (tmp_path / CA_CERT).is_file()
        assert (tmp_path / CA_KEY).is_file()
        assert (tmp_path / SERVER_CERT).is_file()
        assert plane.info()["ca"] is True
    finally:
        plane.stop()


def test_a_second_start_keeps_the_existing_ca(tmp_path: Path) -> None:
    plane, _sync = _plane(tmp_path)
    key_before = (tmp_path / CA_KEY).read_bytes()
    cert_before = (tmp_path / CA_CERT).read_bytes()
    plane.stop()
    plane, _sync = _plane(tmp_path)
    try:
        assert (tmp_path / CA_KEY).read_bytes() == key_before
        assert (tmp_path / CA_CERT).read_bytes() == cert_before
    finally:
        plane.stop()


@pytest.mark.parametrize("present", [CA_CERT, CA_KEY])
def test_partial_ca_material_is_a_startup_error(tmp_path: Path, present: str) -> None:
    (tmp_path / present).write_bytes(b"partial")
    plane = AgentControlPlane(
        SyncStore(tmp_path / "app.db", tree_configured=True),
        tmp_path,
        host="127.0.0.1",
        port=0,
    )
    with pytest.raises(AgentControlError, match="incomplete"):
        plane.start()


def test_empty_ca_material_is_a_startup_error(tmp_path: Path) -> None:
    (tmp_path / CA_CERT).write_bytes(b"")
    (tmp_path / CA_KEY).write_bytes(b"")
    plane = AgentControlPlane(
        SyncStore(tmp_path / "app.db", tree_configured=True),
        tmp_path,
        host="127.0.0.1",
        port=0,
    )
    with pytest.raises(AgentControlError, match="unreadable or empty"):
        plane.start()


def test_the_listener_certificate_carries_every_agent_name(tmp_path: Path) -> None:
    plane, _sync = _plane(
        tmp_path,
        hostname="credarr.test",
        sans=("credarr", "credarr.internal"),
    )
    try:
        cert = x509.load_pem_x509_certificate(
            (tmp_path / SERVER_CERT).read_bytes()
        )
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        names = set(san.get_values_for_type(x509.DNSName))
        assert {"credarr.test", "credarr", "credarr.internal", "localhost"} <= names
        addresses = {str(item) for item in san.get_values_for_type(x509.IPAddress)}
        assert {"127.0.0.1", "::1"} <= addresses
    finally:
        plane.stop()


def test_a_brought_ca_must_match_its_key(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    _load_or_create_ca(first)
    _load_or_create_ca(second)
    plane = AgentControlPlane(
        SyncStore(tmp_path / "app.db", tree_configured=True),
        tmp_path / "config",
        host="127.0.0.1",
        port=0,
        ca_cert=first / CA_CERT,
        ca_key=second / CA_KEY,
    )
    with pytest.raises(AgentControlError, match="does not match"):
        plane.start()


def test_a_brought_certificate_must_be_a_ca(tmp_path: Path) -> None:
    external = tmp_path / "external"
    external.mkdir()
    key, cert = _load_or_create_ca(external)
    _server_certificate(
        tmp_path,
        key,
        cert,
        hostname="credarr.test",
    )
    server_key = tmp_path / SERVER_KEY
    server_cert = tmp_path / SERVER_CERT
    plane = AgentControlPlane(
        SyncStore(tmp_path / "app.db", tree_configured=True),
        tmp_path / "config",
        host="127.0.0.1",
        port=0,
        ca_cert=server_cert,
        ca_key=server_key,
    )
    with pytest.raises(AgentControlError, match="not a CA certificate"):
        plane.start()


def test_an_expired_brought_ca_is_refused(tmp_path: Path) -> None:
    external = tmp_path / "expired"
    _expired_ca(external)
    plane = AgentControlPlane(
        SyncStore(tmp_path / "app.db", tree_configured=True),
        tmp_path / "config",
        host="127.0.0.1",
        port=0,
        ca_cert=external / CA_CERT,
        ca_key=external / CA_KEY,
    )
    with pytest.raises(AgentControlError, match="expired"):
        plane.start()


def test_a_brought_ca_issues_the_listener_certificate(tmp_path: Path) -> None:
    external = tmp_path / "external-ca"
    external.mkdir()
    _key, ca_cert = _load_or_create_ca(external)
    sync = SyncStore(tmp_path / "app.db", tree_configured=True)
    config = tmp_path / "config"
    config.mkdir()
    plane = AgentControlPlane(
        sync,
        config,
        host="127.0.0.1",
        port=0,
        hostname="credarr.test",
        ca_cert=external / CA_CERT,
        ca_key=external / CA_KEY,
    )
    plane.start()
    try:
        public = (config / CA_CERT).read_text(encoding="utf-8")
        listener = x509.load_pem_x509_certificate(
            (config / SERVER_CERT).read_bytes()
        )
        assert "BEGIN CERTIFICATE" in public
        assert listener.issuer == ca_cert.subject
        assert plane.info()["ca"] is True
    finally:
        plane.stop()


def test_a_brought_ca_needs_both_paths(tmp_path: Path) -> None:
    sync = SyncStore(tmp_path / "app.db", tree_configured=True)
    config = tmp_path / "config"
    config.mkdir()
    cert = tmp_path / "ca.crt"
    cert.write_text("not a certificate", encoding="utf-8")
    plane = AgentControlPlane(
        sync,
        config,
        host="127.0.0.1",
        port=0,
        ca_cert=cert,
    )
    with pytest.raises(AgentControlError, match="both CREDARR_AGENT_CA_CERT"):
        plane.start()


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
