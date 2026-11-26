"""The agent control plane: mTLS enrollment and pull-only job delivery.

The BFF never runs Docker. This listener issues short-lived client certificates,
leases one job at a time to an enrolled agent, and records the agent's result.
It speaks TLS 1.3 only and requires a client certificate on every route except
enrollment. The agent pulls; there is no inbound privileged listener on the
agent host and no value crosses this channel.

Certificate material is a private key beside the database (`agent-ca.key`,
`agent-server.key`), included in the encrypted backup. The CA key is protected
by file mode, not the KEK: it signs agents, it does not decrypt values, and
feeding it through the value store would couple two independent failure modes.
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .sync_store import Agent, PolicyViolation, SyncError, SyncStore
from .vault import _write_private

CA_KEY = "agent-ca.key"
CA_CERT = "agent-ca.crt"
SERVER_KEY = "agent-server.key"
SERVER_CERT = "agent-server.crt"
CLIENT_DAYS = 1
SERVER_DAYS = 30
CA_DAYS = 3650
MAX_BODY = 64 * 1024
CLOCK_SKEW_SECONDS = 300.0


class AgentControlError(Exception):
    pass


def _pem_key(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _load_or_create_ca(config_dir: Path) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key_path = config_dir / CA_KEY
    cert_path = config_dir / CA_CERT
    if key_path.is_file() and cert_path.is_file():
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        if not isinstance(key, ec.EllipticCurvePrivateKey):  # pragma: no cover - defensive
            raise AgentControlError("the agent CA key is not an EC key")
        return key, cert
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "credarr agent CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    _write_private(key_path, _pem_key(key))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert


def _server_certificate(
    config_dir: Path,
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    *,
    hostname: str | None = None,
) -> tuple[Path, Path]:
    key_path = config_dir / SERVER_KEY
    cert_path = config_dir / SERVER_CERT
    names = ["localhost", "127.0.0.1", "::1"]
    if hostname:
        names.append(hostname)
    if key_path.is_file() and cert_path.is_file():
        try:
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            renew_after = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
            if cert.not_valid_after_utc > renew_after and _covers(cert, names):
                return key_path, cert_path
        except (ValueError, OSError):
            pass
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "credarr agent listener")])
    san = []
    for name in dict.fromkeys(names):
        try:
            san.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            san.append(x509.DNSName(name))
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=SERVER_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    _write_private(key_path, _pem_key(key))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path


def _covers(certificate: x509.Certificate, names: list[str]) -> bool:
    try:
        san = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        return False
    for name in names:
        try:
            if ipaddress.ip_address(name) in san.get_values_for_type(x509.IPAddress):
                continue
        except ValueError:
            if name in san.get_values_for_type(x509.DNSName):
                continue
        return False
    return True


def _sign_csr(
    csr_pem: str,
    *,
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    common_name: str,
    days: int = CLIENT_DAYS,
) -> tuple[str, x509.Certificate]:
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
    except (ValueError, TypeError):
        raise AgentControlError(
            "the enrollment request is not a PEM certificate request"
        ) from None
    if not csr.is_signature_valid:
        raise AgentControlError("the certificate request signature is not valid")
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name[:64])])
        )
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"), cert


def _fingerprint(certificate: x509.Certificate) -> str:
    return hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()


class _Server(ThreadingHTTPServer):
    authority: AgentControlPlane


class _Handler(BaseHTTPRequestHandler):
    server_version = "credarr-agent/1"
    sys_version = ""

    def log_message(self, fmt: str, *args: object) -> None:
        return

    @property
    def authority(self) -> AgentControlPlane:
        return self.server.authority  # type: ignore[attr-defined]

    def _body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("content-length", "0"))
        except ValueError:
            raise AgentControlError("invalid content length") from None
        if length <= 0 or length > MAX_BODY:
            raise AgentControlError("the request body is missing or too large")
        try:
            value = json.loads(self.rfile.read(length))
        except ValueError:
            raise AgentControlError("the request body is not JSON") from None
        if not isinstance(value, dict):
            raise AgentControlError("the request body must be an object")
        return value

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.send_header("cache-control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _peer(self) -> x509.Certificate | None:
        der = self.connection.getpeercert(binary_form=True)
        if not der:
            return None
        try:
            return x509.load_der_x509_certificate(der)
        except ValueError:
            return None

    def _agent(self) -> Agent:
        certificate = self._peer()
        if certificate is None:
            raise AgentControlError("a client certificate is required")
        agent = self.authority.sync.authenticate(_fingerprint(certificate))
        if agent is None:
            raise PolicyViolation("the agent certificate is unknown or revoked")
        self.authority.sync.touch(agent.id)
        return agent

    def _clock(self, body: dict[str, Any]) -> None:
        stamp = body.get("timestamp")
        if not isinstance(stamp, (int, float)) or isinstance(stamp, bool):
            raise AgentControlError("a timestamp is required")
        if abs(time.time() - float(stamp)) > CLOCK_SKEW_SECONDS:
            raise AgentControlError(
                "the agent clock is too far from the server clock; check NTP"
            )

    def _certificate(self, agent_name: str, csr: str) -> tuple[str, x509.Certificate]:
        ca_key, ca_cert = _load_or_create_ca(self.authority.config_dir)
        return _sign_csr(csr, ca_key=ca_key, ca_cert=ca_cert, common_name=agent_name)

    def do_GET(self) -> None:
        if self.path == "/v1/info":
            self._send(200, self.authority.info())
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        try:
            body = self._body()
            if self.path == "/v1/enroll":
                self._enroll(body)
            elif self.path == "/v1/heartbeat":
                self._heartbeat(body)
            elif self.path == "/v1/jobs/lease":
                self._lease(body)
            elif self.path.startswith("/v1/jobs/"):
                self._job(body)
            elif self.path == "/v1/certificate/renew":
                self._renew(body)
            else:
                self._send(404, {"error": "not found"})
        except PolicyViolation as exc:
            self._send(403, {"error": str(exc)})
        except (AgentControlError, SyncError) as exc:
            self._send(409, {"error": str(exc)})
        except Exception:
            self._send(
                500,
                {"error": "the control plane could not complete the request"},
            )

    def _enroll(self, body: dict[str, Any]) -> None:
        token = body.get("token")
        name = body.get("name")
        csr = body.get("csr")
        if not isinstance(token, str) or not token:
            raise AgentControlError("an enrollment token is required")
        if not isinstance(name, str) or not name:
            raise AgentControlError("an agent name is required")
        if not isinstance(csr, str):
            raise AgentControlError("a certificate request is required")
        certificate, parsed = self._certificate(name, csr)
        agent = self.authority.sync.consume_enrollment(
            token,
            fingerprint=_fingerprint(parsed),
            expires_at=parsed.not_valid_after_utc.timestamp(),
            rootful=bool(body.get("rootful")),
            ack=bool(body.get("rootful_ack")),
        )
        self._send(
            200,
            {
                "agent": agent.as_json(),
                "certificate": certificate,
                "ca": (self.authority.config_dir / CA_CERT).read_text(encoding="utf-8"),
                "expires_at": parsed.not_valid_after_utc.timestamp(),
            },
        )

    def _rootful_guard(self, agent: Agent, body: dict[str, Any]) -> None:
        if bool(body.get("rootful")) and not agent.rootful_ack:
            self.authority.sync.disable(
                agent.id,
                "the agent reported rootful mode without an acknowledgment",
            )
            raise PolicyViolation(
                "rootful mode needs an explicit acknowledgment before use"
            )

    def _heartbeat(self, body: dict[str, Any]) -> None:
        agent = self._agent()
        self._clock(body)
        self._rootful_guard(agent, body)
        self._send(200, {"status": agent.status, "now": time.time()})

    def _lease(self, body: dict[str, Any]) -> None:
        agent = self._agent()
        self._clock(body)
        self._rootful_guard(agent, body)
        leased = self.authority.sync.lease(agent)
        if leased is None:
            self._send(200, {"job": None})
            return
        job, target = leased
        self._send(
            200,
            {"job": job.as_json(), "target": target.as_json(), "now": time.time()},
        )

    def _job(self, body: dict[str, Any]) -> None:
        parts = self.path.strip("/").split("/")
        if len(parts) != 4 or parts[:2] != ["v1", "jobs"]:
            self._send(404, {"error": "not found"})
            return
        agent = self._agent()
        self._clock(body)
        job_id, action = parts[2], parts[3]
        if action == "begin":
            job = self.authority.sync.begin(job_id, agent)
            self._send(200, {"job": job.as_json()})
            return
        if action == "result":
            services = body.get("services")
            if not isinstance(services, dict):
                raise AgentControlError("services must be an object of booleans")
            job = self.authority.sync.report(
                job_id,
                agent,
                services=services,
                detail=str(body.get("detail") or "")[:500],
            )
            self._send(200, {"job": job.as_json()})
            return
        self._send(404, {"error": "not found"})

    def _renew(self, body: dict[str, Any]) -> None:
        agent = self._agent()
        self._clock(body)
        csr = body.get("csr")
        if not isinstance(csr, str):
            raise AgentControlError("a certificate request is required")
        certificate, parsed = self._certificate(agent.name, csr)
        self.authority.sync.renew_certificate(
            agent.id,
            fingerprint=_fingerprint(parsed),
            expires_at=parsed.not_valid_after_utc.timestamp(),
        )
        self._send(
            200,
            {
                "certificate": certificate,
                "expires_at": parsed.not_valid_after_utc.timestamp(),
            },
        )


class AgentControlPlane:
    """The HTTPS listener, its CA, and its connection to the sync store."""

    def __init__(
        self,
        sync: SyncStore,
        config_dir: Path,
        *,
        host: str = "127.0.0.1",
        port: int = 8443,
        hostname: str | None = None,
    ) -> None:
        self.sync = sync
        self.config_dir = Path(config_dir)
        self.host = host
        self.port = port
        self.hostname = hostname
        self.failure: str | None = None
        self.pq_group: str | None = None
        self.tls_version: str = "TLSv1.3"
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None

    def _context(self) -> ssl.SSLContext:
        ca_key, ca_cert = _load_or_create_ca(self.config_dir)
        key_path, cert_path = _server_certificate(
            self.config_dir, ca_key, ca_cert, hostname=self.hostname
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_OPTIONAL
        context.load_cert_chain(cert_path, key_path)
        context.load_verify_locations(cafile=str(self.config_dir / CA_CERT))
        # Prefer the hybrid group when the linked OpenSSL exposes it. A
        # classical TLS 1.3 group is the documented fallback; cleartext is not.
        for group in ("X25519MLKEM768", "X25519"):
            try:
                context.set_ecdh_curve(group)
                self.pq_group = group
                break
            except (ValueError, ssl.SSLError):
                continue
        return context

    def info(self) -> dict[str, Any]:
        url = None
        if self._server is not None and self.hostname and self.port:
            url = f"https://{self.hostname}:{self.port}"
        return {
            "enabled": self._server is not None,
            "host": self.host,
            "port": self.port,
            "hostname": self.hostname,
            "url": url,
            "tls": self.tls_version,
            "group": self.pq_group,
            "failure": self.failure,
            "ca": (self.config_dir / CA_CERT).is_file(),
        }

    def start(self) -> None:
        if self._server is not None:
            return
        context = self._context()
        server = _Server((self.host, self.port), _Handler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.authority = self
        self.port = server.server_address[1]
        self._server = server

        def serve() -> None:
            try:
                server.serve_forever(poll_interval=0.5)
            except Exception as exc:  # pragma: no cover - listener failure
                self.failure = f"{type(exc).__name__}: {exc}"

        self._thread = threading.Thread(
            target=serve, name="credarr-agent-plane", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
