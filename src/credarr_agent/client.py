"""The outbound agent: enrollment, pull, and allowlisted compose deploys.

This process is the only place Docker is touched. It holds no inbound listener,
reads values from the shared vault tree, and sends the BFF only job ids,
booleans and short failure sentences. Its allowed stack roots and capabilities
are checked again on every job, not only at enrollment.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from credarr.paths import fsync_directory

MAX_BODY = 64 * 1024
REQUEST_TIMEOUT = 30.0
COMPOSE_TIMEOUT = 180.0


class AgentError(Exception):
    pass


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


@dataclass(frozen=True, slots=True)
class AgentConfig:
    server: str
    state_dir: Path
    vault_root: Path
    vault_key: Path
    allowed_roots: tuple[Path, ...]
    ca_path: Path
    cert_path: Path
    key_path: Path
    rootful: bool
    ack_rootful: bool
    poll_seconds: float = 5.0

    @property
    def certificate(self) -> bool:
        return self.cert_path.is_file() and self.key_path.is_file()


class AgentClient:
    """One HTTPS client: TLS 1.3 only, CA-pinned, client certificate when enrolled."""

    def __init__(self, config: AgentConfig) -> None:
        parsed = urllib.parse.urlsplit(config.server)
        if parsed.scheme != "https" or not parsed.netloc:
            raise AgentError("the agent server must be an https URL")
        self.base = f"{parsed.scheme}://{parsed.netloc}"
        self.config = config
        self.context = ssl.create_default_context(cafile=str(config.ca_path))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        if config.certificate:
            self.context.load_cert_chain(config.cert_path, config.key_path)

    def post(self, path: str, body: dict[str, object]) -> dict[str, object]:
        raw = json.dumps(body, sort_keys=True).encode("utf-8")
        if len(raw) > MAX_BODY:
            raise AgentError("the request body is too large")
        request = urllib.request.Request(  # noqa: S310 - https URL checked above
            self.base + path,
            data=raw,
            method="POST",
            headers={"content-type": "application/json"},
        )
        try:
            with urllib.request.urlopen(  # noqa: S310 - https URL checked above
                request, context=self.context, timeout=REQUEST_TIMEOUT
            ) as response:
                payload = json.loads(response.read(MAX_BODY))
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read(MAX_BODY)).get("error", "")
            except (ValueError, AttributeError):
                detail = ""
            raise AgentError(f"the server refused the request ({exc.code}): {detail}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise AgentError(f"the agent could not reach the server: {exc}") from None
        if not isinstance(payload, dict):
            raise AgentError("the server sent a non-object response")
        return payload


def certificate_expiry(config: AgentConfig) -> float | None:
    """The client certificate's notAfter as a Unix timestamp, if readable."""
    try:
        from cryptography import x509

        certificate = x509.load_pem_x509_certificate(config.cert_path.read_bytes())
        return certificate.not_valid_after_utc.timestamp()
    except (OSError, ValueError):
        return None


def renew(config: AgentConfig, *, name: str) -> None:
    """Replace the client certificate using the existing key."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    key = serialization.load_pem_private_key(config.key_path.read_bytes(), password=None)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name[:64])]))
        .sign(key, hashes.SHA256())
    )
    client = AgentClient(config)
    answer = client.post(
        "/v1/certificate/renew",
        {
            "timestamp": time.time(),
            "csr": csr.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        },
    )
    certificate = answer.get("certificate")
    if not isinstance(certificate, str):
        raise AgentError("the server did not return a renewed certificate")
    _write_private(config.cert_path, certificate.encode("utf-8"))


def enroll(config: AgentConfig, token: str, *, name: str, capabilities: tuple[str, ...]) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    if not config.ca_path.is_file():
        raise AgentError(
            f"the server CA certificate is not at {config.ca_path}; copy it from "
            "the BFF data directory before enrolling"
        )
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name[:64])]))
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    client = AgentClient(config)
    answer = client.post(
        "/v1/enroll",
        {
            "token": token,
            "name": name,
            "csr": csr_pem,
            "capabilities": list(capabilities),
            "rootful": config.rootful,
            "rootful_ack": config.ack_rootful,
        },
    )
    certificate = answer.get("certificate")
    if not isinstance(certificate, str):
        raise AgentError("the server did not return a client certificate")
    _write_private(config.key_path, key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    _write_private(config.cert_path, certificate.encode("utf-8"))


class Workflow:
    """The fixed, allowlisted deploy surface. No shell, no user code."""

    def __init__(self, config: AgentConfig) -> None:
        self.config = config

    def _rooted(self, path: str) -> Path:
        candidate = Path(path).resolve()
        roots = [root.resolve() for root in self.config.allowed_roots]
        if not any(candidate == root or root in candidate.parents for root in roots):
            raise AgentError("the target stack is outside the agent's allowed roots")
        if not candidate.is_dir():
            raise AgentError("the target stack directory does not exist")
        return candidate

    def _compose_file(self, stack: Path) -> str:
        for name in ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"):
            if (stack / name).is_file():
                return name
        raise AgentError("the target stack has no compose file")

    def _rootless(self) -> bool:
        try:
            completed = subprocess.run(
                ["docker", "info", "--format", "{{json .SecurityOptions}}"],  # noqa: S607
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            raise AgentError(f"docker is unavailable: {exc}") from None
        if completed.returncode != 0:
            raise AgentError("docker info failed; the agent cannot determine its privilege mode")
        return "rootless" in completed.stdout.lower()

    def preflight(self) -> None:
        if not self._rootless() and not (self.config.rootful and self.config.ack_rootful):
            raise AgentError(
                "the Docker daemon is rootful; start a rootless daemon or pass "
                "--rootful --ack-rootful after reading the threat model"
            )

    def _env_path(self, stack: Path, raw: object) -> Path:
        candidate = str(raw or "")
        if (
            not candidate
            or Path(candidate).is_absolute()
            or ".." in Path(candidate).parts
        ):
            raise AgentError("the target env file must be a relative path without '..'")
        path = (stack / candidate).resolve()
        if path != stack and stack not in path.parents:
            raise AgentError("the target env file escapes the allowed stack")
        return path

    def _update_env(self, target: dict[str, object], credential: str, value: str) -> None:
        stack = self._rooted(str(target["stack_path"]))
        path = self._env_path(stack, target.get("env_file"))
        mapping = target.get("values")
        if not isinstance(mapping, dict) or not mapping:
            raise AgentError("the env target has no key mapping")
        keys = sorted(
            str(key) for key, owner in mapping.items() if str(owner) == credential
        )
        if not keys:
            raise AgentError("the env target has no key for this credential")
        if (
            not value
            or value != value.strip()
            or value.startswith("#")
            or any(character in value for character in "\r\n\x00")
        ):
            raise AgentError("the value cannot be represented safely in an env file")
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            text = ""
        except OSError as exc:
            raise AgentError(f"the env file is unreadable: {exc.strerror}") from None
        selected = set(keys)
        seen: set[str] = set()
        output: list[str] = []
        for line in text.splitlines():
            match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=", line)
            if match and match.group(1) in selected:
                key = match.group(1)
                if key in seen:
                    continue
                output.append(f"{key}={value}")
                seen.add(key)
            else:
                output.append(line)
        for key in keys:
            if key not in seen:
                output.append(f"{key}={value}")
        path.parent.mkdir(parents=True, exist_ok=True)
        _write_private(path, ("\n".join(output) + "\n").encode("utf-8"))
        fsync_directory(path.parent)

    def write_env(
        self, target: dict[str, object], credential: str, value: str
    ) -> dict[str, bool]:
        self._update_env(target, credential, value)
        return self.compose(target)

    def probe(self, target: dict[str, object]) -> dict[str, bool]:
        """Validate a target without writing a value or recreating a service."""
        stack = self._rooted(str(target["stack_path"]))
        compose_file = self._compose_file(stack)
        services = [str(name) for name in target.get("services") or []]
        if not services:
            raise AgentError("the target declares no services")
        if str(target.get("workflow") or "compose") == "env":
            path = self._env_path(stack, target.get("env_file"))
            mapping = target.get("values")
            if not isinstance(mapping, dict) or not mapping:
                raise AgentError("the env target has no key mapping")
            if not path.is_file() or not os.access(path, os.W_OK):
                raise AgentError("the env file is missing or not writable")
        try:
            completed = subprocess.run(  # noqa: S603
                [  # noqa: S607
                    "docker", "compose",
                    "-f", str(stack / compose_file),
                    "-p", str(target["project_name"]),
                    "--project-directory", str(stack),
                    "config", "--quiet",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=COMPOSE_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            return dict.fromkeys(services, False)
        ok = completed.returncode == 0
        return dict.fromkeys(services, ok)

    def compose(self, target: dict[str, object]) -> dict[str, bool]:
        stack = self._rooted(str(target["stack_path"]))
        compose_file = self._compose_file(stack)
        project = str(target["project_name"])
        services = list(target.get("services") or [])
        if not services:
            raise AgentError("the target declares no services")
        results: dict[str, bool] = {}
        for service in services:
            try:
                completed = subprocess.run(  # noqa: S603
                    [  # noqa: S607
                        "docker", "compose",
                        "-f", str(stack / compose_file),
                        "-p", project,
                        "--project-directory", str(stack),
                        "up", "-d", "--no-deps", "--force-recreate",
                        str(service),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=COMPOSE_TIMEOUT,
                )
            except subprocess.TimeoutExpired:
                results[str(service)] = False
                continue
            results[str(service)] = completed.returncode == 0
        return results


def run(config: AgentConfig, *, once: bool = False) -> int:
    from credarr_server.vault import VaultError, VaultTree

    if not config.certificate:
        raise AgentError("the agent has no certificate; enroll it first")
    tree = VaultTree(config.vault_root, config.vault_key)
    workflow = Workflow(config)
    workflow.preflight()
    client = AgentClient(config)
    while True:
        try:
            expiry = certificate_expiry(config)
            if expiry is not None and expiry - time.time() < 6 * 3600:
                renew(config, name=config.cert_path.parent.name or "agent")
                client = AgentClient(config)
            lease = client.post(
                "/v1/jobs/lease",
                {"timestamp": time.time(), "rootful": config.rootful},
            )
            job = lease.get("job")
            if not isinstance(job, dict):
                if once:
                    return 0
                time.sleep(config.poll_seconds + secrets.randbelow(1000) / 4000.0)
                continue
            target = lease.get("target")
            if not isinstance(target, dict):
                raise AgentError("the lease carried no target")
            probe = str(job.get("kind") or "delivery") == "probe"
            if probe:
                value = ""
            else:
                try:
                    value = tree.verify(
                        str(job["credential"]), str(job["value_version"])
                    )
                except VaultError as exc:
                    client.post(
                        f"/v1/jobs/{job['id']}/result",
                        {
                            "timestamp": time.time(),
                            "services": {
                                str(name): False for name in target["services"]
                            },
                            "detail": f"shared vault preflight failed: {exc}",
                        },
                    )
                    if once:
                        return 1
                    continue
            client.post(f"/v1/jobs/{job['id']}/begin", {"timestamp": time.time()})
            try:
                if probe:
                    results = workflow.probe(target)
                elif str(target.get("workflow") or "compose") == "env":
                    results = workflow.write_env(
                        target, str(job["credential"]), value
                    )
                else:
                    results = workflow.compose(target)
            except AgentError as exc:
                results = {str(name): False for name in target["services"]}
                detail = str(exc)
            else:
                detail = ""
            client.post(
                f"/v1/jobs/{job['id']}/result",
                {
                    "timestamp": time.time(),
                    "services": results,
                    "detail": detail,
                },
            )
        except AgentError:
            if once:
                raise
            time.sleep(config.poll_seconds)
        if once:
            return 0
        time.sleep(config.poll_seconds + secrets.randbelow(1000) / 4000.0)
