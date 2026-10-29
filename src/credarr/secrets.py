"""Reading canonical credential values, behind a backend interface.

The tool must not care where secrets live. Two backends ship:

  ansible-vault  decrypts the whole file once, then navigates in Python. The
                 whole document does enter memory, but only for the life of the
                 process and it never reaches argv, a log or a report.

  sops           uses --extract, so exactly one value is decrypted at a time.
                 Lower exposure, at the cost of one subprocess per value. This
                 is the backend to prefer if the choice is open to you.

Both keep plaintext out of argv. The only secret-adjacent argument either takes
is a *path* to a password or key file, never the value itself - a value in argv
is visible to every process on the host through /proc.
"""

from __future__ import annotations

import fcntl
import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Protocol

from .errors import ConfigError, SecretSourceError
from .model import VaultRef
from .redact import Secret

# sops and ansible-vault both write progress and warnings to stderr. Only the
# last few lines are useful and an unbounded dump into an exception would end up
# in a CI log, so stderr is truncated rather than trusted.
_MAX_ERROR_CHARS = 400


class SecretSource(Protocol):
    """Anything that can produce the canonical value for a VaultRef."""

    name: str

    def get(self, ref: VaultRef) -> Secret | None:
        """Return the value, or None when the path is absent from the store.

        None means "this path does not exist", which is different from "this
        backend failed". Callers must treat them differently: a missing path is
        usually a manifest that disagrees with reality, a failure is an
        operational problem.
        """
        ...


class AnsibleVaultSource:
    """Reads an Ansible-encrypted YAML file.

    The file is decrypted once and cached. The vault password is referenced by
    path, never passed on the command line.
    """

    name = "ansible-vault"

    def __init__(
        self,
        *,
        password_file: Path | str,
        binary: str = "ansible-vault",
        root: Path | None = None,
    ) -> None:
        self._password_file = Path(password_file)
        self._binary = binary
        self._root = root or Path.cwd()
        self._cache: dict[Path, Any] = {}

    def get(self, ref: VaultRef) -> Secret | None:
        path = self._resolve(ref.file)
        if path not in self._cache:
            self._cache[path] = self._decrypt(path)
        value = ref.navigate(self._cache[path])
        if value is None:
            return None
        if not isinstance(value, str):
            raise SecretSourceError(
                f"{ref.file}: {'.'.join(ref.path)} is a "
                f"{type(value).__name__}, not a string",
                hint="a credential must be a scalar; a mapping here usually "
                "means the manifest path points one level too high",
            )
        return Secret(value)

    def _resolve(self, candidate: str) -> Path:
        path = Path(candidate)
        return path if path.is_absolute() else self._root / path

    def _decrypt(self, path: Path) -> Any:
        if not self._password_file.is_file():
            raise ConfigError(
                f"vault password file {self._password_file} does not exist",
                hint="set vault_password_file in the config, or pass "
                "--vault-password-file",
            )
        try:
            completed = subprocess.run(  # noqa: S603
                [
                    self._binary,
                    "view",
                    "--vault-password-file",
                    str(self._password_file),
                    str(path),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
            )
        except FileNotFoundError as exc:
            raise ConfigError(
                f"{self._binary} is not installed",
                hint="install Ansible, or switch the vault backend to sops",
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise SecretSourceError(f"decrypting {path} timed out") from exc

        if completed.returncode != 0:
            # Wrong password is the overwhelmingly likely cause and the most
            # common misconfiguration, so name it rather than leaving the
            # operator to decode ansible's message.
            raise SecretSourceError(
                f"could not decrypt {path}: {_tail(completed.stderr)}",
                hint="check the vault password file; a wrong password and an "
                "unreadable file produce the same failure here",
            )
        try:
            return json.loads(json.dumps(_yaml_load(completed.stdout)))
        except Exception as exc:
            raise SecretSourceError(f"{path}: decrypted content is not valid YAML: {exc}") from exc


class SopsSource:
    """Reads a SOPS-encrypted file one value at a time via --extract.

    --extract was chosen over decrypting the whole file because it keeps the
    blast radius of a decrypt to the single value being compared, and the
    values in a vault are overwhelmingly passwords, which are the easiest kind
    of secret to leak and the hardest to rotate after the fact.
    """

    name = "sops"

    def __init__(
        self,
        *,
        binary: str = "sops",
        root: Path | None = None,
        timeout: int = 60,
    ) -> None:
        self._binary = binary
        self._root = root or Path.cwd()
        self._timeout = timeout

    def get(self, ref: VaultRef) -> Secret | None:
        path = Path(ref.file)
        if not path.is_absolute():
            path = self._root / path
        tree_path = "".join(f"[{json.dumps(segment)}]" for segment in ref.path)
        try:
            completed = subprocess.run(  # noqa: S603
                [self._binary, "-d", "--extract", tree_path, str(path)],
                capture_output=True,
                text=True,
                check=False,
                timeout=self._timeout,
            )
        except FileNotFoundError as exc:
            raise ConfigError(
                f"{self._binary} is not installed",
                hint="install sops and age, or switch the vault backend to ansible-vault",
            ) from exc
        except subprocess.TimeoutExpired as exc:
            joined = ".".join(ref.path)
            raise SecretSourceError(f"extracting {joined} from {path} timed out") from exc

        if completed.returncode != 0:
            raise SecretSourceError(
                f"sops could not read {tree_path} from {path}: {_tail(completed.stderr)}",
                hint="the age key comes from SOPS_AGE_KEY or ~/.config/sops/age/keys.txt; "
                "if the key is fine, the path does not exist in this file",
            )
        # A path that is not a scalar still exits 0, and what it prints depends
        # on the *encrypted file's* format rather than the flag: extracting a
        # nested object out of a YAML file yields a YAML fragment like
        # `d: "y"`, and --output-type json does not change that. So the format
        # of the output cannot be assumed, and the only reliable way to tell a
        # collection from a credential is to parse what came back.
        #
        # The parse is used only to detect containers. The value returned is the
        # raw bytes, never the parsed form, so nothing normalises a credential
        # on its way through.
        value = completed.stdout.rstrip("\n")
        if value and _is_collection(value):
            raise SecretSourceError(
                f"sops: {tree_path} in {path} is a collection, not a scalar",
                hint="a vault path must address one credential value",
            )
        return Secret(value) if value != "" else None


class MutableAnsibleVaultSource(AnsibleVaultSource):
    """An ansible-vault source that can also write.

    A rotation that updates the services but not the vault leaves the canonical
    copy stale, which means the next redeploy puts the old key back and every
    check reports drift. Half a rotation is worse than none.

    Writing decrypts the whole file, replaces one value and re-encrypts. The
    file is whole-file encrypted, so there is no finer-grained option. The
    read-modify-write holds an exclusive lock, and the encrypted result is
    renamed over the vault, so a crash or a second writer cannot leave a
    truncated vault. Plaintext lives in memory and in a private 0700 work
    directory that is removed even when encryption fails.
    """

    # Without this, ansible-vault exits 5 on a vault declaring more than one
    # id, because it refuses to guess which one to encrypt to.
    ENCRYPT_VAULT_ID = "default"

    def set(self, ref: VaultRef, value: Secret) -> None:
        import yaml

        path = self._resolve(ref.file)
        with self._write_lock(path):
            document = self._decrypt(path)

            node = document
            for segment in ref.path[:-1]:
                if not isinstance(node, dict) or segment not in node:
                    raise SecretSourceError(
                        f"{ref.file}: cannot set {'.'.join(ref.path)}; "
                        f"{segment!r} does not exist"
                    )
                node = node[segment]
            if not isinstance(node, dict):
                raise SecretSourceError(f"{ref.file}: {'.'.join(ref.path)} is not a mapping")

            node[ref.path[-1]] = value.reveal()

            work = Path(tempfile.mkdtemp(prefix="credarr-vault-", dir=path.parent))
            plaintext = work / "vault.yml"
            encrypted = work / "vault.enc"
            try:
                descriptor = os.open(
                    plaintext, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                )
                with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                    yaml.safe_dump(
                        document, stream, default_flow_style=False, sort_keys=False
                    )
                    stream.flush()
                    os.fsync(stream.fileno())
                # ansible-vault writes the ciphertext to a sibling, so the live
                # vault is untouched until every step has succeeded.
                self._encrypt(plaintext, encrypted)
                if not encrypted.is_file():
                    raise SecretSourceError(
                        f"re-encrypting {path} produced no output"
                    )
                with encrypted.open("rb") as stream:
                    os.fsync(stream.fileno())
                encrypted.replace(path)
                _fsync_directory(path.parent)
            finally:
                # Removed even when the encrypt step failed, or a rotation
                # failure would leave every credential in the homelab in a
                # temporary file. The directory is 0700 and the file 0600.
                shutil.rmtree(work, ignore_errors=True)

        # The cached document is now wrong in a way that matters.
        self._cache.pop(path, None)

    @contextmanager
    def _write_lock(self, path: Path) -> Iterator[None]:
        """Serialize read-modify-write across processes.

        The lock file carries no secret; the vault itself is replaced
        atomically while this is held.
        """
        lock_path = path.with_name(f".{path.name}.lock")
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            # Closing releases the flock; an explicit unlock adds a second
            # failure point with nothing to gain.
            os.close(descriptor)

    def _encrypt(self, source: Path, destination: Path) -> None:
        try:
            completed = subprocess.run(  # noqa: S603
                [
                    self._binary, "encrypt",
                    "--vault-password-file", str(self._password_file),
                    "--encrypt-vault-id", self.ENCRYPT_VAULT_ID,
                    "--output", str(destination),
                    str(source),
                ],
                capture_output=True, text=True, check=False, timeout=120,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            raise SecretSourceError(f"could not re-encrypt {destination}: {exc}") from exc

        if completed.returncode != 0:
            raise SecretSourceError(
                f"re-encrypting {destination} failed: {_tail(completed.stderr)}",
                hint="exit 5 usually means the vault declares more than one "
                "id; --encrypt-vault-id names the one to use",
            )


class StaticSource:
    """An in-memory source. Used by the test suite and by anyone who wants to
    try the tool against a fixture without a real vault."""

    name = "static"

    def __init__(self, document: Mapping[str, Any]) -> None:
        self._document = document

    def get(self, ref: VaultRef) -> Secret | None:
        value = ref.navigate(self._document)
        if value is None:
            return None
        if not isinstance(value, str):
            raise SecretSourceError(f"{'.'.join(ref.path)} is not a string")
        return Secret(value)


# Registered backends, by the name a manifest uses in vault.backend.
BACKENDS = ("ansible-vault", "sops")


def build_source(
    backend: str,
    *,
    config_dir: Path,
    vault_password_file: Path | None = None,
    mutable: bool = False,
) -> SecretSource:
    """Construct a backend by name, validating its prerequisites up front so the
    failure names the missing piece rather than surfacing later as a mystery.

    `mutable` returns a backend that can also write. Rotation needs one; an
    audit does not, and handing a read-only capability to code that only reads
    is the safer default.
    """
    if backend == "ansible-vault":
        if vault_password_file is None:
            raise ConfigError(
                "the ansible-vault backend needs a vault password file",
                hint="set vault_password_file in the config",
            )
        factory = MutableAnsibleVaultSource if mutable else AnsibleVaultSource
        return factory(password_file=vault_password_file, root=config_dir)
    if backend == "sops":
        if shutil.which("sops") is None:
            raise ConfigError(
                "sops is not on PATH",
                hint="install sops and age, or set the credential's "
                "vault.backend to ansible-vault",
            )
        return SopsSource(root=config_dir)
    raise ConfigError(
        f"unknown vault backend {backend!r}",
        hint=f"known backends: {', '.join(BACKENDS)}",
    )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _is_collection(text: str) -> bool:
    """Does this look like a mapping or a sequence rather than a scalar?

    A credential that happens to parse as a mapping - one literally containing a
    colon - would be rejected. That errs towards refusing a value, which is the
    right direction: returning a plausible-looking string that is not the
    credential is far worse than reporting that the path needs attention.
    """
    import yaml

    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError:
        # Not parseable, therefore not a container we can recognise. Treat it as
        # an opaque scalar rather than guessing.
        return False
    return isinstance(parsed, (dict, list))


def _yaml_load(text: str) -> Any:
    import yaml

    return yaml.safe_load(text)


def _tail(stderr: str) -> str:
    """The last meaningful lines of a subprocess error, bounded."""
    lines = [line for line in stderr.strip().splitlines() if line.strip()]
    return " | ".join(lines[-3:])[:_MAX_ERROR_CHARS] or "no output"
