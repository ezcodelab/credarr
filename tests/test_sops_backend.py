"""SOPS backend, tested against the real sops binary.

This is an integration test because the backend is a thin wrapper around a
subprocess, and a wrapper that has only ever been reasoned about is exactly the
kind of thing that is wrong. The --extract path syntax, the exit codes, and the
behaviour when the age key is missing are all properties of sops rather than of
this package, and only running it establishes them.

Skipped when sops or age is not installed, so a contributor without them still
gets the rest of the suite. Everything else in the tool is covered offline.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from credarr.errors import ConfigError, SecretSourceError
from credarr.model import VaultRef
from credarr.secrets import SopsSource, build_source

pytestmark = pytest.mark.skipif(
    shutil.which("sops") is None or shutil.which("age-keygen") is None,
    reason="sops and age are needed to test the sops backend",
)

PLAINTEXT = {
    "vault_env_secrets": {
        "sonarr": {"API_KEY": "value-one", "EMPTY": ""},
        "prowlarr": {"API_KEY": "value-two"},
        "odd": {"NOT_A_SCALAR": {"nested": "dict"}},
        "tricky": {"WITH SPACE": "value three", "WITH-DASH": "value-four"},
    }
}


@pytest.fixture
def sops_file(tmp_path: Path) -> tuple[Path, str]:
    """A real SOPS-encrypted file, encrypted to a throwaway age key."""
    age_dir = tmp_path / "age"
    age_dir.mkdir()
    key_file = age_dir / "keys.txt"
    subprocess.run(
        ["age-keygen", "-o", str(key_file)], check=True, capture_output=True
    )
    key_text = key_file.read_text()
    public = next(
        line.split("public key: ")[1].strip()
        for line in key_text.splitlines()
        if "public key:" in line
    )

    plain = tmp_path / "secrets.yaml"
    plain.write_text(json.dumps(PLAINTEXT, indent=2))

    encrypted = tmp_path / "secrets.enc.yaml"
    completed = subprocess.run(
        ["sops", "--encrypt", "--age", public, str(plain)],
        check=True, capture_output=True, text=True,
    )
    encrypted.write_text(completed.stdout)
    plain.unlink()
    return encrypted, key_text.strip()


def _ref(*path: str) -> VaultRef:
    return VaultRef(backend="sops", file="secrets.enc.yaml", path=path)


def _source(tmp_path: Path, key_text: str, monkeypatch) -> SopsSource:
    monkeypatch.setenv("SOPS_AGE_KEY", key_text)
    return SopsSource(root=tmp_path)


def test_reads_a_single_value_by_path(sops_file, tmp_path, monkeypatch):
    _encrypted, key_text = sops_file
    source = _source(tmp_path, key_text, monkeypatch)

    secret = source.get(_ref("vault_env_secrets", "sonarr", "API_KEY"))

    assert secret is not None
    assert secret.reveal() == "value-one"


def test_distinct_values_come_back_distinct(sops_file, tmp_path, monkeypatch):
    """--extract must actually select, not return the whole document or the
    first value. A backend that silently returns the wrong key would compare
    correctly-formatted nonsense."""
    _encrypted, key_text = sops_file
    source = _source(tmp_path, key_text, monkeypatch)

    sonarr = source.get(_ref("vault_env_secrets", "sonarr", "API_KEY"))
    prowlarr = source.get(_ref("vault_env_secrets", "prowlarr", "API_KEY"))

    assert sonarr.reveal() == "value-one"
    assert prowlarr.reveal() == "value-two"
    assert sonarr != prowlarr


def test_keys_with_spaces_and_dashes_resolve(sops_file, tmp_path, monkeypatch):
    """Path components are JSON-encoded into the --extract argument. If that
    encoding is wrong, a key with a space is unreachable and the failure looks
    like a missing credential."""
    _encrypted, key_text = sops_file
    source = _source(tmp_path, key_text, monkeypatch)

    assert source.get(_ref("vault_env_secrets", "tricky", "WITH SPACE")).reveal() == "value three"
    assert source.get(_ref("vault_env_secrets", "tricky", "WITH-DASH")).reveal() == "value-four"


def test_a_missing_path_is_an_error_not_a_wrong_value(sops_file, tmp_path, monkeypatch):
    _encrypted, key_text = sops_file
    source = _source(tmp_path, key_text, monkeypatch)

    with pytest.raises(SecretSourceError):
        source.get(_ref("vault_env_secrets", "sonarr", "NO_SUCH_KEY"))


def test_the_wrong_age_key_fails_rather_than_returning_junk(sops_file, tmp_path, monkeypatch):
    """The dangerous failure for a secrets backend is returning something
    plausible. A wrong key has to be an error."""
    _encrypted, _ = sops_file
    other = tmp_path / "other"
    other.mkdir()
    subprocess.run(["age-keygen", "-o", str(other / "k.txt")], check=True, capture_output=True)
    monkeypatch.setenv("SOPS_AGE_KEY", (other / "k.txt").read_text().strip())

    with pytest.raises(SecretSourceError):
        SopsSource(root=tmp_path).get(_ref("vault_env_secrets", "sonarr", "API_KEY"))


def test_a_collection_is_rejected_rather_than_serialised(sops_file, tmp_path, monkeypatch):
    """sops prints a document when the path is not a scalar. Returning its
    repr as a credential would produce a plausible-looking string."""
    _encrypted, key_text = sops_file
    source = _source(tmp_path, key_text, monkeypatch)

    with pytest.raises(SecretSourceError, match="not a scalar"):
        source.get(_ref("vault_env_secrets", "odd", "NOT_A_SCALAR"))


def test_an_empty_value_is_distinguishable_from_a_missing_one(sops_file, tmp_path, monkeypatch):
    _encrypted, key_text = sops_file
    source = _source(tmp_path, key_text, monkeypatch)

    # An empty credential is a real, reportable condition; a missing path is a
    # manifest that disagrees with reality. They must not collapse.
    assert source.get(_ref("vault_env_secrets", "sonarr", "EMPTY")) is None


def test_missing_sops_is_reported_as_a_configuration_problem(tmp_path, monkeypatch):
    monkeypatch.setattr("credarr.secrets.shutil.which", lambda name: None)
    with pytest.raises(ConfigError, match="not on PATH"):
        build_source("sops", config_dir=tmp_path)


def test_the_backend_is_registered_under_the_name_the_manifest_uses():
    assert "sops" in __import__("credarr.secrets", fromlist=["BACKENDS"]).BACKENDS
