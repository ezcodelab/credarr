"""The facade: the audit and rotation wiring the CLI and the server share.

Parity is the point. The CLI is a caller of this module, not a second
implementation of it, so a run driven through `cli.main` and a run driven by
calling the facade directly must produce byte-identical output and the same exit
code. Where they differ, one of them is wrong.
"""

from __future__ import annotations

import io
import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import PROWLARR_KEY
from credarr import cli, facade
from credarr.config import Config, HostConfig, load_config
from credarr.errors import CredctlError, ExitCode
from credarr.executor import HolderOutcome
from credarr.model import Credential, Manifest, VaultRef
from credarr.report import exit_code_for, render_json, render_rotation_json
from credarr.secrets import StaticSource, build_source
from credarr.targets import build_registry

REGISTRY = build_registry()

MANIFEST = """
version: 1
credentials:
  prowlarr_api_key:
    class: A-unv
    max_age_days: 90
    vault:
      backend: ansible-vault
      file: vault.yml
      path: [vault_env_secrets, prowlarr, HOMEPAGE_VAR_PROWLARR_API_KEY]
    write: {mechanism: servarr_command}
    consumers:
      - target: sonarr.indexers
        count: 2
      - target: radarr.indexers
        count: 1
      - target: homepage.label
        count: 1
        mechanism: redeploy
"""


@pytest.fixture
def wired_stack(stack: Path) -> Path:
    """`stack` plus a real config, manifest and ansible-vault file.

    The vault is a genuine ansible-vault file, so the CLI builds its own source
    through the same code path production uses rather than a stub.
    """
    if shutil.which("ansible-vault") is None:
        pytest.skip("ansible-vault is needed to build the fixture vault")
    (stack / "vault-password").write_text("test-password\n", encoding="utf-8")
    (stack / "vault.yml").write_text(
        "vault_env_secrets:\n"
        "  prowlarr:\n"
        f"    HOMEPAGE_VAR_PROWLARR_API_KEY: {PROWLARR_KEY}\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "ansible-vault", "encrypt",
            "--vault-password-file", str(stack / "vault-password"),
            str(stack / "vault.yml"),
        ],
        check=True,
        capture_output=True,
    )
    (stack / "manifest.yml").write_text(MANIFEST, encoding="utf-8")
    (stack / "credarr.yaml").write_text(
        "version: 1\n"
        "default_host: local\n"
        "manifest: manifest.yml\n"
        "vault_password_file: vault-password\n"
        # Pinned so the CLI run and the facade run produce the same fingerprints;
        # the parity claim is about identical output, not identical salts.
        "fingerprint:\n"
        "  pinned_salt: '00112233445566778899aabbccddeeff'\n"
        "hosts:\n"
        "  local: {}\n",
        encoding="utf-8",
    )
    return stack


def _facade_audit(config_path: Path) -> tuple[str, int]:
    """Run the audit the way the server would, without the CLI."""
    config = load_config(config_path)
    manifest = facade.read_manifest(config.manifest, REGISTRY)
    source = build_source(
        "ansible-vault",
        config_dir=config.manifest.parent,
        vault_password_file=config_path.parent / "vault-password",
    )
    result = facade.audit(config, manifest, source)
    stream = io.StringIO()
    render_json(result, stream)
    return stream.getvalue(), exit_code_for(result)


def test_audit_output_and_exit_code_match_between_cli_and_facade(wired_stack, capsys):
    """The clean case. `cli.main` must be the facade plus rendering, nothing more."""
    config_path = wired_stack / "credarr.yaml"

    exit_code = cli.main(["-c", str(config_path), "audit", "--json"])
    cli_stdout = capsys.readouterr().out
    facade_stdout, facade_exit_code = _facade_audit(config_path)

    assert cli_stdout == facade_stdout
    assert exit_code == facade_exit_code
    assert exit_code == ExitCode.OK


# -- 2. rotate plan parity ----------------------------------------------------


def test_rotate_plan_json_matches_between_cli_and_facade(wired_stack, monkeypatch, capsys):
    """An executable plan, rendered once by the CLI and once by the facade.

    The fixture stack has no live services, so preflight is stubbed: this is
    about the plan JSON and the exit code, not about reachability.
    """
    config_path = wired_stack / "credarr.yaml"
    monkeypatch.setattr(cli, "_preflight", lambda *a, **k: [])

    exit_code = cli.main(
        ["-c", str(config_path), "rotate", "prowlarr_api_key", "--json"]
    )
    cli_stdout = capsys.readouterr().out

    config = load_config(config_path)
    manifest = facade.read_manifest(config.manifest, REGISTRY)
    credential, host, plan = facade.plan_rotation_for(config, manifest, "prowlarr_api_key")
    stream = io.StringIO()
    render_rotation_json(credential, host, plan, stream)

    assert cli_stdout == stream.getvalue()
    assert exit_code == ExitCode.OK


def test_refused_rotate_plan_json_matches_between_cli_and_facade(tmp_path, capsys):
    """A refusal precedes preflight, so this needs no vault and no live host.

    The single blocker is the credential's class, which the plan reports.
    """
    (tmp_path / "manifest.yml").write_text(
        "version: 1\n"
        "credentials:\n"
        "  sonarr_api_key:\n"
        "    class: B\n"
        "    max_age_days: 180\n"
        "    vault: {backend: ansible-vault, file: v.yml, path: [a, b]}\n"
        "    write: {mechanism: servarr_command}\n",
        encoding="utf-8",
    )
    config_path = tmp_path / "credarr.yaml"
    config_path.write_text(
        "version: 1\n"
        "default_host: local\n"
        "manifest: manifest.yml\n"
        "hosts:\n"
        "  local: {}\n",
        encoding="utf-8",
    )

    exit_code = cli.main(["-c", str(config_path), "rotate", "sonarr_api_key", "--json"])
    cli_stdout = capsys.readouterr().out

    config = load_config(config_path)
    manifest = facade.read_manifest(config.manifest, REGISTRY)
    credential, host, plan = facade.plan_rotation_for(config, manifest, "sonarr_api_key")
    stream = io.StringIO()
    render_rotation_json(credential, host, plan, stream)

    assert cli_stdout == stream.getvalue()
    assert exit_code == ExitCode.REFUSED


# -- 3. credential_named ------------------------------------------------------


def test_credential_named_unknown_name_reports_what_is_known():
    manifest = Manifest.parse(
        "version: 1\n"
        "credentials:\n"
        "  prowlarr_api_key:\n"
        "    class: B\n"
        "    never_rotate: true\n",
        known_targets=REGISTRY.known_targets(),
        known_backends=("ansible-vault",),
    )

    with pytest.raises(CredctlError) as excinfo:
        facade.credential_named(manifest, "nope")

    assert str(excinfo.value) == "no credential named 'nope'"
    assert excinfo.value.hint == "known: prowlarr_api_key"


def test_the_cli_reports_an_unknown_credential_cleanly(tmp_path, capsys):
    """The typo path at the CLI boundary: exit 3, the message, no traceback."""
    (tmp_path / "manifest.yml").write_text(MANIFEST, encoding="utf-8")
    config_path = tmp_path / "credarr.yaml"
    config_path.write_text(
        "version: 1\n"
        "default_host: local\n"
        "manifest: manifest.yml\n"
        "hosts:\n"
        "  local: {}\n",
        encoding="utf-8",
    )

    exit_code = cli.main(["-c", str(config_path), "rotate", "nope"])

    err = capsys.readouterr().err
    assert exit_code == ExitCode.CONFIG
    assert "no credential named 'nope'" in err
    assert "known: prowlarr_api_key" in err
    assert "Traceback" not in err


# -- 4. require_mutable -------------------------------------------------------


def test_require_mutable_refuses_a_source_that_cannot_write():
    credential = Credential(
        name="c", vault=VaultRef(backend="ansible-vault", file="v.yml", path=("a",))
    )

    with pytest.raises(CredctlError) as excinfo:
        facade.require_mutable(StaticSource({}), credential)

    assert str(excinfo.value) == "the ansible-vault backend cannot write"
    assert excinfo.value.hint == (
        "rotation needs a mutable backend; the read path alone would leave the "
        "vault stale"
    )


def test_require_mutable_accepts_a_source_that_can_write():
    """The control: the guard must not refuse a source that can write."""

    class Writable:
        name = "writable"

        def get(self, ref):
            return None

        def set(self, ref, value):
            pass

    credential = Credential(
        name="c", vault=VaultRef(backend="ansible-vault", file="v.yml", path=("a",))
    )
    facade.require_mutable(Writable(), credential)  # must not raise


# -- 5. execution_exit_code ---------------------------------------------------


class _Result:
    """The smallest thing `execution_exit_code` looks at."""

    def __init__(self, *, failed=None, manual=None, holders=None):
        self.failed = failed
        self.detail = ""
        self.manual = manual or []
        self.holders = holders or []


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (_Result(), ExitCode.OK),
        (_Result(failed="sonarr.indexers"), ExitCode.DRIFT),
        (_Result(manual=["homepage.label"]), ExitCode.DRIFT),
        (_Result(holders=[HolderOutcome("sonarr.indexers", "7", "not-reached")]), ExitCode.DRIFT),
        (_Result(holders=[HolderOutcome("sonarr.indexers", "7", "failed")]), ExitCode.DRIFT),
        (_Result(holders=[HolderOutcome("sonarr.indexers", "7", "written")]), ExitCode.DRIFT),
        (_Result(holders=[HolderOutcome("sonarr.indexers", "7", "confirmed")]), ExitCode.OK),
    ],
)
def test_execution_exit_code(result, expected):
    assert facade.execution_exit_code(result) == expected


# -- plan_rotation_for: the shared plan entry point ---------------------------


def test_plan_rotation_for_returns_the_credential_host_and_plan():
    manifest = Manifest.parse(
        MANIFEST, known_targets=REGISTRY.known_targets(), known_backends=("ansible-vault",)
    )
    config = Config(
        version=1,
        default_host="media",
        hosts={"media": HostConfig(name="media")},
        manifest=Path("m.yml"),
    )

    credential, host, plan = facade.plan_rotation_for(config, manifest, "prowlarr_api_key")

    assert credential.name == "prowlarr_api_key"
    assert host.name == "media"
    assert plan.credential is credential


# -- 6. execute wiring --------------------------------------------------------


def test_facade_execute_runs_under_the_credential_lock(tmp_path, monkeypatch):
    """The wiring `--apply` depends on: lock first, lease fenced, setter bound.

    `Executor` is stubbed so the test can observe the context it receives; the
    journal, the lock and the lease check are the real thing.
    """
    from credarr import executor as executor_module
    from credarr.journal import Journal
    from credarr.redact import Secret

    journal = Journal(tmp_path / "state" / "rotation.db")
    credential = Credential(
        name="sonarr_api_key",
        vault=VaultRef(backend="ansible-vault", file="v.yml", path=("a",)),
    )

    written = []

    class Writable:
        def set(self, ref, value):
            written.append((ref, value.reveal()))

    class StubExecutor:
        def __init__(self, ctx):
            self.ctx = ctx

        def execute(self, plan):
            # Raises unless this process still holds the lock right now.
            self.ctx.lease_check()
            assert self.ctx.vault_value == "the-canonical"
            self.ctx.vault_setter(Secret("the-new-value"))
            return "executed"

    monkeypatch.setattr(executor_module, "Executor", StubExecutor)

    result = facade.execute(
        plan=object(),
        credential=credential,
        host=HostConfig(name="local"),
        secrets=Writable(),
        journal=journal,
        canonical=Secret("the-canonical"),
        actor="test",
    )

    assert result == "executed"
    assert written == [(credential.vault, "the-new-value")]

    # Released on the way out: the same credential can be locked again.
    with journal.lock(credential.name, "after") as token:
        journal.assert_held(credential.name, token)


def test_facade_execute_reads_the_canonical_after_taking_the_lock(
    tmp_path, monkeypatch
):
    """A paste can land while a run waits for the lock. Re-reading after it is
    held is what keeps the run from comparing against a value the store no
    longer holds."""
    from credarr import executor as executor_module
    from credarr.journal import Journal
    from credarr.redact import Secret

    journal = Journal(tmp_path / "state" / "rotation.db")
    credential = Credential(
        name="sonarr_api_key",
        vault=VaultRef(backend="ansible-vault", file="v.yml", path=("a",)),
    )

    class Writable:
        def set(self, ref, value):
            pass

    def canonical_getter():
        assert journal.held(credential.name) is not None, "read before the lock"
        return Secret("the-fresh-value")

    class StubExecutor:
        def __init__(self, ctx):
            self.ctx = ctx

        def execute(self, plan):
            assert self.ctx.vault_value == "the-fresh-value"
            return "executed"

    monkeypatch.setattr(executor_module, "Executor", StubExecutor)

    result = facade.execute(
        plan=object(),
        credential=credential,
        host=HostConfig(name="local"),
        secrets=Writable(),
        journal=journal,
        canonical=Secret("the-stale-value"),
        canonical_getter=canonical_getter,
        actor="test",
    )

    assert result == "executed"


# -- 7. the disclosed delta ---------------------------------------------------
#
# `rotate` now reads the manifest through the facade, so a missing manifest is
# the same clean `ManifestError` audit already raised, rather than an uncaught
# `FileNotFoundError` traceback. That was the facade extraction's only intended
# behaviour change; section 8 records the later `-m` resolution change.


def test_rotate_reports_a_missing_manifest_like_audit(tmp_path, capsys):
    config_path = tmp_path / "credarr.yaml"
    config_path.write_text(
        "version: 1\n"
        "default_host: local\n"
        "manifest: missing.yml\n"
        "hosts:\n"
        "  local: {}\n",
        encoding="utf-8",
    )

    rotate_code = cli.main(["-c", str(config_path), "rotate", "whatever"])
    rotate_err = capsys.readouterr().err
    audit_code = cli.main(["-c", str(config_path), "audit"])
    audit_err = capsys.readouterr().err

    # errors.py gives ManifestError ExitCode.CONFIG (3), for both commands.
    assert rotate_code == ExitCode.CONFIG
    assert rotate_code == audit_code
    assert "cannot read manifest" in rotate_err
    assert "cannot read manifest" in audit_err
    assert "missing.yml" in rotate_err
    assert "set 'manifest' in the config, or pass --manifest" in rotate_err
    assert "set 'manifest' in the config, or pass --manifest" in audit_err
    assert "Traceback" not in rotate_err
    assert "Traceback" not in audit_err


# -- 8. rotate load resolution ------------------------------------------------


def test_rotate_honors_the_manifest_override(tmp_path, capsys):
    """`-m` names the manifest rotate reads, the way audit already resolves it.

    Without it the config's manifest path is used (here: missing, exit 3);
    with it, the override is read and its refusal decides the exit code.
    """
    (tmp_path / "other.yml").write_text(
        "version: 1\n"
        "credentials:\n"
        "  sonarr_api_key:\n"
        "    class: B\n"
        "    max_age_days: 180\n"
        "    vault: {backend: ansible-vault, file: v.yml, path: [a, b]}\n"
        "    write: {mechanism: servarr_command}\n",
        encoding="utf-8",
    )
    config_path = tmp_path / "credarr.yaml"
    config_path.write_text(
        "version: 1\n"
        "default_host: local\n"
        "manifest: missing.yml\n"
        "hosts:\n"
        "  local: {}\n",
        encoding="utf-8",
    )

    override_code = cli.main(
        ["-c", str(config_path), "rotate", "sonarr_api_key",
         "-m", str(tmp_path / "other.yml")]
    )
    override = capsys.readouterr()

    config_code = cli.main(["-c", str(config_path), "rotate", "sonarr_api_key"])

    assert override_code == ExitCode.REFUSED
    assert "BLOCKED" in override.out
    assert "cannot read manifest" not in override.err
    assert config_code == ExitCode.CONFIG


def test_rotate_honors_the_vault_password_file_flag(wired_stack, capsys):
    """`--vault-password-file` wins over the config's password file.

    Pointed at a file that cannot decrypt the vault, the run must fail at the
    vault read instead of reaching preflight - that failure is what proves the
    flag was used and not silently ignored.
    """
    (wired_stack / "wrong-password").write_text("not-the-password\n", encoding="utf-8")

    exit_code = cli.main(
        ["-c", str(wired_stack / "credarr.yaml"), "rotate", "prowlarr_api_key",
         "--vault-password-file", str(wired_stack / "wrong-password")]
    )

    captured = capsys.readouterr()
    assert exit_code == ExitCode.CONFIG
    assert "could not decrypt" in captured.err
    assert "PREFLIGHT FAILED" not in captured.out
    assert "Traceback" not in captured.err


def test_rotate_reads_the_vault_relative_to_the_resolved_manifest(
    wired_stack, tmp_path, capsys
):
    """A relative vault file follows the manifest that named it, `-m` included.

    The override's vault.yml is not a vault, so failing to decrypt it - and
    naming that path - proves which directory was used; a config-anchored read
    would have decrypted the real vault and reached preflight instead. No
    --vault-password-file is passed, so this also pins that the configured
    password file is used when `-m` is in play.
    """
    second = tmp_path / "second"
    second.mkdir()
    (second / "manifest.yml").write_text(
        (wired_stack / "manifest.yml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (second / "vault.yml").write_text("not a vault\n", encoding="utf-8")

    exit_code = cli.main(
        ["-c", str(wired_stack / "credarr.yaml"), "rotate", "prowlarr_api_key",
         "-m", str(second / "manifest.yml")]
    )

    captured = capsys.readouterr()
    assert exit_code == ExitCode.CONFIG
    assert "could not decrypt" in captured.err
    assert str(second / "vault.yml") in captured.err
    assert "PREFLIGHT FAILED" not in captured.out
