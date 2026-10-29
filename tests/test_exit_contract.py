"""The exit code is the contract, so the contract gets tested.

A rotation tool that reports success while the stack is inconsistent is worse
than one that reports nothing, because a scheduled job cannot tell the
difference between "rotated" and "did nothing".
"""

from __future__ import annotations

import json

import pytest

from credarr.cli import _confirm
from credarr.errors import ConfigError, ExitCode
from credarr.model import Credential
from credarr.rotate import RotationPlan


def _plan() -> RotationPlan:
    cred = Credential(name="c")
    return RotationPlan(credential=cred, host=None)


def test_rendered_advice_has_no_hint_prefix():
    """The corrective sentence follows the error directly."""
    text = ConfigError("the config cannot be read", hint="fix the file").render()
    assert text == "error: the config cannot be read\nfix the file"
    assert "hint:" not in text


def test_no_terminal_is_not_a_confirmation(monkeypatch):
    """EOF means nobody answered, which is not the same as somebody saying no.

    A scheduled `--apply` with no TTY used to exit 0 here: the rotation never
    ran, and the job recorded it as done.
    """
    def boom(prompt=""):
        raise EOFError

    monkeypatch.setattr("builtins.input", boom)
    assert _confirm("some_credential", _plan()) is None


def test_a_declined_confirmation_is_false_not_an_error(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt="": "no")
    assert _confirm("some_credential", _plan()) is False

    monkeypatch.setattr("builtins.input", lambda prompt="": "some_credential")
    assert _confirm("some_credential", _plan()) is True


class _Result:
    """The smallest thing the CLI's tail logic looks at."""

    def __init__(self, *, manual=None, failed=None, holders=None, completed=None,
                 vault_written=False, revokes_before_holders=True):
        self.credential = "c"
        self.completed: list[str] = completed or []
        self.manual = manual or []
        self.failed = failed
        self.detail = ""
        self.holders = holders or []
        self.resumed = False
        self.reclaimed: list[tuple[str, str]] = []
        self.revokes_before_holders = revokes_before_holders
        self.vault_written = vault_written

    def summary(self) -> str:
        return "summary"


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (_Result(), ExitCode.OK),
        (_Result(failed="sonarr.indexers"), ExitCode.DRIFT),
        (_Result(manual=["homepage.label"]), ExitCode.DRIFT),
    ],
)
def test_a_manual_step_outstanding_is_drift(result, expected, capsys):
    """A consumer the tool could not update is still holding a revoked key.

    The vault has the new value and that consumer has the old one. That is
    exactly the state `credarr audit` exists to detect, so the rotation must not
    exit clean while it is true.
    """
    from credarr.cli import _finish

    assert _finish(result) == expected


def test_a_holder_left_not_reached_is_drift(capsys):
    from credarr.cli import _finish
    from credarr.executor import HolderOutcome

    result = _Result(holders=[HolderOutcome("sonarr.indexers", "7", "not-reached")])
    assert _finish(result) == ExitCode.DRIFT


def test_a_holder_written_but_not_confirmed_is_drift(capsys):
    """A write that was never read back, tested where the exit code is decided.

    Nothing raised, no step failed, and the value is in the store. That is what
    a run interrupted mid-propagation leaves behind, and reporting success on the
    strength of an accepted write is the exact claim the holder outcome exists to
    withhold.

    `ExecutionResult.clean` covers the same condition for library callers; this
    covers the CLI, which re-derives from the holders and could stop doing so.
    """
    from credarr.cli import _finish
    from credarr.executor import HolderOutcome

    result = _Result(holders=[
        HolderOutcome("sonarr.indexers", "7", "written"),
    ])
    assert _finish(result) == ExitCode.DRIFT
    assert "NOT confirmed" in capsys.readouterr().out


def test_a_confirmed_holder_is_not_drift(capsys):
    """The negative control.

    If `written` were treated as outstanding but `confirmed` were too, every run
    would exit DRIFT and the exit code would carry no information at all.
    """
    from credarr.cli import _finish
    from credarr.executor import HolderOutcome

    result = _Result(holders=[HolderOutcome("sonarr.indexers", "7", "confirmed")])
    assert _finish(result) == ExitCode.OK


def test_a_manual_step_does_not_claim_the_vault_when_the_write_failed(capsys):
    from credarr.cli import _finish

    """The vault sentence is only true if the vault was actually written.

    Plan order puts MANUAL before RECORD, so a run that fails on the vault write
    has an outstanding manual step and a failed step. Printing "the vault now
    holds the new key" there is the tool asserting something false about the
    system it exists to describe.
    """
    result = _Result(
        manual=["homepage.label"],
        failed="vault_env_secrets.prowlarr.HOMEPAGE_VAR_PROWLARR_API_KEY",
    )
    assert _finish(result) == ExitCode.DRIFT
    out = capsys.readouterr().out
    assert "vault now holds the new key" not in out, out
    assert "has NOT been updated" in out, out


def test_the_vault_claim_is_made_when_the_write_did_succeed(capsys):
    """The negative control for the test above: it must not just always warn."""
    from credarr.cli import _finish

    result = _Result(manual=["homepage.label"], vault_written=True)
    assert _finish(result) == ExitCode.DRIFT
    out = capsys.readouterr().out
    assert "vault now holds the new key" in out, out


def test_a_create_plan_failure_does_not_claim_a_resume(capsys):
    """A failed create-mint run must not be described as resumable in place.

    For this plan shape a re-run mints a fresh key and never adopts the one
    the dead run made, so "re-running resumes from here" would be a false
    instruction at the moment an operator is most likely to follow it.
    """
    from credarr.cli import _finish

    result = _Result(failed="jellyfin", revokes_before_holders=False)

    assert _finish(result) == ExitCode.DRIFT
    out = capsys.readouterr().out
    assert "resumes from" not in out, out
    assert "stays live" in out, out


def test_the_prompt_describes_the_create_shape_truthfully(monkeypatch, capsys):
    """The consent text says which plan shape is about to run.

    A create mint keeps the old key until the revoke step; the reset sentence
    ("stops working at the first step") would be false here, printed by the
    prompt whose whole job is to say what is about to be lost.
    """
    monkeypatch.setattr("builtins.input", lambda prompt="": "some_credential")
    plan = _plan()
    plan.revokes_before_holders = False

    assert _confirm("some_credential", plan) is True

    out = capsys.readouterr().out
    assert "stops working at the first step" not in out, out
    assert "keeps working until the revoke step" in out, out


def test_an_unimplemented_write_mechanism_is_refused_at_plan_time():
    """It must not survive planning and die later inside the executor.

    An unknown mechanism has no strategy behind it. The plan says so instead of
    producing a step whose target the executor would fail on.
    """
    from credarr.model import Credential
    from credarr.rotate import plan_rotation

    cred = Credential(
        name="some_secret",
        write={"mechanism": "no_such_mechanism", "detail": "a value"},
        consumers=(),
    )
    plan = plan_rotation(cred, host=None)

    assert plan.blocked_by, "the mechanism was accepted with no executor behind it"
    assert any("no rotation strategy" in reason for reason in plan.blocked_by)


def _host():
    import types

    return types.SimpleNamespace(name="media")


def _servarr_plan(*, blocked: bool):
    """A real Servarr plan, which is the only thing that sets the window flag."""
    plan = RotationPlan(
        credential=Credential(name="sonarr_api_key", credential_class="A-unv",
                              max_age_days=90,
                              write={"mechanism": "servarr_command"}, consumers=()),
        host=_host(),
    )
    plan.revokes_before_holders = True
    if blocked:
        plan.blocked_by.append("credential is class A-unv")
    return plan


def test_refused_plans_do_not_claim_a_revocation_window():
    """A refused plan revokes nothing, so the window must not be stated.

    The Servarr planner sets `revokes_before_holders` on every plan it builds,
    including a refused one. Publishing that alongside `refused: true` would say
    of the live system that holders are holding dead keys - a statement about a
    run that cannot happen. Built through the planner's own flag so this cannot
    pass merely because a hand-built plan never set it.
    """
    import io

    from credarr.report import render_rotation_json

    refused = _servarr_plan(blocked=True)

    stream = io.StringIO()
    render_rotation_json(refused.credential, _host(), refused, stream)
    payload = json.loads(stream.getvalue())

    assert payload["refused"] is True
    assert payload["revokes_before_holders"] is False


def test_an_executable_plan_does_claim_the_window():
    """The control: the field must not simply be hardcoded False."""
    import io

    from credarr.report import render_rotation_json

    executable = _servarr_plan(blocked=False)

    stream = io.StringIO()
    render_rotation_json(executable.credential, _host(), executable, stream)

    assert json.loads(stream.getvalue())["revokes_before_holders"] is True


def test_the_human_output_states_the_window_only_for_an_executable_plan(monkeypatch, capsys):
    """Same rule, on the path an operator actually reads.

    A refused plan that printed "every holder below holds a dead key" would be a
    false claim about live services, printed by the tool whose entire purpose is
    not to make false claims about them.
    """
    import argparse
    import types

    from credarr import cli, facade

    refused = _servarr_plan(blocked=True)
    credential = refused.credential

    monkeypatch.setattr(
        cli, "load_config", lambda p: types.SimpleNamespace(
            manifest=None, default_host="nas",
            host=lambda h: types.SimpleNamespace(name=h),
        )
    )
    monkeypatch.setattr(facade, "read_manifest", lambda path, registry: None)
    monkeypatch.setattr(
        facade, "plan_rotation_for",
        lambda config, manifest, name: (credential, _host(), refused),
    )

    args = argparse.Namespace(
        config=cli.Path("no-such-credarr.yaml"), credential="sonarr_api_key",
        manifest=None, vault_password_file=None,
        dry_run=True, apply=False, yes=False, as_json=False,
        take_over=False,
    )
    assert cli._rotate(args) == ExitCode.REFUSED

    out = capsys.readouterr().out
    assert "BLOCKED" in out
    assert "dead key" not in out, out


def test_an_executable_plan_does_state_the_window_in_human_output(monkeypatch, capsys):
    """The control for the gate above.

    Without it, a regression that made the condition always false would pass:
    the refused case only asserts the paragraph is *absent*.
    """
    import argparse
    import types

    from credarr import cli, facade

    executable = _servarr_plan(blocked=False)
    credential = executable.credential

    monkeypatch.setattr(
        cli, "load_config", lambda p: types.SimpleNamespace(
            manifest=None, default_host="nas",
            host=lambda h: types.SimpleNamespace(name=h),
        )
    )
    monkeypatch.setattr(facade, "read_manifest", lambda path, registry: None)
    monkeypatch.setattr(
        facade, "plan_rotation_for",
        lambda config, manifest, name: (credential, _host(), executable),
    )
    # A dry run, so nothing is executed: preflight needs a live host.
    monkeypatch.setattr(cli, "_preflight", lambda *a, **k: ["unreachable in this test"])

    args = argparse.Namespace(
        config=cli.Path("no-such-credarr.yaml"), credential="prowlarr_api_key",
        manifest=None, vault_password_file=None,
        dry_run=True, apply=False, yes=False, as_json=False,
        take_over=False,
    )
    assert cli._rotate(args) == ExitCode.CONFIG

    out = capsys.readouterr().out
    assert "dead key" in out, out
    assert "BLOCKED" not in out


def test_take_over_names_the_steps_it_will_close_before_the_prompt(
    monkeypatch, capsys, tmp_path
):
    """The instruction is said out loud, and it reaches the engine.

    It is an assertion the operator is making about a run they cannot see, so
    it is printed before the prompt: which steps, how fresh, and what makes
    the takeover safe. And it travels as `take_over`, which is what stops a
    fresh step being a refusal rather than a decision.
    """
    import argparse
    import types

    from credarr import cli, facade
    from credarr.journal import Journal

    plan = _servarr_plan(blocked=False)
    journal = Journal(tmp_path / "j.db")
    attempt = journal.begin("sonarr_api_key")
    journal.step_started(attempt, 0, "mint", "sonarr", "POST /api/v3/command")

    monkeypatch.setattr(
        cli, "load_config",
        lambda p: types.SimpleNamespace(
            manifest=None, default_host="nas", host=lambda h: _host()
        ),
    )
    monkeypatch.setattr(facade, "read_manifest", lambda path, registry: None)
    monkeypatch.setattr(
        facade, "plan_rotation_for",
        lambda config, manifest, name: (plan.credential, _host(), plan),
    )
    monkeypatch.setattr(facade, "journal_for", lambda config: journal)
    seen: dict = {}

    def fake_preflight(*args, **kwargs):
        seen.update(kwargs)
        return ["sonarr: unreachable in this test"]

    monkeypatch.setattr(cli, "_preflight", fake_preflight)

    args = argparse.Namespace(
        config=cli.Path("no-such-credarr.yaml"), credential="sonarr_api_key",
        manifest=None, vault_password_file=None,
        dry_run=True, apply=False, yes=False, as_json=False,
        take_over=True,
    )
    assert cli._rotate(args) == ExitCode.CONFIG

    out = capsys.readouterr().out
    assert "TAKING OVER 1 unfinished step(s):" in out, out
    assert "sonarr" in out and "POST /api/v3/command" in out, out
    assert "resumed, not repeated" in out, out
    assert seen.get("take_over") is True, seen


def test_a_refused_plan_exits_refused_not_config():
    """Code 5, so a job can tell "this tool is misconfigured" from "not rotatable".

    Both used to be 3. A scheduled `rotate --dry-run && deploy` would read
    "fix the operator's manifest" for a credential that is merely awaiting a
    writer, which is not the same event and does not want the same response.
    """
    from credarr.errors import ExitCode

    assert ExitCode.REFUSED == 5
    assert ExitCode.REFUSED != ExitCode.CONFIG
    assert ExitCode.REFUSED != ExitCode.DRIFT
    assert ExitCode.REFUSED != ExitCode.UNREACHABLE
    # Every pre-existing code keeps its value: this was added, not reassigned.
    assert (ExitCode.OK, ExitCode.DRIFT, ExitCode.USAGE,
            ExitCode.CONFIG, ExitCode.UNREACHABLE) == (0, 1, 2, 3, 4)


@pytest.mark.parametrize("as_json", [False, True], ids=["human", "json"])
def test_the_refused_branch_actually_returns_five(monkeypatch, capsys, as_json):
    """The constant existing is not the claim. The branch returning it is.

    Asserting `ExitCode.REFUSED == 5` would pass against a CLI that still
    returned CONFIG, which is the same failure shape this suite already caught
    once: a test that passes because it checked the declaration rather than the
    behaviour. So this drives `_rotate` with a blocked plan.
    """
    import argparse

    from credarr import cli, facade
    from credarr.errors import ExitCode
    from credarr.model import Credential
    from credarr.rotate import RotationPlan

    blocked = RotationPlan(
        credential=Credential(name="some_secret", write={}, consumers=()), host=None
    )
    plan_blocked_by = "credarr has no rotation writer for profilarr.arr_config"
    blocked.blocked_by.append(plan_blocked_by)
    import types

    config = types.SimpleNamespace(
        manifest=None, default_host="nas", host=lambda h: types.SimpleNamespace(name=h)
    )
    monkeypatch.setattr(cli, "load_config", lambda p: config)
    monkeypatch.setattr(facade, "read_manifest", lambda path, registry: None)
    monkeypatch.setattr(
        facade, "plan_rotation_for",
        lambda config, manifest, name: (blocked.credential, _host(), blocked),
    )
    args = argparse.Namespace(
        config=cli.Path("no-such-credarr.yaml"), credential="some_secret",
        manifest=None, vault_password_file=None,
        dry_run=True, apply=False, yes=False, as_json=as_json,
        take_over=False,
    )

    assert cli._rotate(args) == ExitCode.REFUSED
    out = capsys.readouterr().out
    if as_json:
        payload = json.loads(out)
        # Version 3 added `mint_via`/`manual_mint`; version 2 added
        # `revokes_before_holders`. Asserting the exact key set is what makes a
        # silent, unannounced schema change impossible: a new field without a
        # bump fails here, and a bump without the field fails the assertion
        # below.
        assert payload["version"] == 3, "a payload a UI binds to must be versioned"
        assert set(payload) == {
            "version", "credential", "class", "host", "refused", "blocked_by",
            "revokes_before_holders", "mint_via", "manual_mint", "steps",
            "problems",
        }
        assert payload["refused"] is True
        assert payload["blocked_by"] == [plan_blocked_by]
        # False even though a Servarr plan sets the flag: a refused plan mints
        # nothing, so claiming a window over a run that cannot happen would be a
        # false statement about system state. This hand-built plan is not a
        # Servarr plan, so `test_refused_plans_do_not_claim_a_revocation_window`
        # covers the case where the flag would otherwise be set.
        assert payload["revokes_before_holders"] is False
        # The reason travels in the payload, not only in the exit code, so a
        # consumer learns which holder stopped it without scraping prose.
        assert "BLOCKED" not in out
    else:
        assert "BLOCKED" in out


def test_the_plan_document_carries_what_a_console_needs_to_render_it():
    """The step's own costs, not just its name: a console that can only show
    "mint sonarr" cannot say which part cannot be undone, and a plan document
    without `problems` cannot say why a dry run was exit 3."""
    from credarr.report import rotation_json
    from credarr.rotate import Step, StepKind

    plan = _servarr_plan(blocked=False)
    plan.mint_via = "backup_restore"
    plan.steps.append(Step(
        StepKind.MINT, "sonarr", "POST /api/v3/command backup/restore",
        reversible=False, reason="there is no overlap window",
    ))

    payload = rotation_json(
        plan.credential, _host(), plan, ["sonarr: could not be reached"]
    )

    assert payload["version"] == 3
    assert payload["mint_via"] == "backup_restore"
    assert payload["manual_mint"] is False
    (step,) = payload["steps"]
    assert step == {
        "kind": "mint",
        "target": "sonarr",
        "detail": "POST /api/v3/command backup/restore",
        "reversible": False,
        "reason": "there is no overlap window",
    }
    assert payload["problems"] == ["sonarr: could not be reached"]


def test_preflight_problems_are_json_under_json_and_still_exit_config(
    monkeypatch, capsys
):
    """`rotate --json | jq` must parse in the failure case too.

    The refusal already travelled as JSON; the preflight failure still printed
    prose to stdout, so the one branch a scheduled job most needs to read was
    the one that broke its parser. Exit 3 is unchanged - the code still says
    "nothing was checked".
    """
    import argparse
    import types

    from credarr import cli, facade

    plan = _servarr_plan(blocked=False)
    config = types.SimpleNamespace(
        manifest=None, default_host="nas", host=lambda h: _host()
    )
    monkeypatch.setattr(cli, "load_config", lambda p: config)
    monkeypatch.setattr(facade, "read_manifest", lambda path, registry: None)
    monkeypatch.setattr(
        facade, "plan_rotation_for",
        lambda config, manifest, name: (plan.credential, _host(), plan),
    )
    monkeypatch.setattr(cli, "_preflight", lambda *a, **k: ["sonarr: no answer"])

    args = argparse.Namespace(
        config=cli.Path("no-such-credarr.yaml"), credential="sonarr_api_key",
        manifest=None, vault_password_file=None,
        dry_run=True, apply=False, yes=False, as_json=True,
        take_over=False,
    )
    assert cli._rotate(args) == ExitCode.CONFIG

    payload = json.loads(capsys.readouterr().out)
    assert payload["problems"] == ["sonarr: no answer"]
    assert payload["refused"] is False


def test_json_apply_refuses_to_prompt_because_a_prompt_is_not_json(
    monkeypatch, capsys, tmp_path
):
    """Automation passes --yes; a prompt writes prose to stdout and would
    corrupt the document. Usage error, not a silent mixture."""
    import argparse
    import types

    from credarr import cli, facade

    plan = _servarr_plan(blocked=False)
    config = types.SimpleNamespace(
        manifest=None, default_host="nas", host=lambda h: _host()
    )
    monkeypatch.setattr(cli, "load_config", lambda p: config)
    monkeypatch.setattr(facade, "read_manifest", lambda path, registry: None)
    monkeypatch.setattr(
        facade, "plan_rotation_for",
        lambda config, manifest, name: (plan.credential, _host(), plan),
    )
    monkeypatch.setattr(
        cli, "_apply", lambda *a, **k: pytest.fail("a prompt cannot be JSON")
    )
    monkeypatch.setattr(cli, "DEFAULT_CONFIG_DIR", tmp_path)

    args = argparse.Namespace(
        config=tmp_path / "no-such-credarr.yaml", credential="sonarr_api_key",
        manifest=None, vault_password_file=None,
        dry_run=False, apply=True, yes=False, as_json=True,
        take_over=False,
    )
    assert cli._rotate(args) == ExitCode.USAGE
    assert "--yes" in capsys.readouterr().err


def test_the_run_document_is_the_result_the_cli_reports(capsys):
    """One shape for the CLI and the API: the attempt, what completed, every
    holder's outcome, and `clean` - never `ok`, which says only that nothing
    raised."""
    import io

    from credarr.executor import ExecutionResult, HolderOutcome
    from credarr.report import execution_json, render_execution_json

    result = ExecutionResult(
        credential="sonarr_api_key",
        attempt=12,
        completed=["sonarr", "sonarr"],
        holders=[HolderOutcome("sonarr.indexers", "7", "confirmed", "2 rows")],
        vault_written=True,
    )
    payload = execution_json(result)

    assert payload["attempt"] == 12
    assert payload["completed"] == ["sonarr", "sonarr"]
    assert payload["holders"] == [
        {"target": "sonarr.indexers", "label": "7",
         "outcome": "confirmed", "detail": "2 rows", "method": ""}
    ]
    assert payload["vault_written"] is True
    assert payload["clean"] is True
    assert "summary" in payload

    stream = io.StringIO()
    render_execution_json(result, stream)
    assert json.loads(stream.getvalue()) == payload


def test_the_json_apply_path_prints_only_the_document(monkeypatch, capsys):
    """The whole apply tail, with a run that completed: stdout must parse.

    A print left outside the `as_json` branch - a summary line, a hint - is
    invisible in a human run and breaks every machine caller, so the test reads
    stdout as a document rather than searching for a field.
    """
    import types

    from credarr import cli, facade
    from credarr.executor import ExecutionResult
    from credarr.model import Credential, VaultRef
    from credarr.redact import Secret
    from credarr.rotate import RotationPlan

    plan = RotationPlan(
        credential=Credential(
            name="sonarr_api_key", credential_class="A", max_age_days=90,
            write={"mechanism": "servarr_command"}, consumers=(),
            vault=VaultRef(backend="ansible-vault", file="v.yml", path=("a",)),
        ),
        host=_host(),
    )
    result = ExecutionResult(credential="sonarr_api_key", attempt=3,
                             completed=["sonarr"])

    config = types.SimpleNamespace(
        manifest=None, default_host="nas", host=lambda h: _host()
    )
    source = types.SimpleNamespace(
        get=lambda ref: Secret("old"), set=lambda ref, value: None
    )
    monkeypatch.setattr(cli, "build_source", lambda *a, **k: source)
    monkeypatch.setattr(facade, "journal_for", lambda config: object())
    # The fake config has no manifest path; this test's plan never uses the
    # pending store, so the test supplies its own empty slot.
    monkeypatch.setattr(facade, "pending_for", lambda config: None)
    monkeypatch.setattr(facade, "preflight", lambda **k: [])
    monkeypatch.setattr(facade, "execute", lambda **k: result)

    assert cli._apply(
        plan, plan.credential, _host(), config,
        cli.Path("manifest.yaml"), None,
        prompt=False, as_json=True,
    ) == ExitCode.OK

    payload = json.loads(capsys.readouterr().out)
    assert payload["attempt"] == 3
    assert payload["completed"] == ["sonarr"]


def test_the_cli_resolves_holder_service_keys_from_its_vault(monkeypatch, tmp_path):
    """The CLI gets the same store-first resolver as the BFF.

    A service key is a normal credential. The service comes from
    `canonical.service` when declared, otherwise from the credential name, so
    `jellyfin_api_token` works without a `_api_key` suffix.
    """
    from credarr import cli
    from credarr.errors import SecretSourceError
    from credarr.model import Credential, Manifest, VaultRef
    from credarr.redact import Secret

    def credential(name: str, **kwargs) -> Credential:
        return Credential(
            name=name,
            vault=VaultRef(backend="ansible-vault", file="v.yml",
                           path=("keys", name)),
            **kwargs,
        )

    manifest = Manifest(
        version=1,
        credentials={
            "sonarr_api_key": credential("sonarr_api_key"),
            "jellyfin_api_token": credential(
                "jellyfin_api_token", canonical={"service": "jellyfin"}
            ),
            "unprovisioned_key": credential("unprovisioned_key",
                                            provisioned=False),
            "broken_key": credential("broken_key"),
        },
    )

    class Source:
        def get(self, ref):
            if ref.path[-1] == "broken_key":
                raise SecretSourceError("the path is absent")
            return Secret(f"{ref.path[-1]}-value")

    monkeypatch.setattr(cli, "build_source", lambda *a, **k: Source())
    keys = cli._service_keys(
        manifest, manifest.credentials["sonarr_api_key"],
        tmp_path / "manifest.yaml", None,
    )

    assert set(keys) == {"sonarr", "jellyfin"}
    assert keys["sonarr"].reveal() == "sonarr_api_key-value"
    assert keys["jellyfin"].reveal() == "jellyfin_api_token-value"


def test_manual_value_stdin_reaches_preflight_without_echo(monkeypatch, capsys):
    """The opt-out key is data, not a confirmation prompt.

    It must travel to the executor as a Secret, and neither the plan nor the
    JSON may echo it. The dry run with the flag verifies it before anything is
    applied.
    """
    import argparse
    import io
    import types

    from credarr import cli, facade
    from credarr.redact import Secret

    plan = _servarr_plan(blocked=False)
    plan.mint_via = "provided"

    monkeypatch.setattr(
        cli, "load_config", lambda p: types.SimpleNamespace(
            manifest=None, default_host="nas", host=lambda h: _host(),
        )
    )
    monkeypatch.setattr(facade, "read_manifest", lambda path, registry: None)
    monkeypatch.setattr(
        facade, "plan_rotation_for",
        lambda config, manifest, name: (plan.credential, _host(), plan),
    )
    monkeypatch.setattr("sys.stdin", io.StringIO("manual-key-123\n"))
    seen: dict = {}

    def fake_preflight(*args, **kwargs):
        seen.update(kwargs)
        return []

    monkeypatch.setattr(cli, "_preflight", fake_preflight)
    args = argparse.Namespace(
        config=cli.Path("no-such-credarr.yaml"), credential="sonarr_api_key",
        manifest=None, vault_password_file=None,
        dry_run=True, apply=False, yes=False, as_json=False,
        take_over=False, manual_value_stdin=True,
    )

    assert cli._rotate(args) == ExitCode.OK

    assert isinstance(seen.get("provided"), Secret)
    assert seen["provided"].reveal() == "manual-key-123"
    out, err = capsys.readouterr()
    assert "manual-key-123" not in out + err
    assert "manual mint" in out


def test_manual_value_stdin_is_refused_for_a_backup_plan(monkeypatch, capsys):
    import argparse
    import types

    from credarr import cli, facade

    plan = _servarr_plan(blocked=False)
    monkeypatch.setattr(
        cli, "load_config", lambda p: types.SimpleNamespace(
            manifest=None, default_host="nas", host=lambda h: _host(),
        )
    )
    monkeypatch.setattr(facade, "read_manifest", lambda path, registry: None)
    monkeypatch.setattr(
        facade, "plan_rotation_for",
        lambda config, manifest, name: (plan.credential, _host(), plan),
    )
    args = argparse.Namespace(
        config=cli.Path("no-such-credarr.yaml"), credential="sonarr_api_key",
        manifest=None, vault_password_file=None,
        dry_run=True, apply=False, yes=False, as_json=False,
        take_over=False, manual_value_stdin=True,
    )

    assert cli._rotate(args) == ExitCode.USAGE
    out, err = capsys.readouterr()
    assert "only for a plan with write.manual_mint" in err
    assert "manual-key-123" not in out + err


def test_a_parked_manual_key_resumes_without_asking(monkeypatch, capsys):
    """The CLI must resume an interrupted manual mint like the server does.

    The key is already in the pending store; prompting for it again would make
    the documented resume path unreachable, because the service UI cannot show
    an existing key back to the operator.
    """
    import argparse
    import types

    from credarr import cli, facade
    from credarr.redact import Secret

    plan = _servarr_plan(blocked=False)
    plan.mint_via = "provided"

    monkeypatch.setattr(
        cli, "load_config", lambda p: types.SimpleNamespace(
            manifest=None, default_host="nas", host=lambda h: _host(),
        )
    )
    monkeypatch.setattr(facade, "read_manifest", lambda path, registry: None)
    monkeypatch.setattr(
        facade, "plan_rotation_for",
        lambda config, manifest, name: (plan.credential, _host(), plan),
    )
    monkeypatch.setattr(
        facade, "pending_for",
        lambda config: types.SimpleNamespace(
            get=lambda name: Secret("parked-key")
        ),
    )
    seen: dict = {}

    def fake_apply(*args, **kwargs):
        seen.update(kwargs)
        return ExitCode.OK

    monkeypatch.setattr(cli, "_apply", fake_apply)
    args = argparse.Namespace(
        config=cli.Path("no-such-credarr.yaml"), credential="sonarr_api_key",
        manifest=None, vault_password_file=None,
        dry_run=False, apply=True, yes=True, as_json=False,
        take_over=False, manual_value_stdin=False, actor=None,
    )

    assert cli._rotate_locked(args) == ExitCode.OK
    assert seen["provided"] is None


def test_manual_apply_without_a_parked_key_or_tty_is_usage(monkeypatch, capsys):
    import argparse
    import types

    from credarr import cli, facade

    plan = _servarr_plan(blocked=False)
    plan.mint_via = "provided"
    monkeypatch.setattr(
        cli, "load_config", lambda p: types.SimpleNamespace(
            manifest=None, default_host="nas", host=lambda h: _host(),
        )
    )
    monkeypatch.setattr(facade, "read_manifest", lambda path, registry: None)
    monkeypatch.setattr(
        facade, "plan_rotation_for",
        lambda config, manifest, name: (plan.credential, _host(), plan),
    )
    monkeypatch.setattr(
        facade, "pending_for",
        lambda config: types.SimpleNamespace(get=lambda name: None),
    )
    monkeypatch.setattr(
        "sys.stdin.isatty", lambda: False, raising=False
    )
    args = argparse.Namespace(
        config=cli.Path("no-such-credarr.yaml"), credential="sonarr_api_key",
        manifest=None, vault_password_file=None,
        dry_run=False, apply=True, yes=True, as_json=False,
        take_over=False, manual_value_stdin=False, actor=None,
    )

    assert cli._rotate_locked(args) == ExitCode.USAGE
    _, err = capsys.readouterr()
    assert "needs the key" in err
