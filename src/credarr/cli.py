"""Command line entry point.

The exit code is the contract, not the prose. A CI job keys off it and should
never have to parse a message to find out what happened:

    0  everything the manifest claims to check, was checked, and matched
    1  drift or a missing copy - something is wrong and it is actionable
    2  the command line itself was wrong
    3  the config or manifest is unusable - nothing was checked
    4  a host could not be reached - coverage is partial and unknown

3 and 4 are kept distinct from 1 on purpose. "Everything is fine" and "I could
not tell" must never look the same to a scheduled job, or the schedule becomes
a way of not finding out.
"""

from __future__ import annotations

import argparse
import contextlib
import getpass
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from . import __version__, facade
from .config import Config, HostConfig, load_config
from .errors import CredctlError, ExitCode
from .instance import DEFAULT_CONFIG_DIR, InstanceLock
from .model import Credential, Manifest
from .redact import Secret
from .redact import disable_core_dumps as _disable_core_dumps
from .report import (
    exit_code_for,
    render_execution_json,
    render_human,
    render_json,
    render_rotation_json,
)
from .rotate import RotationPlan, service_for, ui_password_names
from .targets import build_registry

if TYPE_CHECKING:  # imported lazily at runtime; only the annotation needs it here
    from .executor import ExecutionResult
from .secrets import build_source


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="credarr",
        description=(
            "Compare the credential manifest against what is actually held on "
            "each host, and report any copy that has drifted."
        ),
    )
    parser.add_argument("--version", action="version", version=f"credarr {__version__}")
    # Global rather than per-subcommand: the config file is needed by every
    # command, and requiring it after the verb is a papercut.
    parser.add_argument(
        "-c", "--config", type=Path, default=Path("credarr.yaml"),
        help="configuration file (default: credarr.yaml)",
    )
    parser.add_argument(
        "--config-dir", type=Path, default=None,
        help="directory holding app.lock (default: CREDARR_CONFIG_DIR or the "
        "config file's directory)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    audit = subparsers.add_parser(
        "audit", help="check every credential the manifest declares"
    )
    _add_common(audit)
    audit.add_argument(
        "--credential",
        action="append",
        dest="credentials",
        metavar="NAME",
        help="only audit this credential (repeatable)",
    )

    rotate = subparsers.add_parser(
        "rotate",
        help="plan a credential rotation (dry run unless --apply is given)",
    )
    _add_common(rotate)
    rotate.add_argument("credential", help="the credential to rotate")
    rotate.add_argument(
        "--dry-run", action="store_true",
        help="plan the rotation and change nothing (the default)",
    )
    rotate.add_argument(
        "--apply", action="store_true",
        help="perform the rotation, prompting for confirmation first",
    )
    rotate.add_argument(
        "--yes", action="store_true",
        help="do not prompt for the typed credential name. For automation, and "
        "only with --apply; the preflight checks still run and still refuse. A "
        "write.manual_mint plan still needs the key: pass --manual-value-stdin",
    )
    rotate.add_argument(
        "--manual-value-stdin", action="store_true", dest="manual_value_stdin",
        help="read the new API key from stdin for a write.manual_mint plan; "
        "the key is never taken from argv and is not echoed",
    )
    rotate.add_argument(
        "--take-over", action="store_true", dest="take_over",
        help="close out this credential's unfinished steps, recording them as "
        "taken over, instead of waiting for them to age out. The run still "
        "reads the service's own state first, so an earlier mint is resumed, "
        "not repeated",
    )
    rotate.add_argument(
        "--actor", metavar="WHO", default=None,
        help="who is asking for this rotation, recorded on the lock for "
        "display while it is held. Diagnostic only: it never grants or proves "
        "ownership, which is the random token. Nothing is inferred from it, so "
        "an unattended run records none",
    )

    subparsers.add_parser(
        "targets", help="list every target this build knows how to read"
    )

    return parser


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-m", "--manifest", type=Path, default=None,
        help="override the manifest path from the config",
    )
    parser.add_argument(
        "--vault-password-file", type=Path, default=None,
        help="path to the Ansible vault password file",
    )
    parser.add_argument(
        "--json", action="store_true", dest="as_json",
        help="machine-readable output",
    )
    parser.add_argument(
        "--no-colour", "--no-color", action="store_true", dest="no_colour",
        help="disable terminal styling",
    )


def main(argv: list[str] | None = None) -> int:
    # Before anything reads a secret, so no later import or exception can leak
    # one into a core file.
    _disable_core_dumps()

    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "targets":
            return _targets(args)
        if args.command == "rotate":
            return _rotate(args)
        return _audit(args)
    except CredctlError as exc:
        print(exc.render(), file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return ExitCode.UNREACHABLE


def _targets(args: argparse.Namespace) -> int:
    load_config(args.config)
    registry = build_registry()
    for key in sorted(registry.known_targets()):
        print(f"{key:<36} {registry.describe(key)}")
    return ExitCode.OK


def _audit(args: argparse.Namespace) -> int:
    config_path = args.config.resolve()
    config = load_config(config_path)
    registry = build_registry()

    manifest_path = args.manifest or config.manifest
    manifest = facade.read_manifest(manifest_path, registry)

    password_file = _password_file(args.vault_password_file, config_path)

    secrets = build_source(
        _primary_backend(manifest),
        # Relative to the manifest, not to this config file. A manifest declares
        # where its values are, so it has to be self-contained: resolving against
        # wherever credarr happened to be installed meant that moving the tool
        # silently broke every manifest that pointed outside its own directory.
        config_dir=manifest_path.parent,
        vault_password_file=password_file,
    )

    result = facade.audit(
        config,
        manifest,
        secrets,
        only=set(args.credentials) if args.credentials else None,
    )

    if args.as_json:
        render_json(result, sys.stdout)
    else:
        render_human(result, sys.stdout, colour=False if args.no_colour else None)
    return exit_code_for(result)


def _primary_backend(manifest: Manifest) -> str:
    """Pick the backend to construct.

    A single process reads one backend, because each backend is a different
    trust decision. Credentials that name a different backend are reported as
    errors rather than silently skipped, so a mixed manifest cannot half-work.
    """
    backends = {
        c.vault.backend
        for c in manifest.credentials.values()
        if c.vault is not None and c.provisioned
    }
    if not backends:
        raise CredctlError("the manifest declares no credential with a vault reference")
    if len(backends) > 1:
        raise CredctlError(
            f"the manifest mixes vault backends: {', '.join(sorted(backends))}",
            hint="run one backend at a time until the tool can hold more than "
            "one open at a time",
        )
    return backends.pop()


def _configured_password_file(config_path: Path) -> str | None:
    """Read vault_password_file out of the config without a second full load."""
    import yaml

    try:
        document = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return None
    value = document.get("vault_password_file")
    if not value:
        return None
    path = Path(str(value))
    return str(path if path.is_absolute() else config_path.parent / path)


def _password_file(override: Path | None, config_path: Path) -> Path | None:
    """`--vault-password-file` wins; otherwise the config that `-c` named.

    A property of this machine, not of the credential, so it is never read
    from the manifest.
    """
    if override is not None:
        return override
    configured = _configured_password_file(config_path)
    return Path(configured) if configured else None


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


def _rotate(args: argparse.Namespace) -> int:
    """Refuse a mutation while the server owns this `/config`, then plan/apply.

    A dry run is read-only and may run while the server is up. An `--apply`
    takes the server's `app.lock` for the whole run, so the CLI and the server
    cannot rotate the same stack at once.
    """
    lock: contextlib.AbstractContextManager[object] = contextlib.nullcontext()
    if args.apply and not args.dry_run:
        lock = InstanceLock(_lock_dir(args))
    with lock:
        return _rotate_locked(args)


def _lock_dir(args: argparse.Namespace) -> Path:
    override = getattr(args, "config_dir", None)
    if override is not None:
        return Path(override).resolve()
    env = os.environ.get("CREDARR_CONFIG_DIR")
    if env:
        return Path(env).resolve()
    if DEFAULT_CONFIG_DIR.is_dir():
        return DEFAULT_CONFIG_DIR
    return args.config.resolve().parent


def _rotate_locked(args: argparse.Namespace) -> int:
    """Print the plan. Apply only when explicitly asked.

    Dry run is the default because the first step of a rotation is
    irreversible: it invalidates the old key before any consumer has the new
    one. That is a thing to agree to, not to discover.
    """
    config_path = args.config.resolve()
    config = load_config(config_path)
    # Resolved the way audit resolves it: -m wins, the vault is read relative
    # to whichever manifest won, and the journal stays with the config.
    manifest_path = args.manifest or config.manifest
    manifest = facade.read_manifest(manifest_path, build_registry())
    credential, host, plan = facade.plan_rotation_for(config, manifest, args.credential)
    password_file = _password_file(args.vault_password_file, config_path)

    # Prose and JSON cannot share stdout, so under --json the plan is emitted
    # once, at the point the human summary would have been. Preflight still
    # runs below: a machine-readable caller still needs to be told the live
    # system is unreachable rather than handed a plan that looks fine.
    if not args.as_json:
        print(f"Rotation plan for {credential.name} "
              f"[{credential.credential_class}, max age {credential.max_age_days}d]")
        print(f"  host: {host.name}    consumers: {credential.declared_copies}")
        # Only for a plan that could run. A refused plan mints nothing, so telling
        # the reader its holders hold dead keys would be a false statement about
        # system state - the exact kind of over-claim this tool exists to avoid.
        if plan.mint_via == "provided" and not plan.blocked_by:
            print()
            print("  This is the manual mint: rotate the key in the service's")
            print("  own UI first. The service revokes the old key at that point,")
            print("  so the key you supply below is the only working one. No")
            print("  backup is read and no config is restored.")
        elif plan.revokes_before_holders and not plan.blocked_by:
            # Stated before the steps, because it is the fact that governs them.
            # A reader who sees only "confirmed" at the end would otherwise have
            # no way to know the old key died before the first write.
            print()
            print("  The mint revokes the old credential before any holder is")
            print("  updated. Every holder below holds a dead key until reached,")
            print("  and this is why a holder that is not confirmed means a")
            print("  non-zero exit rather than a warning.")
        print()

        for step in plan.steps:
            print(f"  {step}")
        print()

    if plan.blocked_by:
        if args.as_json:
            render_rotation_json(credential, host, plan, sys.stdout)
            return ExitCode.REFUSED
        print("  BLOCKED:")
        for reason in plan.blocked_by:
            print(f"    - {reason}")
        print()
        print("  This rotation cannot complete. A rotation that stops halfway is")
        print("  worse than none: the new value would exist in the vault and")
        print("  nowhere else.")
        # REFUSED, not CONFIG. CONFIG means this tool cannot be run - a bad
        # manifest, a missing file. REFUSED means the tool ran fine and
        # declined, because the credential's class or a holder's missing write
        # path makes rotation impossible. A scheduled job needs those apart:
        # one is "fix the operator's input", the other is "not rotatable yet",
        # and the second is not an error to page anyone about.
        return ExitCode.REFUSED

    if args.take_over:
        # Said before the prompt and before anything is read, because it is an
        # assertion the operator is making about a run they cannot see: the
        # steps below are closed as taken over, and what makes the takeover
        # safe is the state read afterwards, not the age of the record.
        taken = [
            step
            for step in facade.journal_for(config).pending()
            if step.credential == credential.name
        ]
        if not args.as_json:
            print()
            if taken:
                print(f"  TAKING OVER {len(taken)} unfinished step(s):")
                for step in taken:
                    minutes = max(1, round(step.seconds_ago / 60))
                    print(
                        f"    - {step.target} ({step.detail or 'no detail'}, "
                        f"{minutes} minutes ago)"
                    )
            else:
                print("  --take-over: this credential has no unfinished step to "
                      "take over; nothing changes.")
            print()
            print("  If this run starts, they are closed as taken over by it, and")
            print("  the mint re-derives from the service's own state: an earlier")
            print("  mint is resumed, not repeated.")
            print()

    service_keys = _service_keys(manifest, credential, manifest_path,
                                  password_file)
    mint_values = _mint_values(manifest, credential, manifest_path,
                               password_file)
    provided: Secret | None = None
    if getattr(args, "manual_value_stdin", False):
        if plan.mint_via != "provided":
            print(
                "--manual-value-stdin is only for a plan with write.manual_mint",
                file=sys.stderr,
            )
            return ExitCode.USAGE
        provided = _manual_value_from_stdin()
        if provided is None:
            return ExitCode.USAGE

    if args.dry_run or not args.apply:
        problems = _preflight(
            plan, credential, host, config, manifest_path, password_file,
            take_over=args.take_over, service_keys=service_keys,
            mint_values=mint_values, provided=provided,
        )
        if problems:
            if args.as_json:
                # Exit 3 still says "nothing was checked", and the reasons
                # travel in the document: prose here would break
                # `rotate --json | jq` in exactly the case a job needs it.
                render_rotation_json(
                    credential, host, plan, sys.stdout, problems=problems
                )
                return ExitCode.CONFIG
            _print_problems(problems)
            return ExitCode.CONFIG
        if args.as_json:
            render_rotation_json(credential, host, plan, sys.stdout)
            return ExitCode.OK
        print()
        print(f"  {len(plan.steps)} step(s) planned, nothing changed.")
        print("  Re-run with --apply to perform it.")
        return ExitCode.OK

    if args.as_json and not args.yes:
        # The prompt is prose, and stdout is the JSON document. Automation
        # passes --yes; the preflight still runs and still refuses.
        print("--json cannot prompt for confirmation; pass --yes", file=sys.stderr)
        return ExitCode.USAGE

    if plan.mint_via == "provided" and provided is None:
        pending = facade.pending_for(config)
        if pending.get(credential.name) is None:
            if not sys.stdin.isatty():
                print(
                    "the manual mint needs the key rotated in the service's UI; "
                    "pass --manual-value-stdin (never the key in argv)",
                    file=sys.stderr,
                )
                return ExitCode.USAGE
            provided = _manual_value_prompt()
            if provided is None:
                return ExitCode.USAGE

    return _apply(plan, credential, host, config, manifest_path, password_file,
                  prompt=not args.yes, actor=args.actor, as_json=args.as_json,
                  take_over=args.take_over, service_keys=service_keys,
                  mint_values=mint_values, provided=provided)


def _manual_value_from_stdin() -> Secret | None:
    """Read the key rotated in the service's UI from stdin, never argv.

    One line, no echo. The value is wrapped immediately so it cannot be printed
    by accident; the executor parks it in the pending store before the first
    holder write.
    """
    line = sys.stdin.readline()
    if not line:
        print(
            "--manual-value-stdin: no key on stdin; nothing was changed",
            file=sys.stderr,
        )
        return None
    value = line.strip()
    if not value:
        print(
            "--manual-value-stdin: the supplied key is empty; nothing was changed",
            file=sys.stderr,
        )
        return None
    return Secret(value)


def _manual_value_prompt() -> Secret | None:
    """Ask for the key the operator rotated in the service's own UI."""
    try:
        value = getpass.getpass(
            "  new API key from the service's UI (input hidden): "
        ).strip()
    except (EOFError, KeyboardInterrupt):
        print("\n  No key supplied. Nothing was changed.")
        return None
    if not value:
        print("  No key supplied. Nothing was changed.")
        return None
    return Secret(value)


def _confirm(credential_name: str, plan: RotationPlan) -> bool:
    """Typed confirmation, not a yes/no.

    True, False, or None for "nobody was there to answer". Those are different
    outcomes and the caller treats them differently: a person deciding not to
    proceed is a decision, while no input at all means the prompt was never
    really answered - and a scheduled run would otherwise record a rotation
    that never happened as a success.

    The first step is irreversible and, for a reset, there is no overlap
    window: the old key dies before any consumer has the new one. A create
    mint is the opposite shape - the old key is revoked last - so the sentence
    below the list says which of the two is happening. Either way a prompt
    answered by muscle memory is not consent, so the operator types the
    credential's name.
    """
    irreversible = [s for s in plan.steps if not s.reversible]
    print("  This will change live services:")
    for step in irreversible:
        print(f"    - {step.target}: {step.detail}")
    print()
    if plan.mint_via == "provided":
        print("  The service's current key has already been revoked by the")
        print("  manual rotation. The supplied key is the only working one, and")
        print("  there is no configuration backup to restore if this run stops.")
    elif plan.revokes_before_holders:
        print("  The current key stops working at the first step and cannot be")
        print("  recalled. Everything after it is verified through the holder's")
        print("  own API where it exposes one, and anything it cannot confirm is")
        print("  named as unproven rather than counted as success.")
    else:
        print("  The current key keeps working until the revoke step; the mint")
        print("  creates a new key alongside it. Everything between is verified")
        print("  the same way, and a failure stops the rotation rather than")
        print("  continuing.")
    print()
    try:
        answer = input(f"  type the credential name to proceed [{credential_name}]: ")
    except EOFError:
        return None
    return answer.strip() == credential_name


def _preflight(plan: RotationPlan, credential: Credential, host: HostConfig,
               config: Config, manifest_path: Path, password_file: Path | None,
               *, take_over: bool = False,
               service_keys: Mapping[str, Secret] | None = None,
               mint_values: Mapping[str, Secret] | None = None,
               provided: Secret | None = None) -> list[str]:
    """Everything checkable, checked without changing anything.

    Read-only by construction: it asks each service for its status and lists
    the rows it would write. That is why a dry run can
    run it - a dry run that only prints a plan tells you what would be done and
    nothing about whether it could be.
    """
    canonical = _canonical(credential, manifest_path, password_file)
    journal = facade.journal_for(config)
    return facade.preflight(
        plan=plan,
        credential=credential,
        host=host,
        journal=journal,
        canonical=canonical,
        take_over=take_over,
        service_keys=service_keys,
        pending=facade.pending_for(config),
        mint_values=mint_values,
        provided=provided,
    )


def _print_problems(problems: list[str]) -> None:
    print("  PREFLIGHT FAILED - nothing was changed:")
    for problem in problems:
        print(f"    - {problem}")
    print()
    print("  The old key is still valid. Fix these and try again.")
    print()
    print("  Preflight is a preflight, not a guarantee. It checks what can be")
    print("  checked before the old key is revoked; it cannot rule out a write")
    print("  that fails afterwards. Every later write is still fallible, which")
    print("  is why each holder is verified through its own API and every")
    print("  unproven one is named individually.")


def _canonical(credential: Credential, manifest_path: Path,
               password_file: Path | None) -> Secret | None:
    """The current vault value, or None when the entry is absent.

    Read relative to the resolved manifest - the same rule audit uses.
    """
    if credential.vault is None:
        return None
    source = build_source(
        credential.vault.backend,
        config_dir=manifest_path.parent,
        vault_password_file=password_file,
    )
    return source.get(credential.vault)


def _service_keys(manifest: Manifest, credential: Credential,
                  manifest_path: Path,
                  password_file: Path | None) -> dict[str, Secret]:
    """The vault's copies of each service's own API key, keyed by service.

    The CLI counterpart of the app's store lookup: the holder's own key comes
    from the same vault that holds the credential being rotated. There is no
    config-file fallback. The service is derived by `service_for`, so
    `jellyfin_api_token` with `canonical.service: jellyfin` is found without a
    naming convention of its own.
    """
    if credential.vault is None:
        return {}
    source = build_source(
        credential.vault.backend,
        config_dir=manifest_path.parent,
        vault_password_file=password_file,
    )
    keys: dict[str, Secret] = {}
    for item in manifest.credentials.values():
        if item.name in ui_password_names(manifest, service_for(item)):
            continue
        if (
            item.vault is None
            or not item.provisioned
            or item.vault.backend != credential.vault.backend
        ):
            continue
        try:
            value = source.get(item.vault)
        except CredctlError:
            # A key this rotation does not need is not a reason to abort it.
            # A holder with no stored service key is reported unverifiable by
            # its own preflight, in the holder's own words.
            continue
        if value is not None:
            keys.setdefault(service_for(item), value)
    return keys


def _mint_values(manifest: Manifest, credential: Credential,
                 manifest_path: Path,
                 password_file: Path | None) -> dict[str, Secret]:
    """The stored values of credentials this one names for a mint.

    `write.mint_with` lets a least-privilege credential be rotated by the admin
    credential that holds the minting grants. `write.ui_password` names the
    credential holding the service's own UI password, which opens the backup
    download when the service's authentication is on. Only the named values
    are read, and only when this credential asks for them; an absent name or
    value comes back empty so preflight and the mint report it in their own
    words.
    """
    declared: set[str] = set()
    for field_name in ("mint_with", "ui_password"):
        name = str(credential.write.get(field_name) or "").strip()
        if name:
            declared.add(name)
    values: dict[str, Secret] = {}
    for name in declared:
        other = manifest.credentials.get(name)
        if other is None or other.vault is None or not other.provisioned:
            continue
        source = build_source(
            other.vault.backend,
            config_dir=manifest_path.parent,
            vault_password_file=password_file,
        )
        try:
            value = source.get(other.vault)
        except CredctlError:
            continue
        if value is not None:
            values[name] = value
    return values


def _apply(plan: RotationPlan, credential: Credential, host: HostConfig,
           config: Config, manifest_path: Path, password_file: Path | None, *,
           prompt: bool, actor: str | None = None, as_json: bool = False,
           take_over: bool = False,
           service_keys: Mapping[str, Secret] | None = None,
           mint_values: Mapping[str, Secret] | None = None,
           provided: Secret | None = None) -> int:
    """Perform the rotation.

    Every failure path ends with the journal holding the evidence, which is what
    lets the next run report the state of the stack instead of guessing at it.
    """
    secrets = build_source(
        credential.vault.backend,
        config_dir=manifest_path.parent,
        vault_password_file=password_file,
        mutable=True,
    )
    facade.require_mutable(secrets, credential)

    canonical = secrets.get(credential.vault)
    journal = facade.journal_for(config)
    pending = facade.pending_for(config)

    # Everything checkable is checked before anything irreversible happens. This
    # runs even in automation: --yes skips the prompt, not the safety.
    problems = facade.preflight(
        plan=plan, credential=credential, host=host, journal=journal,
        canonical=canonical, take_over=take_over, service_keys=service_keys,
        pending=pending, mint_values=mint_values, provided=provided,
    )
    if problems:
        if as_json:
            render_rotation_json(credential, host, plan, sys.stdout, problems=problems)
        else:
            _print_problems(problems)
        return ExitCode.CONFIG

    if prompt:
        answer = _confirm(credential.name, plan)
        if answer is None:
            print()
            print("  Nothing was changed: there was no terminal to confirm on.")
            print("  For unattended use, pass --apply --yes to skip the prompt.")
            return ExitCode.USAGE
        if not answer:
            print("  Not confirmed. Nothing was changed.")
            return ExitCode.OK

    result = facade.execute(
        plan=plan, credential=credential, host=host, secrets=secrets,
        journal=journal, canonical=canonical, actor=actor, take_over=take_over,
        service_keys=service_keys, pending=pending, mint_values=mint_values,
        provided=provided,
    )

    if as_json:
        render_execution_json(result, sys.stdout)
        return _finish(result, as_json=True)

    print()
    for target in result.completed:
        print(f"  done     {target}")
    if result.resumed:
        print()
        print("  This run did NOT mint. The service already held a key the vault")
        print("  did not, so an earlier attempt had rotated it and this run")
        print("  continued from there. Minting again would have invalidated")
        print("  every holder that attempt had already reached.")
    if result.reclaimed:
        print()
        print("  TOOK OVER from the run that stopped here:")
        for target, detail in result.reclaimed:
            print(f"    - {target} (was at: {detail or 'no detail'})")
        print()
        print("  Those steps were closed out, not resumed blindly. This run read")
        print("  the service's actual state and decided what to do from that, so")
        print("  a key already given to a holder is not thrown away here.")
    for target in result.manual:
        print(f"  manual   {target}   redeploy required")

    if result.holders:
        print()
        print("  holders:")
        for holder in result.holders:
            # An unknown outcome must not take the reporting down with it: this
            # runs after a run completes, and a KeyError here would replace the
            # rotation's outcome with a traceback in the operator's terminal.
            mark = _OUTCOME_MARKS.get(holder.outcome, "????? ")
            line = f"    {mark} {holder.target}[{holder.label}]"
            if holder.method:
                line += f"  via {holder.method}"
            if holder.detail:
                line += f"  {holder.detail}"
            print(line)
        print()
        print(f"  {result.summary()}")

    return _finish(result)


# How each holder outcome is marked in the report. `.get` with a default, so a
# holder carrying an outcome this build does not know about is shown as unknown
# rather than raising a KeyError over a completed rotation.
_OUTCOME_MARKS = {
    "confirmed": "ok    ",
    "already-current": "ok    ",
    "written": "unver ",
    "failed": "FAILED",
    "not-reached": "SKIP  ",
}


def _finish(result: ExecutionResult, *, as_json: bool = False) -> int:
    """Report everything outstanding, then decide the exit code.

    Every reason is printed before any of them decides, because returning early
    on the first one hides the others - a run that failed *and* has a manual
    step outstanding must say both, or the operator fixes one and is surprised
    by the other.

    Under `--json` the same facts are already in `execution_json`, so printing
    them here would corrupt the document. The exit code is unchanged.
    """
    if as_json:
        return facade.execution_exit_code(result)
    unreached = [h for h in result.holders if h.outcome == "not-reached"]
    failed_holders = [h for h in result.holders if h.outcome == "failed"]
    # A holder whose write landed but which was never read back and confirmed.
    # Outstanding, never a success. Reported separately from failures because
    # the remedy is not "re-run": the value may already be correct, and
    # re-running would mint a third key for it.
    unconfirmed = [h for h in result.holders if h.outcome == "written"]

    if unconfirmed:
        print()
        print(f"  {len(unconfirmed)} holder(s) written but NOT confirmed:")
        for holder in unconfirmed:
            print(f"    - {holder.target} [{holder.label}]  {holder.detail}")
        print()
        print("  The write was accepted but the holder's own API never confirmed")
        print("  the stored value, so delivery is unproven. This is the")
        print("  state a run interrupted mid-propagation leaves behind.")

    if result.manual:
        print()
        print(f"  INCOMPLETE: {len(result.manual)} step(s) need a human:")
        for target in result.manual:
            print(f"    - {target}")
        print()
        if result.vault_written:
            print("  The vault now holds the new key. Until those are done,")
            print("  those consumers still hold the revoked one and will fail.")
        else:
            # Claiming the vault was written when the write is the step that
            # failed is the tool stating a false thing about the system it was
            # built to describe.
            print("  The vault has NOT been updated, so it still holds the old")
            print("  key. Nothing has been recorded anywhere yet.")

    if result.failed or failed_holders or unreached:
        if result.failed:
            print()
            print(f"  FAILED at {result.failed}: {result.detail}")
        print()
        print(f"  {len(failed_holders)} holder(s) failed, {len(unreached)} never")
        if result.revokes_before_holders:
            print("  reached. The old key is already revoked. Re-running resumes from")
            print("  here rather than minting a third one.")
        else:
            print("  reached. The old key may still be live - this mint revokes")
            print("  it last. Re-running mints a new key, revokes the old one, and")
            print("  sweeps keys a dead run minted under credarr's name. One that")
            print("  carries no such name stays live, and no run can tell it from")
            print("  a key in use: delete it in the service's own key list.")

    # A manual step is a consumer the tool could not update. Until an operator
    # acts it still holds the key that was just revoked, so the stack is
    # inconsistent - which is what DRIFT means here, and is the same condition
    # `credarr audit` would report. Exiting clean would be the exact failure
    # this tool exists to avoid: the vault saying one thing and a live consumer
    # another. An unconfirmed holder is the same argument: the write landed and
    # the service was restarted to load it, but "may well have" is what DRIFT
    # means, and an exit 0 here would tell a scheduled job that Seerr holds the
    # new key when no observation supports it.
    return facade.execution_exit_code(result)
