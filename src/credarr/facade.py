"""The library behind the CLI: audit and rotation wiring, callable as functions.

The CLI is a caller, not an implementation. Everything here is what the command
line does between parsing its arguments and printing a report, exposed as
functions that take objects so a server, a test harness or a future scheduler
can call the same code and get the same blockers, ordering and exit semantics.
When the CLI and the server disagree, this is what to fix - not the caller.

Nothing here parses argv, touches argparse, or prints.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from .audit import Auditor, AuditResult, build_transport
from .config import Config, HostConfig
from .errors import CredctlError, ExitCode, ManifestError
from .fingerprint import Fingerprinter
from .journal import Journal
from .model import Credential, Manifest
from .pending import FilePending, PendingSecrets
from .redact import Secret
from .rotate import RotationPlan, plan_rotation
from .secrets import BACKENDS, SecretSource
from .targets import TargetRegistry

if TYPE_CHECKING:  # imported lazily at runtime; only the annotation needs it here
    from .executor import ExecutionResult


def read_manifest(path: Path, registry: TargetRegistry) -> Manifest:
    """Read and strictly parse a manifest against the registry.

    Parsed once, with the registry supplied, so an unknown target is an error
    here rather than a "skip" later. A manifest that cannot be read at all is a
    reported misconfiguration, not a traceback.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestError(
            f"cannot read manifest {path}: {exc.strerror}",
            hint="set 'manifest' in the config, or pass --manifest",
        ) from exc
    except UnicodeDecodeError as exc:
        raise ManifestError(
            f"cannot read manifest {path}: it is not valid UTF-8 ({exc.reason})",
            hint="save the manifest as UTF-8",
        ) from exc
    return Manifest.parse(
        text,
        origin=path,
        known_targets=registry.known_targets(),
        known_backends=BACKENDS,
    )


def journal_for(config: Config) -> Journal:
    """The stack's rotation ledger, anchored to the config, not to `-m`.

    An override names a variant manifest of the same stack; a second journal
    path would be a second lock, and two runs on the same credential would not
    see each other. The server calls this too, so a rotation started on either
    surface is visible to the other.
    """
    return Journal(config.manifest.parent / "state" / "rotation.db")


def pending_for(config: Config) -> FilePending:
    """The CLI's pending-mint store, beside the journal it belongs to."""
    return FilePending(config.manifest.parent / "state" / "pending.db")


def credential_named(manifest: Manifest, name: str) -> Credential:
    """The credential `name` declares, or an error naming the ones that exist."""
    try:
        return manifest.credentials[name]
    except KeyError as exc:
        known = ", ".join(sorted(manifest.credentials))
        raise CredctlError(
            f"no credential named {name!r}",
            hint=f"known: {known}",
        ) from exc


def plan_rotation_for(
    config: Config, manifest: Manifest, name: str
) -> tuple[Credential, HostConfig, RotationPlan]:
    """The credential, its host, and the plan to rotate it.

    One lookup shared by every caller, so the CLI and the server cannot plan a
    different rotation for the same name.
    """
    credential = credential_named(manifest, name)
    host = config.host(config.default_host)
    return credential, host, plan_rotation(credential, host)


def audit(
    config: Config,
    manifest: Manifest,
    secrets: SecretSource,
    *,
    only: set[str] | None = None,
) -> AuditResult:
    """Compare the manifest against what is held, reading through `secrets`."""
    auditor = Auditor(
        manifest=manifest,
        config=config,
        secrets=secrets,
        fingerprinter=Fingerprinter.from_config(config.fingerprint_salt),
    )
    return auditor.run(only=only)


def require_mutable(secrets: SecretSource, credential: Credential) -> None:
    """Refuse a source that cannot write, before anything irreversible happens."""
    if not hasattr(secrets, "set"):
        raise CredctlError(
            f"the {credential.vault.backend} backend cannot write",
            hint="rotation needs a mutable backend; the read path alone would "
            "leave the vault stale",
        )


def preflight(
    *,
    plan: RotationPlan,
    credential: Credential,
    host: HostConfig,
    journal: Journal,
    canonical: Secret | None,
    take_over: bool = False,
    service_keys: Mapping[str, Secret] | None = None,
    pending: PendingSecrets | None = None,
    mint_values: Mapping[str, Secret] | None = None,
    provided: Secret | None = None,
) -> list[str]:
    """Everything checkable, checked without changing anything.

    Read-only by construction, which is why a dry run can run it: a dry run that
    only prints a plan tells you what would be done and nothing about whether it
    could be. `take_over` says the caller is about to take over this
    credential's unfinished steps, which is the difference between them being a
    problem and being the thing the run was asked to do.

    `provided` is the key an operator rotated in a service's own UI for the
    explicit manual mint. It is verified here, before a run starts; a plan
    preview without it remains ready because the key does not exist yet.
    """
    from .executor import Executor, RotationContext

    ctx = RotationContext(
        credential=credential,
        host=host,
        transport=build_transport(),
        journal=journal,
        vault_value=canonical.reveal() if canonical else None,
        provided=provided.reveal() if provided else None,
        service_keys=service_keys or {},
        pending=pending,
        mint_values=mint_values or {},
        take_over=take_over,
    )
    return Executor(ctx).preflight(plan)


def rotation_options(
    *,
    credential: Credential,
    host: HostConfig,
    journal: Journal,
    canonical: Secret | None,
    service_keys: Mapping[str, Secret] | None = None,
    pending: PendingSecrets | None = None,
    mint_values: Mapping[str, Secret] | None = None,
) -> dict[str, object]:
    """What this credential's service can do, read-only.

    The same probes the plan runs for the selected method, but for every
    Servarr mint path at once: the console uses the answer to recommend backup
    & restore and only surface a fallback when that path is unavailable. This
    never decides a run; the manifest still selects the method.
    """
    from .executor import Executor, RotationContext

    ctx = RotationContext(
        credential=credential,
        host=host,
        transport=build_transport(),
        journal=journal,
        vault_value=canonical.reveal() if canonical else None,
        service_keys=service_keys or {},
        pending=pending,
        mint_values=mint_values or {},
    )
    return Executor(ctx).rotation_options()


def execute(
    *,
    plan: RotationPlan,
    credential: Credential,
    host: HostConfig,
    secrets: SecretSource,
    journal: Journal,
    canonical: Secret | None,
    actor: str | None = None,
    take_over: bool = False,
    service_keys: Mapping[str, Secret] | None = None,
    pending: PendingSecrets | None = None,
    mint_values: Mapping[str, Secret] | None = None,
    canonical_getter: Callable[[], Secret | None] | None = None,
    on_started: Callable[[int], None] | None = None,
    provided: Secret | None = None,
) -> ExecutionResult:
    """Perform the rotation, holding the lock for its whole duration.

    `canonical_getter` lets the HTTP surface re-read the working copy after the
    lock is held. A value read before the lock can be replaced by a paste while
    this run waits, and the executor would then compare against a canonical the
    store no longer holds.

    `provided` is the key the operator rotated in a service's own UI for
    `write.manual_mint`; the executor verifies it and parks it before the first
    holder write.
    """
    from .executor import Executor, RotationContext

    require_mutable(secrets, credential)

    ctx = RotationContext(
        credential=credential,
        host=host,
        transport=build_transport(),
        journal=journal,
        vault_value=canonical.reveal() if canonical else None,
        provided=provided.reveal() if provided else None,
        service_keys=service_keys or {},
        pending=pending,
        mint_values=mint_values or {},
        # Only on the apply path, where the lock is actually held.
        lease_check=None,
        # Bound to this credential's path; the bare method would need it.
        vault_setter=lambda value: secrets.set(credential.vault, value),
        take_over=take_over,
        actor=actor,
        on_started=on_started,
    )
    executor = Executor(ctx)
    with journal.lock(credential.name, actor) as lease:
        # Everything decision-critical is read inside the lock, not before it:
        # the service key, the vault comparison and the mint decision all
        # happen in execute(), so a preflight that ran while this process waited
        # cannot be stale by the time it matters.
        if canonical_getter is not None:
            current = canonical_getter()
            ctx.vault_value = current.reveal() if current else None
        ctx.lease_check = lambda: journal.assert_held(credential.name, lease)
        return executor.execute(plan)


def execution_exit_code(result: ExecutionResult) -> int:
    """The exit code a completed run earns, read off the holders it left behind.

    A holder that failed, was never reached, or was written but never read back
    is drift: the stack is inconsistent, which is the same condition `audit`
    reports. A manual step is a consumer the tool could not update, so it still
    holds the key that was just revoked - drift too.
    """
    unreached = [h for h in result.holders if h.outcome == "not-reached"]
    failed_holders = [h for h in result.holders if h.outcome == "failed"]
    unconfirmed = [h for h in result.holders if h.outcome == "written"]

    if result.failed or failed_holders or unreached:
        return ExitCode.DRIFT
    if result.manual:
        return ExitCode.DRIFT
    if unconfirmed:
        return ExitCode.DRIFT
    return ExitCode.OK
