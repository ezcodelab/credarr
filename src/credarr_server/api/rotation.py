"""Planning, running, and abandoning one credential's rotation.

The plan is the engine's; this domain only assembles the source, takes the
stack lease, and turns the run's journal into the console's JSON."""

from __future__ import annotations

import contextlib
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from credarr import facade, report
from credarr.config import HostConfig
from credarr.errors import CredctlError, ExitCode
from credarr.journal import JournalLocked
from credarr.model import Credential
from credarr.redact import Secret, scrub
from credarr.rotate import RotationPlan
from credarr_server.api.context import ApiContext
from credarr_server.api.http import _actor, new_routers
from credarr_server.api.models import PlanBody, RotateBody
from credarr_server.api.payloads import _holder_names, _rotation_detail
from credarr_server.source import (
    StorePending,
    StoreSource,
    rotation_manifest,
    runtime_config,
    stored_mint_values,
    stored_service_keys,
)
from credarr_server.store import UnknownCredential
from credarr_server.vault import KekUnavailable


def _canonical(store: Any, name: str) -> Secret | None:
    try:
        return store.get_value(name)
    except KekUnavailable as exc:
        raise HTTPException(status_code=503, detail=exc.render()) from None


def routes(ctx: ApiContext) -> tuple[APIRouter, APIRouter]:
    """The domain's routes, over the one process context."""
    store = ctx.store
    log = ctx.log
    config = ctx.config
    stack_write = ctx.stack_write
    public, authed = new_routers()

    def rotation_parts(
        name: str, *, take_over: bool = False, provided: str | None = None
    ) -> tuple[
        Credential, HostConfig, RotationPlan, list[str], int,
        dict[str, Secret], dict[str, Secret],
    ]:
        """The plan and everything checkable, without changing anything.

        The plan endpoint and the start of a run are the same call: the server
        re-plans here rather than trusting a plan the browser read back, so a
        stale or edited plan cannot decide what gets written. A refused plan
        mints nothing, so preflight is skipped for it - it would only ask
        services to answer for a run that cannot happen.

        The exit code travels with the parts because it is not always derivable
        from them: a preflight that fails *before* it can report problems
        (a missing URL or stored key) carries the failing error's own code,
        which is the code `rotate --dry-run` returns.
        """
        if store.vault.lifecycle(name) is not None:
            raise HTTPException(
                status_code=409,
                detail=f"{name} is soft-deleted; restore it before rotating",
            )
        try:
            manifest = rotation_manifest(store, name)
        except UnknownCredential:
            raise HTTPException(
                status_code=404, detail=f"no credential named {name}"
            ) from None
        try:
            service_keys = stored_service_keys(store, manifest)
        except KekUnavailable as exc:
            raise HTTPException(status_code=503, detail=exc.render()) from None
        effective = runtime_config(config, store)
        credential, host, plan = facade.plan_rotation_for(effective, manifest, name)
        try:
            mint_values = stored_mint_values(store, manifest, credential)
        except KekUnavailable as exc:
            raise HTTPException(status_code=503, detail=exc.render()) from None
        if plan.blocked_by:
            return (credential, host, plan, [], ExitCode.REFUSED, service_keys,
                    mint_values)
        try:
            problems = facade.preflight(
                plan=plan,
                credential=credential,
                host=host,
                journal=facade.journal_for(config),
                canonical=_canonical(store, name),
                take_over=take_over,
                service_keys=service_keys,
                pending=StorePending(store),
                mint_values=mint_values,
                provided=Secret(provided) if provided else None,
            )
        except CredctlError as exc:
            # Preflight reports unreachable services as its own problems; a host
            # that cannot even name one, or a missing stored key, fails before
            # it can report at all. Keep the error's own exit code, so this
            # answer and `rotate --dry-run` name the same failure the same way
            # (3 for a missing URL or key).
            return (credential, host, plan, [str(exc)], exc.exit_code,
                    service_keys, mint_values)
        return (
            credential,
            host,
            plan,
            problems,
            ExitCode.CONFIG if problems else ExitCode.OK,
            service_keys,
            mint_values,
        )

    def plan_payload(name: str, *, take_over: bool = False) -> dict[str, Any]:
        credential, host, plan, problems, code, _service_keys, _mint_values = (
            rotation_parts(name, take_over=take_over)
        )
        return {
            **report.rotation_json(credential, host, plan, problems),
            "exit_code": int(code),
            "run": None,
        }

    @authed.post("/credentials/{name}/plan")
    def plan_rotation(name: str, body: PlanBody | None = None) -> dict[str, Any]:
        """The dry run, in the CLI's own document.

        Read-only: planning and preflight change no credential or config. A
        declared UI credential may create a transient service session while
        checking the backup download route; that is an authentication check
        and leaves no credential or config change. `exit_code` is the
        code `rotate --dry-run` would return for the same answer - 0 ready,
        3 preflight failed, 5 refused, or the failing error's own code when
        preflight raises before it can report (4 unreachable / unreadable,
        1 cannot be attempted) - so the console names the same state a job
        would act on.

        `take_over` answers this credential's unfinished steps the way
        `rotate --take-over` does: the plan is read as the run that continues
        from the service's state, so its own interrupted steps are not a
        problem. The steps are closed when the run starts, never here.
        """
        return plan_payload(name, take_over=body.take_over if body else False)

    @authed.get("/credentials/{name}/rotation-options")
    def rotation_options(name: str) -> dict[str, Any]:
        """What this key's service can do, read-only.

        The console uses this to recommend backup & restore without showing a
        method picker, and to explain the fallback only when the backup route
        is unavailable. It runs the same probes as the plan for all Servarr
        paths; nothing here changes a credential or a service. A key must be
        stored first because every check authenticates with it.
        """
        if store.vault.lifecycle(name) is not None:
            raise HTTPException(
                status_code=409,
                detail=f"{name} is soft-deleted; restore it before rotating",
            )
        try:
            manifest = rotation_manifest(store, name)
        except UnknownCredential:
            raise HTTPException(
                status_code=404, detail=f"no credential named {name}"
            ) from None
        try:
            canonical = store.get_value(name)
        except KekUnavailable as exc:
            raise HTTPException(status_code=503, detail=exc.render()) from None
        if canonical is None:
            raise HTTPException(
                status_code=409,
                detail="store the key first; rotation options need it to read "
                "the service",
            )
        effective = runtime_config(config, store)
        try:
            credential, host, _plan = facade.plan_rotation_for(
                effective, manifest, name
            )
            return facade.rotation_options(
                credential=credential,
                host=host,
                journal=facade.journal_for(config),
                canonical=canonical,
                service_keys=stored_service_keys(store, manifest),
                pending=StorePending(store),
                mint_values=stored_mint_values(store, manifest, credential),
            )
        except CredctlError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None

    @authed.post("/credentials/{name}/rotate")
    def rotate(
        name: str, body: RotateBody, actor: str = Depends(_actor)
    ) -> dict[str, Any]:
        """Perform the rotation, after the operator types its name.

        The typed name is checked here because the server, not the form, is the
        trust boundary. Everything after it is the CLI's apply path: preflight,
        execute, and the same exit code. A refusal or a failed preflight returns
        its reasons with `run: null` and changes nothing.
        """
        if body.confirm.strip() != name:
            raise HTTPException(
                status_code=400,
                detail="not confirmed: type the credential's name to proceed",
            )
        provided = (body.manual_value or "").strip() or None
        if body.manual_value is not None and provided is None:
            raise HTTPException(
                status_code=400,
                detail="the manual key is empty; nothing has been changed",
            )
        if provided is not None and len(provided) > 4096:
            raise HTTPException(
                status_code=400,
                detail="the supplied key is unexpectedly long; nothing has "
                "been changed",
            )

        def record_attempt(kind: str, detail: str) -> None:
            """Best-effort, and scrubbed: the events table and the sinks must
            never carry a value.

            The executor scrubs a failed step's sentence at the one place every
            failure passes through, but a preflight problem is built outside
            that boundary (`problems.append(str(exc))`), and this record is a
            new egress path for it. Scrubbing here covers both.

            Best-effort because the journal already holds the run and a
            refusal's reasons are in the response either way; a broken events
            table surfaces through the loops' health, not by telling the
            operator a completed rotation failed (which invites a second mint).
            """
            with contextlib.suppress(Exception):
                log.record_rotation_event(
                    kind,
                    name,
                    scrub(
                        detail, store.get_value(name), provided
                    ),
                )

        with stack_write(actor):
            credential, host, plan, problems, code, service_keys, mint_values = (
                rotation_parts(
                    name, take_over=body.take_over, provided=provided
                )
            )
            manual = plan.mint_via == "provided"
            if provided is not None and not manual:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "this rotation does not use a manual mint; the supplied key "
                        "was not used"
                    ),
                )
            if manual and provided is None and store.get_pending(name) is None:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "the manual mint needs the key you rotated in the service's "
                        "own UI; nothing has been changed"
                    ),
                )
            if plan.blocked_by or problems:
                record_attempt(
                    "rotation_refused" if plan.blocked_by else "rotation_failed",
                    "; ".join(plan.blocked_by or problems),
                )
                return {
                    **report.rotation_json(credential, host, plan, problems),
                    "exit_code": int(code),
                    "run": None,
                }
            try:
                result = facade.execute(
                    plan=plan,
                    credential=credential,
                    host=host,
                    secrets=StoreSource(store, actor=actor, origin="user"),
                    journal=facade.journal_for(config),
                    canonical=None,
                    canonical_getter=lambda: store.get_value(name),
                    actor=actor,
                    take_over=body.take_over,
                    service_keys=service_keys,
                    pending=StorePending(store),
                    mint_values=mint_values,
                    provided=Secret(provided) if provided else None,
                )
            except KekUnavailable as exc:
                raise HTTPException(status_code=503, detail=exc.render()) from None
            except JournalLocked as exc:
                # Another run holds the credential lease. The stack lease is
                # already held above, so this names the real conflict.
                raise HTTPException(status_code=409, detail=str(exc)) from None
            exit_code = int(facade.execution_exit_code(result))
            if exit_code == 0:
                names = _holder_names(
                    holder.target for holder in result.holders
                )
                record_attempt(
                    "rotation_succeeded",
                    f"completed in {', '.join(names)}" if names else "completed",
                )
            else:
                # A clean mint can still exit 1 because a declared manual copy
                # remains. That is a success with a follow-up, not a failure;
                # an actual failed/unreached/unconfirmed holder keeps the
                # failure classification.
                manual_only = (
                    not result.failed
                    and result.manual
                    and not any(
                        holder.outcome in ("failed", "not-reached", "written")
                        for holder in result.holders
                    )
                )
                record_attempt(
                    "rotation_manual" if manual_only else "rotation_failed",
                    _rotation_detail(result),
                )
            return {
                **report.rotation_json(credential, host, plan),
                "exit_code": exit_code,
                "run": report.execution_json(result),
            }

    @authed.post("/credentials/{name}/rotation/abandon")
    def abandon_rotation(name: str, actor: str = Depends(_actor)) -> dict[str, Any]:
        """Close an unfinished rotation without starting a replacement.

        The recovery-baseline guards refuse value, holder and URL edits while a
        run is unfinished. When the service is unreachable no takeover can run,
        so this is the only way to clear the record and let the operator fix the
        service first. It touches the journal only: stored and parked values
        stay exactly as they are, and the next rotation is a new run.
        """
        try:
            with stack_write(actor), facade.journal_for(config).lock(name, actor):
                if name not in store.load_manifest().credentials:
                    raise HTTPException(
                        status_code=404, detail=f"no credential named {name}"
                    )
                closed = facade.journal_for(config).abandon(name, actor)
        except JournalLocked as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        return {
            "ok": True,
            "abandoned": [
                {"target": step.target, "kind": step.kind} for step in closed
            ],
        }

    return public, authed
