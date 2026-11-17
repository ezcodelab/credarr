"""The stored value and the per-credential auto-rotation policy.

A paste is a recovery baseline, so it takes the value guard; a policy write
takes the stack lease and never runs a rotation."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from credarr import facade
from credarr.journal import JournalLocked
from credarr.redact import Secret
from credarr_server import auto_rotation
from credarr_server.api.context import ApiContext
from credarr_server.api.http import _actor, new_routers
from credarr_server.api.models import AutoRotationBody, ValueBody
from credarr_server.api.payloads import _auto_json
from credarr_server.store import UnknownCredential


def routes(ctx: ApiContext) -> tuple[APIRouter, APIRouter]:
    """The domain's routes, over the one process context."""
    store = ctx.store
    loop = ctx.loop
    config = ctx.config
    stack_write = ctx.stack_write
    value_change_guard = ctx.value_change_guard
    public, authed = new_routers()

    @authed.delete("/credentials/{name}/value")
    def clear_value(name: str, actor: str = Depends(_actor)) -> dict[str, bool]:
        """Forget the app's copy. This never touches the service's live value."""
        try:
            journal = facade.journal_for(config)
            with stack_write(actor), journal.lock(name, actor):
                if name not in store.load_manifest().credentials:
                    raise HTTPException(status_code=404, detail=f"no credential named {name}")
                value_change_guard(name, journal)
                store.clear_value(name)
        except JournalLocked as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        return {"ok": True}

    @authed.get("/credentials/{name}/auto-rotation")
    def get_auto_rotation(name: str) -> dict[str, Any]:
        """The policy row, off when absent. Read-only and secret-free."""
        manifest = store.load_manifest()
        if name not in manifest.credentials:
            raise HTTPException(status_code=404, detail=f"no credential named {name}")
        state = store.auto_rotation(name)
        return {
            "auto_rotation": _auto_json(
                state, facade.journal_for(config).last_rotation(name)
            )
        }

    @authed.put("/credentials/{name}/auto-rotation")
    def put_auto_rotation(
        name: str, body: AutoRotationBody, actor: str = Depends(_actor)
    ) -> dict[str, Any]:
        """Enable or disable the policy, never run it.

        Enabling from off or paused resets the due baseline and clears the
        pause, so this request cannot rotate. While enabled and unpaused, an
        interval edit changes the due clock from the existing completed
        rotation; it does not reset the baseline or clear a pause.
        """
        with stack_write(actor):
            manifest = store.load_manifest()
            if name not in manifest.credentials:
                raise HTTPException(status_code=404, detail=f"no credential named {name}")
            journal = facade.journal_for(config)
            if body.enabled:
                if body.confirm.strip() != name:
                    raise HTTPException(
                        status_code=400,
                        detail="not confirmed: type the credential's name to enable auto-rotation",
                    )
                if body.every_days is None:
                    raise HTTPException(status_code=400, detail="every_days is required")
                existing = store.auto_rotation(name)
                if existing is not None and existing.enabled and not existing.paused:
                    # An interval edit is not a new starting point. Keep the
                    # last completed rotation and the pause/last result; the
                    # due clock recalculates from the new length.
                    state = store.set_auto_rotation_interval(name, body.every_days)
                else:
                    manual = auto_rotation.manual_or_unproven_targets(
                        manifest.credentials[name]
                    )
                    if manual and not body.accept_manual:
                        raise HTTPException(
                            status_code=400,
                            detail=(
                                "this credential has copies that need manual rotation "
                                f"({', '.join(sorted(manual))}); confirm them before "
                                "enabling auto-rotation"
                            ),
                        )
                    # Enabling is not a resume. A disabled row can still hide a
                    # run from before the disable, so this is checked from off
                    # as well as from paused.
                    open_attempts = journal.open_attempts()
                    unfinished = {step.credential for step in journal.unfinished()}
                    if name in open_attempts:
                        raise HTTPException(
                            status_code=409,
                            detail=f"resolve the unfinished rotation (attempt "
                            f"{open_attempts[name]}) by running a rotation for {name} "
                            "before enabling auto-rotation",
                        )
                    if name in unfinished:
                        raise HTTPException(
                            status_code=409,
                            detail="resolve the unfinished rotation (resume) "
                            "before enabling auto-rotation",
                        )
                    state = store.enable_auto_rotation(name, body.every_days)
            else:
                state = store.disable_auto_rotation(name)
            # A new policy may already be due, and a disable removes the next
            # due time; either way the scheduler's wait is stale.
            loop.wake()
            return {"auto_rotation": _auto_json(state, journal.last_rotation(name))}

    @authed.put("/credentials/{name}/value")
    def set_value(
        name: str, body: ValueBody, actor: str = Depends(_actor)
    ) -> dict[str, bool]:
        """The paste path: store the app's working copy of a value.

        Write-only by design - the value never comes back to a browser, and it
        is wrapped in `Secret` on the way in so it cannot be interpolated into
        a message. Storing one is not a rotation; the engine learns nothing
        until the next audit compares the stack against this copy.

        The credential's rotation lock serialises this write with a rotation.
        A paste during a run would replace the canonical that run is about to
        record over, so it is refused until the run finishes.
        """
        try:
            journal = facade.journal_for(config)
            with stack_write(actor), journal.lock(name, actor):
                value_change_guard(name, journal)
                store.set_value(name, Secret(body.value))
        except JournalLocked as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        except UnknownCredential:
            raise HTTPException(status_code=404, detail=f"no credential named {name}") from None
        return {"ok": True}

    return public, authed
