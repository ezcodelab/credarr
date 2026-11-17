"""The declared credential, its holders, and its policy.

Every write goes through the stack lease; edits that change what a resume
recovers toward also take the rotation edit guard. Values and the rotation
itself are separate domains."""

from __future__ import annotations

from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException

from credarr import facade
from credarr.config import Config
from credarr.errors import ManifestError
from credarr.model import Manifest
from credarr.secrets import BACKENDS
from credarr.targets import TargetRegistry
from credarr_server.api.context import ApiContext
from credarr_server.api.http import _actor, new_routers
from credarr_server.api.models import (
    CredentialBody,
    HolderBody,
    HoldersBody,
)
from credarr_server.api.payloads import _auto_json, _console_credential_json
from credarr_server.store import CredentialExists, TopologyStore


def _holder_spec(holder: HolderBody) -> dict[str, Any]:
    return {
        "target": holder.target,
        "count": holder.count,
        "mechanism": holder.mechanism,
        "host": holder.host,
        "note": holder.note,
    }

def _credential_spec(body: CredentialBody) -> dict[str, Any]:
    spec: dict[str, Any] = {"class": body.credential_class}
    if body.description:
        spec["description"] = body.description
    if body.max_age_days is not None:
        spec["max_age_days"] = body.max_age_days
    if body.never_rotate:
        spec["never_rotate"] = True
    if not body.provisioned:
        spec["provisioned"] = False
    if body.canonical:
        spec["canonical"] = body.canonical
    if body.write:
        spec["write"] = body.write
    if body.vault is not None:
        spec["vault"] = body.vault.model_dump()
    if body.consumers:
        spec["consumers"] = [_holder_spec(holder) for holder in body.consumers]
    return spec

def _candidate_manifest(
    store: TopologyStore,
    config: Config,
    registry: TargetRegistry,
    name: str,
    spec: dict[str, Any],
) -> Manifest:
    """Validate one edited credential in the context of the whole topology."""
    document = yaml.safe_load(store.export_text()) or {}
    credentials = document.setdefault("credentials", {})
    credentials[name] = spec
    try:
        return Manifest.parse(
            yaml.safe_dump(document, sort_keys=False),
            origin=config.manifest,
            known_targets=registry.known_targets(),
            known_backends=BACKENDS,
        )
    except ManifestError as exc:
        raise HTTPException(status_code=400, detail=exc.render()) from None

def routes(ctx: ApiContext) -> tuple[APIRouter, APIRouter]:
    """The domain's routes, over the one process context."""
    store = ctx.store
    log = ctx.log
    loop = ctx.loop
    config = ctx.config
    registry = ctx.registry
    stack_write = ctx.stack_write
    rotation_edit_guard = ctx.rotation_edit_guard
    public, authed = new_routers()

    @authed.get("/credentials")
    def credentials() -> dict[str, Any]:
        """The declared topology, what the app holds, and what the audit found.

        One row per credential: declared fields, `stored` (a working copy
        exists - the paste path has run), and the newest recorded statuses.
        `stored: false` is what lets the console say "no value stored yet"
        instead of repeating the engine's UNVERIFIABLE wording for a cause that
        is the app's, not the engine's.

        `observed_run` names the run every status here was drawn from, because
        "match" without a time is a claim nobody can date. A status is shown
        only when that run audited holders and they are the ones declared now
        (see `_console_credential_json`).
        """
        manifest = store.load_manifest()
        stored = store.working_copy_times()
        state = log.last_state()
        observed = {row.credential: row for row in state.credentials} if state else {}
        observed_at = state.last_audit.finished_at if state and state.last_audit else None
        auto = store.auto_rotations()
        rotations = facade.journal_for(config).last_rotations()
        return {
            "observed_run": (
                {"id": state.last_audit.id, "finished_at": observed_at}
                if state is not None and state.last_audit is not None
                else None
            ),
            "credentials": [
                _console_credential_json(
                    credential,
                    stored.get(name),
                    observed.get(name),
                    observed_at,
                    _auto_json(auto.get(name), rotations.get(name)),
                )
                for name, credential in manifest.credentials.items()
            ],
        }

    @authed.post("/credentials")
    def create_credential(
        body: CredentialBody, actor: str = Depends(_actor)
    ) -> dict[str, Any]:
        """Declare one credential through the same parser the manifest uses."""
        with stack_write(actor):
            spec = _credential_spec(body)
            manifest = _candidate_manifest(store, config, registry, body.name, spec)
            credential = manifest.credentials[body.name]
            try:
                store.create_credential(credential)
            except CredentialExists:
                raise HTTPException(
                    status_code=409,
                    detail=f"A credential named {body.name} already exists",
                ) from None
        return {
            "ok": True,
            "credential": _console_credential_json(
                credential,
                None,
                None,
                None,
                None,
            ),
        }

    @authed.put("/credentials/{name}/holders")
    def put_holders(
        name: str, body: HoldersBody, actor: str = Depends(_actor)
    ) -> dict[str, Any]:
        """Replace the holder list atomically. The manifest order is kept."""
        with stack_write(actor):
            manifest = store.load_manifest()
            if name not in manifest.credentials:
                raise HTTPException(status_code=404, detail=f"no credential named {name}")
            rotation_edit_guard(
                name, facade.journal_for(config), "changing its holders"
            )
            document = yaml.safe_load(store.export_text()) or {}
            spec = dict(document["credentials"][name])
            if body.consumers:
                spec["consumers"] = [_holder_spec(holder) for holder in body.consumers]
            else:
                spec.pop("consumers", None)
            candidate = _candidate_manifest(store, config, registry, name, spec)
            credential = candidate.credentials[name]
            store.update_credential(name, credential)
        return {
            "ok": True,
            "consumers": [
                {
                    "target": str(holder.target),
                    "count": holder.count,
                    "mechanism": holder.mechanism,
                    "host": holder.host,
                    "note": holder.note,
                }
                for holder in credential.consumers
            ],
        }

    @authed.delete("/credentials/{name}")
    def delete_credential(
        name: str, confirm: str = "", actor: str = Depends(_actor)
    ) -> dict[str, bool]:
        """Delete a declaration, its holders and its policy row."""
        if confirm.strip() != name:
            raise HTTPException(
                status_code=400,
                detail="not confirmed: type the credential's name to delete it",
            )
        with stack_write(actor):
            if name not in store.load_manifest().credentials:
                raise HTTPException(status_code=404, detail=f"no credential named {name}")
            rotation_edit_guard(name, facade.journal_for(config), "deleting the credential")
            if not store.delete_credential(name):
                raise HTTPException(status_code=404, detail=f"no credential named {name}")
            loop.wake()
            return {"ok": True}

    return public, authed
