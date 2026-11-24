"""The audited value surface: reveal, adoption, lifecycle, versions.

The rest of the console is write-only about values. This domain is the one
deliberate exception: an explicit reveal request, audited before the value is
returned, with a short TTL and no-store headers. It also owns the operations
that make a value unusable (soft-delete, purge) and the adoption path that
brings an externally rotated value under the same commit barrier.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response

from credarr import facade
from credarr.audit import Status
from credarr.journal import JournalLocked
from credarr.model import VaultRef
from credarr.redact import Secret, scrub
from credarr_server.api.context import ApiContext
from credarr_server.api.http import _actor, new_routers
from credarr_server.api.models import AdoptBody, LifecycleBody, RevealBody
from credarr_server.source import (
    StoreSource,
    rotation_manifest,
    runtime_config,
    runtime_manifest,
)
from credarr_server.store import UnknownCredential
from credarr_server.vault import (
    SECRET_ADOPTED,
    SECRET_CURRENT_CHANGED,
    UNVERIFIED,
    VERIFIED,
    CredentialTombstoned,
    KekUnavailable,
    VaultError,
    VersionNotFound,
)

REVEAL_TTL_SECONDS = 30


def _vault_error(exc: VaultError) -> HTTPException:
    """Map the vault's refusals to HTTP without losing the operator sentence."""
    if isinstance(exc, KekUnavailable):
        return HTTPException(status_code=503, detail=exc.render())
    if isinstance(exc, CredentialTombstoned):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, VersionNotFound):
        return HTTPException(status_code=404, detail=str(exc))
    return HTTPException(status_code=409, detail=exc.render())


def _known(store: Any, name: str) -> None:
    if name not in store.load_manifest().credentials:
        raise HTTPException(status_code=404, detail=f"no credential named {name}")


class _CandidateSource:
    """The candidate at the audit reference, every other value from the store."""

    name = "adoption candidate"

    def __init__(self, store: Any, name: str, value: str) -> None:
        self.store = store
        self.credential = name
        self.value = value

    def get(self, ref: VaultRef) -> Secret | None:
        if ref.backend == "static" and ref.path == (self.credential,):
            return Secret(self.value)
        return StoreSource(self.store).get(ref)


def _verify_candidate(ctx: ApiContext, name: str, value: str) -> tuple[bool, str]:
    """Run the engine audit against the candidate; true only on a match.

    A credential with no comparable holder has no engine proof to offer, so the
    caller is told to adopt it unverified rather than receiving an invented
    `verified`.
    """
    manifest = runtime_manifest(ctx.store)
    credential = manifest.credentials[name]
    if not credential.consumers:
        return False, (
            "no comparable holder is declared for this credential; adopt it as "
            "unverified instead of claiming a proof the audit cannot make"
        )
    candidate = replace(
        credential,
        vault=VaultRef(backend="static", file="adoption", path=(name,)),
    )
    credentials = dict(manifest.credentials)
    credentials[name] = candidate
    try:
        result = facade.audit(
            runtime_config(ctx.config, ctx.store),
            replace(manifest, credentials=credentials),
            _CandidateSource(ctx.store, name, value),
            only={name},
        )
    except Exception as exc:
        return False, scrub(str(exc))
    row = next((item for item in result.results if item.credential.name == name), None)
    if row is None:
        return False, "the audit returned no result for this credential"
    if row.status is Status.MATCH:
        return True, ""
    return False, scrub(row.detail) or f"the audit reported {row.status.value}"


def routes(ctx: ApiContext) -> tuple[APIRouter, APIRouter]:
    store = ctx.store
    config = ctx.config
    vault = store.vault
    limiter = ctx.reveal
    public, authed = new_routers()

    @authed.post("/credentials/{name}/reveal")
    def reveal_value(
        name: str, body: RevealBody, response: Response, actor: str = Depends(_actor)
    ) -> dict[str, Any]:
        """Return one CURRENT/PREVIOUS value to the authenticated admin.

        The audit row is written before the value leaves this function. A
        failure to audit refuses the reveal: an unrecorded value read is the
        one outcome the security contract does not allow.
        """
        _known(store, name)
        try:
            revealed = vault.reveal(name, body.stage)
        except VaultError as exc:
            raise _vault_error(exc) from None
        refusal = limiter.allow(actor, name)
        if refusal is not None:
            raise HTTPException(status_code=429, detail=refusal)
        try:
            vault.record_reveal(
                revealed, actor=actor, origin=ctx.origin_for(actor)
            )
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail=f"the reveal could not be audited: {scrub(str(exc))}",
            ) from None
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return {
            "credential": revealed.credential,
            "version": revealed.version,
            "stage": revealed.stage,
            "verification": revealed.verification,
            "value": revealed.value.reveal(),
            "expires_in": REVEAL_TTL_SECONDS,
        }

    @authed.get("/credentials/{name}/strategy")
    def strategy(name: str) -> dict[str, Any]:
        """The four-phase view of the concrete plan, with its provenance."""
        _known(store, name)
        try:
            manifest = rotation_manifest(store, name)
        except UnknownCredential:
            raise HTTPException(status_code=404, detail=f"no credential named {name}") from None
        effective = runtime_config(config, store)
        credential, _host, plan = facade.plan_rotation_for(effective, manifest, name)
        from credarr.strategy import strategy_for

        return strategy_for(credential, plan).as_json()

    @authed.get("/credentials/{name}/versions")
    def versions(name: str) -> dict[str, Any]:
        """Version metadata, never a value."""
        _known(store, name)
        return {
            "credential": name,
            "lifecycle": vault.lifecycle(name),
            "versions": [version.as_json() for version in vault.versions(name)],
            "sync": ctx.sync.projection(name) if ctx.sync is not None else None,
        }

    @authed.get("/credentials/{name}/lifecycle")
    def lifecycle(name: str) -> dict[str, Any]:
        _known(store, name)
        return {
            "credential": name,
            "lifecycle": vault.lifecycle(name),
            "stored": vault.current_version(name) is not None,
        }

    @authed.post("/credentials/{name}/lifecycle")
    def lifecycle_change(
        name: str, body: LifecycleBody, actor: str = Depends(_actor)
    ) -> dict[str, Any]:
        """Soft-delete, restore, or the explicit purge after recovery."""
        _known(store, name)
        journal = facade.journal_for(config)
        try:
            with ctx.stack_write(actor), journal.lock(name, actor):
                if body.action == "restore":
                    restored = vault.restore(name, actor=actor, origin=ctx.origin_for(actor))
                    if not restored:
                        raise HTTPException(
                            status_code=409,
                            detail=f"{name} is not soft-deleted",
                        )
                    return {"ok": True, "lifecycle": None}
                if body.confirm.strip() != name:
                    raise HTTPException(
                        status_code=400,
                        detail="not confirmed: type the credential's name",
                    )
                if body.action == "soft_delete":
                    ctx.value_change_guard(name, journal)
                    state = vault.tombstone(
                        name,
                        actor=actor,
                        origin=ctx.origin_for(actor),
                        reason=body.reason,
                    )
                    if ctx.sync is not None:
                        ctx.sync.cancel_credential(name)
                    return {"ok": True, "lifecycle": state}
                if not body.force:
                    raise HTTPException(
                        status_code=400,
                        detail="a purge is explicit: set force=true as well as "
                        "typing the credential's name",
                    )
                if vault.lifecycle(name) is None:
                    raise HTTPException(
                        status_code=409,
                        detail=f"{name} must be soft-deleted before it can be purged",
                    )
                removed = vault.purge_credential(name, actor=actor)
                if ctx.sync is not None:
                    ctx.sync.cancel_credential(name)
                store.delete_credential(name)
                ctx.loop.wake()
                return {"ok": True, "removed_versions": removed}
        except JournalLocked as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        except VaultError as exc:
            raise _vault_error(exc) from None

    @authed.post("/credentials/{name}/adopt")
    def adopt(
        name: str, body: AdoptBody, actor: str = Depends(_actor)
    ) -> dict[str, Any]:
        """Adopt a value after an external rotation, under the same barrier.

        `process_readback` proves the candidate against the declared holders
        before anything is stored. `none` stores it as unverified. Neither path
        emits `match`: that word belongs to the engine's own audit.
        """
        _known(store, name)
        if body.confirm.strip() != name:
            raise HTTPException(
                status_code=400,
                detail="not confirmed: type the credential's name to adopt",
            )
        journal = facade.journal_for(config)
        try:
            with ctx.stack_write(actor), journal.lock(name, actor):
                ctx.value_change_guard(name, journal)
                if vault.lifecycle(name) is not None:
                    raise HTTPException(
                        status_code=409,
                        detail=f"{name} is soft-deleted; restore it before adopting",
                    )
                verification = UNVERIFIED
                if body.verify == "process_readback":
                    proven, detail = _verify_candidate(ctx, name, body.value)
                    if not proven:
                        raise HTTPException(
                            status_code=409,
                            detail=f"the candidate was not proven: {detail}; "
                            "nothing was stored",
                        )
                    verification = VERIFIED
                store.set_value(
                    name,
                    Secret(body.value),
                    actor=actor,
                    origin=ctx.origin_for(actor),
                    verification=verification,
                    event_kind=SECRET_CURRENT_CHANGED,
                    extra_event=SECRET_ADOPTED,
                )
                version = vault.current_version(name)
        except JournalLocked as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        except UnknownCredential:
            raise HTTPException(status_code=404, detail=f"no credential named {name}") from None
        except VaultError as exc:
            raise _vault_error(exc) from None
        return {
            "ok": True,
            "verification": verification,
            "version": version.as_json() if version is not None else None,
        }

    @authed.get("/vault/status")
    def vault_status() -> dict[str, Any]:
        """Non-secret key, tree and sync health for the security panel."""
        return {
            "key": vault.key_status(),
            "tree": {
                "configured": vault.tree is not None,
                "root": str(vault.tree.root) if vault.tree is not None else None,
            },
            "tombstoned": sorted(vault.tombstoned_names()),
            "sync": ctx.sync.status() if ctx.sync is not None else None,
        }

    return public, authed
