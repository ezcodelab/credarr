"""Editing one deployed service, including a URL move.

A URL move invalidates the old server's key, so the edit may carry the new
one; the body is write-only and the guard refuses a half-migrated service."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from credarr import facade
from credarr.redact import Secret
from credarr.rotate import service_for
from credarr.services import declared_services
from credarr_server.api.context import ApiContext
from credarr_server.api.http import _actor, new_routers
from credarr_server.api.models import ServicePatch
from credarr_server.api.services import (
    _clean_url,
    _service_fields,
    _service_json,
    _stored_service_credentials,
)


def routes(ctx: ApiContext) -> tuple[APIRouter, APIRouter]:
    """The domain's routes, over the one process context."""
    store = ctx.store
    config = ctx.config
    stack_write = ctx.stack_write
    value_change_guard = ctx.value_change_guard
    public, authed = new_routers()

    @authed.patch("/services/{name}")
    def patch_service(
        name: str, body: ServicePatch, actor: str = Depends(_actor)
    ) -> dict[str, Any]:
        """Edit URL and notes. Renaming is delete + create in v1."""
        with stack_write(actor):
            existing = store.service(name)
            if existing is None:
                raise HTTPException(status_code=404, detail=f"no service named {name}")
            if "name" in body.model_fields_set and body.name not in (None, name):
                raise HTTPException(
                    status_code=400,
                    detail="service names cannot be renamed; delete it and create the new name",
                )
            fields = body.model_fields_set
            kind = existing.kind if "kind" not in fields else (body.kind or "other")
            url = existing.url if "url" not in fields else body.url
            notes = existing.notes if "notes" not in fields else (body.notes or "")
            kind_changed = "kind" in fields and (body.kind or "other") != existing.kind
            _, kind, url, notes = _service_fields(
                name=name,
                kind=kind,
                url=url,
                notes=notes,
                require_api_url="url" in fields or kind_changed,
            )
            url_changed = _clean_url(url) != _clean_url(existing.url)
            key_supplied = "key" in fields or "credential" in fields
            if key_supplied and not url_changed:
                # The retry after a response loss looks like this: the URL is
                # already there, and the same key is re-sent. Accept it only
                # for the credential that actually owns the stored copy.
                if body.credential is None or body.key is None:
                    raise HTTPException(
                        status_code=400,
                        detail="a key is only accepted with its credential",
                    )
                stored = _stored_service_credentials(
                    store, store.load_manifest(), name
                )
                if body.credential not in stored:
                    raise HTTPException(
                        status_code=400,
                        detail=f"no stored API key for {body.credential} "
                        "belongs to this service",
                    )
                value_change_guard(body.credential, facade.journal_for(config))
                store.set_value(body.credential, Secret(body.key))
                service = store.update_service(
                    name, kind=kind, url=url, notes=notes
                )
            elif url_changed:
                manifest = store.load_manifest()
                service_credentials = [
                    credential.name
                    for credential in manifest.credentials.values()
                    if service_for(credential) == name
                ]
                pending = [
                    credential
                    for credential in service_credentials
                    if store.get_pending(credential) is not None
                ]
                if pending:
                    raise HTTPException(
                        status_code=400,
                        detail="an unfinished rotation has a parked key for "
                        + ", ".join(sorted(pending))
                        + "; resume or abandon it before moving the URL",
                    )
                journal = facade.journal_for(config)
                held = set(service_credentials)
                busy = sorted(
                    ({step.credential for step in journal.unfinished()}
                     | set(journal.open_attempts())) & held
                )
                if busy:
                    raise HTTPException(
                        status_code=400,
                        detail="an unfinished rotation exists for "
                        + ", ".join(busy)
                        + "; resume, take it over or abandon it before moving the URL",
                    )
                stored = _stored_service_credentials(store, manifest, name)
                if len(stored) > 1:
                    raise HTTPException(
                        status_code=400,
                        detail="more than one stored API key belongs to this "
                        "service ("
                        + ", ".join(sorted(stored))
                        + "); forget one stored copy before moving the URL",
                    )
                if stored:
                    if body.key is None or body.credential != stored[0]:
                        raise HTTPException(
                            status_code=400,
                            detail="the service URL changed; re-enter the API "
                            f"key for {stored[0]} to confirm the new destination",
                        )
                    service = store.update_service_destination(
                        name,
                        kind=kind,
                        url=url,
                        notes=notes,
                        credential=body.credential,
                        value=Secret(body.key),
                    )
                else:
                    if body.key is not None or body.credential is not None:
                        raise HTTPException(
                            status_code=400,
                            detail="no stored API key belongs to this service",
                        )
                    service = store.update_service(
                        name, kind=kind, url=url, notes=notes
                    )
            else:
                service = store.update_service(
                    name, kind=kind, url=url, notes=notes
                )
            if service is None:
                raise HTTPException(status_code=404, detail=f"no service named {name}")
            return {
                "ok": True,
                "service": _service_json(
                    service, declared=name in declared_services(store.load_manifest())
                ),
            }

    return public, authed
