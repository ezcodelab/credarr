"""One credential's metadata and plan fields in place.

A rename is delete plus create; this edit only accepts the same name and
takes the rotation edit guard because the fields it writes are the plan a
resume would follow."""

from __future__ import annotations

from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException

from credarr import facade
from credarr.rotate import service_for
from credarr_server.api.context import ApiContext
from credarr_server.api.credentials import (
    _ROTATION_FIELDS,
    _candidate_manifest,
    _holder_spec,
)
from credarr_server.api.http import _actor, new_routers
from credarr_server.api.models import CredentialPatch
from credarr_server.api.payloads import _console_credential_json


def routes(ctx: ApiContext) -> tuple[APIRouter, APIRouter]:
    """The domain's routes, over the one process context."""
    store = ctx.store
    config = ctx.config
    registry = ctx.registry
    stack_write = ctx.stack_write
    rotation_edit_guard = ctx.rotation_edit_guard
    public, authed = new_routers()

    @authed.patch("/credentials/{name}")
    def patch_credential(
        name: str, body: CredentialPatch, actor: str = Depends(_actor)
    ) -> dict[str, Any]:
        """Edit metadata in place. Renames are delete + create, deliberately."""
        with stack_write(actor):
            existing = store.load_manifest().credentials.get(name)
            if existing is None:
                raise HTTPException(status_code=404, detail=f"no credential named {name}")
            if "name" in body.model_fields_set and body.name not in (None, name):
                raise HTTPException(
                    status_code=400,
                    detail="credential names cannot be renamed; delete it and create the new name",
                )
            document = yaml.safe_load(store.export_text()) or {}
            spec = dict(document["credentials"][name])
            fields = body.model_fields_set
            if fields & _ROTATION_FIELDS:
                rotation_edit_guard(
                    name, facade.journal_for(config),
                    "changing its holders, class, vault or mint mechanism",
                )
            if "description" in fields:
                spec["description"] = body.description or ""
            if "credential_class" in fields:
                if body.credential_class is None:
                    spec.pop("class", None)
                else:
                    spec["class"] = body.credential_class
            if "max_age_days" in fields:
                if body.max_age_days is None:
                    spec.pop("max_age_days", None)
                else:
                    spec["max_age_days"] = body.max_age_days
            if "never_rotate" in fields:
                spec["never_rotate"] = bool(body.never_rotate)
            if "provisioned" in fields:
                spec["provisioned"] = bool(body.provisioned)
            if "canonical" in fields:
                if body.canonical:
                    spec["canonical"] = body.canonical
                else:
                    spec.pop("canonical", None)
            if "write" in fields:
                if body.write:
                    spec["write"] = body.write
                else:
                    spec.pop("write", None)
            if "vault" in fields:
                if body.vault is None:
                    spec.pop("vault", None)
                else:
                    spec["vault"] = body.vault.model_dump()
            if "consumers" in fields:
                if body.consumers:
                    spec["consumers"] = [_holder_spec(holder) for holder in body.consumers]
                else:
                    spec.pop("consumers", None)
            manifest = _candidate_manifest(store, config, registry, name, spec)
            credential = manifest.credentials[name]
            store.update_credential(name, credential)
            warning = None
            if service_for(existing) != service_for(credential) and credential.consumers:
                warning = (
                    f"the issuer changed from {service_for(existing)} to "
                    f"{service_for(credential)}; existing holders were not retargeted"
                )
            return {
                "ok": True,
                "credential": _console_credential_json(
                    credential,
                    store.working_copy_times().get(name),
                    None,
                    None,
                    None,
                ),
                "warning": warning,
            }

    return public, authed
