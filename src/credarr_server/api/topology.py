"""Manifest export and import.

The import is one transaction through the engine's parser; a warning names
what the operator must look at, and a failed parse leaves the previous
topology in place."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import ValidationError

from credarr.errors import ManifestError
from credarr.model import Manifest
from credarr.rotate import service_for
from credarr.secrets import BACKENDS
from credarr.writers import known_systems
from credarr_server.api.context import ApiContext
from credarr_server.api.http import _actor, _validation_details, new_routers
from credarr_server.api.models import MAX_MANIFEST_BYTES, ImportBody


def _import_warnings(
    manifest: Manifest,
    previous: Manifest | None = None,
    stored: set[str] | None = None,
) -> list[dict[str, str]]:
    """Name imported declarations that need an operator's attention.

    Audit-only API keys: a warning, not a refusal, because a password or a
    deliberately frozen key is legitimately class B. The `_api_key` name and a
    service with a mint are the two facts that make the declaration surprising
    enough to mention.

    Issuer changes: import preserves working copies by name, so a surviving
    name that now derives a different service still holds the old service's
    key. The copy is kept (clearing it is destructive); the warning says so.
    """
    mintable = known_systems()
    warnings: list[dict[str, str]] = []
    for name, credential in manifest.credentials.items():
        if (
            (credential.credential_class == "B" or credential.never_rotate)
            and name.endswith("_api_key")
        ):
            service = service_for(credential)
            if service in mintable:
                warnings.append(
                    {"credential": name, "service": service, "kind": "audit_only"}
                )
        old = previous.credentials.get(name) if previous is not None else None
        if old is not None and name in (stored or ()):
            was, now = service_for(old), service_for(credential)
            if was != now:
                warnings.append({
                    "credential": name,
                    "service": now,
                    "previous_service": was,
                    "kind": "issuer_changed",
                })
    return warnings


def routes(ctx: ApiContext) -> tuple[APIRouter, APIRouter]:
    """The domain's routes, over the one process context."""
    store = ctx.store
    config = ctx.config
    registry = ctx.registry
    loop = ctx.loop
    stack_write = ctx.stack_write
    public, authed = new_routers()

    @authed.get("/topology/export")
    def export_topology() -> Response:
        """The stored topology as manifest YAML, through the engine's emitter.

        Not a backup: the manifest declares where values live, never the values
        themselves. It is the text the CLI would write for the same model, so
        it can be edited by hand and imported again.
        """
        return Response(content=store.export_text(), media_type="application/yaml")

    @authed.post("/topology/import")
    async def import_topology(
        request: Request, actor: str = Depends(_actor)
    ) -> dict[str, Any]:
        """Import manifest YAML, replacing or merging.

        A JSON body is the console's contract and carries `mode`, `prune` and a
        typed confirmation. Raw YAML is the legacy replace shape and requires
        `?confirm=replace` because omitted names lose their working copies.

        The import itself is one transaction: a failure leaves the previous
        topology in place.

        shortcut: the body is buffered before the size check, so the cap bounds
        what is parsed, not what is read - the packaging slice's reverse proxy
        should cap request bodies as well.
        """
        raw = await request.body()
        if len(raw) > MAX_MANIFEST_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"a manifest over {MAX_MANIFEST_BYTES} bytes is not accepted",
            )
        content_type = request.headers.get("content-type", "").split(";")[0].strip()
        if content_type == "application/json":
            try:
                body = ImportBody.model_validate_json(raw)
            except ValidationError as exc:
                raise HTTPException(
                    status_code=422, detail=_validation_details(exc)
                ) from None
            text, mode, prune, confirm = body.yaml, body.mode, body.prune, body.confirm
            required = "replace" if mode == "replace" else ("merge" if prune else "")
            if required and confirm.strip() != required:
                raise HTTPException(
                    status_code=400,
                    detail=f"not confirmed: type {required!r} to import this way",
                )
        else:
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                raise HTTPException(status_code=400, detail="the manifest must be UTF-8") from None
            mode, prune, confirm = "replace", False, request.query_params.get("confirm", "")
            if confirm.strip() != "replace":
                raise HTTPException(
                    status_code=400,
                    detail="not confirmed: raw YAML replace requires ?confirm=replace",
                )
        if len(text.encode("utf-8")) > MAX_MANIFEST_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"a manifest over {MAX_MANIFEST_BYTES} bytes is not accepted",
            )
        try:
            manifest = Manifest.parse(
                text,
                origin=config.manifest,
                known_targets=registry.known_targets(),
                known_backends=BACKENDS,
            )
        except ManifestError as exc:
            raise HTTPException(status_code=400, detail=exc.render()) from None
        with stack_write(actor):
            previous = store.load_manifest()
            summary = store.import_model(manifest, mode=mode, prune=prune)
            loop.wake()
            return {
                "ok": True,
                **asdict(summary),
                "warnings": _import_warnings(
                    manifest, previous, set(store.working_copy_times())
                ),
            }

    return public, authed
