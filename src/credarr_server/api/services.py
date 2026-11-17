"""Service deployment facts, probes, and the read-only Docker scan.

A service is a URL and a kind, never a secret; the probe is the one place
a key leaves the app, and only to the service the operator named."""

from __future__ import annotations

import time
import urllib.parse
from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from credarr.config import Config
from credarr.model import NAME_RE, Manifest
from credarr.rotate import service_for, ui_password_names
from credarr.services import (
    declared_services,
    probe_service_connection,
    service_report,
)
from credarr_server.api.context import ApiContext
from credarr_server.api.http import _actor, new_routers
from credarr_server.api.models import ServiceBody, ServiceTestBody
from credarr_server.discovery import discover
from credarr_server.source import runtime_config, stored_service_keys
from credarr_server.store import Service, ServiceExists, TopologyStore

# Kinds whose ordinary use is an HTTP API, so a definition without a base URL
# cannot be acted on. `other` is deliberately allowed to be path-only.
API_SERVICE_KINDS = frozenset({"servarr", "jellyfin", "seerr", "qbittorrent", "qui",
                               "grafana", "arcane", "gitea"})


def _kind_for(name: str) -> str:
    if name in {"sonarr", "radarr", "lidarr", "readarr", "prowlarr", "whisparr"}:
        return "servarr"
    if name == "jellyfin":
        return "jellyfin"
    if name in {"seerr", "overseerr"}:
        return "seerr"
    if name == "qbittorrent":
        return "qbittorrent"
    if name == "qui":
        return "qui"
    if name in {"grafana", "arcane", "gitea"}:
        return name
    return "other"

def _clean_url(raw: str | None) -> str | None:
    if raw is None or raw.strip() == "":
        return None
    url = raw.strip()
    if any(ord(char) < 0x20 or char == "\x7f" for char in url):
        raise HTTPException(status_code=400, detail="the service URL contains a control character")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise HTTPException(
            status_code=400, detail="the service URL must be an absolute http:// or https:// URL"
        )
    if parts.username is not None or parts.password is not None:
        raise HTTPException(
            status_code=400,
            detail="the service URL must not contain a username or password; use a credential",
        )
    if parts.query or parts.fragment:
        raise HTTPException(
            status_code=400, detail="the service URL must not contain a query or fragment"
        )
    return url.rstrip("/")

def _service_fields(
    *,
    name: str,
    kind: str,
    url: str | None,
    notes: str,
    require_api_url: bool,
) -> tuple[str, str, str | None, str]:
    if not NAME_RE.fullmatch(name):
        raise HTTPException(
            status_code=400,
            detail="service names must be lowercase letters, digits, underscores or dashes",
        )
    kind = (kind or "other").strip() or "other"
    if not NAME_RE.fullmatch(kind):
        raise HTTPException(
            status_code=400,
            detail="service kind must be lowercase letters, digits, underscores or dashes",
        )
    clean_url = _clean_url(url)
    if require_api_url and kind in API_SERVICE_KINDS and clean_url is None:
        raise HTTPException(
            status_code=400,
            detail=f"a {kind} service needs a base URL",
        )
    return name, kind, clean_url, (notes or "").strip()

def _service_json(service: Service, *, declared: bool) -> dict[str, Any]:
    return {
        "name": service.name,
        "kind": service.kind,
        "url": service.url,
        "notes": service.notes,
        "position": service.position,
        "declared": declared,
    }

def _seed_services(store: TopologyStore, config: Config, manifest: Manifest) -> None:
    """One-time copy of `credarr.yaml` deployment facts into the store."""
    host = config.host(config.default_host)
    names = set(host.urls) | set(host.containers)
    names.update(declared_services(manifest))
    store.seed_services(
        [
            Service(
                name=name,
                kind=_kind_for(name),
                url=host.urls.get(name),
                notes="",
                position=position,
            )
            for position, name in enumerate(sorted(names))
        ]
    )

def _service_dependents(store: TopologyStore, name: str) -> list[str]:
    manifest = store.load_manifest()
    dependents: list[str] = []
    for credential in manifest.credentials.values():
        if service_for(credential) == name:
            dependents.append(f"credential {credential.name!r} is minted by it")
        for holder in credential.consumers:
            if holder.target.system == name:
                dependents.append(
                    f"credential {credential.name!r} declares holder {holder.target}"
                )
    return dependents

def _stored_service_credentials(
    store: TopologyStore, manifest: Manifest, name: str
) -> list[str]:
    """API-key credentials with a working copy for this service.

    A UI password is a different kind of destination credential; the app-page
    re-entry flow only presents the API key, so it is not part of this guard.
    The helper still refuses when more than one API key belongs to the service:
    one form cannot honestly re-enter both.
    """
    return [
        credential.name
        for credential in manifest.credentials.values()
        if service_for(credential) == name
        and credential.name not in ui_password_names(manifest, name)
        and store.get_value(credential.name) is not None
    ]


def routes(ctx: ApiContext) -> tuple[APIRouter, APIRouter]:
    """The domain's routes, over the one process context."""
    settings = ctx.settings
    store = ctx.store
    config = ctx.config
    stack_write = ctx.stack_write
    public, authed = new_routers()

    @authed.get("/services")
    def services(observe: bool = True) -> dict[str, Any]:
        """Every service the topology names: what it needs, what is missing.

        The host calls are read-only and bounded (`OBSERVE_TIMEOUT`), and each
        one is allowed to fail into a sentence: a service that cannot answer is
        a row that says so, never an error page - "nothing answered" is itself
        an observation. `managed` still comes from `provenance`, and a running
        version is never allowed to lift it. The version read uses the store's
        service key first, so observing a service does not require a config
        directory to be mounted.

        `observe=false` is the definitions projection: the console needs the
        saved URLs and declared flags to open Apps or the editor, and does not
        render a running version there. It returns no `services` rows and null
        `observed_at`, because nothing was observed.
        """
        manifest = store.load_manifest()
        effective = runtime_config(config, store)
        services = store.services()
        definitions = [
            _service_json(service, declared=service.name in declared_services(manifest))
            for service in services
        ]
        seen = {service.name for service in services}
        host = effective.host(effective.default_host)
        for name in declared_services(manifest):
            if name in seen:
                continue
            definitions.append(
                {
                    "name": name,
                    "kind": _kind_for(name),
                    "url": host.urls.get(name),
                    "notes": "",
                    "position": len(definitions),
                    "declared": True,
                }
            )
        if not observe:
            return {
                "observed_at": None,
                "services": [],
                "definitions": definitions,
            }
        return {
            "observed_at": time.time(),
            **asdict(
                service_report(
                    manifest,
                    effective,
                    service_keys=stored_service_keys(store, manifest),
                    docker_url=settings.docker_url,
                )
            ),
            "definitions": definitions,
        }

    @authed.post("/services/test")
    def test_service(body: ServiceTestBody) -> dict[str, Any]:
        """Try a URL/key pair without storing either.

        A typed key always wins. A stored key is used only at the service's
        currently saved URL: otherwise this endpoint would be a write-only
        secret exfiltration path to any URL an authenticated caller typed.
        """
        if not NAME_RE.fullmatch(body.service):
            raise HTTPException(status_code=400, detail="invalid service name")
        url = _clean_url(body.url)
        if url is None:
            raise HTTPException(status_code=400, detail="a service URL is required")
        key = (body.key or "").strip() or None
        if key is None:
            stored = stored_service_keys(store, store.load_manifest()).get(body.service)
            if stored is not None:
                effective = runtime_config(config, store)
                saved = effective.host(effective.default_host).urls.get(body.service)
                if saved is None or url != _clean_url(saved):
                    raise HTTPException(
                        status_code=400,
                        detail="Save this URL before testing with the stored key. "
                        "The key is only used at its saved URL.",
                    )
                key = stored.reveal()
        result = probe_service_connection(body.service, url, key)
        return {
            "ok": result.ok,
            "detail": result.detail,
            "version": result.version,
        }

    @authed.post("/services")
    def create_service(
        body: ServiceBody, actor: str = Depends(_actor)
    ) -> dict[str, Any]:
        """Define a service's URL without editing `credarr.yaml`."""
        name, kind, url, notes = _service_fields(
            name=body.name,
            kind=body.kind,
            url=body.url,
            notes=body.notes,
            require_api_url=True,
        )
        with stack_write(actor):
            try:
                service = store.create_service(
                    name, kind=kind, url=url, notes=notes
                )
            except ServiceExists:
                raise HTTPException(
                    status_code=409, detail=f"A service named {name} already exists"
                ) from None
        return {"ok": True, "service": _service_json(service, declared=False)}

    @authed.delete("/services/{name}")
    def delete_service(
        name: str, confirm: str = "", actor: str = Depends(_actor)
    ) -> dict[str, Any]:
        """Delete an unused definition. A referenced service is blocked."""
        if confirm.strip() != name:
            raise HTTPException(
                status_code=400,
                detail="not confirmed: type the service's name to delete it",
            )
        with stack_write(actor):
            if store.service(name) is None:
                raise HTTPException(status_code=404, detail=f"no service named {name}")
            dependents = _service_dependents(store, name)
            if dependents:
                raise HTTPException(
                    status_code=409,
                    detail={
                        "message": f"cannot delete service {name!r}: it is still referenced",
                        "dependents": dependents,
                    },
                )
            store.delete_service(name)
            return {"ok": True}

    @authed.get("/discovery")
    def discovery() -> dict[str, Any]:
        """Optional read-only Docker scan: proposals and capability diffs.

        Off unless `CREDARR_DOCKER_URL` points at a Docker API, normally a
        read-only socket proxy. The scan never changes the topology: a proposal
        is shown to the operator, who confirms it by importing a manifest. A
        declared service is never proposed; a rescan only reports a changed
        container identity, image family or self-named URL.
        """
        return discover(
            settings.docker_url, store.load_manifest(), runtime_config(config, store)
        )

    return public, authed
