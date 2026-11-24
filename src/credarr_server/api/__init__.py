"""The HTTP surface, split by domain.

`app.py` builds the process and hands one `ApiContext` here. Each module owns
one domain's routes and shares the context's guards; the OpenAPI operation set
is pinned by `tests/server/test_app.py`."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import APIRouter, FastAPI

from credarr_server.api.auth import routes as auth_routes
from credarr_server.api.context import ApiContext
from credarr_server.api.credential_edit import routes as credential_edit_routes
from credarr_server.api.credentials import routes as credential_routes
from credarr_server.api.notifications import routes as notification_routes
from credarr_server.api.rotation import routes as rotation_routes
from credarr_server.api.secrets import routes as secret_routes
from credarr_server.api.service_edit import routes as service_edit_routes
from credarr_server.api.services import routes as service_routes
from credarr_server.api.status import routes as status_routes
from credarr_server.api.sync import routes as sync_routes
from credarr_server.api.topology import routes as topology_routes
from credarr_server.api.values import routes as value_routes

RouteBuilder = Callable[[ApiContext], tuple[APIRouter, APIRouter]]


def mount_api(app: FastAPI, ctx: ApiContext) -> None:
    """Include every domain, in the order the surface has always had."""
    builders: tuple[RouteBuilder, ...] = (
        status_routes,
        auth_routes,
        credential_routes,
        credential_edit_routes,
        value_routes,
        secret_routes,
        rotation_routes,
        service_routes,
        service_edit_routes,
        topology_routes,
        notification_routes,
        sync_routes,
    )
    for build in builders:
        public, authed = build(ctx)
        app.include_router(public)
        app.include_router(authed)
