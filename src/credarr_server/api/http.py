"""HTTP plumbing shared by every router: cookies, CSRF, and the caller.

The session cookie is opaque and server-side; the Origin check and the CSRF
token are two locks on the same write, and the actor dependency is where a
session's sliding expiry is renewed. None of this knows a domain."""

from __future__ import annotations

import hmac
import urllib.parse
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError

from credarr_server.auth import SESSION_IDLE_SECONDS, Session

if TYPE_CHECKING:
    from credarr_server.app import ServerSettings

SESSION_COOKIE = "credarr_session"
# The prefix is only legal when the Secure flag is set, Path is "/", and no
# Domain is sent; the cookie helper below keeps all three true together.
SESSION_COOKIE_SECURE = "__Host-credarr_session"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
PREFIX = "/api/v1"


def new_routers() -> tuple[APIRouter, APIRouter]:
    """One public and one authenticated router, both under the version prefix."""
    return (
        APIRouter(prefix=PREFIX),
        APIRouter(prefix=PREFIX, dependencies=[Depends(_actor)]),
    )


def _validation_details(
    exc: ValidationError | RequestValidationError,
) -> list[dict[str, Any]]:
    """The safe half of a validation error: where, what kind, and what to fix.

    Pydantic puts the rejected input and validator context on every error by
    default. A rejected credential value or password is still a secret, and a
    write-only API must not return it in a diagnostic. The message is enough
    for the console and the operator.
    """
    return [
        {key: error[key] for key in ("type", "loc", "msg") if key in error}
        for error in exc.errors()
    ]


def _session_cookie_name(settings: ServerSettings) -> str:
    return SESSION_COOKIE_SECURE if settings.secure_cookies else SESSION_COOKIE


def _set_session_cookie(response: Response, token: str, settings: ServerSettings) -> None:
    """Write the opaque session cookie with the strongest portable attributes."""
    response.set_cookie(
        _session_cookie_name(settings),
        token,
        max_age=SESSION_IDLE_SECONDS,
        path="/",
        httponly=True,
        samesite="strict",
        secure=settings.secure_cookies,
    )


def _clear_session_cookie(response: Response, settings: ServerSettings) -> None:
    response.delete_cookie(
        _session_cookie_name(settings),
        path="/",
        httponly=True,
        samesite="strict",
        secure=settings.secure_cookies,
    )


def _session_token(request: Request) -> str:
    return request.cookies.get(_session_cookie_name(request.app.state.settings), "")


def _origin_ok(request: Request) -> bool:
    """A browser Origin, when present, must name this same host.

    This is a second lock behind the CSRF token: a cross-site form cannot send
    the token, and its Origin cannot match. A non-browser client that sends
    neither is judged by the token alone. No forwarded header is trusted.
    """
    origin = request.headers.get("origin")
    if origin is None:
        return True
    parsed = urllib.parse.urlsplit(origin)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return False
    return parsed.netloc == request.headers.get("host", "")


def _require_csrf(request: Request, session: Session) -> None:
    """Protect cookie-authenticated writes; Bearer keys are exempt elsewhere."""
    if request.method in SAFE_METHODS:
        return
    if not _origin_ok(request):
        raise HTTPException(status_code=403, detail="cross-site request refused")
    presented = request.headers.get(CSRF_HEADER, "")
    if not presented or not hmac.compare_digest(presented, session.csrf_token):
        raise HTTPException(status_code=403, detail="the CSRF token is missing or wrong")


def _actor(request: Request, response: Response) -> str:
    """Who is calling: the admin's session, or an API key by id.

    Session first: the SPA is the ordinary caller, and a browser that happens to
    carry a key must not need it on every request. The dependency is also where
    a sliding cookie is renewed, because it receives the response.
    """
    token = _session_token(request)
    if token:
        lookup = request.app.state.auth.authenticate_session(token)
        if lookup is not None:
            _require_csrf(request, lookup.session)
            request.state.session = lookup.session
            if lookup.renewed:
                _set_session_cookie(response, token, request.app.state.settings)
            return "admin"
    request.state.session = None
    scheme, _, presented = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not presented:
        raise _unauthorized("authentication required")
    key_id = request.app.state.auth.verify_key(presented)
    if key_id is None:
        raise _unauthorized("that API key is not valid")
    return f"key:{key_id}"


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(status_code=401, detail=detail, headers={"WWW-Authenticate": "Bearer"})

