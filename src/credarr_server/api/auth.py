"""Sign-in, sessions, the admin password, and API keys.

The cookie and CSRF mechanics live in `http`; this module decides who may
sign in, what a session may do, and when a key is shown exactly once."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from credarr_server.api.context import ApiContext
from credarr_server.api.http import (
    _actor,
    _clear_session_cookie,
    _origin_ok,
    _require_csrf,
    _session_token,
    _set_session_cookie,
    _unauthorized,
    new_routers,
)
from credarr_server.api.models import ApiKeyBody, LoginBody, PasswordBody, SetupBody
from credarr_server.auth import (
    InvalidCredentials,
    LoginLocked,
    SetupAlreadyDone,
    WrongPassword,
)


def routes(ctx: ApiContext) -> tuple[APIRouter, APIRouter]:
    """The domain's routes, over the one process context."""
    settings = ctx.settings
    auth = ctx.auth
    public, authed = new_routers()

    @public.get("/auth/state")
    def auth_state() -> dict[str, bool]:
        """Whether first-run setup is still open. No secrets, so it is public."""
        return {"needs_setup": auth.needs_setup()}

    @public.post("/auth/setup")
    def setup(body: SetupBody, request: Request, response: Response) -> dict[str, bool]:
        if not _origin_ok(request):
            raise HTTPException(status_code=403, detail="cross-site request refused")
        try:
            auth.set_password(body.password)
        except SetupAlreadyDone:
            raise HTTPException(status_code=409, detail="An admin already exists") from None
        auth.revoke_token(_session_token(request))
        issued = auth.create_session(request.headers.get("user-agent", ""))
        _set_session_cookie(response, issued.token, settings)
        return {"ok": True}

    @public.post("/auth/login")
    def login(body: LoginBody, request: Request, response: Response) -> dict[str, bool]:
        if not _origin_ok(request):
            raise HTTPException(status_code=403, detail="cross-site request refused")
        try:
            auth.login(body.password)
        except LoginLocked as exc:
            raise HTTPException(
                status_code=429,
                detail=f"too many failed sign-in attempts; try again in {exc.seconds} seconds",
                headers={"Retry-After": str(exc.seconds)},
            ) from None
        except InvalidCredentials:
            # One account, so the answer names no other account. A generic
            # sentence still avoids turning a future account model into an
            # enumeration oracle.
            raise _unauthorized("wrong password") from None
        # A new token on every authentication; an old session is not reused.
        auth.revoke_token(_session_token(request))
        issued = auth.create_session(request.headers.get("user-agent", ""))
        _set_session_cookie(response, issued.token, settings)
        return {"ok": True}

    @public.post("/auth/logout")
    def logout(request: Request, response: Response) -> dict[str, bool]:
        token = _session_token(request)
        if token:
            lookup = auth.authenticate_session(token)
            if lookup is not None:
                _require_csrf(request, lookup.session)
                auth.revoke_token(token)
        _clear_session_cookie(response, settings)
        return {"ok": True}

    @authed.get("/auth/me")
    def me(request: Request, actor: str = Depends(_actor)) -> dict[str, Any]:
        session = request.state.session
        return {
            "actor": actor,
            "auth": "session" if session is not None else "key",
            "csrf": session.csrf_token if session is not None else None,
        }

    @authed.get("/auth/sessions")
    def sessions(request: Request) -> dict[str, Any]:
        """Live browser sessions for the one admin; never a token or a hash."""
        current = request.state.session
        return {
            "sessions": [
                {
                    "id": session.id,
                    "current": current is not None and current.id == session.id,
                    "created_at": session.created_at,
                    "last_seen_at": session.last_seen_at,
                    "idle_expires_at": session.idle_expires_at,
                    "absolute_expires_at": session.absolute_expires_at,
                    "device": session.device,
                }
                for session in auth.list_sessions()
            ]
        }

    @authed.delete("/auth/sessions/{session_id}")
    def revoke_session(session_id: int, request: Request, response: Response) -> dict[str, bool]:
        current = request.state.session
        if not auth.revoke_session(session_id):
            raise HTTPException(status_code=404, detail="no such session")
        if current is not None and current.id == session_id:
            _clear_session_cookie(response, settings)
        return {"ok": True}

    @authed.delete("/auth/sessions")
    def revoke_sessions(response: Response) -> dict[str, Any]:
        """Revoke every session, including this one, and clear the cookie."""
        revoked = auth.revoke_all_sessions()
        _clear_session_cookie(response, settings)
        return {"ok": True, "revoked": revoked}

    @authed.post("/auth/password")
    def change_password(
        body: PasswordBody, request: Request, response: Response
    ) -> dict[str, bool]:
        """Change the password; a browser session is required, not a Bearer key."""
        session = request.state.session
        if session is None:
            raise HTTPException(
                status_code=403,
                detail="changing the password requires a signed-in browser session",
            )
        try:
            issued = auth.change_password(
                body.current_password,
                body.new_password,
                session_id=session.id,
            )
        except WrongPassword:
            raise HTTPException(status_code=403, detail="current password is wrong") from None
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None
        _set_session_cookie(response, issued.token, settings)
        return {"ok": True}

    @authed.post("/keys")
    def create_key(body: ApiKeyBody | None = None) -> dict[str, Any]:
        """Issue an API key; the response is the only time it exists in clear."""
        key_id, key = auth.create_key(body.origin if body else "user")
        return {"id": key_id, "key": key, "origin": body.origin if body else "user"}

    @authed.get("/keys")
    def list_keys() -> list[dict[str, Any]]:
        return [
            {
                "id": key.id,
                "prefix": key.prefix,
                "origin": key.origin,
                "created_at": key.created_at,
                "last_used_at": key.last_used_at,
            }
            for key in auth.list_keys()
        ]

    @authed.delete("/keys/{key_id}")
    def revoke_key(key_id: int) -> dict[str, bool]:
        if not auth.revoke_key(key_id):
            raise HTTPException(status_code=404, detail="no such key")
        return {"ok": True}

    return public, authed
