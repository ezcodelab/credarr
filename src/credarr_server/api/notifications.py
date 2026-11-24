"""Notification services, their test sends, and the event feed.

A stored destination's write-only secret may be reused only for that same
destination; the rules here refuse the carry-over in the draft-test path."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, HTTPException

from credarr_server.api.context import ApiContext
from credarr_server.api.http import new_routers
from credarr_server.api.models import (
    NotificationServiceBody,
    NotificationServicePatch,
)
from credarr_server.notifier import EVENT_KINDS, SILENT_KINDS, SINKS, payload


def _merged(
    body: NotificationServiceBody | NotificationServicePatch,
    stored: Any,
    name: str,
) -> Any:
    """One field's new value: what the body named, else what is stored.

    An empty string clears an optional field; a cleared URL is refused by the
    callers that need one, with a message about the URL.
    """
    if name in body.model_fields_set:
        return getattr(body, name) or None
    return getattr(stored, name) if stored else None

def _ntfy_token_rule(
    kind: str, stored: Any, url: str | None, provided: Any
) -> None:
    """Refuse a changed ntfy server without a fresh token.

    A token belongs to the server it was issued by; after the URL moves, the
    stored one is a guess. Re-entering it (even the same string) is a claim the
    operator checked, which is the whole point of the rule. `provided` is the
    request's `model_fields_set`.
    """
    if (
        kind == "ntfy"
        and stored is not None
        and stored.token
        and url != stored.url
        and "token" not in provided
    ):
        raise HTTPException(
            status_code=400,
            detail="the ntfy server URL changed; re-enter the access token",
        )

def _email_password_rule(
    stored: Any,
    host: str | None,
    port: int | None,
    provided: Any,
) -> None:
    """Refuse a changed SMTP destination without the password again."""
    if (
        stored is not None
        and stored.kind == "email"
        and stored.token
        and (host != stored.smtp_host or port != stored.smtp_port)
        and "token" not in provided
    ):
        raise HTTPException(
            status_code=400,
            detail="the SMTP server changed; re-enter the password",
        )

def _telegram_token_rule(
    kind: str, stored: Any, url: str | None, provided: Any
) -> None:
    """Refuse a changed Telegram API base without a fresh bot token."""
    if (
        kind == "telegram"
        and stored is not None
        and stored.token
        and url != stored.url
        and "token" not in provided
    ):
        raise HTTPException(
            status_code=400,
            detail="the Telegram API base changed; re-enter the bot token",
        )

def _webhook_secret_rule(
    kind: str, stored: Any, url: str | None, provided: Any
) -> None:
    """Refuse a changed webhook URL without its stored secrets again.

    The URL chooses the receiver, so reusing either the receiver's authorization
    header or the signing secret at a new URL is the same write-only-secret
    exfiltration path as the ntfy token rule.
    """
    if kind != "webhook" or stored is None or url == stored.url:
        return
    if stored.auth_header and "auth_header" not in provided:
        raise HTTPException(
            status_code=400,
            detail="the webhook URL changed; re-enter the authorization header",
        )
    if stored.secret and "secret" not in provided:
        raise HTTPException(
            status_code=400,
            detail="the webhook URL changed; re-enter the signing secret",
        )

def _draft_destination_unchanged(stored: Any, body: NotificationServiceBody) -> bool:
    """Whether a draft test may reuse the stored row's write-only secrets.

    The secret belongs to the destination it was stored for. A caller may
    change the destination and supply a fresh secret, but may never make the
    server carry the old one to the new one.
    """
    if stored is None:
        return False
    if body.kind == "email":
        return body.smtp_host == stored.smtp_host and body.smtp_port == stored.smtp_port
    return body.url == stored.url


def routes(ctx: ApiContext) -> tuple[APIRouter, APIRouter]:
    """The domain's routes, over the one process context."""
    log = ctx.log
    notifier = ctx.notifier
    public, authed = new_routers()

    def _write_service(name: str, kind: str, body: Any, stored: Any) -> Any:
        """Merge one request into one service and write it.

        The merge rules live in `_merged`; the switches and the list are here
        because "omitted keeps, `null` clears" reads differently for a boolean
        and for "every event kind".
        """
        fields = body.model_fields_set
        if "enabled" in fields and body.enabled is None:
            raise HTTPException(status_code=400, detail="enabled is a switch; it cannot be cleared")
        if "discord_here" in fields and body.discord_here is None:
            raise HTTPException(
                status_code=400, detail="discord_here is a switch; it cannot be cleared"
            )
        if "allow_hook_origin" in fields and body.allow_hook_origin is None:
            raise HTTPException(
                status_code=400,
                detail="allow_hook_origin is a switch; it cannot be cleared",
            )
        if "enabled_types" in fields:
            # `null` clears like `[]` does: the list reads same as the strings,
            # omitted keeps, an explicit clear means "every kind".
            enabled_types = tuple(body.enabled_types or ())
        elif stored is not None:
            enabled_types = stored.enabled_types
        else:
            enabled_types = ()
        if "credential_filter" in fields:
            credential_filter = tuple(body.credential_filter or ())
        elif stored is not None:
            credential_filter = stored.credential_filter
        else:
            credential_filter = ()
        try:
            return notifier.save_service(
                name,
                kind,
                url=_merged(body, stored, "url"),
                topic=_merged(body, stored, "topic"),
                token=_merged(body, stored, "token"),
                secret=_merged(body, stored, "secret"),
                auth_header=_merged(body, stored, "auth_header"),
                discord_username=_merged(body, stored, "discord_username"),
                discord_avatar=_merged(body, stored, "discord_avatar"),
                discord_here=(
                    body.discord_here
                    if body.discord_here is not None
                    else (stored.discord_here if stored else False)
                ),
                smtp_host=_merged(body, stored, "smtp_host"),
                smtp_port=(
                    body.smtp_port
                    if "smtp_port" in fields
                    else (stored.smtp_port if stored else 587)
                ),
                smtp_username=_merged(body, stored, "smtp_username"),
                smtp_from=_merged(body, stored, "smtp_from"),
                smtp_to=_merged(body, stored, "smtp_to"),
                smtp_tls=_merged(body, stored, "smtp_tls") or "starttls",
                smtp_auth=_merged(body, stored, "smtp_auth") or "auto",
                enabled=(
                    body.enabled
                    if body.enabled is not None
                    else (stored.enabled if stored else True)
                ),
                enabled_types=enabled_types,
                credential_filter=credential_filter,
                allow_hook_origin=(
                    body.allow_hook_origin
                    if body.allow_hook_origin is not None
                    else (stored.allow_hook_origin if stored else False)
                ),
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None

    @authed.get("/notifications/services")
    def notification_services() -> dict[str, Any]:
        """Every service, without their secrets, with their per-service stats."""
        return {
            "services": [asdict(view) for view in notifier.views().values()],
            "types": list(SINKS),
            "kinds": list(EVENT_KINDS),
        }

    @authed.post("/notifications/services")
    def create_notification_service(body: NotificationServiceBody) -> dict[str, Any]:
        """Create one named service."""
        if body.kind not in SINKS:
            raise HTTPException(status_code=400, detail=f"unknown service type: {body.kind}")
        if notifier.service(body.name) is not None:
            raise HTTPException(
                status_code=409, detail=f"A service named {body.name} already exists"
            )
        view = _write_service(body.name, body.kind, body, None)
        return {"ok": True, "service": asdict(view)}

    @authed.post("/notifications/services/test")
    def test_notification_draft(
        body: NotificationServiceBody, existing: str | None = None
    ) -> dict[str, Any]:
        """Prove an unsaved notification config, without storing it."""
        if body.kind not in SINKS:
            raise HTTPException(status_code=400, detail=f"unknown service type: {body.kind}")
        stored = notifier.service(existing) if existing else None
        if existing and stored is None:
            raise HTTPException(status_code=404, detail=f"no service named {existing}")
        if stored is not None and stored.kind != body.kind:
            raise HTTPException(
                status_code=400,
                detail=f"{existing} is a {stored.kind} service",
            )
        _ntfy_token_rule(body.kind, stored, body.url, body.model_fields_set)
        _email_password_rule(
            stored, body.smtp_host, body.smtp_port, body.model_fields_set
        )
        _telegram_token_rule(body.kind, stored, body.url, body.model_fields_set)
        _webhook_secret_rule(body.kind, stored, body.url, body.model_fields_set)
        reuse = _draft_destination_unchanged(stored, body)
        try:
            reason = notifier.test_unsaved(
                body.name or (stored.name if stored else "test"),
                body.kind,
                url=body.url,
                topic=body.topic,
                token=body.token if body.token is not None else (stored.token if reuse else None),
                secret=(
                    body.secret
                    if body.secret is not None
                    else (stored.secret if reuse else None)
                ),
                auth_header=(
                    body.auth_header
                    if body.auth_header is not None
                    else (stored.auth_header if reuse else None)
                ),
                discord_username=body.discord_username,
                discord_avatar=body.discord_avatar,
                discord_here=body.discord_here,
                smtp_host=body.smtp_host,
                smtp_port=body.smtp_port,
                smtp_username=body.smtp_username,
                smtp_from=body.smtp_from,
                smtp_to=body.smtp_to,
                smtp_tls=body.smtp_tls,
                smtp_auth=body.smtp_auth,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None
        return {"ok": not reason, "detail": reason}

    @authed.patch("/notifications/services/{name}")
    def patch_notification_service(name: str, body: NotificationServicePatch) -> dict[str, Any]:
        """Edit one service. The name and the kind are not patchable."""
        stored = notifier.service(name)
        if stored is None:
            raise HTTPException(status_code=404, detail=f"no service named {name}")
        _ntfy_token_rule(
            stored.kind, stored, _merged(body, stored, "url"), body.model_fields_set
        )
        _email_password_rule(
            stored,
            _merged(body, stored, "smtp_host"),
            body.smtp_port if "smtp_port" in body.model_fields_set else stored.smtp_port,
            body.model_fields_set,
        )
        _telegram_token_rule(
            stored.kind, stored, _merged(body, stored, "url"), body.model_fields_set
        )
        _webhook_secret_rule(
            stored.kind, stored, _merged(body, stored, "url"), body.model_fields_set
        )
        view = _write_service(name, stored.kind, body, stored)
        return {"ok": True, "service": asdict(view)}

    @authed.delete("/notifications/services/{name}")
    def delete_notification_service(name: str) -> dict[str, Any]:
        """Delete one service. Delivery rows stay: they are the history."""
        if not notifier.delete_service(name):
            raise HTTPException(status_code=404, detail=f"no service named {name}")
        return {"ok": True}

    @authed.post("/notifications/services/{name}/test")
    def test_notification_service(name: str) -> dict[str, Any]:
        """Send one test event to this service, and report what it answered."""
        stored = notifier.service(name)
        if stored is None:
            raise HTTPException(status_code=404, detail=f"no service named {name}")
        if not stored.enabled:
            raise HTTPException(status_code=400, detail=f"{name} is disabled")
        event = log.record_test_event(name)
        try:
            notifier.tick_service(name)
        except ValueError as exc:  # unknown or disabled, both impossible here
            raise HTTPException(status_code=400, detail=str(exc)) from None
        deliveries = notifier.deliveries([event.id]).get(event.id, ())
        return {
            "event": {**payload(event), "sink": event.sink},
            "deliveries": [asdict(delivery) for delivery in deliveries],
        }

    @authed.get("/events")
    def events(limit: int = 50) -> dict[str, Any]:
        """The recorded status changes, newest first, with what went out.

        Read-only, and complete: an event exists because a run recorded it,
        whether or not a service was configured at the time. The delivery list
        is what the notifier has done about it so far.
        """
        limit = max(1, min(limit, 500))
        rows = log.recent_events(limit)
        deliveries = notifier.deliveries([event.id for event in rows])
        return {
            "events": [
                {
                    **payload(event),
                    # A test names its one service; ordinary events carry None.
                    "sink": event.sink,
                    # Silence is the delivery path's decision; publish it so the
                    # console can say "recorded, not notified" instead of
                    # "queued" for an event that will never be sent.
                    "silent": event.kind in SILENT_KINDS,
                    "deliveries": [
                        asdict(delivery) for delivery in deliveries.get(event.id, ())
                    ],
                }
                for event in rows
            ],
            # The services' own age travels with the list: an event older than
            # the service it would go to is never sent, and the console must be
            # able to say that instead of "queued" forever.
            "sinks": [
                {"name": config.name, "updated_at": config.updated_at}
                for config in sorted(notifier.services().values(), key=lambda item: item.name)
            ],
        }

    return public, authed
