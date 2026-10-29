"""The BFF: one HTTP surface over the engine, for one admin.

The engine does the work; this module wires it into a process. It builds the
topology store, the audit log and the scheduler over one `app.db` under the
config directory, serves them under `/api/v1`, and keeps the audit loop alive.
Every endpoint calls the same library the command line calls, so the CLI and
the API cannot plan or audit differently; the OpenAPI document is the contract
and `tests/server/test_app.py` pins it.

BFF discipline (DECISIONS standing rule 2): a service secret never reaches a
payload. The only credential a browser sees is the app's own API key, and only
in the response that creates it.
"""

from __future__ import annotations

import argparse
import contextlib
import hmac
import math
import os
import sqlite3
import sys
import threading
import time
import urllib.parse
import zoneinfo
from collections.abc import Awaitable, Callable, Iterable, Iterator, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from credarr import __version__, facade, provenance, report
from credarr.audit import CredentialResult, Status
from credarr.config import Config, HostConfig, load_config
from credarr.errors import ConfigError, CredctlError, ExitCode, ManifestError
from credarr.instance import DEFAULT_CONFIG_DIR, InstanceLock
from credarr.journal import STACK_LOCK, JournalLocked
from credarr.model import (
    MAX_EXACT_INT,
    NAME_RE,
    Consumer,
    Credential,
    Manifest,
)
from credarr.redact import Secret, disable_core_dumps, scrub
from credarr.rotate import RotationPlan, service_for, ui_password_names
from credarr.secrets import BACKENDS
from credarr.services import (
    declared_services,
    probe_service_connection,
    service_report,
)
from credarr.targets import TargetRegistry, build_registry
from credarr.writers import holder_for, known_systems
from credarr_server import auto_rotation, mounts
from credarr_server.audit_jobs import AuditJobs
from credarr_server.audit_log import AuditLog, AuditRun, ConsumerState, CredentialState
from credarr_server.auth import (
    MIN_PASSWORD_LENGTH,
    SESSION_IDLE_SECONDS,
    AdminAuth,
    InvalidCredentials,
    LoginLocked,
    Session,
    SetupAlreadyDone,
    WrongPassword,
)
from credarr_server.discovery import discover
from credarr_server.notifier import (
    EVENT_KINDS,
    SILENT_KINDS,
    SINKS,
    DeliveryLoop,
    Notifier,
    payload,
)
from credarr_server.scheduler import (
    MAX_AUDIT_INTERVAL_SECONDS,
    MIN_AUDIT_INTERVAL_SECONDS,
    Scheduler,
)
from credarr_server.source import (
    StorePending,
    StoreSource,
    rotation_manifest,
    runtime_config,
    stored_mint_values,
    stored_service_keys,
)
from credarr_server.store import (
    AutoRotation,
    CredentialExists,
    Service,
    ServiceExists,
    TopologyStore,
    UnknownCredential,
)

# The console binds every interface on purpose: it exists to be reached over
# the LAN, and the container publishes a single port. `--host` narrows it.
DEFAULT_HOST = "0.0.0.0"  # noqa: S104

SESSION_COOKIE = "credarr_session"
# The prefix is only legal when the Secure flag is set, Path is "/", and no
# Domain is sent; the cookie helper below keeps all three true together.
SESSION_COOKIE_SECURE = "__Host-credarr_session"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

# A manifest is a few hundred lines of YAML; a megabyte is already absurd, and
# the cap is what keeps a bad upload from being parsed.
MAX_MANIFEST_BYTES = 1024 * 1024
# Tokens and passwords are short. The cap bounds what a write can put in the
# database (characters: it is a pydantic `str` length, not a byte count), not a
# judgement about anyone's key format.
MAX_VALUE_LENGTH = 8192


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


@dataclass(frozen=True, slots=True)
class ServerSettings:
    """How the process boots: the engine config, the data directory, the socket.

    The command line and the environment fill this in; tests build it directly.
    `config_path` is the same `credarr.yaml` the CLI reads - hosts and paths are
    one deployment's facts, and the app must audit where the CLI audits.
    """

    config_path: Path
    config_dir: Path
    host: str = DEFAULT_HOST
    port: int = 8080
    audit_interval: float = 3600.0
    secure_cookies: bool = False
    # Decision 8: a local filesystem is the assumption SQLite's locks and WAL
    # rest on. This is the documented way to accept a network mount anyway.
    allow_network_config: bool = False
    # Optional, read-only Docker API used by the discovery endpoint. None is
    # the default posture: no socket, no scan.
    docker_url: str | None = None
    # The zone the console renders timestamps in. It comes from TZ, the same
    # variable the container uses for its clock; an invalid value falls back to
    # UTC rather than letting Intl throw in the browser.
    timezone: str = "UTC"
    # The built SPA, inside the package: `make web` puts it there and the
    # image's node stage does the same (DECISIONS: one image, one version).
    web_dir: Path = field(default_factory=lambda: Path(__file__).parent / "web")

    @property
    def database(self) -> Path:
        """One database: topology, working copies, audit history, admin."""
        return self.config_dir / "app.db"


class AuditLoop:
    """The scheduler thread, and the failure that ends it.

    `Scheduler.serve` deliberately ends when a run cannot be recorded: a loop
    that cannot write to the ledger is a dashboard quietly going stale. The
    caller owns restarting it or surfacing it - here it is surfaced, and
    `/api/v1/health` reports it as degraded.
    """

    def __init__(
        self, scheduler: Scheduler, auto: auto_rotation.AutoRotator | None = None
    ) -> None:
        self.scheduler = scheduler
        self.auto = auto
        self.failure: str | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="credarr-audit", daemon=True)

    @property
    def running(self) -> bool:
        return self._thread.is_alive()

    def set_interval(self, seconds: float) -> None:
        """Apply a cadence change to both the loop and the auto freshness gate."""
        self.scheduler.set_interval(seconds)
        if self.auto is not None:
            self.auto.set_interval(seconds)

    def set_enabled(self, enabled: bool) -> None:
        """Apply the audit-schedule switch without stopping the loop."""
        self.scheduler.set_enabled(enabled)

    def wake(self) -> None:
        self.scheduler.wake()

    def start(self) -> None:
        # Auto reconciles the journal before the first audit can signal it.
        if self.auto is not None:
            self.auto.start()
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self.auto is not None:
            self.auto.stop()
        # An audit in flight can hold the thread past the join; it is a daemon,
        # and the run it is finishing is read-only.
        self._thread.join(timeout=10)

    def _run(self) -> None:
        try:
            self.scheduler.serve(self._stop)
        except Exception as exc:
            self.failure = f"{type(exc).__name__}: {exc}"
            # No audit means no completed-audit signal auto may act on.
            if self.auto is not None:
                self.auto.stop()


class SetupBody(BaseModel):
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=1024)


class LoginBody(BaseModel):
    """Login compares any string; the length policy belongs to creation."""

    password: str = Field(max_length=1024)


class PasswordBody(BaseModel):
    """Change the admin password; the current one is the step-up check."""

    current_password: str = Field(max_length=1024)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=1024)


class ValueBody(BaseModel):
    """A pasted credential value. Write-only: nothing reads it back."""

    value: str = Field(min_length=1, max_length=MAX_VALUE_LENGTH)

    @field_validator("value")
    @classmethod
    def _no_surrounding_whitespace(cls, value: str) -> str:
        """Refuse, never mangle.

        Every holdable value in this stack is a token, and a paste carries a
        trailing newline often enough that an audit would read it as drift.
        Trimming it silently would change a secret the operator never typed
        that way; saying so puts the decision back where it belongs.
        """
        if value != value.strip():
            raise ValueError("the value has leading or trailing whitespace")
        return value


class RotateBody(BaseModel):
    """The typed confirmation: the credential's own name, not a boolean.

    A boolean is one click; a name is a sentence the operator had to read. The
    console disables its button until the two match, and this repeats the check
    because the console is not the only caller.

    `take_over` is a second, separate assertion: the unfinished steps of this
    credential belong to a run that is not coming back. It is not the
    confirmation's job to imply it - the console offers it only when there is
    something to take over, and says what it means.

    `manual_value` is the key the operator rotated in the service's own UI for a
    `write.manual_mint` credential. It is a secret, so it is hidden from reprs
    and scrubbed from every event and message; a plan that does not use the
    manual mint refuses it rather than silently ignoring it.
    """

    confirm: str = Field(max_length=256)
    take_over: bool = False
    # Deliberately unconstrained: a validation error for a secret field would
    # echo the input into the 422 body. The route checks blank/length itself
    # and refuses without copying the value into a message.
    manual_value: str | None = Field(default=None, repr=False)


class PlanBody(BaseModel):
    """What the plan endpoint may be told. Read-only, so only one thing."""

    take_over: bool = False


class AuditIntervalBody(BaseModel):
    """The persisted audit cadence, in seconds."""

    model_config = ConfigDict(extra="forbid")

    interval_seconds: float = Field(
        ge=MIN_AUDIT_INTERVAL_SECONDS, le=MAX_AUDIT_INTERVAL_SECONDS
    )
    enabled: bool | None = None


class AutoRotationBody(BaseModel):
    """The per-credential policy write.

    Enabling is a future mutation and therefore requires the same typed-name
    assertion as a manual run; disabling does not. When the credential has
    copies auto cannot finish, `accept_manual` is the explicit acknowledgement
    that the rotation will leave them for a human. The interval is bounded here
    as well as in the store, because the HTTP layer is a trust boundary.
    """

    enabled: bool
    every_days: int | None = Field(default=None, ge=1, le=365)
    confirm: str = Field(default="", max_length=256)
    accept_manual: bool = False


class ServiceBody(BaseModel):
    """One service's deployment facts, as the console edits them."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    kind: str = Field(default="other", max_length=64)
    url: str | None = Field(default=None, max_length=2048)
    notes: str = Field(default="", max_length=2000)


class ServicePatch(BaseModel):
    """A partial edit. A name in the body is refused: delete + create instead.

    A URL change on a service with a stored API key also carries the key again;
    the old key belonged to the old server. The value is write-only and has a
    hidden repr, so a validation error cannot print it.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, max_length=64)
    kind: str | None = Field(default=None, max_length=64)
    url: str | None = Field(default=None, max_length=2048)
    notes: str | None = Field(default=None, max_length=2000)
    credential: str | None = Field(default=None, max_length=64)
    key: str | None = Field(
        default=None, min_length=1, max_length=4096, repr=False
    )


class ServiceTestBody(BaseModel):
    """A URL and key to try, never a write."""

    model_config = ConfigDict(extra="forbid")

    service: str = Field(min_length=1, max_length=64)
    url: str = Field(min_length=1, max_length=2048)
    key: str | None = Field(default=None, max_length=4096)


class VaultBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    backend: str = Field(min_length=1, max_length=64)
    file: str = Field(min_length=1, max_length=4096)
    path: list[str] = Field(default_factory=list)


class HolderBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, max_length=512)
    count: int = Field(default=1, ge=1, le=MAX_EXACT_INT)
    mechanism: str = Field(default="", max_length=256)
    host: str | None = Field(default=None, max_length=512)
    note: str = Field(default="", max_length=2000)


class CredentialBody(BaseModel):
    """A credential declaration; the same shape the manifest parser accepts."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    description: str = Field(default="", max_length=2000)
    credential_class: str = Field(default="B", alias="class", max_length=16)
    max_age_days: int | None = Field(default=None, ge=1, le=MAX_EXACT_INT)
    never_rotate: bool = False
    provisioned: bool = True
    canonical: dict[str, Any] = Field(default_factory=dict)
    write: dict[str, Any] = Field(default_factory=dict)
    vault: VaultBody | None = None
    consumers: list[HolderBody] = Field(default_factory=list)


class CredentialPatch(BaseModel):
    """Partial metadata edit. `name` is only accepted when it matches."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    name: str | None = Field(default=None, max_length=64)
    description: str | None = Field(default=None, max_length=2000)
    credential_class: str | None = Field(default=None, alias="class", max_length=16)
    max_age_days: int | None = Field(default=None, ge=1, le=MAX_EXACT_INT)
    never_rotate: bool | None = None
    provisioned: bool | None = None
    canonical: dict[str, Any] | None = None
    write: dict[str, Any] | None = None
    vault: VaultBody | None = None
    consumers: list[HolderBody] | None = None


class HoldersBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    consumers: list[HolderBody] = Field(default_factory=list)


class ImportBody(BaseModel):
    """The console's import. Raw YAML remains a legacy replace body."""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["replace", "merge"] = "replace"
    prune: bool = False
    yaml: str = Field(min_length=1)
    confirm: str = Field(default="", max_length=64)


class NotificationServiceBody(BaseModel):
    """A new notification service, whole.

    The name is the operator's label and part of the API path; the kind picks
    which fields matter. Fields that do not apply to the kind are accepted and
    stored as NULL rather than refused - the form hides them, and a later edit
    should not have to retype anything.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    kind: str = Field(min_length=1, max_length=32)
    enabled: bool = True
    url: str = Field(default="", max_length=1024)
    topic: str | None = Field(default=None, max_length=256)
    token: str | None = Field(default=None, max_length=4096)
    secret: str | None = Field(default=None, max_length=4096)
    auth_header: str | None = Field(default=None, max_length=4096)
    discord_username: str | None = Field(default=None, max_length=256)
    discord_avatar: str | None = Field(default=None, max_length=1024)
    discord_here: bool = False
    smtp_host: str = Field(default="", max_length=255)
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str = Field(default="", max_length=256)
    smtp_from: str = Field(default="", max_length=512)
    smtp_to: str = Field(default="", max_length=4096)
    smtp_tls: str = Field(default="starttls", max_length=16)
    smtp_auth: str = Field(default="auto", max_length=16)
    enabled_types: list[str] = Field(default_factory=list)


class NotificationServicePatch(BaseModel):
    """An edit to one service. `model_fields_set` decides what was sent.

    The kind is not patchable: a different mechanism is a different service,
    and its fields, validators and delivery rows are its own. Neither is the
    name - a rename is delete plus create, deliberately, like a credential.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    url: str | None = Field(default=None, max_length=1024)
    topic: str | None = Field(default=None, max_length=256)
    token: str | None = Field(default=None, max_length=4096)
    secret: str | None = Field(default=None, max_length=4096)
    auth_header: str | None = Field(default=None, max_length=4096)
    discord_username: str | None = Field(default=None, max_length=256)
    discord_avatar: str | None = Field(default=None, max_length=1024)
    discord_here: bool | None = None
    smtp_host: str | None = Field(default=None, max_length=255)
    smtp_port: int | None = Field(default=None, ge=1, le=65535)
    smtp_username: str | None = Field(default=None, max_length=256)
    smtp_from: str | None = Field(default=None, max_length=512)
    smtp_to: str | None = Field(default=None, max_length=4096)
    smtp_tls: str | None = Field(default=None, max_length=16)
    smtp_auth: str | None = Field(default=None, max_length=16)
    enabled_types: list[str] | None = None


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


def _import_warnings(manifest: Manifest) -> list[dict[str, str]]:
    """Name API keys that were imported as audit-only despite a mint source.

    This is a warning, not a refusal: a password or a deliberately frozen key
    is legitimately class B. The `_api_key` name and a service with a mint are
    the two facts that make the declaration surprising enough to mention.
    """
    mintable = known_systems()
    warnings: list[dict[str, str]] = []
    for name, credential in manifest.credentials.items():
        if credential.credential_class != "B" and not credential.never_rotate:
            continue
        if not name.endswith("_api_key"):
            continue
        service = service_for(credential)
        if service not in mintable:
            continue
        warnings.append({"credential": name, "service": service})
    return warnings


def _mount(app: FastAPI) -> None:
    """The `/api/v1` surface. The version is in the path; there is no other."""
    settings: ServerSettings = app.state.settings
    store: TopologyStore = app.state.store
    auth: AdminAuth = app.state.auth
    log: AuditLog = app.state.audit_log
    audit_jobs: AuditJobs = app.state.audit_jobs
    loop: AuditLoop = app.state.loop
    auto: auto_rotation.AutoRotator = app.state.auto
    notifier: Notifier = app.state.notifier
    delivery: DeliveryLoop = app.state.delivery
    config: Config = app.state.config
    scheduler = loop.scheduler
    registry: TargetRegistry = scheduler.registry

    @contextlib.contextmanager
    def stack_write(actor: str) -> Iterator[None]:
        """Keep topology, values and service URLs fixed for a whole rotation.

        The journal's reserved stack lease closes the check/write race: every
        server rotation takes it before planning, and every topology mutation
        takes it before reading candidate state. CLI apply cannot overlap the
        server because the instance owns `/config/app.lock`.

        Only the acquisition is translated. A credential lease conflict inside
        the body must keep the engine's own sentence, which names the holder
        and the age of the lock.
        """
        lease = facade.journal_for(config).lock(STACK_LOCK, actor)
        try:
            lease.__enter__()
        except JournalLocked:
            held = facade.journal_for(config).held(STACK_LOCK)
            detail = "a rotation or configuration change is in progress"
            if held is not None:
                changed = max(0, int(time.time() - held["acquired_at"]))
                who = held["actor"] or f"pid {held['pid']} on {held['host']}"
                detail = (
                    f"a rotation or configuration change is in progress "
                    f"({who}, {changed}s ago)"
                )
            raise HTTPException(
                status_code=409,
                detail=f"{detail}; retry after it finishes",
            ) from None
        try:
            yield
        finally:
            lease.__exit__(None, None, None)

    public = APIRouter(prefix="/api/v1")
    authed = APIRouter(prefix="/api/v1", dependencies=[Depends(_actor)])

    @public.get("/health")
    def health() -> JSONResponse:
        """Liveness for the container: degraded unless both loops are alive.

        A process whose loop died is not healthy even though it still answers
        requests, because everything it serves from that point is the past -
        and neither is one whose loop never started (a host run without the
        lifespan), because then there is no ledger at all. The delivery loop
        counts for the same reason: a console that records changes nobody hears
        about is a monitor that quietly stopped monitoring.
        """
        for name, alive, failure in (
            ("scheduler", loop.running, loop.failure),
            ("notifier", delivery.running, delivery.failure),
        ):
            if failure is not None:
                return JSONResponse({"status": "degraded", name: failure}, status_code=503)
            if not alive:
                return JSONResponse({"status": "degraded", name: "not running"}, status_code=503)
        if auto.failure is not None:
            return JSONResponse(
                {"status": "degraded", "auto_rotation": auto.failure}, status_code=503
            )
        if any(
            state.enabled for state in store.auto_rotations().values()
        ) and not auto.running:
            return JSONResponse(
                {"status": "degraded", "auto_rotation": "not running"}, status_code=503
            )
        return JSONResponse({"status": "ok"})

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
    def create_key() -> dict[str, Any]:
        """Issue an API key; the response is the only time it exists in clear."""
        key_id, key = auth.create_key()
        return {"id": key_id, "key": key}

    @authed.get("/keys")
    def list_keys() -> list[dict[str, Any]]:
        return [
            {
                "id": key.id,
                "prefix": key.prefix,
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

    def state_payload(*, include_job: bool = True) -> dict[str, Any]:
        """What Overview shows: the loop's health, the ledger, the counts.

        Statuses are the engine's vocabulary (`audit.Status`), and details are
        the strings the audit already writes to be safe in a log; nothing here
        has ever seen a value.

        `imported` is the honest half of the empty case: a store with no
        topology audits as exit 0 / match - the engine treats zero credentials
        as nothing wrong, and the CLI reads an empty manifest the same way - so
        the counts alone would let "never looked" read as "all clean". The flag
        says which one it is.

        `audit_job` is the running background full audit, if any. A reloaded
        console resumes polling it instead of showing the previous verdict as
        if nothing were happening.
        """
        manifest = store.load_manifest()
        state = log.last_state()
        journal = facade.journal_for(config)
        return {
            "version": __version__,
            "timezone": settings.timezone,
            "audit_job": audit_jobs.active() if include_job else None,
            "scheduler": {
                "running": loop.running,
                "failure": loop.failure,
                "interval_seconds": loop.scheduler.interval,
                "enabled": loop.scheduler.enabled,
            },
            "auto_rotation": {
                "running": auto.running,
                "failure": auto.failure,
                # "Enabled" is policy; eligible is whether a completed audit
                # can actually reach the worker right now.
                "eligible": loop.running
                and auto.running
                and loop.failure is None
                and auto.failure is None,
                "enabled": sum(
                    1 for state in store.auto_rotations().values() if state.enabled
                ),
            },
            "topology": {
                "imported": bool(manifest.credentials),
                "credentials": len(manifest.credentials),
                "holders": sum(len(c.consumers) for c in manifest.credentials.values()),
                # Names only, no probing: the console's menu and the Services
                # view must agree on which services exist before a host is
                # asked anything.
                "services": declared_services(manifest),
            },
            "last_run": _run_json(state.last_run) if state else None,
            "last_audit": (
                _run_json(state.last_audit) if state and state.last_audit is not None else None
            ),
            # An unfinished rotation is a state, not a history row: the console
            # has to show it before anything else can be run. This is the
            # unwindowed query on purpose - a crash older than `stale_after`
            # still blocks auto-rotation, so hiding it would leave the 409
            # pointing at a banner the operator cannot see. Continuing takes
            # over from the service's observed state rather than minting blind;
            # the lock still refuses a takeover while a live run holds it.
            "rotation": {
                "pending": [
                    {
                        "credential": step.credential,
                        "target": step.target,
                        "kind": step.kind,
                        "detail": step.detail,
                        "ordinal": step.ordinal,
                        "started_at": step.started_at,
                        "seconds_ago": step.seconds_ago,
                    }
                    for step in journal.unfinished()
                ],
                "stale_after_seconds": journal.stale_after,
            },
        }

    @authed.get("/status")
    def status() -> dict[str, Any]:
        """Overview's summary. The per-credential rows are `/credentials`."""
        return state_payload()

    @authed.get("/settings/audit")
    def get_audit_settings() -> dict[str, Any]:
        """The effective cadence and the bounds the UI may offer."""
        return {
            "interval_seconds": loop.scheduler.interval,
            "enabled": loop.scheduler.enabled,
            "minimum_seconds": MIN_AUDIT_INTERVAL_SECONDS,
            "maximum_seconds": MAX_AUDIT_INTERVAL_SECONDS,
            "boot_seconds": settings.audit_interval,
        }

    @authed.put("/settings/audit")
    def put_audit_settings(
        body: AuditIntervalBody, actor: str = Depends(_actor)
    ) -> dict[str, Any]:
        """Persist and apply a new cadence without restarting the process.

        The scheduler wake is part of the write: a change that only landed in
        the database would not take effect until the old interval elapsed.
        """
        with stack_write(actor):
            store.set_audit_interval(body.interval_seconds)
            loop.set_interval(body.interval_seconds)
            if body.enabled is not None:
                store.set_audit_enabled(body.enabled)
                loop.set_enabled(body.enabled)
        return get_audit_settings()

    @authed.get("/audit")
    def audit_history(only: str = "", limit: int = 20) -> dict[str, Any]:
        """The per-app history for one credential, newest first.

        A full audit's credential row and a scoped check are both history. The
        filter is the same `only` the run endpoint takes, so the history and
        the action name the same scope and cannot drift into two conventions.
        """
        name = only.strip()
        if not name:
            raise HTTPException(
                status_code=400,
                detail="only is required for per-app check history",
            )
        if not NAME_RE.fullmatch(name):
            raise HTTPException(status_code=400, detail="invalid credential name")
        if not 1 <= limit <= 100:
            raise HTTPException(
                status_code=400,
                detail="limit must be between 1 and 100",
            )
        if name not in store.load_manifest().credentials:
            raise HTTPException(status_code=404, detail=f"no credential named {name}")
        return {
            "credential": name,
            "checks": [
                {
                    "at": check.at,
                    "status": check.status.value,
                    "detail": check.detail,
                    "source": check.source,
                }
                for check in log.checks(name, limit=limit)
            ],
        }

    @authed.post(
        "/audit",
        responses={202: {"description": "audit started as a background job"}},
    )
    def run_audit(only: str | None = None, wait: bool = True) -> Any:
        """Audit now, and answer with the state that run produced.

        With `only=<credential>`, run the same engine audit for that credential
        alone and record it in per-app check history. That is a diagnostic, not
        a stack audit: it cannot satisfy auto-rotation's exact-coverage gate or
        replace `last_audit`.

        Without `only`, the default keeps the old synchronous contract and
        answers with the state the run produced. `wait=false` starts the same
        run in a background job and answers 202 immediately; the console polls
        `GET /audit/jobs/{job_id}` so a proxy or tunnel can drop without
        losing the server-side audit. A scoped check is deliberately not
        asynchronous: it is one bounded credential check, not a stack run.

        The only thing `Scheduler.once` lets escape is a ledger it cannot write
        (`sqlite3.Error`), which is the failure that ends the loop; that is the
        503, and the loop itself dies at its next tick. Anything else escaping
        is a bug, and a bug reported as "degraded" would be a lie with a
        status code in front of it, so it stays a 500. A background job records
        that same failure in its status instead of having a caller to raise to.
        """
        if only is not None:
            if not wait:
                raise HTTPException(
                    status_code=400,
                    detail="a scoped check is synchronous; omit wait=false",
                )
            name = only.strip()
            if not name or not NAME_RE.fullmatch(name):
                raise HTTPException(
                    status_code=400, detail="invalid credential name"
                )
            if name not in store.load_manifest().credentials:
                raise HTTPException(
                    status_code=404, detail=f"no credential named {name}"
                )
            try:
                checked_at, check = scheduler.check(name)
            except UnknownCredential:
                raise HTTPException(
                    status_code=404, detail=f"no credential named {name}"
                ) from None
            except sqlite3.Error as exc:
                raise HTTPException(
                    status_code=503,
                    detail=f"{type(exc).__name__}: {exc}",
                ) from None
            return {
                "checked_at": checked_at,
                "check": _check_json(check),
            }
        if wait:
            try:
                scheduler.once()
            except sqlite3.Error as exc:
                raise HTTPException(
                    status_code=503,
                    detail=f"{type(exc).__name__}: {exc}",
                ) from None
            return state_payload()

        def run() -> dict[str, Any]:
            if scheduler.once() is None:
                state = log.last_state()
                detail = (
                    state.last_run.detail
                    if state is not None and state.last_run is not None
                    else ""
                )
                raise RuntimeError(detail or "the audit did not complete; see the audit ledger")
            return state_payload(include_job=False)

        job = audit_jobs.start(run)
        return JSONResponse(
            status_code=202,
            content=audit_jobs.get(job.id) or {"job_id": job.id, "status": "running"},
        )

    @authed.get("/audit/jobs/{job_id}")
    def audit_job(job_id: str) -> dict[str, Any]:
        """One background audit's status and, when finished, its result."""
        job = audit_jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="no such audit job")
        return job

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
        (see `_credential_json`).
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
                _credential_json(
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
            "credential": _credential_json(
                credential,
                None,
                None,
                None,
                None,
            ),
        }

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
                "credential": _credential_json(
                    credential,
                    store.working_copy_times().get(name),
                    None,
                    None,
                    None,
                ),
                "warning": warning,
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
            journal = facade.journal_for(config)
            pending = sorted(
                {str(step.target) for step in journal.unfinished()
                 if step.credential == name}
            )
            attempt = journal.open_attempts().get(name)
            if pending or attempt is not None:
                detail = (
                    f"attempt {attempt} did not finish"
                    if attempt is not None
                    else "an unfinished step remains"
                )
                raise HTTPException(
                    status_code=409,
                    detail=f"{name}: {detail}; resume or take it over before "
                    "deleting the credential",
                )
            if not store.delete_credential(name):
                raise HTTPException(status_code=404, detail=f"no credential named {name}")
            loop.wake()
            return {"ok": True}

    @authed.delete("/credentials/{name}/value")
    def clear_value(name: str, actor: str = Depends(_actor)) -> dict[str, bool]:
        """Forget the app's copy. This never touches the service's live value."""
        try:
            with stack_write(actor), facade.journal_for(config).lock(name, actor):
                if name not in store.load_manifest().credentials:
                    raise HTTPException(status_code=404, detail=f"no credential named {name}")
                store.clear_value(name)
        except JournalLocked as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        return {"ok": True}

    @authed.get("/credentials/{name}/auto-rotation")
    def get_auto_rotation(name: str) -> dict[str, Any]:
        """The policy row, off when absent. Read-only and secret-free."""
        manifest = store.load_manifest()
        if name not in manifest.credentials:
            raise HTTPException(status_code=404, detail=f"no credential named {name}")
        state = store.auto_rotation(name)
        return {
            "auto_rotation": _auto_json(
                state, facade.journal_for(config).last_rotation(name)
            )
        }

    @authed.put("/credentials/{name}/auto-rotation")
    def put_auto_rotation(
        name: str, body: AutoRotationBody, actor: str = Depends(_actor)
    ) -> dict[str, Any]:
        """Enable or disable the policy, never run it.

        Enabling from off or paused resets the due baseline and clears the
        pause, so this request cannot rotate. While enabled and unpaused, an
        interval edit changes the due clock from the existing completed
        rotation; it does not reset the baseline or clear a pause.
        """
        with stack_write(actor):
            manifest = store.load_manifest()
            if name not in manifest.credentials:
                raise HTTPException(status_code=404, detail=f"no credential named {name}")
            journal = facade.journal_for(config)
            if body.enabled:
                if body.confirm.strip() != name:
                    raise HTTPException(
                        status_code=400,
                        detail="not confirmed: type the credential's name to enable auto-rotation",
                    )
                if body.every_days is None:
                    raise HTTPException(status_code=400, detail="every_days is required")
                existing = store.auto_rotation(name)
                if existing is not None and existing.enabled and not existing.paused:
                    # An interval edit is not a new starting point. Keep the
                    # last completed rotation and the pause/last result; the
                    # due clock recalculates from the new length.
                    state = store.set_auto_rotation_interval(name, body.every_days)
                else:
                    manual = auto_rotation.manual_or_unproven_targets(
                        manifest.credentials[name]
                    )
                    if manual and not body.accept_manual:
                        raise HTTPException(
                            status_code=400,
                            detail=(
                                "this credential has copies that need manual rotation "
                                f"({', '.join(sorted(manual))}); confirm them before "
                                "enabling auto-rotation"
                            ),
                        )
                    # Enabling is not a resume. A disabled row can still hide a
                    # run from before the disable, so this is checked from off
                    # as well as from paused.
                    open_attempts = journal.open_attempts()
                    unfinished = {step.credential for step in journal.unfinished()}
                    if name in open_attempts:
                        raise HTTPException(
                            status_code=409,
                            detail=f"resolve the unfinished rotation (attempt "
                            f"{open_attempts[name]}) by running a rotation for {name} "
                            "before enabling auto-rotation",
                        )
                    if name in unfinished:
                        raise HTTPException(
                            status_code=409,
                            detail="resolve the unfinished rotation (resume) "
                            "before enabling auto-rotation",
                        )
                    state = store.enable_auto_rotation(name, body.every_days)
            else:
                state = store.disable_auto_rotation(name)
            # A new policy may already be due, and a disable removes the next
            # due time; either way the scheduler's wait is stale.
            loop.wake()
            return {"auto_rotation": _auto_json(state, journal.last_rotation(name))}

    @authed.put("/credentials/{name}/value")
    def set_value(
        name: str, body: ValueBody, actor: str = Depends(_actor)
    ) -> dict[str, bool]:
        """The paste path: store the app's working copy of a value.

        Write-only by design - the value never comes back to a browser, and it
        is wrapped in `Secret` on the way in so it cannot be interpolated into
        a message. Storing one is not a rotation; the engine learns nothing
        until the next audit compares the stack against this copy.

        The credential's rotation lock serialises this write with a rotation.
        A paste during a run would replace the canonical that run is about to
        record over, so it is refused until the run finishes.
        """
        try:
            with stack_write(actor), facade.journal_for(config).lock(name, actor):
                store.set_value(name, Secret(body.value))
        except JournalLocked as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        except UnknownCredential:
            raise HTTPException(status_code=404, detail=f"no credential named {name}") from None
        return {"ok": True}

    def rotation_parts(
        name: str, *, take_over: bool = False, provided: str | None = None
    ) -> tuple[
        Credential, HostConfig, RotationPlan, list[str], int,
        dict[str, Secret], dict[str, Secret],
    ]:
        """The plan and everything checkable, without changing anything.

        The plan endpoint and the start of a run are the same call: the server
        re-plans here rather than trusting a plan the browser read back, so a
        stale or edited plan cannot decide what gets written. A refused plan
        mints nothing, so preflight is skipped for it - it would only ask
        services to answer for a run that cannot happen.

        The exit code travels with the parts because it is not always derivable
        from them: a preflight that fails *before* it can report problems
        (a missing URL or stored key) carries the failing error's own code,
        which is the code `rotate --dry-run` returns.
        """
        try:
            manifest = rotation_manifest(store, name)
        except UnknownCredential:
            raise HTTPException(
                status_code=404, detail=f"no credential named {name}"
            ) from None
        service_keys = stored_service_keys(store, manifest)
        effective = runtime_config(config, store)
        credential, host, plan = facade.plan_rotation_for(effective, manifest, name)
        mint_values = stored_mint_values(store, manifest, credential)
        if plan.blocked_by:
            return (credential, host, plan, [], ExitCode.REFUSED, service_keys,
                    mint_values)
        try:
            problems = facade.preflight(
                plan=plan,
                credential=credential,
                host=host,
                journal=facade.journal_for(config),
                canonical=store.get_value(name),
                take_over=take_over,
                service_keys=service_keys,
                pending=StorePending(store),
                mint_values=mint_values,
                provided=Secret(provided) if provided else None,
            )
        except CredctlError as exc:
            # Preflight reports unreachable services as its own problems; a host
            # that cannot even name one, or a missing stored key, fails before
            # it can report at all. Keep the error's own exit code, so this
            # answer and `rotate --dry-run` name the same failure the same way
            # (3 for a missing URL or key).
            return (credential, host, plan, [str(exc)], exc.exit_code,
                    service_keys, mint_values)
        return (
            credential,
            host,
            plan,
            problems,
            ExitCode.CONFIG if problems else ExitCode.OK,
            service_keys,
            mint_values,
        )

    # The auto worker must use exactly the same plan and preflight path as the
    # HTTP route; wiring it after this function exists avoids a second copy.
    auto.prepare = rotation_parts

    def plan_payload(name: str, *, take_over: bool = False) -> dict[str, Any]:
        credential, host, plan, problems, code, _service_keys, _mint_values = (
            rotation_parts(name, take_over=take_over)
        )
        return {
            **report.rotation_json(credential, host, plan, problems),
            "exit_code": int(code),
            "run": None,
        }

    @authed.post("/credentials/{name}/plan")
    def plan_rotation(name: str, body: PlanBody | None = None) -> dict[str, Any]:
        """The dry run, in the CLI's own document.

        Read-only: planning and preflight change no credential or config. A
        declared UI credential may create a transient service session while
        checking the backup download route; that is an authentication check
        and leaves no credential or config change. `exit_code` is the
        code `rotate --dry-run` would return for the same answer - 0 ready,
        3 preflight failed, 5 refused, or the failing error's own code when
        preflight raises before it can report (4 unreachable / unreadable,
        1 cannot be attempted) - so the console names the same state a job
        would act on.

        `take_over` answers this credential's unfinished steps the way
        `rotate --take-over` does: the plan is read as the run that continues
        from the service's state, so its own interrupted steps are not a
        problem. The steps are closed when the run starts, never here.
        """
        return plan_payload(name, take_over=body.take_over if body else False)

    @authed.get("/credentials/{name}/rotation-options")
    def rotation_options(name: str) -> dict[str, Any]:
        """What this key's service can do, read-only.

        The console uses this to recommend backup & restore without showing a
        method picker, and to explain the fallback only when the backup route
        is unavailable. It runs the same probes as the plan for all Servarr
        paths; nothing here changes a credential or a service. A key must be
        stored first because every check authenticates with it.
        """
        try:
            manifest = rotation_manifest(store, name)
        except UnknownCredential:
            raise HTTPException(
                status_code=404, detail=f"no credential named {name}"
            ) from None
        canonical = store.get_value(name)
        if canonical is None:
            raise HTTPException(
                status_code=409,
                detail="store the key first; rotation options need it to read "
                "the service",
            )
        effective = runtime_config(config, store)
        try:
            credential, host, _plan = facade.plan_rotation_for(
                effective, manifest, name
            )
            return facade.rotation_options(
                credential=credential,
                host=host,
                journal=facade.journal_for(config),
                canonical=canonical,
                service_keys=stored_service_keys(store, manifest),
                pending=StorePending(store),
                mint_values=stored_mint_values(store, manifest, credential),
            )
        except CredctlError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None

    @authed.post("/credentials/{name}/rotate")
    def rotate(
        name: str, body: RotateBody, actor: str = Depends(_actor)
    ) -> dict[str, Any]:
        """Perform the rotation, after the operator types its name.

        The typed name is checked here because the server, not the form, is the
        trust boundary. Everything after it is the CLI's apply path: preflight,
        execute, and the same exit code. A refusal or a failed preflight returns
        its reasons with `run: null` and changes nothing.
        """
        if body.confirm.strip() != name:
            raise HTTPException(
                status_code=400,
                detail="not confirmed: type the credential's name to proceed",
            )
        provided = (body.manual_value or "").strip() or None
        if body.manual_value is not None and provided is None:
            raise HTTPException(
                status_code=400,
                detail="the manual key is empty; nothing has been changed",
            )
        if provided is not None and len(provided) > 4096:
            raise HTTPException(
                status_code=400,
                detail="the supplied key is unexpectedly long; nothing has "
                "been changed",
            )

        def record_attempt(kind: str, detail: str) -> None:
            """Best-effort, and scrubbed: the events table and the sinks must
            never carry a value.

            The executor scrubs a failed step's sentence at the one place every
            failure passes through, but a preflight problem is built outside
            that boundary (`problems.append(str(exc))`), and this record is a
            new egress path for it. Scrubbing here covers both.

            Best-effort because the journal already holds the run and a
            refusal's reasons are in the response either way; a broken events
            table surfaces through the loops' health, not by telling the
            operator a completed rotation failed (which invites a second mint).
            """
            with contextlib.suppress(Exception):
                log.record_rotation_event(
                    kind,
                    name,
                    scrub(
                        detail, store.get_value(name), provided
                    ),
                )

        with stack_write(actor):
            credential, host, plan, problems, code, service_keys, mint_values = (
                rotation_parts(
                    name, take_over=body.take_over, provided=provided
                )
            )
            manual = plan.mint_via == "provided"
            if provided is not None and not manual:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "this rotation does not use a manual mint; the supplied key "
                        "was not used"
                    ),
                )
            if manual and provided is None and store.get_pending(name) is None:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "the manual mint needs the key you rotated in the service's "
                        "own UI; nothing has been changed"
                    ),
                )
            if plan.blocked_by or problems:
                record_attempt(
                    "rotation_refused" if plan.blocked_by else "rotation_failed",
                    "; ".join(plan.blocked_by or problems),
                )
                return {
                    **report.rotation_json(credential, host, plan, problems),
                    "exit_code": int(code),
                    "run": None,
                }
            try:
                result = facade.execute(
                    plan=plan,
                    credential=credential,
                    host=host,
                    secrets=StoreSource(store),
                    journal=facade.journal_for(config),
                    canonical=None,
                    canonical_getter=lambda: store.get_value(name),
                    actor=actor,
                    take_over=body.take_over,
                    service_keys=service_keys,
                    pending=StorePending(store),
                    mint_values=mint_values,
                    provided=Secret(provided) if provided else None,
                )
            except JournalLocked as exc:
                # Another run holds the credential lease. The stack lease is
                # already held above, so this names the real conflict.
                raise HTTPException(status_code=409, detail=str(exc)) from None
            exit_code = int(facade.execution_exit_code(result))
            if exit_code == 0:
                names = _holder_names(
                    holder.target for holder in result.holders
                )
                record_attempt(
                    "rotation_succeeded",
                    f"completed in {', '.join(names)}" if names else "completed",
                )
            else:
                # A clean mint can still exit 1 because a declared manual copy
                # remains. That is a success with a follow-up, not a failure;
                # an actual failed/unreached/unconfirmed holder keeps the
                # failure classification.
                manual_only = (
                    not result.failed
                    and result.manual
                    and not any(
                        holder.outcome in ("failed", "not-reached", "written")
                        for holder in result.holders
                    )
                )
                record_attempt(
                    "rotation_manual" if manual_only else "rotation_failed",
                    _rotation_detail(result),
                )
            return {
                **report.rotation_json(credential, host, plan),
                "exit_code": exit_code,
                "run": report.execution_json(result),
            }

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
            summary = store.import_model(manifest, mode=mode, prune=prune)
            loop.wake()
            return {
                "ok": True,
                **asdict(summary),
                "warnings": _import_warnings(manifest),
            }

    # -- notification services -----------------------------------------------
    #
    # One named-services surface: two Discord webhooks can have different
    # audiences, and each row owns its enable switch, event-kind selection and
    # delivery stats.

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
        if "enabled_types" in fields:
            # `null` clears like `[]` does: the list reads same as the strings,
            # omitted keeps, an explicit clear means "every kind".
            enabled_types = tuple(body.enabled_types or ())
        elif stored is not None:
            enabled_types = stored.enabled_types
        else:
            enabled_types = ()
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

    app.include_router(public)
    app.include_router(authed)


def _check_json(check: CredentialResult) -> dict[str, Any]:
    """One scoped result for the app page. No values and no fingerprints."""
    return {
        "name": check.credential.name,
        "status": check.status.value,
        "detail": check.detail,
        "reason": check.reason,
        "consumers": [
            {
                "target": str(consumer.consumer.target),
                "status": consumer.status.value,
                "detail": consumer.detail,
                "reason": consumer.reason,
                "observed_count": consumer.observed_count,
            }
            for consumer in check.consumers
        ],
    }


def _run_json(run: AuditRun) -> dict[str, Any]:
    return {
        "id": run.id,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "exit_code": run.exit_code,
        "exit_status": run.exit_status.value if run.exit_status is not None else None,
        "detail": run.detail,
    }


def _rotation_detail(result: Any) -> str:
    """Why a finished rotation is not clean, in the engine's own words.

    The shapes `execution_exit_code` gives 1 for: a step that failed (the
    engine's scrubbed sentence, hint included), a failed/unreached holder,
    holders that were written but never confirmed, or manual steps the build
    could not perform. A real failure outranks a remaining manual step so the
    row never hides the reason the stack is inconsistent. The summary is the
    fallback for a shape this build cannot name.

    Holder targets are mapped to plain service names and deduped: the operator
    reads which services were touched, and the target stubs stay in the run's
    own holder list.
    """
    if result.failed:
        return result.detail
    broken = _holder_names(
        holder.target
        for holder in result.holders
        if holder.outcome in ("failed", "not-reached")
    )
    if broken:
        return "failed: " + ", ".join(broken)
    unconfirmed = _holder_names(
        holder.target for holder in result.holders if holder.outcome == "written"
    )
    if unconfirmed:
        return "not confirmed: " + ", ".join(unconfirmed)
    if result.manual:
        return "manual steps outstanding: " + ", ".join(
            _holder_names(result.manual)
        )
    return "not confirmed: " + (result.summary() or "a holder was never confirmed")


# Target systems whose plain name is not title case. Everything else is
# title-cased, so a new service does not need a line here to read correctly.
_SERVICE_LABELS = {"qbittorrent": "qBittorrent", "qui": "qui"}


def _holder_names(targets: Iterable[str]) -> list[str]:
    """Plain service names for holder targets, in order, without repeats."""
    names: list[str] = []
    for target in targets:
        system = str(target).split(".", 1)[0]
        name = _SERVICE_LABELS.get(system, system.title())
        if name not in names:
            names.append(name)
    return names


def _auto_json(state: AutoRotation | None, last_rotation: float | None) -> dict[str, Any]:
    """The policy as the console reads it. No secret exists in this row."""
    if state is None:
        return {
            "enabled": False,
            "every_days": None,
            "next_due_at": None,
            "last_check_at": None,
            "last_outcome": None,
            "last_detail": "",
            "paused": False,
        }
    return {
        "enabled": state.enabled,
        "every_days": state.every_days,
        "next_due_at": auto_rotation.next_due_at(state, last_rotation),
        "last_check_at": state.last_check_at,
        "last_outcome": state.last_outcome,
        "last_detail": state.last_detail,
        "paused": state.paused,
    }


def _credential_json(
    credential: Credential,
    stored_at: float | None,
    observed: CredentialState | None,
    observed_at: float | None,
    auto_rotation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """One credential as the console reads it: declared, stored, observed.

    A recorded status is only shown while it is about the state declared now.
    Three ways it stops being:

    - the value moved. A run that finished before the last paste measured a
      different canonical, so `stored_at` after `observed_at` voids every
      status (`stored` stays true - the app does hold a value).
    - `provisioned` moved. ABSENT is the run's word for an unprovisioned
      credential; any other recorded status is a word about a provisioned one.
      Either stops applying when the flag no longer agrees.
    - the holders changed. A holder shows the status the run recorded for
      *that holder at that position*, and the credential only when the run
      audited holders and they are exactly the ones declared now - same count,
      same targets, same order. A declared credential with holders that the
      run never measured (no value stored, or not provisioned) still gets the
      run's own finding: that is a real result, not "not audited yet". A
      credential that declares no holders has no aggregate to show either way.

    shortcut: the ledger records each holder's target and position, not its
    host, mechanism or count, so an edit to only those keeps the previous run's
    score, and a paste that lands inside the run's own evaluation window is
    treated as measured by it. Recording the canonical read time and the full
    holder shape per run is a ledger column plus a migration; it lands if a
    view ever needs the distinction (DECISIONS names it).
    """
    audited = list(observed.consumers) if observed is not None else []
    declared = [str(consumer.target) for consumer in credential.consumers]
    matches: list[ConsumerState | None] = []
    for index, target in enumerate(declared):
        found = audited[index] if index < len(audited) else None
        matches.append(found if found is not None and found.target == target else None)
    provisioning_matches = observed is not None and (
        (observed.status is Status.ABSENT) == (not credential.provisioned)
    )
    current = (
        observed is not None
        and observed_at is not None
        and provisioning_matches
        and (stored_at is None or stored_at <= observed_at)
    )
    whole_shape = (
        current and bool(audited) and len(audited) == len(declared) and all(matches)
    )
    # A run can finish before it reaches a holder: no value is stored, the
    # credential is not provisioned, or its canonical could not be read. With
    # holders declared, that finding is about this credential and the status
    # column should show it. INDIRECT is not in this set: it means the run had
    # no holders at all, so it lends nothing to a holder set declared now.
    ran_out = (
        current
        and bool(declared)
        and not audited
        and observed is not None
        and observed.status in (Status.UNVERIFIABLE, Status.ABSENT, Status.ERROR)
    )
    reported = whole_shape or ran_out
    detail = observed.detail if reported and observed is not None else None
    reason = observed.reason if reported and observed is not None else None
    if (
        reported
        and not audited
        and observed is not None
        and observed.status is Status.UNVERIFIABLE
        and stored_at is None
    ):
        detail = "no value stored yet"
        reason = "value_missing"
    vault = credential.vault
    return {
        "name": credential.name,
        "description": credential.description,
        "class": credential.credential_class,
        "max_age_days": credential.max_age_days,
        "never_rotate": credential.never_rotate,
        "provisioned": credential.provisioned,
        "canonical": dict(credential.canonical),
        "write": dict(credential.write),
        "stored": stored_at is not None,
        "vault": (
            {"backend": vault.backend, "file": vault.file, "path": list(vault.path)}
            if vault is not None
            else None
        ),
        "status": observed.status.value if reported else None,
        "detail": detail,
        "reason": reason,
        "auto_rotation": auto_rotation or _auto_json(None, None),
        "consumers": [
            _consumer_json(consumer, matches[index] if current else None)
            for index, consumer in enumerate(credential.consumers)
        ],
    }


def _consumer_json(consumer: Consumer, observed: ConsumerState | None) -> dict[str, Any]:
    """One holder: declared shape, whether this build can write it, the finding.

    `managed` is `provenance.managed`'s answer - the display gate, never a
    rotation decision - and `holder` plus `provenance` are its ingredients, so
    the console can say why a holder is monitor-only instead of just wearing
    the badge.
    """
    target = consumer.target
    holder = holder_for(target.system, target.slot)
    return {
        "target": str(target),
        "count": consumer.count,
        # What the holder's API listed in the audited run, when it could be
        # counted. Next to the declaration so a console can offer to set
        # `count` to the live number instead of asking for a hand count; None
        # means the run could not count it, not "no rows".
        "observed_count": observed.observed_count if observed else None,
        "mechanism": consumer.mechanism,
        "host": consumer.host,
        "note": consumer.note,
        "holder": holder is not None,
        "manual": consumer.indirect or holder is None,
        "exercised": (
            not consumer.indirect
            and holder is not None
            and bool(holder.test_path or holder.readback)
        ),
        "managed": provenance.managed(target.system, target.slot),
        "version": provenance.measured_version(target.system),
        "provenance": provenance.provenance_text(target.system),
        "status": observed.status.value if observed else None,
        "detail": observed.detail if observed else None,
        "reason": observed.reason if observed else None,
    }


def _check_local_filesystem(settings: ServerSettings, config: Config) -> None:
    """Refuse `/config` or the journal on a network filesystem (decision 8).

    The refusal is the safe direction: the failure it prevents is a rotation
    lock that voids silently, while a wrong refusal is a message and a moved
    directory. `CREDARR_ALLOW_NETWORK_CONFIG=1` is the documented way to read
    the warning and accept the risk.
    """
    # The journal is `<manifest dir>/state/rotation.db`. Checking the journal's
    # own directory, not just the manifest's, is what catches a mount placed
    # exactly at `state/` - the one place the lock would then void.
    for path, what in (
        (settings.config_dir, "the data directory"),
        (facade.journal_for(config).path.parent, "the rotation journal"),
    ):
        mount = mounts.network_mount(path)
        if mount is None:
            continue
        finding = f"{what} {path} is on {mount.fstype} (mounted at {mount.point})"
        if not settings.allow_network_config:
            raise CredctlError(
                f"{finding}: SQLite's locks and WAL need a local filesystem",
                hint="move it to a local disk, or set CREDARR_ALLOW_NETWORK_CONFIG=1 "
                "to accept the documented risk",
            )
        print(
            f"warning: {finding}; SQLite's locks and WAL are not guaranteed there",
            file=sys.stderr,
        )


def _run_once(settings: ServerSettings, *, as_json: bool) -> int:
    """One audit of the app's own store, for cron: the CLI's verdict and code.

    The store is `app.db`, not a manifest file: the console is where the
    topology lives, and a cron run reading a stale YAML would audit a different
    stack from the one the operator edited. Notifications are sent once too, so
    a deployment that only has cron is still a monitor; a delivery problem is a
    warning, never the audit's exit code.
    """
    config = load_config(settings.config_path)
    _check_local_filesystem(settings, config)
    store = TopologyStore(settings.database)
    if not store.load_manifest().credentials:
        # The console refuses to audit an unimported store and says why; a cron
        # run that recorded "0 credentials matched" would be the same lie with
        # no view to correct it.
        print(
            "error: no topology has been imported: nothing was checked",
            file=sys.stderr,
        )
        return ExitCode.CONFIG
    log = AuditLog(settings.database)
    result = Scheduler(store, log, config, interval=settings.audit_interval).once()
    try:
        Notifier(settings.database).tick()
    except (OSError, sqlite3.Error) as exc:
        print(f"warning: the notifications did not run: {exc}", file=sys.stderr)
    if result is None:
        state = log.last_state()
        run = state.last_run if state is not None else None
        detail = run.detail if run is not None and run.detail else "nothing was recorded"
        print(f"the audit did not complete: {detail}", file=sys.stderr)
        if run is not None and run.exit_code is not None:
            return int(run.exit_code)
        return ExitCode.CONFIG
    if as_json:
        report.render_json(result, sys.stdout)
    else:
        report.render_human(result, sys.stdout, colour=None)
    return report.exit_code_for(result)


BOOTSTRAP_CONFIG = """\
# Created by credarr on first boot. The console writes deployment facts and
# keys into /config/app.db; this file only supplies the host name and where a
# CLI manifest would live. Edit it if you deploy the CLI beside the server.
version: 1
default_host: local
manifest: credentials.yaml
hosts:
  local:
    urls: {}
"""

BOOTSTRAP_MANIFEST = """\
# Created by credarr on first boot. The console's topology lives in app.db;
# this file is the empty starting point a CLI run or export can use.
version: 1
credentials: {}
"""


def _write_new_file(path: Path, text: str, *, mode: int) -> bool:
    """Create `path` once, atomically, and never replace an existing file."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ConfigError(
            f"cannot create {path.parent}: {exc.strerror}",
            hint="credarr needs a writable directory for its first-run config",
        ) from None
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError:
        return False
    except OSError as exc:
        raise ConfigError(
            f"cannot create {path}: {exc.strerror}",
            hint="credarr needs to write its first-run config here; make the "
            "directory writable or pass -c/--config at a writable path",
        ) from None
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    return True


def _bootstrap_config(settings: ServerSettings) -> None:
    """Create the minimal config a first-run console needs, once.

    The server audits the store, not a manifest file, so this is the only file
    it cannot start without. The empty manifest is written beside it so a CLI
    run or export has the path the config names; an existing file is never
    replaced, and an existing config is never rewritten (a typo must still be
    an error, not silently repaired).
    """
    path = settings.config_path
    if path.exists():
        return
    if not settings.allow_network_config:
        # Do not create anything on a mount the server is about to refuse.
        for candidate, what in (
            (settings.config_dir, "the data directory"),
            (path.parent, "the config and journal directory"),
        ):
            mount = mounts.network_mount(candidate)
            if mount is None:
                continue
            raise CredctlError(
                f"{what} {candidate} is on {mount.fstype} "
                f"(mounted at {mount.point}): SQLite's locks and WAL need a "
                "local filesystem",
                hint="move it to a local disk, or set CREDARR_ALLOW_NETWORK_CONFIG=1 "
                "to accept the documented risk",
            )
    manifest = path.parent / "credentials.yaml"
    if not manifest.exists():
        _write_new_file(manifest, BOOTSTRAP_MANIFEST, mode=0o600)
    if _write_new_file(path, BOOTSTRAP_CONFIG, mode=0o600):
        print(
            f"bootstrapped a first-run config at {path}; edit it if you need "
            "predeclared service URLs",
            file=sys.stderr,
        )


def create_app(settings: ServerSettings) -> FastAPI:
    """The application, wired over `settings.config_path` and `settings.database`."""
    _bootstrap_config(settings)
    config = load_config(settings.config_path)
    _check_local_filesystem(settings, config)
    store = TopologyStore(settings.database)
    _seed_services(store, config, store.load_manifest())
    auth = AdminAuth(settings.database)
    log = AuditLog(settings.database)
    audit_jobs = AuditJobs()
    # One registry for the process: the audit, the topology import and the
    # holder/version answers must agree about what this build knows.
    registry = build_registry()
    journal = facade.journal_for(config)
    persisted_interval = store.audit_interval()
    initial_interval = (
        persisted_interval
        if persisted_interval is not None
        and MIN_AUDIT_INTERVAL_SECONDS
        <= persisted_interval
        <= MAX_AUDIT_INTERVAL_SECONDS
        else settings.audit_interval
    )
    persisted_enabled = store.audit_enabled()
    initial_enabled = True if persisted_enabled is None else persisted_enabled
    auto = auto_rotation.AutoRotator(
        store, config, log, journal, interval=initial_interval
    )
    loop = AuditLoop(
        Scheduler(
            store,
            log,
            config,
            interval=initial_interval,
            enabled=initial_enabled,
            registry=registry,
            on_audit=auto.notify,
            next_due=auto.next_due,
            has_due=auto.has_due,
        ),
        auto,
    )
    # The notifier reads what the audit writes, so it is built after the log and
    # shares the database with it: an event and its delivery state must not be
    # able to disagree across a restart.
    notifier = Notifier(settings.database)
    delivery = DeliveryLoop(notifier)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> Iterator[None]:
        loop.start()
        delivery.start()
        try:
            yield
        finally:
            loop.stop()
            delivery.stop()

    app = FastAPI(title="credarr", version=__version__, lifespan=lifespan)

    @app.exception_handler(RequestValidationError)
    async def validation_error(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Answer a bad request without echoing the rejected value."""
        return JSONResponse(status_code=422, content={"detail": _validation_details(exc)})

    app.state.settings = settings
    app.state.store = store
    app.state.auth = auth
    app.state.audit_log = log
    app.state.audit_jobs = audit_jobs
    app.state.loop = loop
    app.state.auto = auto
    app.state.notifier = notifier
    app.state.delivery = delivery
    app.state.config = config

    @app.middleware("http")
    async def no_store(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Nothing under `/api/v1` is cacheable, and nothing may be framed.

        Authenticated payloads behind a shared cache would be replayable to an
        unauthenticated caller, and health answers must not be served stale.
        The framing ban covers the console as well: a live admin session is
        clickjacking-capable, so one policy is applied to every response.
        """
        response = await call_next(request)
        if request.url.path.startswith("/api/v1"):
            response.headers["Cache-Control"] = "no-store"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
        return response

    _mount(app)
    if (settings.web_dir / "index.html").is_file():
        # The console, served at "/" and nowhere else: no client-side routes
        # exist, so there is no history fallback. Mounted *after* the API, so
        # /api/v1 and the framework's docs pages answer first. A deployment
        # without a build is an API-only deployment, not a broken one - hence
        # the check rather than a hard failure.
        app.mount("/", StaticFiles(directory=settings.web_dir, html=True), name="console")
    return app


def _configured_timezone() -> str:
    """The console's display zone, validated once at boot.

    TZ is the operator-facing knob and the same value the container clock uses.
    An invalid or unset value falls back to UTC; the browser must never receive
    a name Intl will reject.
    """
    name = (os.environ.get("TZ") or "UTC").strip()
    try:
        zoneinfo.ZoneInfo(name)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        return "UTC"
    return name


def _positive_seconds(value: str) -> float:
    """Usage, exit 2 - for anything that would spin the loop.

    That is not only zero and negatives: `Event.wait(nan)` returns
    immediately (a non-blocking acquire), so a `nan` interval would audit
    back-to-back while `/health` stayed green.
    """
    seconds = float(value)
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError("the audit interval must be a positive, finite number")
    return seconds


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="credarr-server",
        description="credarr's BFF: the audit loop and the HTTP API.",
    )
    parser.add_argument(
        "-c", "--config", type=Path, default=Path("credarr.yaml"),
        help="engine configuration file (default: credarr.yaml)",
    )
    parser.add_argument(
        "--config-dir", type=Path,
        default=Path(os.environ.get("CREDARR_CONFIG_DIR", DEFAULT_CONFIG_DIR)),
        help="directory holding app.db (default: /config, env CREDARR_CONFIG_DIR)",
    )
    parser.add_argument(
        "--host", default=os.environ.get("CREDARR_HOST", DEFAULT_HOST),
        help="address to bind (env CREDARR_HOST)",
    )
    parser.add_argument(
        "--port", type=int, default=os.environ.get("CREDARR_PORT", "8080"),
        help="port to bind (env CREDARR_PORT)",
    )
    parser.add_argument(
        "--audit-interval", type=_positive_seconds, metavar="SECONDS",
        default=os.environ.get("CREDARR_AUDIT_INTERVAL", "3600"),
        help="seconds between audits (env CREDARR_AUDIT_INTERVAL, default 3600)",
    )
    parser.add_argument(
        "--secure-cookies", action="store_true",
        help="set the Secure cookie flag: use when serving over HTTPS",
    )
    parser.add_argument(
        "--once", action="store_true",
        help="audit the app's store once, print the run and exit (for cron; no HTTP)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="with --once: print the run as JSON, the CLI's document",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    # Before config or secrets are read: a crash must not leave a core file with
    # the working copies this process handles.
    disable_core_dumps()
    parser = _parser()
    args = parser.parse_args(argv)
    if args.json and not args.once:
        parser.error("--json is only for --once")
    if os.environ.get("CREDARR_RESTART_URL"):
        print(
            "error: CREDARR_RESTART_URL is gone; credarr now asks each service "
            "to restart itself over its own API - remove the variable",
            file=sys.stderr,
        )
        return int(ExitCode.CONFIG)
    settings = ServerSettings(
        config_path=args.config.resolve(),
        config_dir=args.config_dir,
        host=args.host,
        port=args.port,
        audit_interval=args.audit_interval,
        secure_cookies=args.secure_cookies,
        allow_network_config=os.environ.get("CREDARR_ALLOW_NETWORK_CONFIG") == "1",
        docker_url=os.environ.get("CREDARR_DOCKER_URL") or None,
        timezone=_configured_timezone(),
    )
    try:
        # One server per config directory. The lock is held across the whole
        # process lifetime (or the one-shot command) and released by the kernel
        # if this process dies, so a stale app.lock never blocks a restart.
        with InstanceLock(settings.config_dir):
            if args.once:
                return _run_once(settings, as_json=args.json)
            app = create_app(settings)
            import uvicorn

            try:
                uvicorn.run(app, host=settings.host, port=settings.port)
            except OSError as exc:
                # A bind/serve failure is not the config directory's fault;
                # report it as such instead of the setup handler below.
                print(f"error: the server could not run: {exc}", file=sys.stderr)
                return int(ExitCode.CONFIG)
        return 0
    except CredctlError as exc:
        # Same contract as the CLI: a misconfiguration is exit 3 with the
        # engine's own message, not a traceback.
        print(exc.render(), file=sys.stderr)
        return int(exc.exit_code)
    except (OSError, sqlite3.Error) as exc:
        # An unusable data directory - missing, read-only, not a directory, a
        # corrupt database - is configuration too, and the most likely thing an
        # operator gets wrong. The message names the path they passed.
        error = CredctlError(f"{settings.config_dir}: {exc}")
        print(error.render(), file=sys.stderr)
        return int(error.exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
