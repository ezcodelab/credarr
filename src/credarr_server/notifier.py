"""Notifications: what changed, delivered once, out of the machine.

The ledger already records what each audit found; this turns a *change* into
something the operator hears about, and nothing else. An event carries
credential and holder names and statuses - never a value, never a fingerprint -
because it leaves the host. Delivery state lives in the database rather than in
the sender's memory: an event is pending until a sink accepted it, a retry picks
up where the last attempt left off, and a restart does not forget either.

Services, not one sink per kind: `notification_services` holds named rows, so
there can be two Discord webhooks with different audiences, a service can be
disabled without deleting it, each service chooses which event kinds it hears,
and its success/failure counts are derived from `event_deliveries`. A service
is its kind (ntfy, webhook, Discord, Telegram) plus the fields that kind uses:
ntfy a server, topic and optional access token; webhook a URL, an optional HMAC
signing secret and an optional raw `Authorization` header; Discord a webhook
URL plus optional bot username, avatar and `@here`; Telegram an API base, bot
token and chat id. Secrets are write-only in the API: the read path says
whether one is set, never what it is. A Discord webhook URL is itself a
capability and is shown only to the authenticated admin, like an ntfy topic.

Delivery is at-most-once while the process lives - one row per (event, service),
written after the service answers, and one tick at a time under a lock. It can
repeat once if the process dies between the service reading the request and this
row being written, which is the safe direction for a monitor: a duplicate
status is better than a missed one. A webhook body is HMAC-SHA256 signed with
the service's secret and the digest travels in `X-Credarr-Signature`, so a
receiver can prove the sender without the secret crossing the wire.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import re
import smtplib
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formataddr, formatdate, getaddresses
from pathlib import Path
from typing import Any

from .audit_log import Event, event_from_row
from .store import connect, initialise

# The kinds this build knows. A name, not a plugin system. Discord and Telegram
# reuse the same row shape: Discord's webhook URL is the destination, Telegram's
# bot token and chat id sit in the token/topic columns. Email uses the SMTP
# columns; its password is the shared write-only token column.
SINKS = ("ntfy", "webhook", "discord", "telegram", "email")

SMTP_TLS_MODES = ("none", "starttls", "ssl")
SMTP_AUTH_MODES = ("none", "auto", "plain", "login", "crammd5")
SMTP_DEFAULT_PORT = 587

# The event kinds a service can subscribe to. Empty selection means all of them,
# which is what a freshly created service gets.
EVENT_KINDS = (
    "drift",
    "recovered",
    "unverifiable",
    "auto_started",
    "auto_succeeded",
    "auto_manual",
    "auto_blocked",
    "auto_interrupted",
    "rotation_failed",
    "rotation_manual",
    "rotation_succeeded",
    "test",
)

# Recorded for the Activity trail, never notified. A manual refusal is the
# planner's own "cannot rotate" answer to one explicit operator click, and the
# console already shows it in place; paging every service would be noise, and a
# stack that cannot rotate is not news the next audit will not repeat. A failed
# attempt (preflight or run) and a completed run do notify: they answer the
# click with something about the stack, and a sink is often the only second
# reader. The decision lives here, in the delivery path, not in the events
# table - which is why a refusal is not in EVENT_KINDS (a selection that can
# never fire would be a lie) and why `/events` marks it silent.
SILENT_KINDS = frozenset({"rotation_refused"})

# A Service Name is the operator's label and part of the API path, so it is
# bounded to characters that survive a URL and a log line.
_NAME_RE = re.compile(r"^[A-Za-z0-9 _.@-]{1,64}$")


def _clean_smtp_host(value: str | None) -> str:
    host = (value or "").strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if (
        not host
        or any(character.isspace() for character in host)
        or "://" in host
        or "/" in host
        or "@" in host
        or (":" in host and host.count(":") < 2)
    ):
        raise ValueError("email needs an SMTP host name, not a URL")
    return host


def _clean_mailbox(value: str | None, what: str) -> str:
    text = (value or "").strip()
    if not text or "\r" in text or "\n" in text:
        raise ValueError(f"{what} must be one email address")
    pairs = getaddresses([text])
    if len(pairs) != 1 or not pairs[0][1] or "@" not in pairs[0][1]:
        raise ValueError(f"{what} must be one email address")
    name, address = pairs[0]
    if any(ord(character) < 32 for character in name):
        raise ValueError(f"{what} contains an invalid display name")
    return formataddr((name.strip(), address.strip()))


def _clean_mailboxes(value: str | None) -> str:
    text = (value or "").strip()
    if not text:
        raise ValueError("email needs at least one recipient")
    if "\r" in text:
        raise ValueError("email recipients must not contain carriage returns")
    pairs = getaddresses(text.replace(";", "\n").splitlines())
    if not pairs or any(
        not address
        or "@" not in address
        or any(ord(character) < 32 for character in name)
        for name, address in pairs
    ):
        raise ValueError("email needs valid recipient addresses")
    return "\n".join(formataddr((name.strip(), address.strip())) for name, address in pairs)


def _envelope_address(value: str | None) -> str:
    pairs = getaddresses([(value or "").strip()])
    return pairs[0][1] if pairs else ""


def _envelope_addresses(value: str | None) -> list[str]:
    return [address for _, address in getaddresses((value or "").splitlines()) if address]

# Ten attempts, 30s doubling to an hour: a bit over three hours of trying
# before an event is marked failed. Long enough to outlast a service restart or
# a DNS hiccup, short enough that a permanently wrong URL does not retry
# forever.
MAX_ATTEMPTS = 10
BACKOFF_BASE_SECONDS = 30.0
BACKOFF_CAP_SECONDS = 3600.0

# One request must not pin a delivery tick. The audit loop is a different
# thread, but the console's test button runs a tick on the request's thread.
REQUEST_TIMEOUT_SECONDS = 10.0

# The delivery loop's own cadence. Not configurable: how often the audit runs
# is the operator's business, how often a queued notification is retried is not.
TICK_SECONDS = 30.0

SCHEMA = """
-- One row per notification service. `name` is the operator's Service Name;
-- `kind` is the mechanism; the columns a kind does not use stay NULL.
-- `enabled_types` is a comma-separated list of event kinds, empty for all.
-- `updated_at` is also the delivery floor: a service configured (or edited)
-- now does not replay the events recorded before it existed - saving a form
-- must not fire an hour of history at a freshly-pasted URL.
CREATE TABLE IF NOT EXISTS notification_services (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT    NOT NULL UNIQUE,
    kind             TEXT    NOT NULL,
    enabled          INTEGER NOT NULL DEFAULT 1,
    url              TEXT    NOT NULL,
    topic            TEXT,
    token            TEXT,
    secret           TEXT,
    auth_header      TEXT,
    discord_username TEXT,
    discord_avatar   TEXT,
    discord_here     INTEGER NOT NULL DEFAULT 0,
    smtp_host        TEXT,
    smtp_port        INTEGER,
    smtp_username    TEXT,
    smtp_from        TEXT,
    smtp_to          TEXT,
    smtp_tls         TEXT,
    smtp_auth        TEXT,
    enabled_types    TEXT    NOT NULL DEFAULT '',
    created_at       REAL    NOT NULL,
    updated_at       REAL    NOT NULL
);

-- What has been delivered where. `sink` is the service's name. No row means
-- queued; 'pending' means tried and waiting for the next attempt, 'delivered'
-- and 'failed' are terminal.
CREATE TABLE IF NOT EXISTS event_deliveries (
    event_id        INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    sink            TEXT    NOT NULL,
    state           TEXT    NOT NULL,
    attempts        INTEGER NOT NULL,
    next_attempt_at REAL,
    last_error      TEXT,
    delivered_at    REAL,
    PRIMARY KEY (event_id, sink)
);
"""


def _migrate_sinks(connection: Any) -> None:
    """Copy the one-sink-per-type rows into named services, once.

    The old names were the kinds, so a delivery row for `ntfy` stays attached
    to the service the migration names `ntfy`. The old table is dropped: one
    store, not two.
    """
    columns = {
        row[1] for row in connection.execute("PRAGMA table_info(notification_sinks)")
    }
    if not columns:
        return
    rows = connection.execute("SELECT * FROM notification_sinks").fetchall()
    for row in rows:
        connection.execute(
            "INSERT OR IGNORE INTO notification_services "
            "(name, kind, enabled, url, topic, token, secret, enabled_types, "
            " created_at, updated_at) "
            "VALUES (?, ?, 1, ?, ?, ?, ?, '', ?, ?)",
            (
                row["name"],
                row["name"],
                row["url"],
                row["topic"],
                row["token"],
                row["secret"],
                row["updated_at"],
                row["updated_at"],
            ),
        )
    connection.execute("DROP TABLE notification_sinks")


_EMAIL_COLUMNS = (
    ("smtp_host", "TEXT"),
    ("smtp_port", "INTEGER"),
    ("smtp_username", "TEXT"),
    ("smtp_from", "TEXT"),
    ("smtp_to", "TEXT"),
    ("smtp_tls", "TEXT"),
    ("smtp_auth", "TEXT"),
)


def _migrate_email_columns(connection: Any) -> None:
    """Add the SMTP columns to a database created before email support."""
    columns = {
        row[1] for row in connection.execute("PRAGMA table_info(notification_services)")
    }
    for name, kind in _EMAIL_COLUMNS:
        if name not in columns:
            connection.execute(
                f"ALTER TABLE notification_services ADD COLUMN {name} {kind}"
            )


@dataclass(frozen=True, slots=True)
class ServiceConfig:
    """One service as the sender needs it. Secrets included; never echoed."""

    id: int
    name: str
    kind: str
    enabled: bool
    url: str
    topic: str | None
    token: str | None = field(repr=False)
    secret: str | None = field(repr=False)
    auth_header: str | None = field(repr=False)
    discord_username: str | None
    discord_avatar: str | None
    discord_here: bool
    smtp_host: str | None
    smtp_port: int | None
    smtp_username: str | None
    smtp_from: str | None
    smtp_to: str | None
    smtp_tls: str
    smtp_auth: str
    enabled_types: tuple[str, ...]
    created_at: float
    updated_at: float

    def accepts(self, kind: str) -> bool:
        """Whether this service hears about an event kind.

        Empty selection means all. `test` is always accepted: it is written
        only by the Test button, whose whole job is proving this service can be
        reached, and filtering it out would turn a broken URL into a silent
        no-op.
        """
        return kind == "test" or not self.enabled_types or kind in self.enabled_types


@dataclass(frozen=True, slots=True)
class ServiceStats:
    """What the delivery rows say this service has done."""

    delivered: int
    failed: int
    pending: int


@dataclass(frozen=True, slots=True)
class ServiceView:
    """One service as the console may see it: the shape, not the secret."""

    id: int
    name: str
    kind: str
    enabled: bool
    url: str
    topic: str | None
    token_configured: bool
    secret_configured: bool
    auth_header_configured: bool
    discord_username: str | None
    discord_avatar: str | None
    discord_here: bool
    smtp_host: str | None
    smtp_port: int | None
    smtp_username: str | None
    smtp_from: str | None
    smtp_to: str | None
    smtp_tls: str
    smtp_auth: str
    enabled_types: tuple[str, ...]
    updated_at: float
    stats: ServiceStats


@dataclass(frozen=True, slots=True)
class Delivery:
    """One (event, sink) attempt history, as the Events view shows it."""

    sink: str
    state: str
    attempts: int
    next_attempt_at: float | None
    last_error: str | None
    delivered_at: float | None


def payload(event: Event) -> dict[str, Any]:
    """The webhook document: identities and statuses, and nothing else.

    The key set is the secrecy boundary, so it is a literal: a field added here
    is a field that leaves the machine, and a test pins the set. `id` is the
    idempotency key a receiver can deduplicate on.
    """
    return {
        "id": event.id,
        "at": event.at,
        "kind": event.kind,
        "credential": event.credential,
        "previous_status": event.previous_status.value if event.previous_status else None,
        "status": event.status.value if event.status else None,
        "detail": event.detail,
    }


def _title(event: Event) -> str:
    if event.kind == "test":
        return "credarr: test notification"
    if event.kind == "recovered":
        return f"credarr: {event.credential} recovered"
    if event.kind == "unverifiable":
        return f"credarr: {event.credential} cannot be verified"
    if event.kind == "rotation_manual":
        return f"credarr: {event.credential} rotated; manual steps remain"
    if event.kind == "auto_manual":
        return f"credarr: {event.credential} requires manual rotation"
    if event.kind.startswith("auto_"):
        return f"credarr: {event.credential} auto-rotation {event.kind.removeprefix('auto_')}"
    if event.kind.startswith("rotation_"):
        return (
            f"credarr: {event.credential} rotation "
            f"{event.kind.removeprefix('rotation_')}"
        )
    return f"credarr: {event.credential} drifted"


def _ntfy_body(event: Event) -> str:
    if event.kind == "test":
        return "If you can read this, the sink is configured and credarr can reach it."
    if event.kind.startswith(("auto_", "rotation_")):
        # Action events are actions, not equality transitions; a "? → ?" line
        # would invent a measurement the run never made.
        return event.detail
    was = event.previous_status.value if event.previous_status else "?"
    now = event.status.value if event.status else "?"
    return f"{was} → {now}\n{event.detail}"


def _message(event: Event, limit: int) -> str:
    """One chat message, cut to the sink's own limit without splitting a value.

    The event is already names, statuses and the audit's scrubbed sentence; the
    limit is a transport detail, not a reason to add a payload field.
    """
    text = f"{_title(event)}\n{_ntfy_body(event)}"
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


# ntfy's own scale: 4 is "high", 3 is "default". A recovery is worth knowing,
# not waking up for; a drift may be.
_PRIORITY = {"drift": "4", "unverifiable": "3", "recovered": "3", "test": "3"}


class RefusedURL(Exception):
    """A stored URL this sender will not open. The message names the scheme,
    never the URL."""


def _reason(exc: BaseException) -> str:
    """A sentence naming the failure, not the address.

    `str(HTTPError)` embeds the URL, and a sink's URL is capability-shaped (an
    ntfy topic is the topic's password). The parts that are safe to keep are
    the type, the status code and the underlying reason; anything else is
    reduced to its type, because `http.client.InvalidURL` has the same problem
    and the next exception's message is not something this function can know.

    SMTP failures are reduced the same way: a server response may echo a
    recipient address, and auth exceptions must never be allowed to carry the
    password into a delivery row.
    """
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "SMTP authentication failed"
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "SMTP refused one or more recipients"
    if isinstance(exc, smtplib.SMTPSenderRefused):
        return "SMTP refused the sender"
    if isinstance(exc, smtplib.SMTPDataError):
        return "SMTP refused the message"
    if isinstance(exc, smtplib.SMTPConnectError):
        return "SMTP connection failed"
    if isinstance(exc, smtplib.SMTPServerDisconnected):
        return "SMTP server disconnected"
    if isinstance(exc, smtplib.SMTPException):
        return "SMTP error"
    if isinstance(exc, ssl.SSLError):
        return "SMTP TLS failed"
    if isinstance(exc, TimeoutError):
        return "SMTP timed out"
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code} {exc.reason}"
    if isinstance(exc, urllib.error.URLError):
        return f"{type(exc.reason).__name__}: {exc.reason}"
    if isinstance(exc, RefusedURL):
        return str(exc)
    if isinstance(exc, OSError):
        return f"{type(exc).__name__}: {exc.strerror or 'connection failed'}"
    return type(exc).__name__


def _request(url: str, data: bytes, *, content_type: str | None = None) -> urllib.request.Request:
    """A POST request to a sink, refused unless it is http(s).

    The URL is stored state, so the scheme is checked here as well as at the API
    that wrote it: `urlopen` accepts a `file:` URL in some builds, and what it
    would then read is this machine's disk. The message names the scheme, never
    the URL, because the URL may carry a topic or a token.
    """
    scheme = urllib.parse.urlsplit(url).scheme
    if scheme not in ("http", "https"):
        raise RefusedURL(f"refusing to post to a {scheme or 'relative'} url")
    request = urllib.request.Request(url, data=data, method="POST")  # noqa: S310 - scheme checked above
    if content_type:
        request.add_header("Content-Type", content_type)
    return request


def _normalise_service(
    name: str,
    kind: str,
    *,
    url: str,
    topic: str | None,
    token: str | None,
    secret: str | None,
    auth_header: str | None,
    discord_username: str | None,
    discord_avatar: str | None,
    discord_here: bool,
    smtp_host: str | None,
    smtp_port: int | None,
    smtp_username: str | None,
    smtp_from: str | None,
    smtp_to: str | None,
    smtp_tls: str,
    smtp_auth: str,
    enabled_types: tuple[str, ...],
) -> dict[str, Any]:
    """Validate one service and return the values the row stores."""
    if kind not in SINKS:
        raise ValueError(f"unknown service type: {kind}")
    if not _NAME_RE.fullmatch(name):
        raise ValueError(
            "a service name is 1-64 characters of letters, digits, space, "
            "'_', '-', '.' or '@'"
        )
    if kind == "email":
        host = _clean_smtp_host(smtp_host)
        try:
            port = int(smtp_port or SMTP_DEFAULT_PORT)
        except (TypeError, ValueError):
            raise ValueError("email needs a valid SMTP port") from None
        if not 1 <= port <= 65535:
            raise ValueError("email needs a port between 1 and 65535")
        from_address = _clean_mailbox(smtp_from, "email needs a From address")
        recipients = _clean_mailboxes(smtp_to)
        tls = (smtp_tls or "starttls").strip().lower()
        auth = (smtp_auth or "auto").strip().lower()
        if tls not in SMTP_TLS_MODES:
            raise ValueError("email TLS must be none, starttls or ssl")
        if auth not in SMTP_AUTH_MODES:
            raise ValueError("email authentication is not a known mode")
        if auth != "none":
            if not (smtp_username or "").strip():
                raise ValueError("email authentication needs a username")
            if not (token or "").strip():
                raise ValueError("email authentication needs a password")
        url = f"smtp://{host}:{port}"
    else:
        if not url:
            raise ValueError(f"{name} needs a url")
        if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
            raise ValueError(f"{name}'s url must start with http:// or https://")
        host, port, from_address, recipients, tls, auth = (
            None, None, None, None, "starttls", "auto",
        )
    if kind == "ntfy" and not (topic or "").strip():
        raise ValueError("ntfy needs a topic")
    if kind == "telegram":
        if not (topic or "").strip():
            raise ValueError("telegram needs a chat id")
        if not (token or "").strip():
            raise ValueError("telegram needs a bot token")
    unknown = [item for item in enabled_types if item not in EVENT_KINDS]
    if unknown:
        raise ValueError(f"unknown notification type: {unknown[0]}")
    return {
        "url": url,
        "topic": (topic or "").strip() or None,
        "token": (token or "").strip() or None,
        "secret": (secret or "").strip() or None,
        "auth_header": (auth_header or "").strip() or None,
        "discord_username": (discord_username or "").strip() or None,
        "discord_avatar": (discord_avatar or "").strip() or None,
        "discord_here": 1 if discord_here else 0,
        "smtp_host": host,
        "smtp_port": port,
        "smtp_username": (smtp_username or "").strip() or None,
        "smtp_from": from_address,
        "smtp_to": recipients,
        "smtp_tls": tls,
        "smtp_auth": auth,
    }


class Notifier:
    """Service configuration, delivery state, and the two send paths."""

    def __init__(self, path: Path | str, *, timeout: float = REQUEST_TIMEOUT_SECONDS) -> None:
        self.path = Path(path)
        initialise(self.path, SCHEMA)
        with connect(self.path) as connection:
            _migrate_sinks(connection)
            _migrate_email_columns(connection)
        self.timeout = timeout
        # The delivery loop and the console's test button can both tick. Two
        # overlapping ticks are exactly the double delivery this class exists to
        # prevent, so a whole tick is one critical section.
        self._lock = threading.Lock()

    # -- configuration -------------------------------------------------------

    def services(self) -> dict[str, ServiceConfig]:
        """Every configured service, secrets included: the sender's view."""
        with connect(self.path) as connection:
            rows = connection.execute(
                "SELECT * FROM notification_services ORDER BY id"
            ).fetchall()
        return {row["name"]: _config(row) for row in rows}

    def service(self, name: str) -> ServiceConfig | None:
        return self.services().get(name)

    def stats(self) -> dict[str, ServiceStats]:
        """Per-service counters, derived from the delivery rows.

        Derived, not stored: a counter that drifts from the rows it summarises
        is a number nobody can trust, and the rows are the record. `pending`
        counts only rows the retry path can still reach: an edit moves the
        service's floor, which permanently drops older events, and a dropped
        row must not sit in the console as a queue that will never move.
        """
        with connect(self.path) as connection:
            if connection.execute(
                "SELECT 1 FROM event_deliveries LIMIT 1"
            ).fetchone() is None:
                # Nothing has ever been delivered, so there is nothing to
                # count - and the query below joins `events`, which an install
                # that has not audited yet does not have.
                return {}
            rows = connection.execute(
                "SELECT d.sink, "
                "SUM(CASE WHEN d.state = 'delivered' THEN 1 ELSE 0 END) AS delivered, "
                "SUM(CASE WHEN d.state = 'failed' THEN 1 ELSE 0 END) AS failed, "
                "SUM(CASE WHEN d.state = 'pending' AND e.at >= s.updated_at "
                "THEN 1 ELSE 0 END) AS pending "
                "FROM event_deliveries d "
                "JOIN events e ON e.id = d.event_id "
                "JOIN notification_services s ON s.name = d.sink "
                "GROUP BY d.sink"
            ).fetchall()
        return {
            row["sink"]: ServiceStats(
                int(row["delivered"] or 0),
                int(row["failed"] or 0),
                int(row["pending"] or 0),
            )
            for row in rows
        }

    def views(self) -> dict[str, ServiceView]:
        """Every configured service, secrets reduced to "is one set"."""
        counts = self.stats()
        empty = ServiceStats(0, 0, 0)
        return {
            name: _view(config, counts.get(name, empty))
            for name, config in self.services().items()
        }

    def save_service(
        self,
        name: str,
        kind: str,
        *,
        url: str,
        topic: str | None = None,
        token: str | None = None,
        secret: str | None = None,
        auth_header: str | None = None,
        discord_username: str | None = None,
        discord_avatar: str | None = None,
        discord_here: bool = False,
        smtp_host: str | None = None,
        smtp_port: int | None = None,
        smtp_username: str | None = None,
        smtp_from: str | None = None,
        smtp_to: str | None = None,
        smtp_tls: str = "starttls",
        smtp_auth: str = "auto",
        enabled: bool = True,
        enabled_types: tuple[str, ...] = (),
    ) -> ServiceView:
        """Write one service whole.

        Validation lives here rather than only at the API, because the store is
        also written through the delivery code's tests and a row that the
        sender cannot use must not be storable. `updated_at` moves to now: a
        service the operator edits is reset, so history is not replayed at a
        new URL.
        """
        if kind not in SINKS:
            raise ValueError(f"unknown service type: {kind}")
        normalised = _normalise_service(
            name,
            kind,
            url=url,
            topic=topic,
            token=token,
            secret=secret,
            auth_header=auth_header,
            discord_username=discord_username,
            discord_avatar=discord_avatar,
            discord_here=discord_here,
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            smtp_username=smtp_username,
            smtp_from=smtp_from,
            smtp_to=smtp_to,
            smtp_tls=smtp_tls,
            smtp_auth=smtp_auth,
            enabled_types=enabled_types,
        )

        now = time.time()
        with connect(self.path) as connection:
            existing = connection.execute(
                "SELECT kind FROM notification_services WHERE name = ?", (name,)
            ).fetchone()
            if existing is not None and existing["kind"] != kind:
                # The store's own guard behind "the kind is not patchable": a
                # conflicting name must not be able to rewrite a mechanism.
                raise ValueError(
                    f"{name} is already a {existing['kind']} service; a "
                    "different type needs a different name"
                )
            connection.execute(
                "INSERT INTO notification_services "
                "(name, kind, enabled, url, topic, token, secret, auth_header, "
                " discord_username, discord_avatar, discord_here, "
                " smtp_host, smtp_port, smtp_username, smtp_from, smtp_to, "
                " smtp_tls, smtp_auth, enabled_types, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET kind = excluded.kind, "
                "enabled = excluded.enabled, url = excluded.url, "
                "topic = excluded.topic, token = excluded.token, "
                "secret = excluded.secret, auth_header = excluded.auth_header, "
                "discord_username = excluded.discord_username, "
                "discord_avatar = excluded.discord_avatar, "
                "discord_here = excluded.discord_here, "
                "smtp_host = excluded.smtp_host, smtp_port = excluded.smtp_port, "
                "smtp_username = excluded.smtp_username, "
                "smtp_from = excluded.smtp_from, smtp_to = excluded.smtp_to, "
                "smtp_tls = excluded.smtp_tls, smtp_auth = excluded.smtp_auth, "
                "enabled_types = excluded.enabled_types, "
                "updated_at = excluded.updated_at",
                (
                    name,
                    kind,
                    1 if enabled else 0,
                    normalised["url"],
                    normalised["topic"],
                    normalised["token"],
                    normalised["secret"],
                    normalised["auth_header"],
                    normalised["discord_username"],
                    normalised["discord_avatar"],
                    normalised["discord_here"],
                    normalised["smtp_host"],
                    normalised["smtp_port"],
                    normalised["smtp_username"],
                    normalised["smtp_from"],
                    normalised["smtp_to"],
                    normalised["smtp_tls"],
                    normalised["smtp_auth"],
                    ",".join(enabled_types or ()),
                    now,
                    now,
                ),
            )
        view = self.views().get(name)
        if view is None:  # pragma: no cover - the row was just written
            raise RuntimeError(f"service {name!r} vanished after its write")
        return view

    def test_unsaved(
        self,
        name: str,
        kind: str,
        *,
        url: str,
        topic: str | None = None,
        token: str | None = None,
        secret: str | None = None,
        auth_header: str | None = None,
        discord_username: str | None = None,
        discord_avatar: str | None = None,
        discord_here: bool = False,
        smtp_host: str | None = None,
        smtp_port: int | None = None,
        smtp_username: str | None = None,
        smtp_from: str | None = None,
        smtp_to: str | None = None,
        smtp_tls: str = "starttls",
        smtp_auth: str = "auto",
    ) -> str:
        """Send one test event from a config that is not stored.

        The console can prove a service before saving it. No row, event or
        delivery is written; the password exists only in this call.
        """
        normalised = _normalise_service(
            name or "test",
            kind,
            url=url,
            topic=topic,
            token=token,
            secret=secret,
            auth_header=auth_header,
            discord_username=discord_username,
            discord_avatar=discord_avatar,
            discord_here=discord_here,
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            smtp_username=smtp_username,
            smtp_from=smtp_from,
            smtp_to=smtp_to,
            smtp_tls=smtp_tls,
            smtp_auth=smtp_auth,
            enabled_types=(),
        )
        now = time.time()
        config = ServiceConfig(
            id=0,
            name=name or "test",
            kind=kind,
            enabled=True,
            url=normalised["url"],
            topic=normalised["topic"],
            token=normalised["token"],
            secret=normalised["secret"],
            auth_header=normalised["auth_header"],
            discord_username=normalised["discord_username"],
            discord_avatar=normalised["discord_avatar"],
            discord_here=bool(normalised["discord_here"]),
            smtp_host=normalised["smtp_host"],
            smtp_port=normalised["smtp_port"],
            smtp_username=normalised["smtp_username"],
            smtp_from=normalised["smtp_from"],
            smtp_to=normalised["smtp_to"],
            smtp_tls=normalised["smtp_tls"],
            smtp_auth=normalised["smtp_auth"],
            enabled_types=(),
            created_at=now,
            updated_at=now,
        )
        event = Event(
            id=0,
            at=now,
            kind="test",
            credential=None,
            previous_status=None,
            status=None,
            detail="a test notification from the console",
            sink=config.name,
        )
        try:
            self._send(config, event)
        except Exception as exc:
            return _reason(exc)
        return ""

    def delete_service(self, name: str) -> bool:
        with connect(self.path) as connection:
            cursor = connection.execute(
                "DELETE FROM notification_services WHERE name = ?", (name,)
            )
        return cursor.rowcount == 1

    # -- delivery ------------------------------------------------------------

    def tick(self) -> None:
        """Try every due event against every enabled service, once each.

        A service that accepts the request is recorded delivered; one that does
        not is recorded waiting, with a backoff, and the reason is kept for the
        Events view. Nothing here raises for a service - the loop's job is to
        keep trying.
        A database error is different and propagates: a notifier that cannot
        remember what it did would deliver twice.
        """
        with self._lock:
            for config in self.services().values():
                if not config.enabled:
                    continue
                self._tick_config(config)

    def tick_service(self, name: str) -> None:
        """Deliver one service's due events, once: the per-service Test button.

        Raises for an unknown or disabled service - the caller is a request
        that named it, so the refusal belongs in that request's answer.
        """
        with self._lock:
            config = self.service(name)
            if config is None:
                raise ValueError(f"unknown service: {name}")
            if not config.enabled:
                raise ValueError(f"{name} is disabled")
            self._tick_config(config)

    def _tick_config(self, config: ServiceConfig) -> None:
        for event in self._pending(config):
            try:
                self._send(config, event)
            except Exception as exc:  # a service being down is not a crash
                self._record(config, event, reason=_reason(exc))
            else:
                self._record(config, event)

    def deliveries(self, event_ids: Iterable[int]) -> dict[int, tuple[Delivery, ...]]:
        """The delivery rows for these events, keyed by event id, by sink.

        `event_id >= min(ids)` rather than an IN list of unknown length: events
        are never deleted, so the range is exactly the page of events the
        caller asked about, and the SQL stays a literal (no string building).
        """
        wanted = set(event_ids)
        if not wanted:
            return {}
        with connect(self.path) as connection:
            rows = connection.execute(
                "SELECT * FROM event_deliveries WHERE event_id >= ? ORDER BY sink",
                (min(wanted),),
            ).fetchall()
        found: dict[int, list[Delivery]] = {}
        for row in rows:
            if row["event_id"] not in wanted:
                continue
            found.setdefault(row["event_id"], []).append(
                Delivery(
                    sink=row["sink"],
                    state=row["state"],
                    attempts=row["attempts"],
                    next_attempt_at=row["next_attempt_at"],
                    last_error=row["last_error"],
                    delivered_at=row["delivered_at"],
                )
            )
        return {event_id: tuple(items) for event_id, items in found.items()}

    def _pending(self, config: ServiceConfig) -> list[Event]:
        """Events this service has not accepted yet, oldest first.

        `e.at >= config.updated_at` is the floor that keeps a new service from
        replaying the ledger; the rest is the retry state machine. The
        per-service event-kind selection is applied here, so a service that
        does not hear about `auto_*` never gets a delivery row for one.
        """
        now = time.time()
        with connect(self.path) as connection:
            rows = connection.execute(
                "SELECT e.* FROM events e "
                "LEFT JOIN event_deliveries d ON d.event_id = e.id AND d.sink = ? "
                "WHERE e.at >= ? "
                "  AND (e.sink IS NULL OR e.sink = ?) "
                "  AND (d.state IS NULL OR (d.state = 'pending' AND d.next_attempt_at <= ?)) "
                "ORDER BY e.id",
                (config.name, config.updated_at, config.name, now),
            ).fetchall()
        return [
            event for event in (event_from_row(row) for row in rows)
            if event.kind not in SILENT_KINDS and config.accepts(event.kind)
        ]

    def _send(self, config: ServiceConfig, event: Event) -> None:
        if config.kind == "email":
            self._send_email(config, event)
            return
        if config.kind == "ntfy":
            topic = urllib.parse.quote(config.topic or "", safe="")
            request = _request(f"{config.url.rstrip('/')}/{topic}", _ntfy_body(event).encode())
            request.add_header("Title", _title(event))
            request.add_header("Priority", _PRIORITY.get(event.kind, "3"))
            if config.token:
                request.add_header("Authorization", f"Bearer {config.token}")
        elif config.kind == "discord":
            content = _message(event, 2000)
            body: dict[str, Any] = {
                "content": f"@here\n{content}" if config.discord_here else content,
                # Pinging a channel is the operator's explicit choice; without
                # it, a credential name is not a reason to wake anyone.
                "allowed_mentions": {
                    "parse": ["everyone"] if config.discord_here else []
                },
            }
            if config.discord_username:
                body["username"] = config.discord_username
            if config.discord_avatar:
                body["avatar_url"] = config.discord_avatar
            request = _request(
                config.url, json.dumps(body).encode(), content_type="application/json"
            )
        elif config.kind == "telegram":
            if not config.token or not config.topic:
                raise RefusedURL("telegram needs a bot token and a chat id")
            # Quote the token into the path: it is stored state and must not be
            # able to change the endpoint. The token never enters the body.
            token = urllib.parse.quote(config.token, safe=":")
            body = json.dumps(
                {
                    "chat_id": config.topic,
                    "text": _message(event, 4096),
                    "disable_web_page_preview": True,
                }
            ).encode()
            request = _request(
                f"{config.url.rstrip('/')}/bot{token}/sendMessage",
                body,
                content_type="application/json",
            )
        elif config.kind == "webhook":
            body = json.dumps(payload(event)).encode()
            request = _request(config.url, body, content_type="application/json")
            if config.auth_header:
                # A raw header the receiver asked for; it is a secret in the
                # same read path as a token and never comes back out.
                request.add_header("Authorization", config.auth_header)
            if config.secret:
                request.add_header(
                    "X-Credarr-Signature",
                    "sha256="
                    + hmac.new(config.secret.encode(), body, hashlib.sha256).hexdigest(),
                )
        else:
            raise ValueError(f"unknown service type: {config.kind}")
        with urllib.request.urlopen(request, timeout=self.timeout) as answer:  # noqa: S310 - see _request
            # Only a bounded prefix is read: the answer is remote-controlled,
            # and only Telegram's short JSON result is used at all.
            response_body = answer.read(8192)
        if config.kind == "telegram":
            try:
                result = json.loads(response_body)
            except ValueError:
                result = None
            if not isinstance(result, dict) or result.get("ok") is not True:
                # The code is a bounded integer and cannot carry the token.
                # Deliberately no description: remote text could echo the bot
                # token that travelled in the path.
                code = result.get("error_code") if isinstance(result, dict) else None
                suffix = (
                    f" (error {code})"
                    if isinstance(code, int) and not isinstance(code, bool) and 100 <= code <= 999
                    else ""
                )
                raise RefusedURL(f"telegram refused the message{suffix}")

    def _send_email(self, config: ServiceConfig, event: Event) -> None:
        """Send one plain-text notification over SMTP.

        The SMTP password is the service's write-only token. TLS verification
        is always on; the operator chooses none, STARTTLS or implicit TLS and
        the authentication mechanism, matching Arcane's email settings.
        """
        if (
            not config.smtp_host
            or not config.smtp_port
            or not config.smtp_from
            or not config.smtp_to
        ):
            raise RefusedURL("email is not fully configured")
        if config.smtp_auth != "none" and (
            not config.smtp_username or not config.token
        ):
            raise RefusedURL("email authentication needs a username and password")

        from_address = _envelope_address(config.smtp_from)
        recipients = _envelope_addresses(config.smtp_to)
        if not from_address or not recipients:
            raise RefusedURL("email needs a From address and at least one recipient")

        message = EmailMessage()
        message["From"] = config.smtp_from
        message["To"] = ", ".join(config.smtp_to.splitlines())
        message["Subject"] = _title(event)
        message["Date"] = formatdate(localtime=True)
        message["Auto-Submitted"] = "auto-generated"
        message.set_content(_ntfy_body(event))

        context = ssl.create_default_context()
        smtp: smtplib.SMTP | None = None
        try:
            if config.smtp_tls == "ssl":
                smtp = smtplib.SMTP_SSL(
                    config.smtp_host,
                    config.smtp_port,
                    timeout=self.timeout,
                    context=context,
                )
            else:
                smtp = smtplib.SMTP(
                    config.smtp_host, config.smtp_port, timeout=self.timeout
                )
                if config.smtp_tls == "starttls":
                    smtp.ehlo()
                    smtp.starttls(context=context)
                    smtp.ehlo()
            if config.smtp_auth != "none":
                # The store validates both fields; this is the sender's guard
                # against a row written by an older build.
                assert config.smtp_username is not None
                assert config.token is not None
                if config.smtp_auth == "auto":
                    smtp.login(config.smtp_username, config.token)
                else:
                    smtp.user = config.smtp_username
                    smtp.password = config.token
                    mechanism, authobject = {
                        "plain": ("PLAIN", smtp.auth_plain),
                        "login": ("LOGIN", smtp.auth_login),
                        "crammd5": ("CRAM-MD5", smtp.auth_cram_md5),
                    }[config.smtp_auth]
                    smtp.auth(
                        mechanism,
                        authobject,
                        initial_response_ok=True,
                    )
            smtp.send_message(
                message, from_addr=from_address, to_addrs=recipients
            )
        finally:
            if smtp is not None:
                try:
                    smtp.quit()
                except Exception:
                    with contextlib.suppress(Exception):
                        smtp.close()

    def _record(self, config: ServiceConfig, event: Event, *, reason: str | None = None) -> None:
        """One delivery attempt's outcome, in one transaction.

        The attempt counter is read and written here rather than in a statement
        that increments it, because the *state* and the backoff both depend on
        the number this attempt makes - and doing the arithmetic in Python over
        SQLite's math functions keeps this readable.
        """
        now = time.time()
        with connect(self.path) as connection:
            # Read attempts and write the next state in one write transaction.
            # A deferred BEGIN would upgrade after the read and can fail
            # immediately with SQLITE_BUSY_SNAPSHOT if an audit committed first.
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT attempts FROM event_deliveries WHERE event_id = ? AND sink = ?",
                    (event.id, config.name),
                ).fetchone()
                attempts = (row["attempts"] if row else 0) + 1
                if reason is None:
                    state, next_attempt, error, delivered_at = (
                        "delivered", None, None, now,
                    )
                else:
                    state = "failed" if attempts >= MAX_ATTEMPTS else "pending"
                    delay = min(
                        BACKOFF_BASE_SECONDS * (2 ** (attempts - 1)), BACKOFF_CAP_SECONDS
                    )
                    next_attempt, error, delivered_at = now + delay, reason, None
                connection.execute(
                    "INSERT INTO event_deliveries (event_id, sink, state, attempts, "
                    "next_attempt_at, last_error, delivered_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(event_id, sink) DO UPDATE SET state = excluded.state, "
                    "attempts = excluded.attempts, "
                    "next_attempt_at = excluded.next_attempt_at, "
                    "last_error = excluded.last_error, "
                    "delivered_at = excluded.delivered_at",
                    (
                        event.id,
                        config.name,
                        state,
                        attempts,
                        next_attempt,
                        error,
                        delivered_at,
                    ),
                )
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise


class DeliveryLoop:
    """The notifier's thread, and the failure that ends it.

    The same shape as the audit loop, for the same reason: a loop that cannot
    write to the database is not a delivery problem, it is a dashboard quietly
    going stale, so it stops and `/health` says so. A sink being down never
    reaches this - that is an event's retry state, not the loop's.
    """

    def __init__(self, notifier: Notifier, *, interval: float = TICK_SECONDS) -> None:
        self.notifier = notifier
        self.interval = interval
        self.failure: str | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="credarr-notify", daemon=True)

    @property
    def running(self) -> bool:
        return self._thread.is_alive()

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=10)

    def _run(self) -> None:
        try:
            while not self._stop.is_set():
                # Tick first: an event left pending by the last shutdown should
                # not wait for this process's first interval.
                self.notifier.tick()
                self._stop.wait(self.interval)
        except Exception as exc:
            self.failure = f"{type(exc).__name__}: {exc}"


def _config(row: Any) -> ServiceConfig:
    return ServiceConfig(
        id=row["id"],
        name=row["name"],
        kind=row["kind"],
        enabled=bool(row["enabled"]),
        url=row["url"],
        topic=row["topic"],
        token=row["token"],
        secret=row["secret"],
        auth_header=row["auth_header"],
        discord_username=row["discord_username"],
        discord_avatar=row["discord_avatar"],
        discord_here=bool(row["discord_here"]),
        smtp_host=row["smtp_host"],
        smtp_port=int(row["smtp_port"]) if row["smtp_port"] is not None else None,
        smtp_username=row["smtp_username"],
        smtp_from=row["smtp_from"],
        smtp_to=row["smtp_to"],
        smtp_tls=row["smtp_tls"] or "starttls",
        smtp_auth=row["smtp_auth"] or "auto",
        enabled_types=tuple(
            part for part in (row["enabled_types"] or "").split(",") if part
        ),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _view(config: ServiceConfig, stats: ServiceStats) -> ServiceView:
    return ServiceView(
        id=config.id,
        name=config.name,
        kind=config.kind,
        enabled=config.enabled,
        url=config.url,
        topic=config.topic,
        token_configured=bool(config.token),
        secret_configured=bool(config.secret),
        auth_header_configured=bool(config.auth_header),
        discord_username=config.discord_username,
        discord_avatar=config.discord_avatar,
        discord_here=config.discord_here,
        smtp_host=config.smtp_host,
        smtp_port=config.smtp_port,
        smtp_username=config.smtp_username,
        smtp_from=config.smtp_from,
        smtp_to=config.smtp_to,
        smtp_tls=config.smtp_tls,
        smtp_auth=config.smtp_auth,
        enabled_types=config.enabled_types,
        updated_at=config.updated_at,
        stats=stats,
    )
