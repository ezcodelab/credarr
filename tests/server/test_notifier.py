"""Notifications: what leaves the machine, once, and what happens when nobody
answers.

Every test here sends to a real HTTP server on 127.0.0.1. A mocked `urlopen`
would prove the call and not the wire, and the one thing that must never be on
that wire is a credential value - so the tests read the captured request bytes
directly.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import socketserver
import sqlite3
import threading
import time
import urllib.error
from base64 import b64decode
from email import policy
from email.parser import BytesParser

import pytest

from credarr import facade
from credarr.audit import AuditResult
from credarr.redact import Secret
from credarr.targets import build_registry
from credarr_server.audit_log import AuditLog, Event
from credarr_server.notifier import MAX_ATTEMPTS, DeliveryLoop, Notifier, _reason
from credarr_server.source import StoreSource, runtime_manifest
from credarr_server.store import connect

REGISTRY = build_registry()


def _audit(app) -> AuditResult:
    return facade.audit(app.config, runtime_manifest(app.store), StoreSource(app.store))


def _drift(app, log: AuditLog) -> Event:
    """A real transition, recorded the way the audit loop records one."""
    log.record(_audit(app), started_at=1.0)  # baseline: match
    app.store.set_value("sonarr_api_key", Secret("0" * 32))
    log.record(_audit(app), started_at=2.0)  # match -> drift
    return log.recent_events()[0]


def _make_due(path, event_id: int) -> None:
    """The backoff has elapsed. Waiting it out for real would add minutes."""
    with connect(path) as connection:
        connection.execute(
            "UPDATE event_deliveries SET next_attempt_at = 0 WHERE event_id = ?", (event_id,)
        )


def _seed_attempts(path, event_id: int, sink: str, attempts: int) -> None:
    with connect(path) as connection:
        connection.execute(
            "INSERT INTO event_deliveries (event_id, sink, state, attempts, "
            "next_attempt_at, last_error, delivered_at) "
            "VALUES (?, ?, 'pending', ?, 0, 'HTTP 500 Internal Server Error', NULL)",
            (event_id, sink, attempts),
        )


class SmtpSink:
    """A disposable SMTP server on 127.0.0.1, just enough for one message."""

    def __init__(self) -> None:
        self.messages: list[bytes] = []
        self.auth: bytes | None = None
        sink = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                self.wfile.write(b"220 credarr-test\r\n")
                body: list[bytes] | None = None
                while True:
                    line = self.rfile.readline()
                    if not line:
                        return
                    if body is not None:
                        if line in (b".\r\n", b".\n"):
                            sink.messages.append(b"".join(body))
                            body = None
                            self.wfile.write(b"250 OK\r\n")
                        else:
                            body.append(line)
                        continue
                    raw = line.strip()
                    command = raw.upper()
                    if command.startswith((b"EHLO", b"HELO")):
                        self.wfile.write(
                            b"250-test\r\n250-AUTH PLAIN\r\n250 OK\r\n"
                        )
                    elif command.startswith(b"AUTH PLAIN "):
                        sink.auth = b64decode(raw.split(b" ", 2)[2])
                        self.wfile.write(b"235 2.7.0 Authentication successful\r\n")
                    elif command.startswith(
                        (b"MAIL FROM", b"RCPT TO")
                    ):
                        self.wfile.write(b"250 OK\r\n")
                    elif command.startswith(b"DATA"):
                        body = []
                        self.wfile.write(b"354 End data\r\n")
                    elif command.startswith(b"QUIT"):
                        self.wfile.write(b"221 Bye\r\n")
                        return
                    else:
                        self.wfile.write(b"250 OK\r\n")

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self.server = Server(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )
        self.thread.start()

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def test_a_transition_reaches_both_sinks_without_a_value(app, sink) -> None:
    """The whole point, in one test: a drift is heard about, with the two
    statuses and the audit's own sentence, and with nothing else on the wire.
    """
    log = AuditLog(app.store.path)
    notifier = Notifier(app.store.path)
    notifier.save_service("ntfy", "ntfy", url=sink.url, topic="credarr", token="ntfy-token")
    notifier.save_service("webhook", "webhook", url=f"{sink.url}/hook", secret="hook-secret")
    event = _drift(app, log)
    notifier.tick()

    by_path = {request["path"]: request for request in sink.requests}
    ntfy = by_path["/credarr"]
    assert ntfy["headers"]["title"] == "credarr: sonarr_api_key drifted"
    assert ntfy["headers"]["priority"] == "4"
    assert ntfy["headers"]["authorization"] == "Bearer ntfy-token"
    assert ntfy["body"].startswith(b"match \xe2\x86\x92 drift\n")

    hook = by_path["/hook"]
    document = json.loads(hook["body"])
    assert set(document) == {
        "id",
        "at",
        "kind",
        "credential",
        "previous_status",
        "status",
        "detail",
    }
    assert document["id"] == event.id
    assert document["kind"] == "drift"
    assert document["credential"] == "sonarr_api_key"
    assert document["previous_status"] == "match"
    assert document["status"] == "drift"
    assert document["detail"]
    # The signature is over the exact bytes, so a receiver can verify the body
    # without the secret ever crossing the wire.
    assert hook["headers"]["x-credarr-signature"] == (
        "sha256=" + hmac.new(b"hook-secret", hook["body"], hashlib.sha256).hexdigest()
    )

    # Neither secret, and not the drifted value, is anywhere in what left.
    for request in sink.requests:
        assert b"ntfy-token" not in request["body"]
        assert b"hook-secret" not in request["body"]
        assert b"0" * 32 not in request["body"]
        assert b"127.0.0.1" not in request["body"]

    deliveries = notifier.deliveries([event.id])[event.id]
    assert {delivery.sink: delivery.state for delivery in deliveries} == {
        "ntfy": "delivered",
        "webhook": "delivered",
    }
    assert all(delivery.attempts == 1 for delivery in deliveries)
    assert all(delivery.delivered_at is not None for delivery in deliveries)


def test_email_sends_plain_smtp_without_the_value(app) -> None:
    """The email sink is one real SMTP exchange, not a mocked send."""
    smtp = SmtpSink()
    try:
        log = AuditLog(app.store.path)
        notifier = Notifier(app.store.path)
        notifier.save_service(
            "email",
            "email",
            url="",
            smtp_host="127.0.0.1",
            smtp_port=smtp.port,
            smtp_from="Credarr <credarr@example.test>",
            smtp_to="ops@example.test\noncall@example.test",
            smtp_tls="none",
            smtp_auth="none",
        )
        event = _drift(app, log)
        notifier.tick()
    finally:
        smtp.close()

    delivery = notifier.deliveries([event.id])[event.id][0]
    assert delivery.state == "delivered"
    message = BytesParser(policy=policy.default).parsebytes(smtp.messages[0])
    assert message["Subject"] == "credarr: sonarr_api_key drifted"
    assert "ops@example.test" in message["To"]
    assert "oncall@example.test" in message["To"]
    assert "credarr@example.test" in message["From"]
    body = message.get_content()
    assert "match → drift" in body
    assert "0" * 32 not in body


def test_email_validation_refuses_incomplete_settings(tmp_path) -> None:
    with pytest.raises(ValueError, match="SMTP host"):
        Notifier(tmp_path / "app.db").save_service(
            "email", "email", url="", smtp_from="a@example.test", smtp_to="b@example.test"
        )


def test_email_can_be_proven_without_a_stored_service(tmp_path) -> None:
    """The pre-save Test path sends email without writing a service row."""
    smtp = SmtpSink()
    notifier = Notifier(tmp_path / "app.db")
    try:
        reason = notifier.test_unsaved(
            "draft",
            "email",
            url="",
            smtp_host="127.0.0.1",
            smtp_port=smtp.port,
            smtp_from="credarr@example.test",
            smtp_to="ops@example.test",
            smtp_tls="none",
            smtp_auth="none",
        )
    finally:
        smtp.close()

    assert reason == ""
    assert notifier.services() == {}
    message = BytesParser(policy=policy.default).parsebytes(smtp.messages[0])
    assert message["Subject"] == "credarr: test notification"
    assert "ops@example.test" in message["To"]


def test_smtp_auth_auto_uses_the_offered_plain_login(app) -> None:
    """The form default `auto` is exercised, not only the explicit modes."""
    smtp = SmtpSink()
    try:
        log = AuditLog(app.store.path)
        notifier = Notifier(app.store.path)
        notifier.save_service(
            "email",
            "email",
            url="",
            smtp_host="127.0.0.1",
            smtp_port=smtp.port,
            smtp_username="credarr@example.test",
            token="pw",
            smtp_from="credarr@example.test",
            smtp_to="ops@example.test",
            smtp_tls="none",
            smtp_auth="auto",
        )
        event = _drift(app, log)
        notifier.tick()
    finally:
        smtp.close()

    delivery = notifier.deliveries([event.id])[event.id][0]
    assert delivery.state == "delivered"
    assert smtp.auth == b"\x00credarr@example.test\x00pw"
    assert b"pw" not in smtp.messages[0]


def test_smtp_auth_plain_uses_the_builtin_smtplib_authobject(app) -> None:
    """An explicit auth mode must complete a real SMTP AUTH exchange."""
    smtp = SmtpSink()
    try:
        log = AuditLog(app.store.path)
        notifier = Notifier(app.store.path)
        notifier.save_service(
            "email",
            "email",
            url="",
            smtp_host="127.0.0.1",
            smtp_port=smtp.port,
            smtp_username="credarr@example.test",
            token="smtp-secret",
            smtp_from="credarr@example.test",
            smtp_to="ops@example.test",
            smtp_tls="none",
            smtp_auth="plain",
        )
        event = _drift(app, log)
        notifier.tick()
    finally:
        smtp.close()

    delivery = notifier.deliveries([event.id])[event.id][0]
    assert delivery.state == "delivered"
    assert smtp.auth == b"\x00credarr@example.test\x00smtp-secret"
    assert b"smtp-secret" not in smtp.messages[0]


def test_smtp_auth_failure_does_not_leak_the_password() -> None:
    import smtplib

    reason = _reason(smtplib.SMTPAuthenticationError(535, b"bad smtp-secret"))
    assert reason == "SMTP authentication failed"
    assert "smtp-secret" not in reason


def test_an_old_notification_table_gains_email_columns(tmp_path) -> None:
    """An existing app.db gets the SMTP columns without losing its services."""
    path = tmp_path / "app.db"
    with connect(path) as connection:
        connection.execute(
            "CREATE TABLE notification_services ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, "
            "kind TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, "
            "url TEXT NOT NULL, topic TEXT, token TEXT, secret TEXT, "
            "auth_header TEXT, discord_username TEXT, discord_avatar TEXT, "
            "discord_here INTEGER NOT NULL DEFAULT 0, "
            "enabled_types TEXT NOT NULL DEFAULT '', "
            "created_at REAL NOT NULL, updated_at REAL NOT NULL)"
        )
        connection.execute(
            "INSERT INTO notification_services "
            "(name, kind, url, created_at, updated_at) "
            "VALUES ('old', 'webhook', 'https://example.test', 1, 1)"
        )
    notifier = Notifier(path)
    with connect(path) as connection:
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(notification_services)")
        }
    assert {"smtp_host", "smtp_port", "smtp_from", "smtp_to", "smtp_tls", "smtp_auth"} <= columns
    assert notifier.services()["old"].kind == "webhook"


def test_discord_and_telegram_send_the_same_scrubbed_event(app, sink) -> None:
    """Two chat sinks, one event shape. Discord has no signature; Telegram's bot
    token travels in the path (its API requires it) and never in the body. The
    value that drifted is in neither request."""
    log = AuditLog(app.store.path)
    sink.body = b'{"ok": true}'
    notifier = Notifier(app.store.path)
    notifier.save_service("discord", "discord", url=f"{sink.url}/discord")
    notifier.save_service(
        "telegram",
        "telegram",
        url=sink.url,
        topic="4242",
        token="123:bot-token",
    )
    event = _drift(app, log)
    notifier.tick()

    by_path = {request["path"]: request for request in sink.requests}
    discord = json.loads(by_path["/discord"]["body"])
    assert set(discord) == {"content", "allowed_mentions"}
    assert discord["allowed_mentions"] == {"parse": []}
    assert discord["content"].startswith("credarr: sonarr_api_key drifted")
    assert "match → drift" in discord["content"]

    telegram = by_path["/bot123:bot-token/sendMessage"]
    document = json.loads(telegram["body"])
    assert document["chat_id"] == "4242"
    assert document["disable_web_page_preview"] is True
    assert document["text"].startswith("credarr: sonarr_api_key drifted")
    assert "match → drift" in document["text"]
    # The token is in the path because Telegram's API puts it there; it is not
    # also copied into the message body.
    assert b"bot-token" not in telegram["body"]
    for request in sink.requests:
        assert b"0" * 32 not in request["body"]
        assert b"127.0.0.1" not in request["body"]

    deliveries = notifier.deliveries([event.id])[event.id]
    assert {delivery.sink: delivery.state for delivery in deliveries} == {
        "discord": "delivered",
        "telegram": "delivered",
    }


def test_a_telegram_failure_does_not_put_the_token_in_the_error(app, sink) -> None:
    """The token is on the wire in the path; an HTTPError must not carry the
    URL into `/events` or the Events view."""
    log = AuditLog(app.store.path)
    sink.status = 500
    notifier = Notifier(app.store.path)
    notifier.save_service("telegram", "telegram", url=sink.url, topic="4242", token="123:bot-token")
    event = _drift(app, log)
    notifier.tick()

    delivery, = notifier.deliveries([event.id])[event.id]
    assert delivery.state == "pending"
    assert delivery.last_error == "HTTP 500 Internal Server Error"
    assert "bot-token" not in (delivery.last_error or "")
    assert sink.url not in (delivery.last_error or "")


def test_telegram_200_with_ok_false_is_not_a_delivery(app, sink) -> None:
    """Telegram can answer HTTP 200 and still refuse the message. The body says
    so; treating the status alone as success would hide a dead chat id."""
    log = AuditLog(app.store.path)
    sink.body = (
        b'{"ok": false, "error_code": 400, '
        b'"description": "Bad Request: chat not found"}'
    )
    notifier = Notifier(app.store.path)
    notifier.save_service("telegram", "telegram", url=sink.url, topic="4242", token="123:bot-token")
    event = _drift(app, log)
    notifier.tick()

    delivery, = notifier.deliveries([event.id])[event.id]
    assert delivery.state == "pending"
    assert delivery.last_error == "telegram refused the message (error 400)"
    assert "bot-token" not in (delivery.last_error or "")


@pytest.mark.parametrize("body", [b"", b"not json", b"[1]", b'{"ok": "true"}'])
def test_telegram_a_200_without_an_ok_result_is_not_a_delivery(app, sink, body) -> None:
    """A 200 is not an acceptance. Only the JSON object's literal `ok: true` is."""
    log = AuditLog(app.store.path)
    sink.body = body
    notifier = Notifier(app.store.path)
    notifier.save_service("telegram", "telegram", url=sink.url, topic="4242", token="123:bot-token")
    event = _drift(app, log)
    notifier.tick()

    delivery, = notifier.deliveries([event.id])[event.id]
    assert delivery.state == "pending"
    assert delivery.last_error == "telegram refused the message"
    assert "bot-token" not in (delivery.last_error or "")


def test_a_failing_sink_is_retried_with_a_backoff(app, sink) -> None:
    log = AuditLog(app.store.path)
    sink.status = 500
    notifier = Notifier(app.store.path)
    notifier.save_service("webhook", "webhook", url=sink.url)
    event = _drift(app, log)
    notifier.tick()

    delivery, = notifier.deliveries([event.id])[event.id]
    assert delivery.state == "pending"
    assert delivery.attempts == 1
    assert delivery.next_attempt_at is not None and delivery.next_attempt_at > time.time()
    # The failure is named, and the URL is not: `str(HTTPError)` would carry it
    # and an ntfy URL is the topic's password.
    assert delivery.last_error == "HTTP 500 Internal Server Error"
    assert sink.url not in (delivery.last_error or "")

    # A tick before the backoff elapses does not try again...
    notifier.tick()
    assert len(sink.requests) == 1
    # ...and the retry after it succeeds, counting both attempts.
    _make_due(app.store.path, event.id)
    sink.status = 200
    notifier.tick()

    delivery, = notifier.deliveries([event.id])[event.id]
    assert delivery.state == "delivered"
    assert delivery.attempts == 2
    assert delivery.last_error is None
    assert len(sink.requests) == 2


def test_a_sink_that_never_answers_is_given_up_on(app, sink) -> None:
    """Retrying is bounded: after the cap the event is `failed`, visible in
    the Events view, and no longer tries."""
    log = AuditLog(app.store.path)
    sink.status = 500
    notifier = Notifier(app.store.path)
    notifier.save_service("webhook", "webhook", url=sink.url)
    event = _drift(app, log)
    _seed_attempts(app.store.path, event.id, "webhook", MAX_ATTEMPTS - 1)
    notifier.tick()

    delivery, = notifier.deliveries([event.id])[event.id]
    assert delivery.state == "failed"
    assert delivery.attempts == MAX_ATTEMPTS

    sink.status = 200
    notifier.tick()
    delivery, = notifier.deliveries([event.id])[event.id]
    assert delivery.state == "failed"
    assert len(sink.requests) == 1


def test_a_failure_reason_cannot_carry_the_url() -> None:
    """The address-free branches keep their text; anything else is reduced to
    its type. `http.client.InvalidURL` embeds the URL - an ntfy URL is the
    topic's password - so its message must not become a delivery error."""
    from http.client import InvalidURL

    from credarr_server.notifier import _reason

    assert _reason(InvalidURL("http://127.0.0.1:1/secret-topic")) == "InvalidURL"
    assert (
        _reason(urllib.error.HTTPError("http://x/secret-topic", 404, "Not Found", {}, None))
        == "HTTP 404 Not Found"
    )


def test_the_read_path_shows_the_shape_and_not_the_secret(app) -> None:
    AuditLog(app.store.path)  # the notifier's delivery state reads the events
    notifier = Notifier(app.store.path)
    notifier.save_service(
        "ntfy", "ntfy", url="https://ntfy.example", topic="credarr", token="ntfy-token"
    )
    notifier.save_service(
        "webhook", "webhook", url="https://example.invalid/hook", secret="hook-secret"
    )

    views = notifier.views()
    assert views["ntfy"].url == "https://ntfy.example"
    assert views["ntfy"].topic == "credarr"
    assert views["ntfy"].token_configured is True
    assert views["webhook"].secret_configured is True
    printed = repr(views)
    assert "ntfy-token" not in printed and "hook-secret" not in printed
    # The sender's own view is the one that carries the values; its repr must
    # not either, or the next debug print is the leak.
    assert "ntfy-token" not in repr(notifier.services())


def test_a_new_sink_does_not_replay_history_but_hears_what_happens_next(app, sink) -> None:
    """Configuring a URL is testing a sink, not asking for the ledger: the
    delivery floor is the sink's own age."""
    log = AuditLog(app.store.path)
    original = app.store.get_value("sonarr_api_key")
    assert original is not None
    _drift(app, log)

    notifier = Notifier(app.store.path)
    notifier.save_service("webhook", "webhook", url=sink.url)
    notifier.tick()
    assert sink.requests == [], "a freshly configured sink was sent the history"

    app.store.set_value("sonarr_api_key", original)
    log.record(_audit(app), started_at=3.0)
    notifier.tick()

    assert len(sink.requests) == 1
    assert json.loads(sink.requests[0]["body"])["kind"] == "recovered"


def test_a_tick_is_one_critical_section(app, sink, monkeypatch) -> None:
    """The delivery loop and the console's test button can tick at once, and
    two ticks sending at once is exactly the double delivery this is built to
    prevent. Ticks are serialised, so the second one sees the first one's
    result and sends nothing."""
    log = AuditLog(app.store.path)
    notifier = Notifier(app.store.path)
    notifier.save_service("webhook", "webhook", url=sink.url)
    _drift(app, log)
    inside = threading.Event()
    release = threading.Event()
    send = notifier._send

    def held(config, event):
        inside.set()
        release.wait(timeout=5)
        send(config, event)

    monkeypatch.setattr(notifier, "_send", held)
    first = threading.Thread(target=notifier.tick)
    first.start()
    assert inside.wait(timeout=5), "the first tick never reached the send"
    # The point of the lock is that it is held *across* the send; if it is
    # not, a second tick can read the same pending row and send it twice.
    assert notifier._lock.locked()
    second = threading.Thread(target=notifier.tick)
    second.start()
    release.set()
    first.join(timeout=5)
    second.join(timeout=5)

    assert len(sink.requests) == 1


def test_an_event_recorded_before_the_sink_existed_is_not_sent(app, sink) -> None:
    """The other half of the floor: an event with no configured sink is still
    recorded (the Events view shows it), it just has nobody to go to yet."""
    log = AuditLog(app.store.path)
    event = _drift(app, log)

    notifier = Notifier(app.store.path)
    notifier.tick()
    assert notifier.deliveries([event.id]) == {}
    assert log.recent_events()[0].kind == "drift"


def test_a_test_event_reaches_the_sink(app, sink) -> None:
    log = AuditLog(app.store.path)
    notifier = Notifier(app.store.path)
    notifier.save_service("ntfy", "ntfy", url=sink.url, topic="credarr")

    event = log.record_test_event("ntfy")
    notifier.tick()

    assert sink.requests[0]["path"] == "/credarr"
    assert sink.requests[0]["headers"]["title"] == "credarr: test notification"
    delivery, = notifier.deliveries([event.id])[event.id]
    assert delivery.state == "delivered"
    assert event.credential is None


def test_a_stored_url_of_another_scheme_is_refused_not_opened(app) -> None:
    """Two layers, one rule. The store refuses to write a URL this app will
    not post to; a URL that arrived by any other path - a hand-edited
    database, a restore that outlived its validation - still fails at the
    send, so a `file:` URL is never opened."""
    log = AuditLog(app.store.path)
    notifier = Notifier(app.store.path)
    with pytest.raises(ValueError, match="must start with http"):
        notifier.save_service("webhook", "webhook", url="file:///etc/passwd")

    with connect(app.store.path) as connection:
        connection.execute(
            "INSERT INTO notification_services (name, kind, url, created_at, "
            "updated_at) VALUES ('webhook', 'webhook', 'file:///etc/passwd', 0, 0)"
        )

    event = log.record_test_event("webhook")
    notifier.tick()

    delivery, = notifier.deliveries([event.id])[event.id]
    assert delivery.state == "pending"
    assert delivery.last_error == "refusing to post to a file url"


def test_the_delivery_loop_survives_a_sink_and_stops_on_a_broken_database(app, sink) -> None:
    """A sink being down is an event's problem; the loop keeps running. A
    database it cannot write is the loop's own, and it stops instead of
    pretending - the same contract the audit loop has."""
    log = AuditLog(app.store.path)
    notifier = Notifier(app.store.path)
    notifier.save_service("webhook", "webhook", url=sink.url)
    sink.status = 503
    _drift(app, log)

    loop = DeliveryLoop(notifier, interval=0.01)
    loop.start()
    assert sink.arrived.wait(timeout=5)
    loop.stop()
    assert loop.failure is None

    broken = Notifier(app.store.path)
    broken.tick = lambda: (_ for _ in ()).throw(sqlite3.OperationalError("disk gone"))
    stopped = DeliveryLoop(broken, interval=0.01)
    stopped.start()
    for _ in range(200):
        if stopped.failure is not None:
            break
        time.sleep(0.01)
    stopped.stop()
    assert stopped.failure == "OperationalError: disk gone"


def test_a_restart_retries_what_the_last_process_left_pending(app, sink) -> None:
    """Delivery state is in the database, not in the sender's memory: the
    event a dead process left pending is the next process's first tick."""
    log = AuditLog(app.store.path)
    before = Notifier(app.store.path)
    before.save_service("webhook", "webhook", url=sink.url)
    event = _drift(app, log)
    sink.status = 500
    before.tick()
    delivery, = before.deliveries([event.id])[event.id]
    assert delivery.state == "pending"

    _make_due(app.store.path, event.id)
    sink.status = 200
    after = Notifier(app.store.path)  # a new process, same database
    after.tick()

    delivery, = after.deliveries([event.id])[event.id]
    assert delivery.state == "delivered"
    assert delivery.attempts == 2


def test_a_manual_refusal_is_recorded_but_never_delivered(app, sink) -> None:
    """The notification decision, pinned: a refusal is one operator click the
    console already answered, so no service hears it - not even one subscribed
    to every kind. A failed or completed run is news and goes out."""
    log = AuditLog(app.store.path)
    notifier = Notifier(app.store.path)
    notifier.save_service("hook", "webhook", url=sink.url)

    refused = log.record_rotation_event(
        "rotation_refused", "sonarr_api_key", "no rotation strategy"
    )
    notifier.tick()
    assert sink.requests == []
    assert notifier.deliveries([refused.id]) == {}
    assert notifier.views()["hook"].stats.pending == 0

    failed = log.record_rotation_event(
        "rotation_failed", "sonarr_api_key", "failed: HTTP 403 Forbidden"
    )
    notifier.tick()
    assert len(sink.requests) == 1
    document = json.loads(sink.requests[0]["body"])
    assert document["kind"] == "rotation_failed"
    assert document["previous_status"] is None and document["status"] is None
    assert document["detail"] == "failed: HTTP 403 Forbidden"
    delivery, = notifier.deliveries([failed.id])[failed.id]
    assert delivery.state == "delivered"


def test_a_rotation_event_does_not_invent_a_status_transition() -> None:
    """A failed or completed run has no `previous_status`/`status`; the title
    names the action and the body is the engine's sentence, never "? → ?"."""
    from dataclasses import replace

    from credarr_server.notifier import _message, _ntfy_body, _title

    event = Event(
        id=1,
        at=1.0,
        kind="rotation_failed",
        credential="sonarr_api_key",
        previous_status=None,
        status=None,
        detail="failed: HTTP 403 Forbidden",
    )
    assert _title(event) == "credarr: sonarr_api_key rotation failed"
    assert _ntfy_body(event) == event.detail
    assert "?" not in _message(event, 2_000)

    done = replace(event, kind="rotation_succeeded", detail="completed: 2 confirmed")
    assert _title(done) == "credarr: sonarr_api_key rotation succeeded"
    assert _ntfy_body(done) == "completed: 2 confirmed"

    manual = replace(
        event,
        kind="rotation_manual",
        detail="manual steps outstanding: homepage.label",
    )
    assert _title(manual) == "credarr: sonarr_api_key rotated; manual steps remain"
    assert _ntfy_body(manual) == "manual steps outstanding: homepage.label"


def test_an_auto_event_never_invents_a_status_transition() -> None:
    """Auto events are actions, not equality measurements.

    Their previous/current columns are NULL, so chat text must use the detail
    sentence rather than rendering "? → ?" as if an audit had compared
    something.
    """
    from dataclasses import replace

    from credarr_server.notifier import _message, _ntfy_body, _title

    event = Event(
        id=1,
        at=1.0,
        kind="auto_blocked",
        credential="sonarr_api_key",
        previous_status=None,
        status=None,
        detail="the last completed audit is drift, not match",
    )
    assert _title(event) == "credarr: sonarr_api_key auto-rotation blocked"
    assert _ntfy_body(event) == event.detail
    assert "?" not in _message(event, 2_000)

    manual = replace(
        event,
        kind="auto_manual",
        detail="attempt 2: key rotated; Homepage needs manual rotation",
    )
    assert _title(manual) == "credarr: sonarr_api_key requires manual rotation"
    assert _ntfy_body(manual) == manual.detail
    assert "?" not in _message(manual, 2_000)


def test_two_services_of_a_kind_are_two_destinations(app, sink) -> None:
    """The old store's unit was the kind; a named service makes the kind a
    mechanism. Two webhooks with different audiences are two rows, with their
    own delivery state."""
    log = AuditLog(app.store.path)
    notifier = Notifier(app.store.path)
    notifier.save_service("audit-room", "webhook", url=f"{sink.url}/audit")
    notifier.save_service("ops-room", "webhook", url=f"{sink.url}/ops")
    event = _drift(app, log)
    notifier.tick()

    assert sorted(request["path"] for request in sink.requests) == ["/audit", "/ops"]
    deliveries = notifier.deliveries([event.id])[event.id]
    assert {delivery.sink: delivery.state for delivery in deliveries} == {
        "audit-room": "delivered",
        "ops-room": "delivered",
    }


def test_a_disabled_service_is_kept_but_not_sent_to(app, sink) -> None:
    """Enable/disable is a switch, not a delete: the row, its secrets and its
    history stay, and nothing goes out."""
    log = AuditLog(app.store.path)
    notifier = Notifier(app.store.path)
    notifier.save_service("webhook", "webhook", url=sink.url, enabled=False)
    event = _drift(app, log)
    notifier.tick()

    assert sink.requests == []
    assert notifier.deliveries([event.id]) == {}
    assert notifier.views()["webhook"].enabled is False

    notifier.save_service("webhook", "webhook", url=sink.url, enabled=True)
    notifier.tick()
    # Enabling it is a reconfiguration, so the floor holds: the event that
    # happened while it was off is not replayed.
    assert sink.requests == []


def test_a_service_hears_only_the_event_kinds_it_selected(app, sink) -> None:
    """The per-service Notification Types grid: a service subscribed to
    recoveries does not get drift - and gets no delivery row either, so the
    Events view does not show a queue that will never move."""
    log = AuditLog(app.store.path)
    notifier = Notifier(app.store.path)
    notifier.save_service(
        "recoveries", "webhook", url=sink.url, enabled_types=("recovered",)
    )
    original = app.store.get_value("sonarr_api_key")
    assert original is not None

    event = _drift(app, log)  # match -> drift, not selected
    notifier.tick()
    assert sink.requests == []
    assert notifier.deliveries([event.id]) == {}

    app.store.set_value("sonarr_api_key", original)
    log.record(_audit(app), started_at=3.0)  # drift -> match = recovered
    notifier.tick()
    assert len(sink.requests) == 1
    assert json.loads(sink.requests[0]["body"])["kind"] == "recovered"


def test_the_stats_are_derived_from_the_delivery_rows(app, sink) -> None:
    """Success/failure counts are a query over `event_deliveries`, not a
    counter that can drift from the rows it summarises."""
    from credarr_server.notifier import ServiceStats

    log = AuditLog(app.store.path)
    notifier = Notifier(app.store.path)
    notifier.save_service("hook", "webhook", url=sink.url)
    _drift(app, log)
    notifier.tick()
    assert notifier.views()["hook"].stats == ServiceStats(delivered=1, failed=0, pending=0)

    sink.status = 500
    retry = log.record_test_event("hook")
    notifier.tick()
    assert notifier.views()["hook"].stats == ServiceStats(delivered=1, failed=0, pending=1)

    # The next attempt is the last one the cap allows; the retry clock is moved
    # by hand because waiting out the backoff for real would add minutes.
    with connect(app.store.path) as connection:
        connection.execute(
            "UPDATE event_deliveries SET attempts = ?, next_attempt_at = 0 "
            "WHERE event_id = ? AND sink = 'hook'",
            (MAX_ATTEMPTS - 1, retry.id),
        )
    notifier.tick()
    assert notifier.views()["hook"].stats == ServiceStats(delivered=1, failed=1, pending=0)


def test_discord_can_name_itself_show_an_avatar_and_mention_here(app, sink) -> None:
    """The three payload fields Discord honours, and the one opt-in mention:
    a credential name is not a reason to ping a channel, so `@here` is a
    stored choice and `allowed_mentions` follows it."""
    log = AuditLog(app.store.path)
    notifier = Notifier(app.store.path)
    notifier.save_service(
        "loud",
        "discord",
        url=f"{sink.url}/loud",
        discord_username="credarr",
        discord_avatar="https://example.invalid/a.png",
        discord_here=True,
    )
    _drift(app, log)
    notifier.tick()

    request = sink.requests[0]
    document = json.loads(request["body"])
    assert request["path"] == "/loud"
    assert document["username"] == "credarr"
    assert document["avatar_url"] == "https://example.invalid/a.png"
    assert document["allowed_mentions"] == {"parse": ["everyone"]}
    assert document["content"].startswith("@here\ncredarr: sonarr_api_key drifted")
    assert b"0" * 32 not in request["body"]


def test_a_webhook_can_carry_a_raw_authorization_header(app, sink) -> None:
    """Some receivers want a header they chose rather than an HMAC they
    compute. It is a secret on the same read path as a token: stored, sent,
    never echoed."""
    log = AuditLog(app.store.path)
    notifier = Notifier(app.store.path)
    notifier.save_service(
        "hook", "webhook", url=sink.url, auth_header="Bearer receiver-token"
    )
    _drift(app, log)
    notifier.tick()

    assert sink.requests[0]["headers"]["authorization"] == "Bearer receiver-token"
    assert notifier.views()["hook"].auth_header_configured is True
    assert "receiver-token" not in repr(notifier.views())


def test_a_retry_the_floor_dropped_is_not_counted_as_pending(app, sink) -> None:
    """Editing a service moves its floor, which permanently drops older
    events. The count the console shows must say history, not a queue that
    will never move."""
    log = AuditLog(app.store.path)
    notifier = Notifier(app.store.path)
    notifier.save_service("hook", "webhook", url=sink.url)
    sink.status = 500
    log.record_test_event("hook")
    notifier.tick()
    assert notifier.views()["hook"].stats.pending == 1

    notifier.save_service("hook", "webhook", url=f"{sink.url}/2")
    assert notifier.views()["hook"].stats.pending == 0


def test_a_test_event_targets_one_service_and_never_broadcasts(app, sink) -> None:
    """The per-service Test button probes exactly that service.

    A later ordinary tick must not replay the probe to every other sink.
    """
    log = AuditLog(app.store.path)
    notifier = Notifier(app.store.path)
    notifier.save_service("one", "webhook", url=f"{sink.url}/one")
    notifier.save_service("two", "webhook", url=f"{sink.url}/two")

    event = log.record_test_event("one")
    notifier.tick_service("one")
    notifier.tick()

    assert [request["path"] for request in sink.requests] == ["/one"]
    deliveries = notifier.deliveries([event.id])[event.id]
    assert {delivery.sink: delivery.state for delivery in deliveries} == {"one": "delivered"}
    assert notifier.views()["two"].stats.pending == 0
    with pytest.raises(ValueError, match="unknown service"):
        notifier.tick_service("three")


def test_a_notifier_response_cannot_make_the_server_buffer_it(app, sink) -> None:
    """The answer is remote-controlled. Only a bounded prefix is read, so a
    sink that holds the rest of a large body cannot pin the delivery thread."""
    log = AuditLog(app.store.path)
    notifier = Notifier(app.store.path)
    notifier.save_service("hook", "webhook", url=f"{sink.url}/stream")
    sink.body = b"x" * (16 * 1024)
    sink.release.clear()
    try:
        event = log.record_test_event("hook")
        notifier.tick_service("hook")
    finally:
        sink.release.set()

    delivery, = notifier.deliveries([event.id])[event.id]
    assert delivery.state == "delivered"


def test_a_service_name_must_survive_a_url_and_a_log_line(app) -> None:
    notifier = Notifier(app.store.path)
    with pytest.raises(ValueError, match="service name"):
        notifier.save_service("bad/name", "webhook", url="https://example.invalid/h")
    with pytest.raises(ValueError, match="unknown service type"):
        notifier.save_service("ok", "carrier-pigeon", url="https://example.invalid/h")


def test_the_one_sink_per_type_rows_migrate_into_named_services(app, sink) -> None:
    """The old table becomes services named after their kind, the old table is
    dropped, and a delivery row written against `ntfy` stays attached to the
    service now called `ntfy`."""
    log = AuditLog(app.store.path)
    with connect(app.store.path) as connection:
        connection.execute("DROP TABLE IF EXISTS notification_services")
        connection.execute(
            "CREATE TABLE notification_sinks (name TEXT PRIMARY KEY, url TEXT NOT NULL, "
            "topic TEXT, token TEXT, secret TEXT, updated_at REAL NOT NULL)"
        )
        connection.execute(
            "INSERT INTO notification_sinks VALUES (?, ?, 'credarr', 'ntfy-token', NULL, 0.0)",
            ("ntfy", sink.url),
        )
    log.record_test_event("ntfy")

    notifier = Notifier(app.store.path)  # the migration runs on construction
    config = notifier.services()["ntfy"]
    assert config.kind == "ntfy"
    assert config.token == "ntfy-token"
    assert notifier.views()["ntfy"].token_configured is True
    notifier.tick()
    assert [request["path"] for request in sink.requests] == ["/credarr"]
    assert notifier.views()["ntfy"].stats.delivered == 1

    with connect(app.store.path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    assert "notification_sinks" not in tables
