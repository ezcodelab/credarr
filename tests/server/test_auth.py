"""The admin's own storage: hashed password, sessions, one-time setup, keys.

Unit level, one database and nothing else: what is stored is a hash, setup is
once, a session authenticates exactly while its opaque token is live, and the
two expiries are enforced by the server rather than by a cookie's Max-Age.
"""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from credarr_server.auth import (
    LOGIN_LOCKOUT_SECONDS,
    MAX_LOGIN_FAILURES,
    SESSION_ABSOLUTE_SECONDS,
    SESSION_IDLE_SECONDS,
    AdminAuth,
    InvalidCredentials,
    LoginLocked,
    SetupAlreadyDone,
    WrongPassword,
)

PASSWORD = "correct-horse-battery"  # gitleaks:allow - a test fixture, not a secret


def test_setup_is_one_time_and_stores_only_a_hash(tmp_path: Path) -> None:
    auth = AdminAuth(tmp_path / "app.db")
    assert auth.needs_setup() is True
    auth.set_password(PASSWORD)
    assert auth.needs_setup() is False
    with pytest.raises(SetupAlreadyDone):
        auth.set_password("another-password-entirely")

    with sqlite3.connect(tmp_path / "app.db") as connection:
        stored = connection.execute(
            "SELECT value FROM settings WHERE key = 'admin_password'"
        ).fetchone()[0]
    assert stored.startswith("$argon2id$")
    assert PASSWORD not in stored


def test_a_short_password_is_refused(tmp_path: Path) -> None:
    auth = AdminAuth(tmp_path / "app.db")
    with pytest.raises(ValueError):
        auth.set_password("short")
    assert auth.needs_setup() is True


def test_verification(tmp_path: Path) -> None:
    auth = AdminAuth(tmp_path / "app.db")
    auth.set_password(PASSWORD)
    assert auth.verify_password(PASSWORD) is True
    assert auth.verify_password("wrong") is False


def test_a_session_stores_only_the_hash_and_authenticates_its_token(tmp_path: Path) -> None:
    auth = AdminAuth(tmp_path / "app.db")
    issued = auth.create_session("Firefox/120\non Linux", now=1_000)

    assert issued.token not in {issued.session.device, issued.session.csrf_token}
    assert "\n" not in issued.session.device
    with sqlite3.connect(tmp_path / "app.db") as connection:
        stored = connection.execute("SELECT token_hash FROM app_sessions").fetchone()[0]
    assert stored == hashlib.sha256(issued.token.encode("utf-8")).hexdigest()
    assert stored != issued.token

    lookup = auth.authenticate_session(issued.token, now=1_001)
    assert lookup is not None
    assert lookup.session.id == issued.session.id
    assert lookup.session.csrf_token == issued.session.csrf_token
    assert auth.authenticate_session("not-the-token", now=1_001) is None


def test_the_idle_window_slides_at_the_halfway_point(tmp_path: Path) -> None:
    auth = AdminAuth(tmp_path / "app.db")
    issued = auth.create_session(now=0)
    first = auth.authenticate_session(issued.token, now=SESSION_IDLE_SECONDS - 1)
    assert first is not None and first.renewed is True
    assert first.session.idle_expires_at == SESSION_IDLE_SECONDS - 1 + SESSION_IDLE_SECONDS

    # A second request immediately after is not another renewal.
    second = auth.authenticate_session(issued.token, now=SESSION_IDLE_SECONDS)
    assert second is not None and second.renewed is False


def test_the_absolute_lifetime_caps_renewal_and_then_refuses(tmp_path: Path) -> None:
    auth = AdminAuth(tmp_path / "app.db")
    issued = auth.create_session(now=0)
    last = None
    for at in range(1_000, SESSION_ABSOLUTE_SECONDS, 1_000):
        last = auth.authenticate_session(issued.token, now=at)
        assert last is not None
    assert last is not None
    assert last.session.idle_expires_at <= SESSION_ABSOLUTE_SECONDS
    assert auth.authenticate_session(issued.token, now=SESSION_ABSOLUTE_SECONDS) is None


def test_an_idle_expired_session_is_refused_and_revoked(tmp_path: Path) -> None:
    auth = AdminAuth(tmp_path / "app.db")
    issued = auth.create_session(now=0)
    assert auth.authenticate_session(issued.token, now=SESSION_IDLE_SECONDS) is None
    with sqlite3.connect(tmp_path / "app.db") as connection:
        revoked_at = connection.execute(
            "SELECT revoked_at FROM app_sessions WHERE id = ?", (issued.session.id,)
        ).fetchone()[0]
    assert revoked_at is not None
    assert auth.authenticate_session(issued.token, now=1) is None


def test_revocation_is_by_row_and_by_token(tmp_path: Path) -> None:
    auth = AdminAuth(tmp_path / "app.db")
    first = auth.create_session(now=0)
    second = auth.create_session(now=1)
    assert auth.revoke_session(first.session.id) is True
    assert auth.authenticate_session(first.token, now=2) is None
    assert auth.authenticate_session(second.token, now=2) is not None

    assert auth.revoke_token(second.token) is True
    assert auth.authenticate_session(second.token, now=3) is None
    assert auth.revoke_session(999) is False


def test_listing_and_revoking_all_is_scoped_and_includes_the_current_row(tmp_path: Path) -> None:
    auth = AdminAuth(tmp_path / "app.db")
    first = auth.create_session(now=0)
    second = auth.create_session(now=1)
    listed = auth.list_sessions(now=2)
    assert [entry.id for entry in listed] == [second.session.id, first.session.id]

    assert auth.revoke_all_sessions(now=3) == 2
    assert auth.list_sessions(now=4) == ()
    assert auth.authenticate_session(first.token, now=4) is None
    assert auth.authenticate_session(second.token, now=4) is None


def test_changing_the_password_requires_the_old_one_and_revokes_every_session(
    tmp_path: Path,
) -> None:
    auth = AdminAuth(tmp_path / "app.db")
    auth.set_password(PASSWORD)
    first = auth.create_session(now=0)
    second = auth.create_session(now=1)

    with pytest.raises(WrongPassword):
        auth.change_password("wrong", "another-password-entirely")
    assert auth.authenticate_session(first.token, now=2) is not None

    auth.change_password(PASSWORD, "another-password-entirely")
    assert auth.verify_password(PASSWORD) is False
    assert auth.verify_password("another-password-entirely") is True
    assert auth.authenticate_session(first.token, now=2) is None
    assert auth.authenticate_session(second.token, now=2) is None

    with pytest.raises(ValueError):
        auth.change_password("another-password-entirely", "short")


def test_keys_are_stored_hashed_and_revoked_by_id(tmp_path: Path) -> None:
    auth = AdminAuth(tmp_path / "app.db")
    key_id, key = auth.create_key()
    assert key.startswith("credarr_")
    assert auth.verify_key(key) == key_id
    assert auth.verify_key("credarr_nonsense") is None

    with sqlite3.connect(tmp_path / "app.db") as connection:
        key_hash, prefix = connection.execute(
            "SELECT key_hash, prefix FROM app_api_keys"
        ).fetchone()
    assert key_hash == hashlib.sha256(key.encode("utf-8")).hexdigest()
    assert prefix == key[: len("credarr_") + 8]

    listed = auth.list_keys()
    assert [entry.id for entry in listed] == [key_id]
    assert listed[0].last_used_at is not None  # verify_key recorded the use

    assert auth.revoke_key(key_id) is True
    assert auth.revoke_key(key_id) is False
    assert auth.verify_key(key) is None


def test_last_used_is_written_at_most_once_a_minute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A polling client must not turn every read into a SQLite write."""
    auth = AdminAuth(tmp_path / "app.db")
    key_id, key = auth.create_key()
    assert auth.verify_key(key) == key_id
    with sqlite3.connect(tmp_path / "app.db") as connection:
        first = connection.execute(
            "SELECT last_used_at FROM app_api_keys WHERE id = ?", (key_id,)
        ).fetchone()[0]
        connection.execute(
            "UPDATE app_api_keys SET last_used_at = 123 WHERE id = ?", (key_id,)
        )
    assert first is not None
    assert auth.verify_key(key) == key_id
    with sqlite3.connect(tmp_path / "app.db") as connection:
        assert connection.execute(
            "SELECT last_used_at FROM app_api_keys WHERE id = ?", (key_id,)
        ).fetchone()[0] == 123

    # Once the window has elapsed, the next use is recorded again.
    monkeypatch.setattr(
        "credarr_server.auth.LAST_USED_THROTTLE_SECONDS", 0.0
    )
    assert auth.verify_key(key) == key_id
    with sqlite3.connect(tmp_path / "app.db") as connection:
        assert connection.execute(
            "SELECT last_used_at FROM app_api_keys WHERE id = ?", (key_id,)
        ).fetchone()[0] > 123


def test_too_many_failures_lock_the_one_account_temporarily(tmp_path: Path) -> None:
    auth = AdminAuth(tmp_path / "app.db")
    auth.set_password(PASSWORD)
    now = 1_000.0
    for _ in range(MAX_LOGIN_FAILURES - 1):
        with pytest.raises(InvalidCredentials):
            auth.login("wrong", now=now)
    with pytest.raises(InvalidCredentials):
        auth.login("wrong", now=now)
    with pytest.raises(LoginLocked) as locked:
        auth.login(PASSWORD, now=now + 1)
    assert locked.value.seconds > 0

    # The expired lock also resets the counter: one new typo does not instantly
    # lock the account again for another full window.
    with pytest.raises(InvalidCredentials):
        auth.login("wrong", now=now + LOGIN_LOCKOUT_SECONDS + 1)
    with sqlite3.connect(tmp_path / "app.db") as connection:
        failures = connection.execute(
            "SELECT failures FROM login_failures WHERE subject = 'admin'"
        ).fetchone()[0]
    assert failures == 1
    auth.login(PASSWORD, now=now + LOGIN_LOCKOUT_SECONDS + 2)


def test_changing_the_password_rotates_the_callers_session_in_place(
    tmp_path: Path,
) -> None:
    """No revoke-then-create window for the browser that changed it.

    The caller's row keeps its id and receives a new token and CSRF value in the
    same transaction that revokes every other session. An in-flight request that
    authenticated before the commit is unaffected; one that arrives afterwards
    with the old cookie is refused, which is why the console also retries a read
    once.
    """
    auth = AdminAuth(tmp_path / "app.db")
    auth.set_password(PASSWORD)
    mine = auth.create_session(now=0)
    other = auth.create_session(now=1)

    issued = auth.change_password(
        PASSWORD,
        "another-password-entirely",
        session_id=mine.session.id,
        now=2,
    )

    assert issued is not None
    assert issued.session.id == mine.session.id, "the row is rotated, not replaced"
    assert issued.token != mine.token
    assert issued.session.csrf_token != mine.session.csrf_token
    assert auth.authenticate_session(mine.token, now=3) is None
    assert auth.authenticate_session(issued.token, now=3) is not None
    assert auth.authenticate_session(other.token, now=3) is None
    assert auth.verify_password("another-password-entirely") is True


def test_a_failed_password_change_changes_nothing(tmp_path: Path) -> None:
    auth = AdminAuth(tmp_path / "app.db")
    auth.set_password(PASSWORD)
    mine = auth.create_session(now=0)
    other = auth.create_session(now=1)

    with pytest.raises(WrongPassword):
        auth.change_password(
            "wrong", "another-password-entirely", session_id=mine.session.id
        )

    assert auth.authenticate_session(mine.token, now=2) is not None
    assert auth.authenticate_session(other.token, now=2) is not None
    assert auth.verify_password(PASSWORD) is True


def test_rotating_a_session_that_is_already_revoked_is_refused(tmp_path: Path) -> None:
    auth = AdminAuth(tmp_path / "app.db")
    auth.set_password(PASSWORD)
    mine = auth.create_session(now=0)
    auth.revoke_session(mine.session.id)

    with pytest.raises(ValueError):
        auth.change_password(
            PASSWORD, "another-password-entirely", session_id=mine.session.id
        )

    # The password change rolled back with the rotation.
    assert auth.verify_password(PASSWORD) is True
