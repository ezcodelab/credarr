"""The BFF: auth, the contract, and the loop behind the health endpoint.

These drive the real application over the fixture stack the scheduler suite
already audits, through the real HTTP surface. The claims pinned here are the
plan's: one admin with a hashed password and a cookie a browser cannot leak,
API keys hashed and shown once, `/api/v1` as the pinned contract, the recorded
audit readable as JSON, no service value in any payload, and a dead audit loop
visible as degraded rather than as a healthy process serving the past.
"""

from __future__ import annotations

import json
import sqlite3
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from conftest import (
    PASSWORD,
    PROWLARR_KEY,
    RADARR_KEY,
    SONARR_KEY,
    make_server,
    poll_for,
    refresh_csrf,
    server_config,
    setup_admin,
    wait_for_audit,
)
from credarr import __version__, facade
from credarr.redact import Secret
from credarr_server.app import (
    ServerSettings,
    create_app,
    main,
    resolve_session_security,
)
from credarr_server.notifier import Notifier
from credarr_server.scheduler import Scheduler


def test_a_missing_config_is_bootstrapped_for_a_first_run(app, tmp_path) -> None:
    """A brand-new /config must not require hand-written YAML to reach setup."""
    data = tmp_path / "fresh"
    data.mkdir()
    config_path = data / "credarr.yaml"
    server = create_app(
        ServerSettings(
            config_path=config_path,
            config_dir=data,
            audit_interval=3600.0,
            web_dir=tmp_path / "web",
        )
    )
    assert config_path.is_file()
    assert (data / "credentials.yaml").is_file()
    assert config_path.stat().st_mode & 0o777 == 0o600
    assert (data / "credentials.yaml").stat().st_mode & 0o777 == 0o600
    assert "default_host: local" in config_path.read_text(encoding="utf-8")
    assert "credentials: {}" in (data / "credentials.yaml").read_text(encoding="utf-8")

    with TestClient(server) as client:
        assert client.get("/api/v1/health").json()["status"] == "ok"
        state = client.get("/api/v1/auth/state").json()
    assert state["needs_setup"] is True


def test_bootstrap_never_rewrites_an_existing_config_or_manifest(app, tmp_path) -> None:
    data = tmp_path / "existing"
    data.mkdir()
    config_path = data / "credarr.yaml"
    config_path.write_text("version: 2\n", encoding="utf-8")
    manifest = data / "credentials.yaml"
    manifest.write_text(
        "version: 1\ncredentials:\n  keep_me:\n    class: B\n"
        "    never_rotate: true\n",
        encoding="utf-8",
    )

    with pytest.raises(Exception, match="version 2"):
        create_app(
            ServerSettings(
                config_path=config_path,
                config_dir=data,
                web_dir=tmp_path / "web",
            )
        )
    assert config_path.read_text(encoding="utf-8") == "version: 2\n"
    assert "keep_me" in manifest.read_text(encoding="utf-8")


def test_an_existing_config_without_a_manifest_still_boots(app, tmp_path) -> None:
    """The server audits the store; a missing manifest must not be invented."""
    data = tmp_path / "no-manifest"
    data.mkdir()
    config_path = data / "credarr.yaml"
    config_path.write_text(
        "version: 1\ndefault_host: local\nmanifest: credentials.yaml\n"
        "hosts:\n  local:\n    urls: {}\n",
        encoding="utf-8",
    )
    server = create_app(
        ServerSettings(
            config_path=config_path,
            config_dir=data,
            audit_interval=3600.0,
            web_dir=tmp_path / "web",
        )
    )
    assert not (data / "credentials.yaml").exists()
    with TestClient(server) as client:
        assert client.get("/api/v1/health").json()["status"] == "ok"


def test_health_is_public(server) -> None:
    with TestClient(server) as client:
        response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_the_console_is_served_when_it_is_built(app, tmp_path) -> None:
    """`make web` puts the SPA build in the package and the BFF serves it at
    "/"; a deployment without one is API-only, so "/" is an ordinary 404 rather
    than a 500. The mount never shadows the API."""
    console = tmp_path / "console"
    (console / "assets").mkdir(parents=True)
    (console / "index.html").write_text("<html><body>the console</body></html>", encoding="utf-8")
    (console / "assets" / "index.js").write_text("console.log(1)", encoding="utf-8")

    with TestClient(make_server(app, tmp_path, web_dir=console)) as client:
        assert "the console" in client.get("/").text
        assert client.get("/assets/index.js").text == "console.log(1)"
        assert client.get("/api/v1/health").json() == {"status": "ok"}
        # The framework's own pages are routes too, and must still come first.
        assert client.get("/docs").status_code == 200
        assert client.get("/openapi.json").status_code == 200

    with TestClient(make_server(app, tmp_path)) as client:
        assert client.get("/").status_code == 404


def test_setup_login_logout_flow(server) -> None:
    with TestClient(server) as client:
        assert client.get("/api/v1/auth/state").json() == {"needs_setup": True}
        assert client.post("/api/v1/auth/setup", json={"password": "short"}).status_code == 422
        assert client.get("/api/v1/auth/me").status_code == 401

        setup = client.post("/api/v1/auth/setup", json={"password": PASSWORD})
        assert setup.status_code == 200 and setup.json() == {"ok": True}
        assert PASSWORD not in setup.text
        assert client.get("/api/v1/auth/state").json() == {"needs_setup": False}
        # Setup is one-time, and the second attempt cannot replace the first.
        assert client.post("/api/v1/auth/setup", json={"password": PASSWORD}).status_code == 409
        me = client.get("/api/v1/auth/me").json()
        assert me["actor"] == "admin"
        assert me["auth"] == "session"
        assert isinstance(me["csrf"], str) and me["csrf"]
        refresh_csrf(client)

        assert client.post("/api/v1/auth/logout").json() == {"ok": True}
        assert client.get("/api/v1/auth/me").status_code == 401

        assert client.post("/api/v1/auth/login", json={"password": "wrong"}).status_code == 401
        assert client.post("/api/v1/auth/login", json={"password": PASSWORD}).status_code == 200
        me = client.get("/api/v1/auth/me").json()
        assert me["actor"] == "admin" and me["auth"] == "session"


def test_validation_errors_never_echo_a_secret(server) -> None:
    """Rejected credentials are still credentials.

    Pydantic includes the rejected input in its default 422 body; this API is
    write-only for secrets, so the response must carry the location and the fix
    and nothing the operator typed.
    """
    canary = "CANARY-" + ("x" * 1100)
    huge = "CANARY-" + ("x" * 9000)
    with TestClient(server) as client:
        too_long = client.post("/api/v1/auth/setup", json={"password": canary})
        assert too_long.status_code == 422
        assert canary not in too_long.text
        assert all(
            set(error) <= {"type", "loc", "msg"}
            for error in too_long.json()["detail"]
        )

        setup_admin(client)
        login = client.post("/api/v1/auth/login", json={"password": canary})
        assert login.status_code == 422
        assert canary not in login.text

        value = client.put(
            "/api/v1/credentials/sonarr_api_key/value", json={"value": huge}
        )
        assert value.status_code == 422
        assert huge not in value.text

        spaced = client.put(
            "/api/v1/credentials/sonarr_api_key/value",
            json={"value": canary[:20] + "\n"},
        )
        assert spaced.status_code == 422
        assert canary[:20] not in spaced.text

        service_test = client.post(
            "/api/v1/services/test",
            json={"service": "seerr", "url": "http://127.0.0.1:9", "key": huge},
        )
        assert service_test.status_code == 422
        assert huge not in service_test.text

        notification = client.post(
            "/api/v1/notifications/services",
            json={
                "name": "safe",
                "kind": "webhook",
                "url": "https://example.invalid/hook",
                "token": huge,
            },
        )
        assert notification.status_code == 422
        assert huge not in notification.text

        password = client.post(
            "/api/v1/auth/password",
            json={"current_password": PASSWORD, "new_password": canary},
        )
        assert password.status_code == 422
        assert canary not in password.text

        malformed = client.post(
            "/api/v1/topology/import",
            json={
                "yaml": "version: 1\ncredentials: {}\n",
                "mode": "replace",
                "confirm": "replace",
                "extra_canary": canary,
            },
        )
        assert malformed.status_code == 422
        assert canary not in malformed.text
        assert all(
            set(error) <= {"type", "loc", "msg"}
            for error in malformed.json()["detail"]
        )


def test_the_holder_editor_refuses_a_duplicate_target(server) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        refused = client.put(
            "/api/v1/credentials/sonarr_api_key/holders",
            json={
                "consumers": [
                    {"target": "seerr.settings_json[sonarr]", "count": 1},
                    {"target": "seerr.settings_json[sonarr]", "count": 1},
                ]
            },
        )
        assert refused.status_code == 400
        assert "duplicate target" in refused.json()["detail"]


def test_a_credential_with_an_unfinished_rotation_cannot_be_deleted(
    app, tmp_path
) -> None:
    """Deleting the declaration cannot be a back door to abandoning a rotation.

    The journal is the only record of which holder may be holding a dead key;
    clearing it just to satisfy a delete would hide exactly the gap the resume
    flow exists to close.
    """
    journal = facade.journal_for(app.config)
    attempt = journal.begin("sonarr_api_key")
    journal.step_started(attempt, 0, "mint", "sonarr", "test step")

    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        refused = client.delete(
            "/api/v1/credentials/sonarr_api_key?confirm=sonarr_api_key"
        )
        assert refused.status_code == 409
        assert "resume or take it over" in refused.json()["detail"]
        names = {
            row["name"]
            for row in client.get("/api/v1/credentials").json()["credentials"]
        }
        assert "sonarr_api_key" in names
        assert app.store.get_value("sonarr_api_key") is not None
        assert journal.unfinished()

        journal.step_finished(attempt, 0, "completed")
        journal.finish(attempt, "completed")
        accepted = client.delete(
            "/api/v1/credentials/sonarr_api_key?confirm=sonarr_api_key"
        )
        assert accepted.status_code == 200
        assert journal.unfinished() == []
        assert journal.open_attempts() == {}


def test_an_open_attempt_without_a_step_also_blocks_deletion(app, tmp_path) -> None:
    journal = facade.journal_for(app.config)
    attempt = journal.begin("sonarr_api_key")

    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        refused = client.delete(
            "/api/v1/credentials/sonarr_api_key?confirm=sonarr_api_key"
        )
        assert refused.status_code == 409
        assert f"attempt {attempt} did not finish" in refused.json()["detail"]

        journal.finish(attempt, "completed")
        assert client.delete(
            "/api/v1/credentials/sonarr_api_key?confirm=sonarr_api_key"
        ).status_code == 200


def test_setup_and_login_refuse_a_cross_site_origin(server) -> None:
    """A login CSRF is how a victim's browser adopts the attacker's account."""
    with TestClient(server) as client:
        client.headers["Origin"] = "https://evil.example"
        refused = client.post("/api/v1/auth/setup", json={"password": PASSWORD})
        assert refused.status_code == 403
        assert refused.json()["detail"] == "cross-site request refused"
        assert client.get("/api/v1/auth/state").json() == {"needs_setup": True}

        # The same request from this origin is accepted: the refusal above is
        # the origin check, not the body.
        client.headers["Origin"] = "http://testserver"
        assert client.post("/api/v1/auth/setup", json={"password": PASSWORD}).status_code == 200
        client.post("/api/v1/auth/logout")
        client.headers["Origin"] = "https://evil.example"
        assert client.post("/api/v1/auth/login", json={"password": PASSWORD}).status_code == 403


def test_login_compares_any_string(server) -> None:
    """The length policy is about creation; a short guess is wrong, not invalid."""
    with TestClient(server) as client:
        setup_admin(client)
        client.post("/api/v1/auth/logout")
        response = client.post("/api/v1/auth/login", json={"password": "x"})
    assert response.status_code == 401


def test_unauthenticated_status_is_401(server) -> None:
    with TestClient(server) as client:
        response = client.get("/api/v1/status")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_the_session_cookie_is_httponly_and_strict(server) -> None:
    with TestClient(server) as client:
        response = client.post("/api/v1/auth/setup", json={"password": PASSWORD})
    cookie = response.headers["set-cookie"]
    attributes = {part.strip().lower() for part in cookie.split(";")}
    assert cookie.lower().startswith("credarr_session=")
    assert "httponly" in attributes
    assert "samesite=strict" in attributes
    assert "max-age=1800" in attributes  # the 30-minute idle window
    assert "secure" not in attributes  # plain HTTP until a deployment says otherwise


def test_secure_cookies_flag_sets_the_secure_attribute(app, tmp_path) -> None:
    """For HTTPS deployments; plain-HTTP LAN installs must leave it off, or the
    browser would never send the cookie back."""
    server = make_server(app, tmp_path, secure_cookies=True)
    with TestClient(server) as client:
        response = client.post("/api/v1/auth/setup", json={"password": PASSWORD})
    cookie = response.headers["set-cookie"]
    attributes = {part.strip().lower() for part in cookie.split(";")}
    assert cookie.lower().startswith("__host-credarr_session=")
    assert "secure" in attributes
    assert "path=/" in attributes
    assert "domain=" not in attributes


def test_a_cookie_write_requires_the_session_csrf_token_and_a_matching_origin(
    server,
) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        token = client.headers["X-CSRF-Token"]
        del client.headers["X-CSRF-Token"]
        assert client.post("/api/v1/audit").status_code == 403

        client.headers["X-CSRF-Token"] = "wrong"
        assert client.post("/api/v1/audit").status_code == 403

        client.headers["X-CSRF-Token"] = token
        client.headers["Origin"] = "https://evil.example"
        assert client.post("/api/v1/audit").status_code == 403

        client.headers["Origin"] = "http://testserver"
        assert client.post("/api/v1/audit").status_code == 200


def test_sessions_are_listed_without_tokens_and_revoked_by_id(server) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        assert client.post("/api/v1/auth/login", json={"password": PASSWORD}).status_code == 200
        refresh_csrf(client)
        listed = client.get("/api/v1/auth/sessions").json()["sessions"]
        assert len(listed) == 1
        assert listed[0]["current"] is True
        assert "token" not in json.dumps(listed).lower()
        assert "csrf" not in json.dumps(listed).lower()
        assert "device" in listed[0]

        assert client.delete(f"/api/v1/auth/sessions/{listed[0]['id']}").status_code == 200
        assert client.get("/api/v1/auth/me").status_code == 401


def test_revoke_all_sessions_includes_the_current_one_and_clears_the_cookie(server) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        response = client.delete("/api/v1/auth/sessions")
        assert response.status_code == 200
        assert response.json()["revoked"] == 1
        assert client.get("/api/v1/auth/me").status_code == 401
        assert client.cookies.get("credarr_session") is None


def test_login_rotates_the_token_and_a_replayed_cookie_is_rejected(server) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        old = client.cookies.get("credarr_session")
        assert old
        assert client.post("/api/v1/auth/login", json={"password": PASSWORD}).status_code == 200
        new = client.cookies.get("credarr_session")
        assert new and new != old
        # Clearing first: httpx keeps the domain-scoped cookie from the
        # response, so a plain set() would leave two cookies of the same name
        # and the live one would win. This sends only the old token.
        client.cookies.clear()
        client.cookies.set("credarr_session", old)
        assert client.get("/api/v1/auth/me").status_code == 401


def test_changing_the_password_rotates_the_session_and_revokes_the_old_one(server) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        old = client.cookies.get("credarr_session")
        token = client.headers["X-CSRF-Token"]
        assert client.post(
            "/api/v1/auth/password",
            json={"current_password": "wrong", "new_password": "another-password-entirely"},
        ).status_code == 403

        response = client.post(
            "/api/v1/auth/password",
            json={"current_password": PASSWORD, "new_password": "another-password-entirely"},
        )
        assert response.status_code == 200
        new = client.cookies.get("credarr_session")
        assert new and new != old
        assert response.headers.get("set-cookie", "").lower().startswith("credarr_session=")

        client.headers["X-CSRF-Token"] = token
        # Clearing first: httpx keeps the domain-scoped cookie from the
        # response, so a plain set() would leave two cookies of the same name
        # and the live one would win. This sends only the old token.
        client.cookies.clear()
        client.cookies.set("credarr_session", old)
        assert client.get("/api/v1/auth/me").status_code == 401

        client.cookies.set("credarr_session", new)
        refresh_csrf(client)
        assert client.get("/api/v1/auth/me").status_code == 200
        assert len(client.get("/api/v1/auth/sessions").json()["sessions"]) == 1

        assert client.post(
            "/api/v1/auth/password",
            json={
                "current_password": "another-password-entirely",
                "new_password": PASSWORD,
            },
        ).status_code == 200


def test_sliding_renewal_refreshes_the_cookie_at_the_halfway_point(server, monkeypatch) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        # Move the clock to the renewal threshold. Pinned to the session's own
        # idle deadline rather than to `now`, because time spent in setup would
        # otherwise push the shifted clock past that deadline and expire the
        # session instead of renewing it (a load-dependent flake).
        import credarr_server.auth as auth_module

        (session,) = client.get("/api/v1/auth/sessions").json()["sessions"]
        shifted = session["idle_expires_at"] - 1
        monkeypatch.setattr(auth_module.time, "time", lambda: shifted)
        response = client.get("/api/v1/auth/me")
        assert response.status_code == 200
        cookie = response.headers.get("set-cookie", "")
        assert cookie.lower().startswith("credarr_session=")
        assert "max-age=1800" in {part.strip().lower() for part in cookie.split(";")}


def test_main_reports_a_bad_config_as_exit_3(tmp_path, capsys) -> None:
    """The process contract: misconfiguration is the CLI's exit 3 with the
    engine's message, not a traceback from inside uvicorn."""
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 2\n", encoding="utf-8")
    assert main(["-c", str(bad), "--config-dir", str(tmp_path)]) == 3
    assert "error:" in capsys.readouterr().err


def test_the_server_entry_point_disables_core_dumps_before_config(
    tmp_path, monkeypatch
) -> None:
    import credarr_server.app as server_app

    calls: list[str] = []
    monkeypatch.setattr(server_app, "disable_core_dumps", lambda: calls.append("called"))
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 2\n", encoding="utf-8")
    assert server_app.main(["-c", str(bad), "--config-dir", str(tmp_path)]) == 3
    assert calls == ["called"]


def test_api_key_lifecycle(server) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        created = client.post("/api/v1/keys").json()
        assert created["key"].startswith("credarr_")

        listed = client.get("/api/v1/keys").json()
        assert listed[0]["id"] == created["id"]
        assert listed[0]["prefix"] == created["key"][: len("credarr_") + 8]
        assert created["key"] not in json.dumps(listed)

        # A key authenticates on its own: no session, no cookie.
        client.cookies.clear()
        headers = {"Authorization": f"Bearer {created['key']}"}
        assert client.get("/api/v1/status", headers=headers).status_code == 200
        assert client.get("/api/v1/auth/me", headers=headers).json() == {
            "actor": f"key:{created['id']}",
            "auth": "key",
            "csrf": None,
        }
        assert client.get("/api/v1/keys", headers=headers).json()[0]["last_used_at"] is not None

        assert client.delete(f"/api/v1/keys/{created['id']}", headers=headers).status_code == 200
        assert client.get("/api/v1/status", headers=headers).status_code == 401
        assert client.delete(f"/api/v1/keys/{created['id']}", headers=headers).status_code == 401

        # Revoking something that is not there is a 404 for an authenticated
        # caller, not an auth failure for a revoked key.
        assert client.post("/api/v1/auth/login", json={"password": PASSWORD}).status_code == 200
        refresh_csrf(client)
        assert client.delete("/api/v1/keys/999").status_code == 404


def test_configured_timezone_is_validated(monkeypatch) -> None:
    from credarr_server.app import _configured_timezone

    monkeypatch.setenv("TZ", "America/New_York")
    assert _configured_timezone() == "America/New_York"
    monkeypatch.setenv("TZ", "Not/A_Zone")
    assert _configured_timezone() == "UTC"
    monkeypatch.delenv("TZ")
    assert _configured_timezone() == "UTC"


def test_status_reports_the_recorded_audit(server) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        state = wait_for_audit(client)
    assert state["version"] == __version__
    assert state["timezone"] == "UTC"
    assert state["scheduler"]["running"] is True and state["scheduler"]["failure"] is None
    assert state["topology"] == {
        "imported": True,
        "credentials": 2,
        "holders": 1,
        "services": ["seerr", "sonarr"],
    }
    assert state["last_run"]["exit_code"] == 0
    assert state["last_audit"]["exit_status"] == "match"
    assert state["auto_rotation"] == {
        "running": True,
        "failure": None,
        "eligible": True,
        "enabled": 0,
    }


def test_service_connection_test_never_stores_or_echoes_the_key(server) -> None:
    """The wizard tests a URL/key pair before anything is written.

    The key is request-only: a refused URL cannot put it in a response, and an
    untestable service cannot turn it into a stored credential.
    """
    secret = "super-secret-service-key"  # gitleaks:allow - test fixture
    with TestClient(server) as client:
        setup_admin(client)
        before = server.state.store.working_copy_times()
        refused = client.post(
            "/api/v1/services/test",
            json={"service": "sonarr", "url": "not-a-url", "key": secret},
        )
        assert refused.status_code == 400
        assert secret not in refused.text

        untestable = client.post(
            "/api/v1/services/test",
            json={"service": "not-in-catalog", "url": "http://host:1", "key": secret},
        )
        assert untestable.status_code == 200
        assert untestable.json()["ok"] is False
        assert secret not in untestable.text

        assert secret not in client.get("/api/v1/topology/export").text
        assert secret not in client.get("/api/v1/services").text
        # A test is a response, not a write: no working copy appeared or moved.
        assert server.state.store.working_copy_times() == before


def test_service_connection_test_uses_the_stored_key_when_none_is_typed(server) -> None:
    """Pressing Test with an empty key field tests the stored key at the URL
    the app already saved. The value never reaches the browser either way;
    only the verdict does."""
    secret = "seerr-service-key-000000000000"
    with TestClient(server) as client:
        setup_admin(client)
        # Radarr has no stored key here, so the engine still asks for one.
        unstored = client.post(
            "/api/v1/services/test",
            json={"service": "radarr", "url": "http://127.0.0.1:9", "key": None},
        )
        assert unstored.status_code == 200
        assert unstored.json()["ok"] is False
        assert "Enter the service API key" in unstored.json()["detail"]
        # Seerr's key is stored and this is its saved URL, so the probe runs
        # with it: a trailing slash is the same URL, and the key appears
        # nowhere in the answer.
        saved = server.state.config.host("local").urls["seerr"]
        stored = client.post(
            "/api/v1/services/test",
            json={"service": "seerr", "url": saved + "/", "key": None},
        )
        assert stored.status_code == 200
        assert stored.json()["ok"] is True, stored.json()
        assert "API key was accepted" in stored.json()["detail"]
        assert secret not in stored.text


def test_a_stored_key_is_never_sent_to_another_url(server, monkeypatch) -> None:
    """The stored key is a capability; the caller-supplied URL is not a place
    to spend it. A different URL requires a typed key, before any probe."""
    calls: list[tuple] = []

    def record(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("the probe must not run with the stored key")

    monkeypatch.setattr("credarr_server.app.probe_service_connection", record)
    with TestClient(server) as client:
        setup_admin(client)
        for url in ("http://attacker.invalid:8989", "http://127.0.0.1:9"):
            response = client.post(
                "/api/v1/services/test",
                json={"service": "seerr", "url": url, "key": None},
            )
            assert response.status_code == 400
            assert "Save this URL before testing" in response.json()["detail"]
            assert "seerr-service-key" not in response.text
    assert calls == []


def test_a_typed_key_may_test_any_url(server, monkeypatch) -> None:
    """The escape hatch is intentional: a different URL is fine when the
    operator supplies the key, because then the stored value is not involved."""
    seen: list[tuple] = []

    def record(system, url, key, *args, **kwargs):
        seen.append((system, url, key))
        return SimpleNamespace(ok=True, detail="accepted", version=None)

    monkeypatch.setattr("credarr_server.app.probe_service_connection", record)
    with TestClient(server) as client:
        setup_admin(client)
        response = client.post(
            "/api/v1/services/test",
            json={
                "service": "seerr",
                "url": "http://elsewhere.invalid:5055",
                "key": "typed-key-0123456789",
            },
        )
    assert response.status_code == 200
    assert response.json() == {"ok": True, "detail": "accepted", "version": None}
    assert seen == [("seerr", "http://elsewhere.invalid:5055", "typed-key-0123456789")]
    assert "typed-key-0123456789" not in response.text


def test_no_service_secret_reaches_a_payload(server) -> None:
    """BFF discipline: the browser never receives a service credential.

    Every read endpoint is asked, because the discipline is about the surface,
    not about the one endpoint that happened to expose a value first.
    """
    with TestClient(server) as client:
        setup_admin(client)
        state = wait_for_audit(client)
        payloads = [
            json.dumps(state),
            client.get("/api/v1/status").text,
            client.get("/api/v1/credentials").text,
            client.get("/api/v1/topology/export").text,
            client.get("/api/v1/keys").text,
            client.get("/api/v1/events").text,
            client.get("/api/v1/credentials/sonarr_api_key/auto-rotation").text,
            client.get("/api/v1/credentials/sonarr_api_key/rotation-options").text,
            client.get("/api/v1/health").text,
        ]
    for payload in payloads:
        for value in (SONARR_KEY, RADARR_KEY, PROWLARR_KEY):
            assert value not in payload


def test_a_dead_scheduler_is_surfaced_as_degraded(server, monkeypatch) -> None:
    """An unwritable database ends the loop; the process must stop looking healthy."""

    def dead(self) -> None:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(Scheduler, "once", dead)
    with TestClient(server) as client:
        setup_admin(client)
        def degraded():
            answer = client.get("/api/v1/health")
            return answer if answer.status_code == 503 else None

        response = poll_for(degraded, "the health endpoint never reported degraded")
        assert response.status_code == 503
        body = response.json()
        assert body["status"] == "degraded" and "database is locked" in body["scheduler"]
        state = client.get("/api/v1/status").json()
        assert state["scheduler"]["failure"] is not None
        assert state["auto_rotation"]["eligible"] is False


def test_a_dead_auto_worker_is_degraded(server) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        server.state.auto.failure = "worker stopped"
        response = client.get("/api/v1/health")
    assert response.status_code == 503
    assert response.json()["auto_rotation"] == "worker stopped"


def test_enabled_auto_without_a_worker_is_degraded(server, app) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        auto = server.state.auto
        auto.stop()
        app.store.enable_auto_rotation("sonarr_api_key", 30, now=0)
        response = client.get("/api/v1/health")
    assert response.status_code == 503
    assert response.json()["auto_rotation"] == "not running"


def test_a_loop_that_never_started_is_not_healthy(server) -> None:
    """A host that runs the app without the lifespan has no ledger at all, and
    `/status` would say so while `/health` said ok."""
    response = TestClient(server).get("/api/v1/health")  # no context: no lifespan
    assert response.status_code == 503
    assert response.json() == {"status": "degraded", "scheduler": "not running"}


def test_api_responses_are_not_cacheable(server) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        for path in (
            "/api/v1/health",
            "/api/v1/status",
            "/api/v1/credentials",
            "/api/v1/topology/export",
        ):
            assert client.get(path).headers["cache-control"] == "no-store"
        assert "cache-control" not in client.get("/docs").headers


def test_responses_cannot_be_framed(server) -> None:
    """A live admin session must not be clickjackable, including /docs."""
    with TestClient(server) as client:
        for path in ("/api/v1/health", "/docs"):
            response = client.get(path)
            assert response.headers["x-frame-options"] == "DENY"
            assert response.headers["content-security-policy"] == "frame-ancestors 'none'"


def test_the_audit_interval_is_persisted_and_applied_without_a_restart(
    app, tmp_path
) -> None:
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        current = client.get("/api/v1/settings/audit").json()
        assert current["interval_seconds"] == 3600.0
        assert current["minimum_seconds"] == 60.0

        changed = client.put(
            "/api/v1/settings/audit", json={"interval_seconds": 120}
        )
        assert changed.status_code == 200
        assert changed.json()["interval_seconds"] == 120.0
        assert client.get("/api/v1/status").json()["scheduler"]["interval_seconds"] == 120.0

        for bad in (30, 60 * 60 * 24 * 8, "soon"):
            assert client.put(
                "/api/v1/settings/audit", json={"interval_seconds": bad}
            ).status_code == 422

    assert app.store.audit_interval() == 120.0
    # A new process reads the persisted value instead of the boot default.
    restarted = make_server(app, tmp_path)
    assert restarted.state.loop.scheduler.interval == 120.0
    assert restarted.state.auto.interval == 120.0
    assert restarted.state.loop.scheduler.next_due == restarted.state.auto.next_due
    assert restarted.state.loop.scheduler.has_due == restarted.state.auto.has_due


def test_the_audit_schedule_can_be_disabled_and_reenabled(app, tmp_path) -> None:
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        current = client.get("/api/v1/settings/audit").json()
        assert current["enabled"] is True

        disabled = client.put(
            "/api/v1/settings/audit",
            json={"interval_seconds": 120, "enabled": False},
        )
        assert disabled.status_code == 200, disabled.text
        assert disabled.json()["enabled"] is False
        status = client.get("/api/v1/status").json()["scheduler"]
        assert status["enabled"] is False
        assert status["interval_seconds"] == 120.0

        enabled = client.put(
            "/api/v1/settings/audit",
            json={"interval_seconds": 300, "enabled": True},
        )
        assert enabled.status_code == 200, enabled.text
        assert enabled.json()["enabled"] is True
        assert enabled.json()["interval_seconds"] == 300.0

    assert app.store.audit_enabled() is True
    assert app.store.audit_interval() == 300.0
    restarted = make_server(app, tmp_path)
    assert restarted.state.loop.scheduler.enabled is True
    assert restarted.state.loop.scheduler.interval == 300.0


def test_a_disabled_audit_schedule_persists_until_reenabled(app, tmp_path) -> None:
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        assert client.put(
            "/api/v1/settings/audit",
            json={"interval_seconds": 120, "enabled": False},
        ).status_code == 200
    assert app.store.audit_enabled() is False
    restarted = make_server(app, tmp_path)
    assert restarted.state.loop.scheduler.enabled is False


def test_the_audit_interval_needs_an_admin_session(server) -> None:
    with TestClient(server) as client:
        assert client.get("/api/v1/settings/audit").status_code == 401
        assert client.put(
            "/api/v1/settings/audit", json={"interval_seconds": 120}
        ).status_code == 401


def test_status_says_when_no_topology_is_loaded(app, tmp_path) -> None:
    """The false clean this pins: an empty store audits 0 / match - engine
    parity with the CLI reading an empty manifest - so the flag is the only
    thing separating "never looked" from "all clean"."""
    data = tmp_path / "data"
    data.mkdir()
    with TestClient(make_server(app, tmp_path, config_dir=data)) as client:
        setup_admin(client)
        state = wait_for_audit(client)
    assert state["topology"] == {
        "imported": False,
        "credentials": 0,
        "holders": 0,
        "services": [],
    }
    assert state["last_run"]["exit_code"] == 0
    assert state["last_audit"]["exit_status"] == "match"
    assert state["auto_rotation"] == {
        "running": True,
        "failure": None,
        "eligible": True,
        "enabled": 0,
    }


def test_main_refuses_an_interval_that_would_spin_the_loop(tmp_path) -> None:
    """Zero and negatives are obvious; `nan` is not - `Event.wait(nan)` returns
    immediately, so it would audit back-to-back with `/health` green."""
    for bad in ("0", "-5", "nan", "inf"):
        with pytest.raises(SystemExit) as caught:
            main(["--audit-interval", bad, "--config-dir", str(tmp_path)])
        assert caught.value.code == 2, bad


def test_main_reports_an_unusable_data_directory_as_exit_3(app, tmp_path, capsys) -> None:
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")
    config = server_config(app, tmp_path)
    assert main(["-c", str(config), "--config-dir", str(blocked / "sub")]) == 3
    assert "error:" in capsys.readouterr().err


def _paths(app) -> set[str]:
    """Every route the app serves, framework pages included.

    FastAPI 0.146 keeps an included router as a wrapper (`original_router`),
    so the walk descends into it. Touching that attribute is deliberate: a
    FastAPI upgrade that changes the nesting should fail this test, not
    silently widen the surface.
    """
    found: set[str] = set()
    stack = list(app.routes)
    while stack:
        route = stack.pop()
        path = getattr(route, "path", None)
        if path is not None:
            found.add(path)
            continue
        router = getattr(route, "original_router", None)
        if router is not None:
            stack.extend(router.routes)
    return found


def test_the_openapi_contract_is_pinned(server) -> None:
    """Adding an endpoint is fine; adding one outside /api/v1 is a decision.

    The route set is pinned too, because the OpenAPI document cannot see the
    framework's own pages: `/docs`, `/redoc` and `/openapi.json` are public and
    outside the prefix, and that is the whole list.
    """
    document = TestClient(server).get("/openapi.json").json()
    assert set(document["paths"]) == {
        "/api/v1/health",
        "/api/v1/auth/state",
        "/api/v1/auth/setup",
        "/api/v1/auth/login",
        "/api/v1/auth/logout",
        "/api/v1/auth/me",
        "/api/v1/auth/password",
        "/api/v1/auth/sessions",
        "/api/v1/auth/sessions/{session_id}",
        "/api/v1/keys",
        "/api/v1/keys/{key_id}",
        "/api/v1/status",
        "/api/v1/audit",
        "/api/v1/audit/jobs/{job_id}",
        "/api/v1/services",
        "/api/v1/services/test",
        "/api/v1/services/{name}",
        "/api/v1/discovery",
        "/api/v1/credentials",
        "/api/v1/credentials/{name}",
        "/api/v1/credentials/{name}/holders",
        "/api/v1/credentials/{name}/auto-rotation",
        "/api/v1/credentials/{name}/value",
        "/api/v1/credentials/{name}/plan",
        "/api/v1/credentials/{name}/rotate",
        "/api/v1/credentials/{name}/rotation-options",
        "/api/v1/topology/export",
        "/api/v1/topology/import",
        "/api/v1/settings/audit",
        "/api/v1/notifications/services",
        "/api/v1/notifications/services/test",
        "/api/v1/notifications/services/{name}",
        "/api/v1/notifications/services/{name}/test",
        "/api/v1/events",
    }
    assert document["info"]["title"] == "credarr"
    assert document["info"]["version"] == __version__
    assert {"200", "202"} <= set(
        document["paths"]["/api/v1/audit"]["post"]["responses"]
    )
    assert _paths(server) == {
        "/api/v1/health",
        "/api/v1/auth/state",
        "/api/v1/auth/setup",
        "/api/v1/auth/login",
        "/api/v1/auth/logout",
        "/api/v1/auth/me",
        "/api/v1/auth/password",
        "/api/v1/auth/sessions",
        "/api/v1/auth/sessions/{session_id}",
        "/api/v1/keys",
        "/api/v1/keys/{key_id}",
        "/api/v1/status",
        "/api/v1/audit",
        "/api/v1/audit/jobs/{job_id}",
        "/api/v1/services",
        "/api/v1/services/test",
        "/api/v1/services/{name}",
        "/api/v1/discovery",
        "/api/v1/credentials",
        "/api/v1/credentials/{name}",
        "/api/v1/credentials/{name}/holders",
        "/api/v1/credentials/{name}/auto-rotation",
        "/api/v1/credentials/{name}/value",
        "/api/v1/credentials/{name}/plan",
        "/api/v1/credentials/{name}/rotate",
        "/api/v1/credentials/{name}/rotation-options",
        "/api/v1/topology/export",
        "/api/v1/topology/import",
        "/api/v1/settings/audit",
        "/api/v1/notifications/services",
        "/api/v1/notifications/services/test",
        "/api/v1/notifications/services/{name}",
        "/api/v1/notifications/services/{name}/test",
        "/api/v1/events",
        "/openapi.json",
        "/docs",
        "/docs/oauth2-redirect",
        "/redoc",
    }


def test_a_notification_config_can_be_proven_before_saving(server, sink) -> None:
    """The Test button works from the form, not only from a saved row."""
    with TestClient(server) as client:
        setup_admin(client)
        response = client.post(
            "/api/v1/notifications/services/test",
            json={"name": "draft", "kind": "webhook", "url": sink.url},
        )
        assert response.status_code == 200, response.text
        assert response.json() == {"ok": True, "detail": ""}
        assert client.get("/api/v1/notifications/services").json()["services"] == []
        assert json.loads(sink.requests[-1]["body"])["kind"] == "test"


def test_testing_an_edit_reuses_the_stored_secret(server, sink) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        created = client.post(
            "/api/v1/notifications/services",
            json={
                "name": "phone",
                "kind": "ntfy",
                "url": sink.url,
                "topic": "credarr",
                "token": "stored-token",
            },
        )
        assert created.status_code == 200, created.text
        response = client.post(
            "/api/v1/notifications/services/test?existing=phone",
            json={
                "name": "phone",
                "kind": "ntfy",
                "url": sink.url,
                "topic": "credarr",
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["ok"] is True
        assert sink.requests[-1]["headers"]["authorization"] == "Bearer stored-token"


def test_testing_a_changed_destination_does_not_reuse_a_stored_secret(
    server, sink
) -> None:
    """A stored write-only secret belongs to the destination it was saved for."""
    with TestClient(server) as client:
        setup_admin(client)
        created = client.post(
            "/api/v1/notifications/services",
            json={
                "name": "phone",
                "kind": "ntfy",
                "url": sink.url,
                "topic": "credarr",
                "token": "tok",
            },
        )
        assert created.status_code == 200, created.text
        before = len(sink.requests)
        response = client.post(
            "/api/v1/notifications/services/test?existing=phone",
            json={
                "name": "phone",
                "kind": "ntfy",
                "url": f"{sink.url}/elsewhere",
                "topic": "credarr",
            },
        )
        assert response.status_code == 400, response.text
        assert "re-enter the access token" in response.json()["detail"]
        assert len(sink.requests) == before


def test_a_changed_webhook_url_requires_its_secrets_again(server) -> None:
    """The same write-only-secret rule applies to a webhook edit."""
    with TestClient(server) as client:
        setup_admin(client)
        created = client.post(
            "/api/v1/notifications/services",
            json={
                "name": "hook",
                "kind": "webhook",
                "url": "https://old.example/hook",
                "auth_header": "Bearer old",
                "secret": "sig",
            },
        )
        assert created.status_code == 200, created.text
        refused = client.patch(
            "/api/v1/notifications/services/hook",
            json={"url": "https://new.example/hook"},
        )
        assert refused.status_code == 400, refused.text
        assert "re-enter the authorization header" in refused.json()["detail"]
        changed = client.patch(
            "/api/v1/notifications/services/hook",
            json={
                "url": "https://new.example/hook",
                "auth_header": "Bearer new",
                "secret": "sig2",
            },
        )
        assert changed.status_code == 200, changed.text


def test_an_email_draft_reuses_the_password_only_at_the_stored_smtp(
    server, monkeypatch
) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        created = client.post(
            "/api/v1/notifications/services",
            json={
                "name": "email",
                "kind": "email",
                "smtp_host": "smtp.example.test",
                "smtp_port": 587,
                "smtp_username": "credarr@example.test",
                "token": "pw",
                "smtp_from": "credarr@example.test",
                "smtp_to": "ops@example.test",
                "smtp_tls": "none",
                "smtp_auth": "auto",
            },
        )
        assert created.status_code == 200, created.text

        seen: dict[str, object] = {}

        def fake_test_unsaved(self, name, kind, **kwargs):
            seen.update(kwargs)
            return ""

        monkeypatch.setattr(Notifier, "test_unsaved", fake_test_unsaved)
        same = client.post(
            "/api/v1/notifications/services/test?existing=email",
            json={
                "name": "email",
                "kind": "email",
                "smtp_host": "smtp.example.test",
                "smtp_port": 587,
                "smtp_from": "credarr@example.test",
                "smtp_to": "ops@example.test",
                "smtp_tls": "none",
                "smtp_auth": "auto",
            },
        )
        assert same.status_code == 200, same.text
        assert seen["token"] == "pw"

        seen.clear()
        changed = client.post(
            "/api/v1/notifications/services/test?existing=email",
            json={
                "name": "email",
                "kind": "email",
                "smtp_host": "smtp.example.test",
                "smtp_port": 2525,
                "smtp_from": "credarr@example.test",
                "smtp_to": "ops@example.test",
                "smtp_tls": "none",
                "smtp_auth": "auto",
            },
        )
        assert changed.status_code == 400, changed.text
        assert "re-enter the password" in changed.json()["detail"]
        assert seen == {}


def test_a_notification_draft_is_validated_before_it_is_sent(server) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        response = client.post(
            "/api/v1/notifications/services/test",
            json={"name": "draft", "kind": "webhook"},
        )
        assert response.status_code == 400
        assert "needs a url" in response.json()["detail"]


def test_named_services_are_plural_and_carry_their_own_switches(server, sink) -> None:
    """Two services of one kind, each with its own name, enabled switch,
    event-kind selection and success/failure counts."""
    with TestClient(server) as client:
        setup_admin(client)
        wait_for_audit(client)
        one = client.post(
            "/api/v1/notifications/services",
            json={"name": "Ops hook", "kind": "webhook", "url": sink.url},
        )
        assert one.status_code == 200, one.text
        two = client.post(
            "/api/v1/notifications/services",
            json={
                "name": "Quiet hook",
                "kind": "webhook",
                "url": f"{sink.url}/quiet",
                "enabled": False,
                "enabled_types": ["auto_blocked"],
            },
        )
        assert two.status_code == 200, two.text

        listed = client.get("/api/v1/notifications/services").json()
        assert [service["name"] for service in listed["services"]] == [
            "Ops hook",
            "Quiet hook",
        ]
        assert listed["types"] == ["ntfy", "webhook", "discord", "telegram", "email"]
        assert "drift" in listed["kinds"]

        tested = client.post("/api/v1/notifications/services/Ops%20hook/test")
        assert tested.status_code == 200, tested.text
        assert [delivery["state"] for delivery in tested.json()["deliveries"]] == [
            "delivered"
        ]
        assert json.loads(sink.requests[-1]["body"])["kind"] == "test"

        # A disabled service is not sent, and says so when asked to test it.
        refused = client.post("/api/v1/notifications/services/Quiet%20hook/test")
        assert refused.status_code == 400
        assert refused.json()["detail"] == "Quiet hook is disabled"

        # The counts are derived from the delivery rows, per service.
        listed = client.get("/api/v1/notifications/services").json()["services"]
        stats = {service["name"]: service["stats"] for service in listed}
        assert stats["Ops hook"]["delivered"] == 1
        assert stats["Quiet hook"] == {"delivered": 0, "failed": 0, "pending": 0}


def test_a_service_is_edited_and_deleted_by_name(server) -> None:
    """Create, patch, conflict, unknown name, delete - the CRUD the console
    needs to stop limiting itself to four fixed sinks."""
    with TestClient(server) as client:
        setup_admin(client)
        created = client.post(
            "/api/v1/notifications/services",
            json={
                "name": "team-discord",
                "kind": "discord",
                "url": "https://discord.example/api/webhooks/1/x",
            },
        )
        assert created.status_code == 200, created.text
        assert created.json()["service"]["enabled"] is True

        patched = client.patch(
            "/api/v1/notifications/services/team-discord",
            json={
                "discord_username": "credarr",
                "discord_avatar": "https://example.invalid/avatar.png",
                "discord_here": True,
                "enabled_types": ["drift", "recovered"],
                "enabled": False,
            },
        )
        assert patched.status_code == 200, patched.text
        service = patched.json()["service"]
        assert service["discord_username"] == "credarr"
        assert service["discord_here"] is True
        assert service["enabled"] is False
        assert service["enabled_types"] == ["drift", "recovered"]
        assert "discord.example" in service["url"]

        # An explicit `null` clears the selection to "every kind".
        cleared = client.patch(
            "/api/v1/notifications/services/team-discord", json={"enabled_types": None}
        )
        assert cleared.json()["service"]["enabled_types"] == []

        # The url and the secret are omitted on the way out, as ever.
        assert "https://discord.example/api/webhooks/1/x" in patched.text

        duplicate = client.post(
            "/api/v1/notifications/services",
            json={"name": "team-discord", "kind": "discord", "url": "https://x.example"},
        )
        assert duplicate.status_code == 409
        unknown_type = client.post(
            "/api/v1/notifications/services",
            json={"name": "pigeon", "kind": "carrier-pigeon", "url": "https://x.example"},
        )
        assert unknown_type.status_code == 400
        assert unknown_type.json()["detail"] == "unknown service type: carrier-pigeon"
        assert client.patch(
            "/api/v1/notifications/services/nope", json={"enabled": False}
        ).status_code == 404
        assert client.delete("/api/v1/notifications/services/nope").status_code == 404
        # The kind is not patchable: a different mechanism is a different row.
        assert (
            client.patch(
                "/api/v1/notifications/services/team-discord", json={"kind": "ntfy"}
            ).status_code
            == 422
        )

        assert client.delete("/api/v1/notifications/services/team-discord").status_code == 200
        assert client.get("/api/v1/notifications/services").json()["services"] == []


def test_the_ntfy_token_rule_covers_named_services_too(server) -> None:
    """A changed ntfy server needs the token re-entered, an explicit empty
    token is a decision, and an unknown notification type is refused before it
    is stored."""
    with TestClient(server) as client:
        setup_admin(client)
        created = client.post(
            "/api/v1/notifications/services",
            json={
                "name": "phone",
                "kind": "ntfy",
                "url": "https://ntfy.example",
                "topic": "credarr",
                "token": "ntfy-token",
            },
        )
        assert created.status_code == 200, created.text

        refused = client.patch(
            "/api/v1/notifications/services/phone", json={"url": "https://other.example"}
        )
        assert refused.status_code == 400
        assert refused.json()["detail"] == (
            "the ntfy server URL changed; re-enter the access token"
        )
        assert (
            client.get("/api/v1/notifications/services").json()["services"][0]["url"]
            == "https://ntfy.example"
        )

        moved = client.patch(
            "/api/v1/notifications/services/phone",
            json={"url": "https://other.example", "token": "ntfy-token"},
        )
        assert moved.status_code == 200, moved.text
        # Clearing it is explicit and unblocks the next URL edit.
        cleared = client.patch(
            "/api/v1/notifications/services/phone", json={"token": ""}
        )
        assert cleared.status_code == 200
        assert cleared.json()["service"]["token_configured"] is False
        assert (
            client.patch(
                "/api/v1/notifications/services/phone",
                json={"url": "https://third.example"},
            ).status_code
            == 200
        )

        bad_kind = client.patch(
            "/api/v1/notifications/services/phone", json={"enabled_types": ["nope"]}
        )
        assert bad_kind.status_code == 400
        assert bad_kind.json()["detail"] == "unknown notification type: nope"


def test_the_test_button_proves_a_service_that_filters_kinds(server, sink) -> None:
    """A service subscribed to one kind of real event must still be provable:
    the test event is a probe, not a subscription, so the filter does not
    swallow it and answer a misleading empty success."""
    with TestClient(server) as client:
        setup_admin(client)
        created = client.post(
            "/api/v1/notifications/services",
            json={
                "name": "quiet",
                "kind": "webhook",
                "url": sink.url,
                "enabled_types": ["drift"],
            },
        )
        assert created.status_code == 200, created.text

        tested = client.post("/api/v1/notifications/services/quiet/test")
        assert tested.status_code == 200, tested.text
        assert [delivery["state"] for delivery in tested.json()["deliveries"]] == [
            "delivered"
        ]


def test_discord_and_telegram_round_trip_without_echoing_the_bot_token(server) -> None:
    """The two chat sinks reuse the row shape: Discord's webhook URL is the
    destination, Telegram keeps its chat id in `topic` and its bot token
    write-only, like every other stored secret."""
    with TestClient(server) as client:
        setup_admin(client)
        discord = client.post(
            "/api/v1/notifications/services",
            json={
                "name": "discord",
                "kind": "discord",
                "url": "https://discord.example/api/webhooks/1/x",
            },
        )
        assert discord.status_code == 200, discord.text
        telegram = client.post(
            "/api/v1/notifications/services",
            json={
                "name": "telegram",
                "kind": "telegram",
                "url": "https://api.telegram.org",
                "topic": "4242",
                "token": "123:bot-token",
            },
        )
        assert telegram.status_code == 200, telegram.text
        assert telegram.json()["service"]["topic"] == "4242"
        assert telegram.json()["service"]["token_configured"] is True
        assert "bot-token" not in telegram.text

        # An edit that does not mention the token keeps it.
        kept = client.patch(
            "/api/v1/notifications/services/telegram", json={"topic": "99"}
        )
        assert kept.status_code == 200
        assert kept.json()["service"]["topic"] == "99"
        assert kept.json()["service"]["token_configured"] is True

        changed_base = client.patch(
            "/api/v1/notifications/services/telegram",
            json={"url": "https://telegram.example"},
        )
        assert changed_base.status_code == 400
        assert "re-enter the bot token" in changed_base.json()["detail"]

        # Clearing it is refused: Telegram cannot send without one.
        refused = client.patch(
            "/api/v1/notifications/services/telegram", json={"token": ""}
        )
        assert refused.status_code == 400
        assert refused.json()["detail"] == "telegram needs a bot token"
        assert client.get("/api/v1/notifications/services").json()["services"][1][
            "token_configured"
        ] is True


def test_email_round_trips_without_echoing_the_smtp_password(server) -> None:
    """Email uses Arcane's field model; the password is write-only like every
    other sink secret, and an omitted edit keeps it."""
    with TestClient(server) as client:
        setup_admin(client)
        created = client.post(
            "/api/v1/notifications/services",
            json={
                "name": "email",
                "kind": "email",
                "smtp_host": "smtp.example.test",
                "smtp_port": 587,
                "smtp_username": "credarr@example.test",
                "token": "smtp-app-password",
                "smtp_from": "Credarr <credarr@example.test>",
                "smtp_to": "ops@example.test\noncall@example.test",
                "smtp_tls": "starttls",
                "smtp_auth": "auto",
            },
        )
        assert created.status_code == 200, created.text
        service = created.json()["service"]
        assert service["smtp_host"] == "smtp.example.test"
        assert service["smtp_port"] == 587
        assert service["smtp_tls"] == "starttls"
        assert service["smtp_auth"] == "auto"
        assert "smtp-app-password" not in created.text
        assert service["token_configured"] is True

        kept = client.patch(
            "/api/v1/notifications/services/email",
            json={"smtp_tls": "ssl"},
        )
        assert kept.status_code == 200, kept.text
        assert kept.json()["service"]["token_configured"] is True
        assert kept.json()["service"]["smtp_tls"] == "ssl"

        refused_move = client.patch(
            "/api/v1/notifications/services/email",
            json={"smtp_port": 465},
        )
        assert refused_move.status_code == 400
        assert refused_move.json()["detail"] == (
            "the SMTP server changed; re-enter the password"
        )
        moved = client.patch(
            "/api/v1/notifications/services/email",
            json={"smtp_port": 465, "token": "smtp-app-password"},
        )
        assert moved.status_code == 200, moved.text

        cleared = client.patch(
            "/api/v1/notifications/services/email", json={"token": ""}
        )
        assert cleared.status_code == 400
        assert cleared.json()["detail"] == "email authentication needs a password"


def test_email_validation_refuses_incomplete_or_invalid_settings(server) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        for body in (
            {"name": "e1", "kind": "email"},
            {
                "name": "e2",
                "kind": "email",
                "smtp_host": "smtp.example.test",
                "smtp_from": "not-an-address",
                "smtp_to": "ops@example.test",
                "smtp_auth": "none",
            },
            {
                "name": "e3",
                "kind": "email",
                "smtp_host": "smtp.example.test",
                "smtp_from": "credarr@example.test",
                "smtp_to": "not-an-address",
                "smtp_auth": "none",
            },
            {
                "name": "e4",
                "kind": "email",
                "smtp_host": "smtp.example.test",
                "smtp_from": "credarr@example.test",
                "smtp_to": "ops@example.test",
                "smtp_tls": "tls",
                "smtp_auth": "none",
            },
            {
                "name": "e5",
                "kind": "email",
                "smtp_host": "smtp.example.test",
                "smtp_from": "credarr@example.test",
                "smtp_to": "ops@example.test",
                "smtp_auth": "auto",
            },
        ):
            assert client.post("/api/v1/notifications/services", json=body).status_code == 400, body


def test_a_sink_that_could_not_be_posted_to_is_refused_where_it_is_typed(server) -> None:
    """Validation at the edge, because the alternative is a notification that
    silently never arrives: a scheme this app will not post to, a sink with no
    URL, and a kind missing the field it cannot send without."""
    with TestClient(server) as client:
        setup_admin(client)
        for body in (
            {"name": "one", "kind": "webhook", "url": "file:///etc/passwd"},
            {"name": "two", "kind": "webhook"},
            {"name": "three", "kind": "ntfy", "url": "https://ntfy.example"},
            {"name": "four", "kind": "ntfy", "url": "ftp://ntfy.example", "topic": "x"},
            {"name": "five", "kind": "discord"},
            {"name": "six", "kind": "discord", "url": "file:///etc/passwd"},
            {"name": "seven", "kind": "telegram", "url": "https://api.telegram.org", "topic": "1"},
            {"name": "eight", "kind": "telegram", "url": "https://api.telegram.org", "token": "x"},
        ):
            assert client.post("/api/v1/notifications/services", json=body).status_code == 400, body
        # A typo'd key is refused, not skipped.
        assert (
            client.post(
                "/api/v1/notifications/services",
                json={"name": "nine", "kind": "webhook", "urll": "https://x.example"},
            ).status_code
            == 422
        )
        assert client.get("/api/v1/notifications/services").json()["services"] == []


def test_a_drift_becomes_an_event_and_the_test_button_delivers_it_now(server, sink) -> None:
    """The whole path over HTTP: a sink is configured, proven with the test
    button, and then a real audit drifts - and `/events` carries the transition
    with the sentence the audit wrote, not a value."""
    with TestClient(server) as client:
        setup_admin(client)
        wait_for_audit(client)  # baseline: match, and no event
        assert client.get("/api/v1/events").json()["events"] == []

        configured = client.post(
            "/api/v1/notifications/services",
            json={"name": "webhook", "kind": "webhook", "url": sink.url},
        )
        assert configured.status_code == 200, configured.text

        tested = client.post("/api/v1/notifications/services/webhook/test")
        assert tested.status_code == 200, tested.text
        assert [delivery["state"] for delivery in tested.json()["deliveries"]] == ["delivered"]
        assert json.loads(sink.requests[-1]["body"])["kind"] == "test"
        assert SONARR_KEY.encode() not in sink.requests[-1]["body"]

        server.state.store.set_value("sonarr_api_key", Secret("0" * 32))
        assert client.post("/api/v1/audit").status_code == 200

        events = client.get("/api/v1/events").json()
        assert [event["kind"] for event in events["events"]] == ["drift", "test"]
        drift, test_event = events["events"]
        assert drift["credential"] == "sonarr_api_key"
        # The sink's age travels with the list, so the console can tell an event
        # that is waiting from one that predates the sink and will never go.
        assert [sink["name"] for sink in events["sinks"]] == ["webhook"]
        # One-sided: the sink was configured before the event, so it must not
        # be newer. A slow audit widens the gap on that side, so a symmetric
        # tolerance here failed on a loaded runner.
        assert events["sinks"][0]["updated_at"] <= drift["at"] + 1
        assert drift["previous_status"] == "match"
        assert drift["status"] == "drift"
        assert drift["detail"].startswith("seerr.settings_json[sonarr]:")
        assert drift["sink"] is None
        assert test_event["credential"] is None
        assert test_event["sink"] == "webhook"
        assert [delivery["state"] for delivery in test_event["deliveries"]] == ["delivered"]


def test_a_dead_notifier_is_surfaced_as_degraded(server, monkeypatch) -> None:
    """A process whose notifier died still audits and still answers - and would
    still claim to notify. The same lie the scheduler's degraded state exists
    to prevent, so the delivery loop gets the same treatment."""
    def dead(self) -> None:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(Notifier, "tick", dead)
    with TestClient(server) as client:
        setup_admin(client)
        def degraded():
            answer = client.get("/api/v1/health")
            return answer if answer.status_code == 503 else None

        response = poll_for(degraded, "the health endpoint never reported degraded")
        assert response.status_code == 503
        assert response.json() == {
            "status": "degraded",
            "notifier": "OperationalError: database is locked",
        }


def test_auto_rotation_is_off_by_default_and_needs_a_typed_name(server) -> None:
    """Enabling is a future mutation, so it takes the typed-name assertion.

    The policy read is part of every credential row (the console's detail view
    uses that data), and the dedicated read has the same shape. Off is the
    default even when the credential was imported long before this feature.
    """
    with TestClient(server) as client:
        setup_admin(client)
        wait_for_audit(client)
        credentials = client.get("/api/v1/credentials").json()
        row = next(
            item for item in credentials["credentials"] if item["name"] == "sonarr_api_key"
        )
        assert row["auto_rotation"] == {
            "enabled": False,
            "every_days": None,
            "next_due_at": None,
            "last_check_at": None,
            "last_outcome": None,
            "last_detail": "",
            "paused": False,
        }
        assert (
            client.get("/api/v1/credentials/sonarr_api_key/auto-rotation").json()[
                "auto_rotation"
            ]
            == row["auto_rotation"]
        )

        path = "/api/v1/credentials/sonarr_api_key/auto-rotation"
        assert (
            client.put(
                path, json={"enabled": True, "every_days": 0, "confirm": "sonarr_api_key"}
            ).status_code
            == 422
        )
        assert (
            client.put(
                path, json={"enabled": True, "every_days": 366, "confirm": "sonarr_api_key"}
            ).status_code
            == 422
        )
        assert (
            client.put(
                path, json={"enabled": True, "every_days": 30, "confirm": "no"}
            ).status_code
            == 400
        )
        assert (
            client.put(
                path, json={"enabled": True, "confirm": "sonarr_api_key"}
            ).status_code
            == 400
        )
        response = client.put(
            path,
            json={"enabled": True, "every_days": 30, "confirm": "sonarr_api_key"},
        )
        assert response.status_code == 200
        policy = response.json()["auto_rotation"]
        assert policy["enabled"] is True and policy["paused"] is False
        assert policy["every_days"] == 30
        assert policy["next_due_at"] > time.time()
        assert client.get(path).status_code == 200
        changed = client.put(
            path,
            json={"enabled": True, "every_days": 7, "confirm": "sonarr_api_key"},
        )
        assert changed.status_code == 200
        changed_policy = changed.json()["auto_rotation"]
        assert changed_policy["enabled"] is True
        assert changed_policy["paused"] is False
        assert changed_policy["every_days"] == 7
        assert changed_policy["next_due_at"] > time.time()
        assert client.put(path, json={"enabled": False}).json()["auto_rotation"]["enabled"] is False


def test_enabling_auto_for_manual_copies_needs_explicit_confirmation(server) -> None:
    """The key may rotate, but the copy is left for a human. That is a separate
    acknowledgement from the typed credential name."""
    manifest = """
version: 1
credentials:
  sonarr_api_key:
    class: A-unv
    max_age_days: 90
    write: {mechanism: servarr_command}
    consumers:
      - target: homepage.label
        count: 1
        mechanism: redeploy
"""
    with TestClient(server) as client:
        setup_admin(client)
        imported = client.post(
            "/api/v1/topology/import?confirm=replace", content=manifest
        )
        assert imported.status_code == 200, imported.text
        row = next(
            item
            for item in client.get("/api/v1/credentials").json()["credentials"]
            if item["name"] == "sonarr_api_key"
        )
        assert row["consumers"][0]["manual"] is True
        assert row["consumers"][0]["holder"] is False
        path = "/api/v1/credentials/sonarr_api_key/auto-rotation"
        refused = client.put(
            path,
            json={"enabled": True, "every_days": 30, "confirm": "sonarr_api_key"},
        )
        assert refused.status_code == 400
        assert "need manual rotation" in refused.json()["detail"]
        assert "homepage.label" in refused.json()["detail"]

        accepted = client.put(
            path,
            json={
                "enabled": True,
                "every_days": 30,
                "confirm": "sonarr_api_key",
                "accept_manual": True,
            },
        )
        assert accepted.status_code == 200, accepted.text
        assert accepted.json()["auto_rotation"]["enabled"] is True


def test_re_enabling_after_a_pause_resets_the_schedule(server, app) -> None:
    """A pause needs a human; the re-enable is a fresh baseline, not a resume."""
    with TestClient(server) as client:
        setup_admin(client)
        wait_for_audit(client)
        path = "/api/v1/credentials/sonarr_api_key/auto-rotation"
        client.put(
            path,
            json={"enabled": True, "every_days": 30, "confirm": "sonarr_api_key"},
        )
        first = app.store.auto_rotation("sonarr_api_key")
        assert first is not None
        app.store.record_auto_rotation(
            "sonarr_api_key", "interrupted", "run did not finish", paused=True
        )
        paused = client.get(path).json()["auto_rotation"]
        assert paused["paused"] is True and paused["next_due_at"] is None
        time.sleep(0.01)
        response = client.put(
            path,
            json={"enabled": True, "every_days": 30, "confirm": "sonarr_api_key"},
        )
        enabled = response.json()["auto_rotation"]
        assert enabled["enabled"] is True and enabled["paused"] is False
        assert enabled["next_due_at"] > time.time()
        assert app.store.auto_rotation("sonarr_api_key").enabled_at > first.enabled_at


def test_re_enabling_a_paused_policy_waits_for_the_unfinished_run(server, app) -> None:
    """Re-enable is not a resume: the old run has to be answered first."""
    with TestClient(server) as client:
        setup_admin(client)
        wait_for_audit(client)
        path = "/api/v1/credentials/sonarr_api_key/auto-rotation"
        client.put(
            path,
            json={"enabled": True, "every_days": 30, "confirm": "sonarr_api_key"},
        )
        app.store.record_auto_rotation(
            "sonarr_api_key", "interrupted", "needs a human", paused=True
        )
        journal = facade.journal_for(app.config)
        attempt = journal.begin("sonarr_api_key")
        response = client.put(
            path,
            json={"enabled": True, "every_days": 30, "confirm": "sonarr_api_key"},
        )
        assert response.status_code == 409
        detail = response.json()["detail"]
        assert "resolve the unfinished rotation" in detail
        assert "attempt" in detail and "running a rotation" in detail
        assert app.store.auto_rotation("sonarr_api_key").paused is True

        # Disabling first is not a way around the unfinished run either.
        assert client.put(path, json={"enabled": False}).status_code == 200
        assert (
            client.put(
                path,
                json={"enabled": True, "every_days": 30, "confirm": "sonarr_api_key"},
            ).status_code
            == 409
        )

        # Once the operator has answered the old attempt, enabling is allowed.
        journal.finish(attempt, "failed")
        assert (
            client.put(
                path,
                json={"enabled": True, "every_days": 30, "confirm": "sonarr_api_key"},
            ).status_code
            == 200
        )


def test_auto_rotation_routes_are_authenticated_and_404_on_unknown_names(server) -> None:
    with TestClient(server) as client:
        path = "/api/v1/credentials/sonarr_api_key/auto-rotation"
        assert client.get(path).status_code == 401
        assert client.put(path, json={"enabled": False}).status_code == 401
        setup_admin(client)
        assert (
            client.put(
                "/api/v1/credentials/nope/auto-rotation",
                json={"enabled": True, "every_days": 30, "confirm": "nope"},
            ).status_code
            == 404
        )
        assert client.get("/api/v1/credentials/nope/auto-rotation").status_code == 404


def test_the_retired_restart_environment_variable_refuses_startup(
    tmp_path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("CREDARR_RESTART_URL", "http://127.0.0.1:2375")
    code = main(["-c", str(tmp_path / "missing.yaml"),
                 "--config-dir", str(tmp_path)])

    assert code == 3
    assert "CREDARR_RESTART_URL is gone" in capsys.readouterr().err


def test_repeated_wrong_logins_return_a_locked_response(server) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        client.post("/api/v1/auth/logout")
        for _ in range(5):
            assert (
                client.post(
                    "/api/v1/auth/login",
                    json={"password": "wrong"},
                ).status_code
                == 401
            )
        locked = client.post(
            "/api/v1/auth/login",
            json={"password": PASSWORD},
        )
        assert locked.status_code == 429
        assert "too many failed sign-in attempts" in locked.json()["detail"]
        assert int(locked.headers["retry-after"]) > 0


def test_secure_cookies_follow_the_environment_and_the_declared_url() -> None:
    """Three inputs, one policy: an https URL turns the flag on for everyone,
    and a contradiction is refused instead of guessed."""
    secure, warnings = resolve_session_security(
        flag=False, env_secure=None, external_url="https://credarr.example", host="0.0.0.0"
    )
    assert secure is True and warnings == []

    secure, _ = resolve_session_security(
        flag=False, env_secure="1", external_url=None, host="0.0.0.0"
    )
    assert secure is True

    secure, warnings = resolve_session_security(
        flag=False, env_secure=None, external_url=None, host="0.0.0.0"
    )
    assert secure is False
    assert warnings and "CREDARR_SECURE_COOKIES=1" in warnings[0]

    _secure, warnings = resolve_session_security(
        flag=False, env_secure=None, external_url=None, host="127.0.0.1"
    )
    assert warnings == [], "a loopback bind needs no warning"


def test_a_contradictory_session_security_is_refused() -> None:
    with pytest.raises(ValueError, match="https but CREDARR_SECURE_COOKIES=0"):
        resolve_session_security(
            flag=False,
            env_secure="0",
            external_url="https://credarr.example",
            host="0.0.0.0",
        )
    with pytest.raises(ValueError, match="http while secure cookies are on"):
        resolve_session_security(
            flag=False,
            env_secure="1",
            external_url="http://credarr.example",
            host="0.0.0.0",
        )
    with pytest.raises(ValueError, match="must be 1 or 0"):
        resolve_session_security(
            flag=False, env_secure="yes please", external_url=None, host="0.0.0.0"
        )
    with pytest.raises(ValueError, match="http or https URL"):
        resolve_session_security(
            flag=False, env_secure=None, external_url="credarr.example", host="0.0.0.0"
        )
