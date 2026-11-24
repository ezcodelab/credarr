"""Adoption and lifecycle: an external rotation joins the same barrier.

Adoption is the path that lets an operator replace a value outside Credarr and
prove it before the console believes it. The proof is the engine audit; a
candidate that does not match a declared holder stores nothing.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from conftest import SONARR_KEY, make_server, setup_admin


def _client(app, tmp_path):
    return TestClient(make_server(app, tmp_path))


def test_adoption_without_verification_is_stored_as_unverified(app, tmp_path) -> None:
    with _client(app, tmp_path) as client:
        setup_admin(client)
        response = client.post(
            "/api/v1/credentials/sonarr_api_key/adopt",
            json={
                "value": "adopted-value-0123456789",
                "confirm": "sonarr_api_key",
                "verify": "none",
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["verification"] == "unverified"
        versions = client.get("/api/v1/credentials/sonarr_api_key/versions").json()
        assert versions["versions"][0]["stage"] == "CURRENT"
        assert versions["versions"][0]["verification"] == "unverified"
        kinds = [event["kind"] for event in client.get("/api/v1/events").json()["events"]]
    assert "secret.adopted" in kinds
    assert "secret.current_changed" in kinds


def test_adoption_with_a_failed_process_readback_stores_nothing(app, tmp_path) -> None:
    with _client(app, tmp_path) as client:
        setup_admin(client)
        before = client.get("/api/v1/credentials/sonarr_api_key/versions").json()
        response = client.post(
            "/api/v1/credentials/sonarr_api_key/adopt",
            json={
                "value": "not-what-seerr-holds-0123456789",
                "confirm": "sonarr_api_key",
                "verify": "process_readback",
            },
        )
        after = client.get("/api/v1/credentials/sonarr_api_key/versions").json()
    assert response.status_code == 409
    assert "nothing was stored" in response.json()["detail"]
    assert before == after


def test_adoption_with_a_proven_value_is_verified(app, tmp_path) -> None:
    with _client(app, tmp_path) as client:
        setup_admin(client)
        response = client.post(
            "/api/v1/credentials/sonarr_api_key/adopt",
            json={
                "value": SONARR_KEY,
                "confirm": "sonarr_api_key",
                "verify": "process_readback",
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["verification"] == "verified"


def test_soft_delete_rejects_reveal_rotate_adopt_and_sync(app, tmp_path) -> None:
    with _client(app, tmp_path) as client:
        setup_admin(client)
        deleted = client.post(
            "/api/v1/credentials/sonarr_api_key/lifecycle",
            json={"action": "soft_delete", "confirm": "sonarr_api_key"},
        )
        assert deleted.status_code == 200, deleted.text
        assert deleted.json()["lifecycle"]["purge_after"] > 0
        for path, method, body in (
            ("/reveal", "post", {"stage": "CURRENT"}),
            ("/rotate", "post", {"confirm": "sonarr_api_key"}),
            (
                "/adopt",
                "post",
                {
                    "value": "candidate",
                    "confirm": "sonarr_api_key",
                    "verify": "none",
                },
            ),
            ("/value", "put", {"value": "candidate"}),
        ):
            response = getattr(client, method)(
                f"/api/v1/credentials/sonarr_api_key{path}", json=body
            )
            assert response.status_code == 409, (path, response.text)
        restored = client.post(
            "/api/v1/credentials/sonarr_api_key/lifecycle",
            json={"action": "restore"},
        )
        assert restored.status_code == 200
        reveal = client.post(
            "/api/v1/credentials/sonarr_api_key/reveal", json={"stage": "CURRENT"}
        )
    assert reveal.status_code == 200
    assert reveal.json()["value"] == SONARR_KEY


def test_a_purge_needs_soft_delete_and_force(app, tmp_path) -> None:
    with _client(app, tmp_path) as client:
        setup_admin(client)
        before = client.post(
            "/api/v1/credentials/sonarr_api_key/lifecycle",
            json={"action": "force_delete", "confirm": "sonarr_api_key", "force": True},
        )
        assert before.status_code == 409
        client.post(
            "/api/v1/credentials/sonarr_api_key/lifecycle",
            json={"action": "soft_delete", "confirm": "sonarr_api_key"},
        )
        without_force = client.post(
            "/api/v1/credentials/sonarr_api_key/lifecycle",
            json={"action": "force_delete", "confirm": "sonarr_api_key"},
        )
        assert without_force.status_code == 400
        purged = client.post(
            "/api/v1/credentials/sonarr_api_key/lifecycle",
            json={"action": "force_delete", "confirm": "sonarr_api_key", "force": True},
        )
        assert purged.status_code == 200, purged.text
        rows = client.get("/api/v1/credentials").json()["credentials"]
    assert all(row["name"] != "sonarr_api_key" for row in rows)
