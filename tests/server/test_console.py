"""The operator console's write surface: services, credentials and undo.

These pin the rules the console must not learn to lie about: a service edit
reaches the engine, a referenced service cannot be deleted, credential edits
go through the manifest parser, and a merge without `prune` never deletes a
name the imported file omits.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from conftest import SONARR_KEY, make_server, setup_admin
from credarr_server.source import runtime_config

NEW_MANIFEST = """
version: 1
credentials:
  prowlarr_api_key:
    class: A
    max_age_days: 90
    consumers:
      - target: sonarr.indexers
"""

MERGE_MANIFEST = """
version: 1
credentials:
  sonarr_api_key:
    class: A
    max_age_days: 90
    consumers:
      - target: sonarr.indexers
  signing_key:
    class: B
    never_rotate: true
"""


def test_service_crud_is_authenticated_and_validated(server) -> None:
    with TestClient(server) as client:
        assert client.post(
            "/api/v1/services",
            json={"name": "jellyfin", "kind": "jellyfin", "url": "http://jellyfin:8096"},
        ).status_code == 401
        setup_admin(client)
        response = client.post(
            "/api/v1/services",
            json={
                "name": "jellyfin",
                "kind": "jellyfin",
                "url": "http://jellyfin:8096/",
                "notes": "media server",
            },
        )
        assert response.status_code == 200
        service = response.json()["service"]
        assert service["url"] == "http://jellyfin:8096"
        assert service["declared"] is False

        definitions = {
            item["name"]: item for item in client.get("/api/v1/services").json()["definitions"]
        }
        assert definitions["jellyfin"]["notes"] == "media server"
        assert definitions["sonarr"]["declared"] is True

        assert client.post(
            "/api/v1/services",
            json={"name": "bad", "kind": "servarr"},
        ).status_code == 400
        assert client.post(
            "/api/v1/services",
            json={"name": "bad", "kind": "other", "url": "ftp://bad"},
        ).status_code == 400

        patched = client.patch(
            "/api/v1/services/jellyfin", json={"url": "http://jellyfin:8097"}
        )
        assert patched.status_code == 200
        assert patched.json()["service"]["url"] == "http://jellyfin:8097"

        # Re-sending the unchanged kind is not a URL edit; a seeded service
        # with no URL must stay editable.
        assert client.patch(
            "/api/v1/services/sonarr", json={"kind": "servarr"}
        ).status_code == 200
        assert client.patch(
            "/api/v1/services/jellyfin", json={"name": "other"}
        ).status_code == 400
        assert client.delete("/api/v1/services/jellyfin").status_code == 400
        assert client.delete(
            "/api/v1/services/jellyfin", params={"confirm": "jellyfin"}
        ).status_code == 200
        assert client.delete(
            "/api/v1/services/jellyfin", params={"confirm": "jellyfin"}
        ).status_code == 404


def test_a_referenced_service_cannot_be_deleted(server) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        response = client.delete(
            "/api/v1/services/sonarr", params={"confirm": "sonarr"}
        )
    assert response.status_code == 409
    assert "sonarr_api_key" in str(response.json()["detail"])
    assert "dependents" in response.json()["detail"]


def test_service_edits_are_the_engines_runtime_config(server) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        response = client.patch(
            "/api/v1/services/sonarr",
            json={
                "url": "http://sonarr:8989",
                "credential": "sonarr_api_key",
                "key": SONARR_KEY,
            },
        )
        assert response.status_code == 200
        effective = runtime_config(server.state.config, server.state.store)
        assert effective.host("local").urls["sonarr"] == "http://sonarr:8989"
        # Clearing a URL on an API service is refused rather than leaving a
        # definition that looks usable but cannot be planned.
        assert client.patch(
            "/api/v1/services/sonarr", json={"url": None}
        ).status_code == 400


def test_credential_and_holder_crud_uses_the_manifest_parser(server) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        body = {
            "name": "jellyfin_api_key",
            "class": "B",
            "never_rotate": True,
            "canonical": {"service": "jellyfin"},
            "consumers": [{"target": "sonarr.indexers", "count": 1}],
        }
        created = client.post("/api/v1/credentials", json=body)
        assert created.status_code == 200
        assert created.json()["credential"]["name"] == "jellyfin_api_key"
        assert created.json()["credential"]["stored"] is False
        assert "SONARR" not in created.text

        assert client.post("/api/v1/credentials", json=body).status_code == 409
        assert client.post(
            "/api/v1/credentials",
            json={**body, "name": "typo_key", "consumers": [{"target": "nope.indexers"}]},
        ).status_code == 400
        assert client.post(
            "/api/v1/credentials", json={**body, "name": "extra_key", "surprise": 1}
        ).status_code == 422

        patched = client.patch(
            "/api/v1/credentials/jellyfin_api_key",
            json={"description": "Jellyfin key", "max_age_days": 30},
        )
        assert patched.status_code == 200
        assert patched.json()["credential"]["description"] == "Jellyfin key"

        holders = client.put(
            "/api/v1/credentials/jellyfin_api_key/holders",
            json={"consumers": [{"target": "sonarr.indexers"}]},
        )
        assert holders.status_code == 200
        assert holders.json()["consumers"][0]["target"] == "sonarr.indexers"
        row = next(
            item
            for item in client.get("/api/v1/credentials").json()["credentials"]
            if item["name"] == "jellyfin_api_key"
        )
        assert [holder["target"] for holder in row["consumers"]] == [
            "sonarr.indexers"
        ]

        assert client.delete("/api/v1/credentials/jellyfin_api_key").status_code == 400
        assert client.delete(
            "/api/v1/credentials/jellyfin_api_key",
            params={"confirm": "jellyfin_api_key"},
        ).status_code == 200
        assert client.delete(
            "/api/v1/credentials/jellyfin_api_key",
            params={"confirm": "jellyfin_api_key"},
        ).status_code == 404


def test_merge_does_not_delete_and_prune_does(app, tmp_path) -> None:
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        replaced = client.post(
            "/api/v1/topology/import",
            params={"confirm": "replace"},
            content=NEW_MANIFEST,
        )
        assert replaced.status_code == 200
        assert replaced.json()["mode"] == "replace"

        merged = client.post(
            "/api/v1/topology/import",
            json={"mode": "merge", "yaml": MERGE_MANIFEST},
        )
        assert merged.status_code == 200
        names = {row["name"] for row in client.get("/api/v1/credentials").json()["credentials"]}
        assert names == {"prowlarr_api_key", "sonarr_api_key", "signing_key"}

        pruned = client.post(
            "/api/v1/topology/import",
            json={"mode": "merge", "prune": True, "yaml": MERGE_MANIFEST, "confirm": "merge"},
        )
        assert pruned.status_code == 200
        assert pruned.json()["pruned"] is True
        names = {row["name"] for row in client.get("/api/v1/credentials").json()["credentials"]}
        assert names == {"sonarr_api_key", "signing_key"}


def test_json_replace_requires_the_typed_word(app, tmp_path) -> None:
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        assert client.post(
            "/api/v1/topology/import",
            json={"mode": "replace", "yaml": NEW_MANIFEST},
        ).status_code == 400
        assert client.post(
            "/api/v1/topology/import",
            json={"mode": "replace", "yaml": NEW_MANIFEST, "confirm": "replace"},
        ).status_code == 200
