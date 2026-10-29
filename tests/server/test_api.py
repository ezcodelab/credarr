"""The console's surface: the declared topology, pasted values, and run-now.

These pin the claims the SPA is built on: the declared topology reads back with
each holder's managed / monitor-only answer, `stored` says whether the app has
a value at all (the difference between "no value stored yet" and the engine's
own UNVERIFIABLE wording), a pasted value is audited as the runtime canonical
and never comes back out, a pasted topology replaces the old one in one
transaction, a bad upload changes nothing, and an audit can be asked for on the
spot.
"""

from __future__ import annotations

import sqlite3
import threading
import time

import pytest
from fastapi.testclient import TestClient

from conftest import SONARR_KEY, make_server, poll_for, setup_admin, wait_for_audit
from credarr import facade
from credarr.errors import TransportError
from credarr.executor import ExecutionResult, HolderOutcome
from credarr.redact import Secret
from credarr.services import HolderFacts, ServiceFacts, ServiceObservation, ServiceReport
from credarr_server.audit_log import AuditLog

# One credential with one API-only holder: the import must be what the console
# knows afterwards, not the store the fixture seeded. The holder is unmanaged,
# because no measured version is recorded for sonarr.
NEW_MANIFEST = """
version: 1
credentials:
  prowlarr_api_key:
    class: A
    max_age_days: 90
    vault:
      backend: sops
      file: secrets.enc.yaml
      path: [keys, prowlarr_api_key]
    consumers:
      - target: sonarr.indexers
        count: 2
"""


def _raw_import(client, content):
    """The legacy raw-YAML body, with the confirmation v1 requires."""
    return client.post(
        "/api/v1/topology/import?confirm=replace", content=content
    )


def test_credentials_read_back_the_declared_topology(server) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        wait_for_audit(client)
        body = client.get("/api/v1/credentials").json()
    assert list(body) == ["observed_run", "credentials"]
    # Every status in the payload is dated by the run it came from.
    assert isinstance(body["observed_run"]["id"], int)
    assert body["observed_run"]["finished_at"] > 0

    row = next(r for r in body["credentials"] if r["name"] == "sonarr_api_key")
    assert row["name"] == "sonarr_api_key"
    assert row["class"] == "A" and row["max_age_days"] == 90
    assert row["never_rotate"] is False and row["provisioned"] is True
    assert row["stored"] is True  # the fixture seeded the working copy
    assert row["vault"] == {
        "backend": "ansible-vault",
        "file": "vault.yml",
        "path": ["keys", "sonarr_api_key"],
    }
    assert row["status"] == "match"
    assert row["reason"] == "match"

    (holder,) = row["consumers"]
    assert holder["target"] == "seerr.settings_json[sonarr]" and holder["count"] == 1
    assert holder["reason"] == "match"
    # The live count the audit saw, next to the declaration: the console can
    # compare them and propose the count instead of asking for a hand count.
    assert holder["observed_count"] == 1
    # The Seerr settings API is readable, and 3.5.0 is the measured version,
    # so this holder can say it is managed.
    assert holder["holder"] is True
    assert holder["exercised"] is True
    assert holder["version"] == "3.5.0"
    assert holder["provenance"] == "measured against 3.5.0"
    assert holder["managed"] is True
    assert holder["status"] == "match"
    assert "running seerr process" in holder["detail"]


def test_a_credential_declared_after_the_last_run_reads_as_not_audited(app, tmp_path) -> None:
    """A fresh declaration has no status, rather than borrowing the one a
    topology that no longer exists was audited with."""
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        wait_for_audit(client)
        assert _raw_import(client, NEW_MANIFEST).status_code == 200
        row = client.get("/api/v1/credentials").json()["credentials"][0]
    assert row["name"] == "prowlarr_api_key"
    assert row["status"] is None and row["detail"] is None
    assert row["stored"] is False
    assert all(consumer["status"] is None for consumer in row["consumers"])

    (indexers,) = row["consumers"]
    # A writer exists for indexers, and Sonarr's version is recorded: the
    # managed claim follows from both facts.
    assert indexers["target"] == "sonarr.indexers" and indexers["count"] == 2
    # Never audited as declared: no live count to compare, not a zero.
    assert indexers["observed_count"] is None
    assert indexers["holder"] is True
    assert indexers["version"] == "4.0.20.3014"
    assert indexers["provenance"] == "measured against 4.0.20.3014"
    assert indexers["managed"] is True


def test_a_holder_edit_under_the_same_name_does_not_borrow_the_old_status(app, tmp_path) -> None:
    """The name is not the identity: the engine's credential status is an
    aggregate over its holders, so once the declared holders change the old
    score is about a topology that no longer exists. The untouched holder keeps
    the status it was actually given; the credential does not."""
    edited = app.manifest.read_text(encoding="utf-8").replace(
        "      - target: seerr.settings_json[sonarr]\n"
        "        count: 1\n"
        "        mechanism: process_api\n",
        "      - target: seerr.settings_json[sonarr]\n"
        "        count: 1\n"
        "        mechanism: process_api\n"
        "      - target: sonarr.indexers\n        count: 2\n",
    )
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        wait_for_audit(client)
        assert _raw_import(client, edited).status_code == 200
        row = next(
            r for r in client.get("/api/v1/credentials").json()["credentials"]
            if r["name"] == "sonarr_api_key"
        )
    assert row["name"] == "sonarr_api_key"
    assert row["status"] is None and row["detail"] is None
    seerr_holder, indexers = row["consumers"]
    assert seerr_holder["status"] == "match"  # audited at this position, unchanged
    assert seerr_holder["observed_count"] == 1
    assert indexers["status"] is None  # never audited as declared
    assert indexers["observed_count"] is None


def test_a_value_pasted_after_the_run_voids_the_old_status(app, tmp_path) -> None:
    """The other half of the same rule: the run measured a different value, so
    its verdict is about a canonical that is no longer the one stored. Until an
    audit runs, `stored` is true and there is no status - not the old one."""
    pasted = "pasted-after-the-run-0123456789"  # gitleaks:allow - a test value
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        wait_for_audit(client)
        assert next(
            r for r in client.get("/api/v1/credentials").json()["credentials"]
            if r["name"] == "sonarr_api_key"
        )["status"] == "match"
        assert client.put(
            "/api/v1/credentials/sonarr_api_key/value", json={"value": pasted}
        ).status_code == 200
        row = next(
            r for r in client.get("/api/v1/credentials").json()["credentials"]
            if r["name"] == "sonarr_api_key"
        )
        assert row["stored"] is True
        assert row["status"] is None and row["detail"] is None
        assert row["consumers"][0]["status"] is None
        # Asking for a run re-measures it, and the new verdict is shown.
        assert client.post("/api/v1/audit").status_code == 200
        row = next(
            r for r in client.get("/api/v1/credentials").json()["credentials"]
            if r["name"] == "sonarr_api_key"
        )
    assert row["status"] == "drift"


def test_import_replaces_the_topology_and_prunes_undeclared_values(app, tmp_path) -> None:
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        response = _raw_import(client, NEW_MANIFEST)
        assert response.status_code == 200
        body = response.json()
        assert body["ok"] is True and body["credentials"] == 1
        assert body["mode"] == "replace"
        assert body["warnings"] == []
        rows = client.get("/api/v1/credentials").json()["credentials"]
    assert [row["name"] for row in rows] == ["prowlarr_api_key"]
    # Replace, not merge: a secret kept for a name nothing references is a
    # secret kept for no reason.
    assert app.store.working_copy_times() == {}
    assert app.store.get_value("sonarr_api_key") is None


def test_import_warns_when_a_mintable_service_key_is_audit_only(app, tmp_path) -> None:
    """A class B service API key is still allowed, but the operator is told.

    A password or a deliberately frozen key is legitimately audit-only; the
    warning names only the `_api_key` shape whose service can actually mint.
    """
    manifest = """
version: 1
credentials:
  seerr_api_key:
    class: B
    max_age_days: 90
  sonarr_ui_password:
    class: B
    never_rotate: true
  sonarr_api_key:
    class: A
    max_age_days: 90
    write: {mechanism: servarr_command}
"""
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        response = _raw_import(client, manifest)
    assert response.status_code == 200, response.text
    assert response.json()["warnings"] == [
        {"credential": "seerr_api_key", "service": "seerr"}
    ]


def test_raw_yaml_replace_requires_the_typed_confirmation(app, tmp_path) -> None:
    """The legacy body still replaces, but silently dropping working copies is
    not a default. Missing or wrong confirmation changes nothing."""
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        before = client.get("/api/v1/topology/export").text
        for params in ({}, {"confirm": ""}, {"confirm": "merge"}):
            response = client.post(
                "/api/v1/topology/import", params=params, content=NEW_MANIFEST
            )
            assert response.status_code == 400, params
            assert "confirm=replace" in response.json()["detail"]
        assert client.get("/api/v1/topology/export").text == before
        assert set(app.store.working_copy_times()) == {
            "sonarr_api_key", "seerr_api_key"
        }
        confirmed = client.post(
            "/api/v1/topology/import",
            params={"confirm": "replace"},
            content=NEW_MANIFEST,
        )
        assert confirmed.status_code == 200
        assert confirmed.json()["mode"] == "replace"


def test_import_keeps_the_value_of_a_name_it_still_declares(app, tmp_path) -> None:
    """Export, edit, import with the secret left in place: the topology can
    change without re-pasting values, which is what makes it a working copy."""
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        response = _raw_import(
            client, app.manifest.read_text(encoding="utf-8")
        )
        assert response.status_code == 200
        assert client.get("/api/v1/credentials").json()["credentials"][0]["stored"] is True
    assert app.store.get_value("sonarr_api_key").reveal() == SONARR_KEY


def test_a_bad_import_is_400_and_changes_nothing(app, tmp_path) -> None:
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        before = client.get("/api/v1/topology/export").text
        for bad in (
            "",  # empty
            "version: 2\ncredentials: {}\n",  # a version this build refuses
            "version: 1\ncredentials: [not, a, mapping]\n",  # wrong shape
            "version: 1\ncredentials:\n  x:\n    consumers:\n      - target: nope.x\n",
            "not: [valid",
        ):
            response = _raw_import(client, bad)
            assert response.status_code == 400, bad
            assert "error:" in response.json()["detail"], bad
        assert client.get("/api/v1/topology/export").text == before
        assert set(app.store.working_copy_times()) == {
        "sonarr_api_key", "seerr_api_key"
    }


def test_import_refuses_bodies_it_cannot_use(app, tmp_path) -> None:
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        # Not UTF-8 at all, and over the cap - checked before any parse.
        assert _raw_import(client, b"\xff\xfe\x00").status_code == 400
        oversized = b"# " + b"x" * (1024 * 1024)
        assert _raw_import(client, oversized).status_code == 413


def test_a_bad_import_names_the_manifest_path_the_cli_reads(app, tmp_path) -> None:
    """`origin` again, this time through the endpoint: the sentence the console
    shows names the file this deployment audits, not a temporary or invented
    path - a paste and a file import are the same failure in the same words."""
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        response = _raw_import(client, b"version: 1\n")
    assert response.status_code == 400
    assert str(app.manifest) in response.json()["detail"]


def test_the_export_is_the_manifest_the_cli_would_write(app, tmp_path) -> None:
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        response = client.get("/api/v1/topology/export")
    assert response.headers["content-type"] == "application/yaml"
    assert response.text == app.store.export_text()
    # A manifest declares where values live, never the values.
    assert SONARR_KEY not in response.text


def test_paste_stores_a_value_that_never_comes_back(app, tmp_path) -> None:
    pasted = "pasted-sonarr-key-0123456789"  # gitleaks:allow - a test value
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        response = client.put(
            "/api/v1/credentials/sonarr_api_key/value", json={"value": pasted}
        )
        assert response.status_code == 200 and response.json() == {"ok": True}
        payloads = [
            client.get(path).text
            for path in (
                "/api/v1/credentials",
                "/api/v1/status",
                "/api/v1/topology/export",
                "/api/v1/keys",
            )
        ]
        assert client.get("/api/v1/credentials").json()["credentials"][0]["stored"] is True
    assert app.store.get_value("sonarr_api_key").reveal() == pasted
    assert all(pasted not in payload for payload in payloads)


def test_a_paste_is_refused_while_a_rotation_holds_the_lock(app, tmp_path) -> None:
    """A paste during a run would replace the canonical value the run is about
    to record over. The lock that stops a second rotation stops the paste too."""
    journal = facade.journal_for(app.config)
    token = journal.try_acquire("sonarr_api_key", "the live rotation")
    assert token is not None
    try:
        with TestClient(make_server(app, tmp_path)) as client:
            setup_admin(client)
            response = client.put(
                "/api/v1/credentials/sonarr_api_key/value",
                json={"value": "pasted-during-rotation-0123456789"},
            )
    finally:
        journal.release("sonarr_api_key", token)

    assert response.status_code == 409, response.text
    assert "already being rotated" in response.json()["detail"]
    assert app.store.get_value("sonarr_api_key").reveal() == SONARR_KEY


def test_paste_refuses_what_it_cannot_use(app, tmp_path) -> None:
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        unknown = client.put("/api/v1/credentials/nope/value", json={"value": "x"})
        assert unknown.status_code == 404 and "nope" in unknown.json()["detail"]
        # Empty, and the whitespace a terminal paste carries: refused with a
        # reason, never silently trimmed into a different secret.
        for bad in ("", "   ", SONARR_KEY + "\n", " " + SONARR_KEY):
            response = client.put(
                "/api/v1/credentials/sonarr_api_key/value", json={"value": bad}
            )
            assert response.status_code == 422, bad
        assert client.put(
            "/api/v1/credentials/sonarr_api_key/value", json={"value": "x" * 8193}
        ).status_code == 422
    assert app.store.get_value("sonarr_api_key").reveal() == SONARR_KEY


def test_a_pasted_value_is_audited_as_the_runtime_canonical(app, tmp_path) -> None:
    """The whole paste path end to end, on a console that starts empty: learn
    the topology over HTTP, be given the value over HTTP, and the audit then
    matches the stack - with no vault file anywhere on disk."""
    data = tmp_path / "data"
    data.mkdir()
    with TestClient(make_server(app, tmp_path, config_dir=data)) as client:
        setup_admin(client)
        manifest = app.manifest.read_text(encoding="utf-8")
        assert _raw_import(client, manifest).status_code == 200

        # Declared, no value: the run has nothing to compare. That is still a
        # real result the console dates and shows - it just names the app's
        # cause instead of repeating the engine's "no canonical" wording. A
        # run that cannot compare is still not a failure: exit 0.
        run = client.post("/api/v1/audit").json()
        assert run["last_run"]["exit_code"] == 0
        row = next(
            r for r in client.get("/api/v1/credentials").json()["credentials"]
            if r["name"] == "sonarr_api_key"
        )
        assert row["stored"] is False
        assert row["status"] == "unverifiable"
        assert row["detail"] == "no value stored yet"
        assert row["reason"] == "value_missing"

        assert client.put(
            "/api/v1/credentials/sonarr_api_key/value", json={"value": SONARR_KEY}
        ).status_code == 200
        assert client.put(
            "/api/v1/credentials/seerr_api_key/value",
            json={"value": "seerr-service-key-000000000000"},
        ).status_code == 200
        assert client.post("/api/v1/audit").status_code == 200
        row = next(
            r for r in client.get("/api/v1/credentials").json()["credentials"]
            if r["name"] == "sonarr_api_key"
        )
    assert row["stored"] is True
    assert row["status"] == "match"


def test_a_credential_with_no_holders_shows_no_aggregate_of_nothing(app, tmp_path) -> None:
    """The credential-level status is an aggregate over holders. With none
    declared there is nothing for it to be about, so the row shows the declared
    facts - `consumers: []`, `stored: false` - and no borrowed engine verdict,
    even though the run itself found nothing to compare (exit 0)."""
    manifest = (
        "version: 1\ncredentials:\n  no_holders:\n"
        "    description: declared, nothing holds it yet\n"
        "    class: B\n    never_rotate: true\n"
    )
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        assert _raw_import(client, manifest).status_code == 200
        run = client.post("/api/v1/audit").json()
        row = client.get("/api/v1/credentials").json()["credentials"][0]
    assert run["last_run"]["exit_code"] == 0
    assert row["name"] == "no_holders"
    assert row["consumers"] == []
    assert row["status"] is None and row["stored"] is False


def test_a_run_with_no_holders_does_not_lend_a_verdict_to_a_new_holder(app, tmp_path) -> None:
    """INDIRECT is an aggregate over an empty holder set, not a statement about
    the holder declared now. Adding one is a new, unaudited shape."""
    bare = "version: 1\ncredentials:\n  sonarr_api_key:\n    class: A\n    max_age_days: 90\n"
    held = (
        "version: 1\ncredentials:\n  sonarr_api_key:\n    class: A\n    max_age_days: 90\n"
        "    consumers:\n      - target: sonarr.indexers\n"
    )
    data = tmp_path / "data"
    data.mkdir()
    with TestClient(make_server(app, tmp_path, config_dir=data)) as client:
        setup_admin(client)
        assert _raw_import(client, bare).status_code == 200
        assert client.put(
            "/api/v1/credentials/sonarr_api_key/value", json={"value": SONARR_KEY}
        ).status_code == 200
        assert client.post("/api/v1/audit").status_code == 200
        assert client.get("/api/v1/credentials").json()["credentials"][0]["status"] is None
        assert _raw_import(client, held).status_code == 200
        row = client.get("/api/v1/credentials").json()["credentials"][0]
        assert row["stored"] is True
        assert row["status"] is None and row["detail"] is None


def test_a_provisioned_flag_change_voids_the_absent_verdict(app, tmp_path) -> None:
    """ABSENT is a statement about the run's flag, not a permanent property of
    the name. Flipping the flag makes the recorded verdict stale."""
    bare = (
        "version: 1\ncredentials:\n  sonarr_api_key:\n    class: A\n"
        "    max_age_days: 90\n    provisioned: false\n"
        "    consumers:\n      - target: sonarr.indexers\n"
    )
    provisioned = bare.replace("    provisioned: false\n", "")
    data = tmp_path / "data"
    data.mkdir()
    with TestClient(make_server(app, tmp_path, config_dir=data)) as client:
        setup_admin(client)
        assert _raw_import(client, bare).status_code == 200
        assert client.post("/api/v1/audit").status_code == 200
        row = client.get("/api/v1/credentials").json()["credentials"][0]
        assert row["provisioned"] is False and row["status"] == "absent"
        assert row["detail"] == "declared but not provisioned yet"
        assert client.post(
            "/api/v1/topology/import?confirm=replace", content=provisioned
        ).status_code == 200
        row = client.get("/api/v1/credentials").json()["credentials"][0]
        assert row["provisioned"] is True
        assert row["status"] is None and row["detail"] is None


def test_run_now_audits_and_answers_with_the_new_state(server) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        first = wait_for_audit(client)["last_run"]["id"]
        response = client.post("/api/v1/audit")
        assert response.status_code == 200
        state = response.json()
    assert state["last_run"]["id"] > first
    assert state["last_run"]["exit_code"] == 0
    assert state["last_audit"]["exit_status"] == "match"
    assert state["topology"] == {
        "imported": True,
        "credentials": 2,
        "holders": 1,
        "services": ["seerr", "sonarr"],
    }


def _wait_for_job(client: TestClient, job_id: str) -> dict:
    """Poll a background audit until it leaves `running`."""

    def finished() -> dict | None:
        response = client.get(f"/api/v1/audit/jobs/{job_id}")
        assert response.status_code == 200, response.text
        job = response.json()
        return job if job["status"] != "running" else None

    return poll_for(finished, "the background audit never finished")


def test_run_now_can_start_a_background_audit(server) -> None:
    """The console starts a full audit without holding a request open.

    The old synchronous call remains the default for API clients; `wait=false`
    is the path that survives a reverse proxy or tunnel timeout.
    """
    with TestClient(server) as client:
        setup_admin(client)
        first = wait_for_audit(client)["last_run"]["id"]
        response = client.post("/api/v1/audit?wait=false")
        assert response.status_code == 202
        started = response.json()
        assert started["job_id"]
        job = _wait_for_job(client, started["job_id"])
    assert job["status"] == "succeeded"
    assert job["result"]["last_run"]["id"] > first
    assert job["result"]["last_audit"]["exit_status"] == "match"


def test_a_second_async_audit_polls_the_running_job(server, monkeypatch) -> None:
    """Two clicks must not start two stack audits."""
    original = facade.audit
    release = threading.Event()

    def slow(*args, **kwargs):
        release.wait(timeout=5)
        return original(*args, **kwargs)

    with TestClient(server) as client:
        setup_admin(client)
        wait_for_audit(client)
        monkeypatch.setattr(facade, "audit", slow)
        first = client.post("/api/v1/audit?wait=false")
        second = client.post("/api/v1/audit?wait=false")
        assert first.status_code == second.status_code == 202
        assert first.json()["job_id"] == second.json()["job_id"]
        active = client.get("/api/v1/status").json()["audit_job"]
        assert active["job_id"] == first.json()["job_id"]
        release.set()
        job = _wait_for_job(client, first.json()["job_id"])
        assert client.get("/api/v1/status").json()["audit_job"] is None
    assert job["status"] == "succeeded"


def test_an_async_audit_reports_a_ledger_failure(server, monkeypatch) -> None:
    """A background job has no caller to raise to; it reports the failure."""
    def dead(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    with TestClient(server) as client:
        setup_admin(client)
        wait_for_audit(client)
        monkeypatch.setattr(AuditLog, "record", dead)
        response = client.post("/api/v1/audit?wait=false")
        assert response.status_code == 202
        job = _wait_for_job(client, response.json()["job_id"])
    assert job["status"] == "failed"
    assert "database is locked" in job["error"]


def test_an_async_audit_surfaces_the_engine_failure(server, monkeypatch) -> None:
    """The job status is not a success when the audit itself did not run."""
    def broken(*args, **kwargs):
        raise RuntimeError("the engine raised")

    with TestClient(server) as client:
        setup_admin(client)
        wait_for_audit(client)
        monkeypatch.setattr(facade, "audit", broken)
        response = client.post("/api/v1/audit?wait=false")
        assert response.status_code == 202
        job = _wait_for_job(client, response.json()["job_id"])
    assert job["status"] == "failed"
    assert "the engine raised" in job["error"]


def test_a_thread_start_failure_does_not_wedge_the_audit_job(server, monkeypatch) -> None:
    """A failed thread start must free the one-active slot, not leave a ghost."""
    def broken_start(self):
        raise RuntimeError("can't start new thread")

    with TestClient(server) as client:
        setup_admin(client)
        wait_for_audit(client)
        monkeypatch.setattr(threading.Thread, "start", broken_start)
        with pytest.raises(RuntimeError, match="can't start new thread"):
            client.post("/api/v1/audit?wait=false")
        monkeypatch.undo()
        response = client.post("/api/v1/audit?wait=false")
        assert response.status_code == 202
        job = _wait_for_job(client, response.json()["job_id"])
    assert job["status"] == "succeeded"


def test_a_failed_async_audit_frees_the_slot(server, monkeypatch) -> None:
    """A failed job must not make every later click poll the dead job."""
    original = AuditLog.record
    first = True

    def fail_once(*args, **kwargs):
        nonlocal first
        if first:
            first = False
            raise sqlite3.OperationalError("database is locked")
        return original(*args, **kwargs)

    with TestClient(server) as client:
        setup_admin(client)
        wait_for_audit(client)
        monkeypatch.setattr(AuditLog, "record", fail_once)
        first_job = client.post("/api/v1/audit?wait=false").json()["job_id"]
        failed = _wait_for_job(client, first_job)
        assert failed["status"] == "failed"
        second = client.post("/api/v1/audit?wait=false")
        assert second.status_code == 202
        assert second.json()["job_id"] != first_job
        done = _wait_for_job(client, second.json()["job_id"])
    assert done["status"] == "succeeded"


def test_an_async_audit_job_must_exist(server) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        assert client.get("/api/v1/audit/jobs/not-a-job").status_code == 404
        assert (
            client.post("/api/v1/audit?only=sonarr_api_key&wait=false").status_code
            == 400
        )



def test_a_scoped_check_is_history_not_a_stack_audit(server) -> None:
    """`POST /audit?only=` checks one app without moving stack-wide state.

    Auto-rotation's freshness gate requires exact stack coverage. A scoped
    check must not become `last_audit`, must not write a full ledger run, and
    must not emit a status-transition event. Its own result is recorded in the
    per-app history beside the last full audit's row.
    """
    with TestClient(server) as client:
        setup_admin(client)
        state = wait_for_audit(client)
        first_run = state["last_run"]["id"]
        first_audit = state["last_audit"]
        response = client.post("/api/v1/audit?only=sonarr_api_key")
        assert response.status_code == 200, response.text
        body = response.json()
        after = client.get("/api/v1/status").json()
        history = client.get(
            "/api/v1/audit?only=sonarr_api_key"
        ).json()
        limited = client.get(
            "/api/v1/audit?only=sonarr_api_key&limit=1"
        ).json()["checks"]
        events = client.get("/api/v1/events").json()["events"]
    assert body["check"]["name"] == "sonarr_api_key"
    assert body["check"]["status"] == "match"
    assert body["check"]["reason"] == "match"
    assert body["check"]["consumers"][0]["target"] == "seerr.settings_json[sonarr]"
    assert body["check"]["consumers"][0]["reason"] == "match"
    assert body["checked_at"] > 0
    assert after["last_run"]["id"] == first_run
    assert after["last_audit"] == first_audit
    assert history["credential"] == "sonarr_api_key"
    assert {row["source"] for row in history["checks"]} == {"audit", "check"}
    assert history["checks"][0]["source"] == "check"
    assert len(limited) == 1
    assert events == []
    assert SONARR_KEY not in response.text
    assert SONARR_KEY not in str(history)


def test_a_scoped_drift_does_not_emit_a_stack_event(server) -> None:
    """A check that finds drift is still only a check: no event, no new run."""
    with TestClient(server) as client:
        setup_admin(client)
        first = wait_for_audit(client)["last_run"]["id"]
        server.state.store.set_value("sonarr_api_key", Secret("0" * 32))
        response = client.post("/api/v1/audit?only=sonarr_api_key")
        assert response.status_code == 200, response.text
        after = client.get("/api/v1/status").json()
        events = client.get("/api/v1/events").json()["events"]
    assert response.json()["check"]["status"] == "drift"
    assert after["last_run"]["id"] == first
    assert events == []


def test_full_audit_history_carries_a_drift_sentence(server) -> None:
    """History must not render a drift pill with an em dash when the audit
    knows why it drifted."""
    with TestClient(server) as client:
        setup_admin(client)
        wait_for_audit(client)
        server.state.store.set_value("sonarr_api_key", Secret("0" * 32))
        assert client.post("/api/v1/audit").status_code == 200
        history = client.get(
            "/api/v1/audit?only=sonarr_api_key"
        ).json()["checks"]
    latest_audit = next(row for row in history if row["source"] == "audit")
    assert latest_audit["status"] == "drift"
    assert latest_audit["detail"]


def test_a_scoped_check_validates_its_name_and_limit(server) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        assert client.post("/api/v1/audit?only=nope").status_code == 404
        assert client.get("/api/v1/audit?only=nope").status_code == 404
        assert client.get("/api/v1/audit").status_code == 400
        assert client.get(
            "/api/v1/audit?only=sonarr_api_key&limit=0"
        ).status_code == 400
        assert client.get(
            "/api/v1/audit?only=sonarr_api_key&limit=101"
        ).status_code == 400


def test_run_now_surfaces_an_unwritable_ledger(server, monkeypatch) -> None:
    """The failure that ends the loop, reported the way `/health` reports it -
    exercised through the real ledger write, not by patching the whole run."""

    def dead(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(AuditLog, "record", dead)
    with TestClient(server) as client:
        setup_admin(client)
        response = client.post("/api/v1/audit")
    assert response.status_code == 503
    assert "database is locked" in response.json()["detail"]


def test_run_now_does_not_dress_a_bug_up_as_degraded(server, monkeypatch) -> None:
    """Only a ledger that cannot be written is a 503. Anything else escaping
    `once()` is a defect, and a defect served as "service unavailable" with a
    status code in front of it is a lie the operator would believe."""

    def broken(*args, **kwargs):
        raise TypeError("a bug, not a degradation")

    monkeypatch.setattr(AuditLog, "record", broken)
    with TestClient(server) as client:
        setup_admin(client)
        with pytest.raises(TypeError):
            client.post("/api/v1/audit")


def test_the_new_endpoints_require_authentication(server) -> None:
    """Including run-now: an unauthenticated POST must not audit anything."""
    with TestClient(server) as client:
        assert client.get("/api/v1/credentials").status_code == 401
        assert client.get("/api/v1/topology/export").status_code == 401
        assert _raw_import(client, NEW_MANIFEST).status_code == 401
        assert client.put(
            "/api/v1/credentials/sonarr_api_key/value", json={"value": "x"}
        ).status_code == 401
        assert client.post("/api/v1/audit").status_code == 401
        assert client.post("/api/v1/audit?wait=false").status_code == 401
        assert client.get("/api/v1/audit/jobs/not-a-job").status_code == 401
        assert client.get(
            "/api/v1/audit?only=sonarr_api_key"
        ).status_code == 401
        assert client.post(
            "/api/v1/audit?only=sonarr_api_key"
        ).status_code == 401
        assert client.post(
            "/api/v1/credentials/sonarr_api_key/plan"
        ).status_code == 401
        assert client.get("/api/v1/services").status_code == 401
        assert client.get("/api/v1/discovery").status_code == 401
        assert client.get("/api/v1/notifications/services").status_code == 401
        assert client.post(
            "/api/v1/notifications/services/test",
            json={"name": "draft", "kind": "webhook", "url": "https://x.example"},
        ).status_code == 401
        assert client.post(
            "/api/v1/notifications/services/ntfy/test"
        ).status_code == 401
        assert client.get("/api/v1/events").status_code == 401
        assert client.post(
            "/api/v1/credentials/sonarr_api_key/rotate",
            json={"confirm": "sonarr_api_key"},
        ).status_code == 401


# -- plan and run --------------------------------------------------------------
#
# The console's plan is the CLI's dry run: the same planner, the same preflight
# and the same exit codes, in one document. The run endpoint is the CLI's apply
# path with the typed name in the body instead of on a terminal - the server is
# the trust boundary, so the check is repeated here and not only in the form.

ROTATABLE_MANIFEST = """
version: 1
credentials:
  sonarr_api_key:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: vault.yml, path: [keys, sonarr_api_key]}
    write: {mechanism: servarr_command}
    consumers:
      - target: sonarr.indexers
        count: 2
"""


def test_the_plan_for_a_credential_that_cannot_rotate_says_why(server) -> None:
    """Refused, exit 5, no steps and no revoke window.

    The window is a statement about a run; a refused plan mints nothing, so
    claiming one would describe a rotation that cannot happen.
    """
    with TestClient(server) as client:
        setup_admin(client)
        response = client.post("/api/v1/credentials/sonarr_api_key/plan")
    assert response.status_code == 200
    body = response.json()
    assert body["refused"] is True
    assert body["blocked_by"] == ["no rotation strategy for write.mechanism ''"]
    assert body["steps"] == [] and body["problems"] == []
    assert body["revokes_before_holders"] is False
    assert body["exit_code"] == 5 and body["run"] is None
    # Nothing observed can be a secret, and the plan carries no value.
    assert SONARR_KEY not in response.text


def test_the_plan_for_a_rotatable_credential_keeps_the_cli_step_order(
    app, tmp_path
) -> None:
    """The same four steps `plan_rotation` produces, in the same order.

    The fixture host names sonarr's path but no URL, so preflight cannot even
    ask the service to answer: that is exit 3, reported as a problem in the
    engine's words, and it is not a refusal (the plan itself is executable).
    """
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        wait_for_audit(client)
        assert client.post(
            "/api/v1/topology/import?confirm=replace", content=ROTATABLE_MANIFEST
        ).status_code == 200
        response = client.post("/api/v1/credentials/sonarr_api_key/plan")
    body = response.json()
    assert body["refused"] is False and body["blocked_by"] == []
    assert [(step["kind"], step["target"]) for step in body["steps"]] == [
        ("mint", "sonarr"),
        ("propagate", "sonarr.indexers"),
        ("record", "sonarr_api_key"),
    ]
    # The first step is the irreversible one, and the document says so rather
    # than leaving a console to infer it from the kind.
    assert body["steps"][0]["reversible"] is False
    assert body["steps"][0]["reason"]
    assert body["revokes_before_holders"] is True
    assert body["exit_code"] == 3
    assert body["problems"] == ["host 'local' has no url configured for 'sonarr'"]
    assert body["run"] is None


def test_a_rotate_without_the_typed_name_changes_nothing(server) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        response = client.post(
            "/api/v1/credentials/sonarr_api_key/rotate", json={"confirm": "nope"}
        )
        events = client.get("/api/v1/events").json()["events"]
    assert response.status_code == 400
    assert "not confirmed" in response.json()["detail"]
    # The value is intact and no attempt was opened: the check happens before
    # the plan, and the plan before anything is written. Nothing was attempted,
    # so Activity gets no row either.
    assert server.state.store.get_value("sonarr_api_key").reveal() == SONARR_KEY
    assert facade.journal_for(server.state.config).last_attempt("sonarr_api_key") is None
    assert [event for event in events if event["kind"].startswith("rotation_")] == []


def test_a_refused_rotate_changes_nothing_but_leaves_an_attempt_in_activity(server) -> None:
    """The click is the event. Nothing is written to the stack and no journal
    attempt opens, but Activity now answers "what happened?" with the refusal -
    recorded, and marked silent because a refusal pages nobody."""
    with TestClient(server) as client:
        setup_admin(client)
        response = client.post(
            "/api/v1/credentials/sonarr_api_key/rotate",
            json={"confirm": "sonarr_api_key"},
        )
        events = client.get("/api/v1/events").json()["events"]
    body = response.json()
    assert body["refused"] is True and body["exit_code"] == 5
    assert body["blocked_by"] == ["no rotation strategy for write.mechanism ''"]
    assert body["run"] is None
    assert server.state.store.get_value("sonarr_api_key").reveal() == SONARR_KEY
    assert facade.journal_for(server.state.config).last_attempt("sonarr_api_key") is None

    attempts = [event for event in events if event["kind"].startswith("rotation_")]
    assert [event["kind"] for event in attempts] == ["rotation_refused"]
    attempt = attempts[0]
    assert attempt["credential"] == "sonarr_api_key"
    assert attempt["detail"] == "no rotation strategy for write.mechanism ''"
    # An action, not a measurement: no invented "was" or "is".
    assert attempt["previous_status"] is None and attempt["status"] is None
    assert attempt["silent"] is True
    assert attempt["deliveries"] == []


def test_a_rotate_that_fails_preflight_does_not_start(app, tmp_path) -> None:
    """Same exit code and wording the CLI's apply path gives a host it cannot
    ask: 3, problems, nothing changed - no journal attempt, and an Activity row
    that a service may hear about (a failure is news, unlike a refusal)."""
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        wait_for_audit(client)
        assert client.post(
            "/api/v1/topology/import?confirm=replace", content=ROTATABLE_MANIFEST
        ).status_code == 200
        response = client.post(
            "/api/v1/credentials/sonarr_api_key/rotate",
            json={"confirm": "sonarr_api_key"},
        )
        events = client.get("/api/v1/events").json()["events"]
    body = response.json()
    assert body["refused"] is False
    assert body["exit_code"] == 3
    assert body["problems"] == ["host 'local' has no url configured for 'sonarr'"]
    assert body["run"] is None
    assert app.store.get_value("sonarr_api_key").reveal() == SONARR_KEY
    assert facade.journal_for(app.config).last_attempt("sonarr_api_key") is None

    attempts = [event for event in events if event["kind"].startswith("rotation_")]
    assert [event["kind"] for event in attempts] == ["rotation_failed"]
    assert attempts[0]["detail"] == "host 'local' has no url configured for 'sonarr'"
    assert attempts[0]["silent"] is False


@pytest.mark.parametrize(
    ("result", "kind", "detail"),
    [
        (
            ExecutionResult(credential="sonarr_api_key", attempt=1),
            "rotation_succeeded",
            "completed",
        ),
        (
            ExecutionResult(
                credential="sonarr_api_key",
                attempt=1,
                holders=[
                    HolderOutcome(
                        target="sonarr.indexers", label="Sonarr", outcome="confirmed"
                    ),
                    HolderOutcome(
                        target="seerr.settings_json[sonarr]", label="Seerr",
                        outcome="confirmed",
                    ),
                ],
            ),
            "rotation_succeeded",
            "completed in Sonarr, Seerr",
        ),
        (
            ExecutionResult(
                credential="sonarr_api_key",
                attempt=1,
                holders=[
                    HolderOutcome(
                        target="sonarr.indexers", label="Sonarr", outcome="confirmed"
                    ),
                    HolderOutcome(
                        target="sonarr.download_clients", label="", outcome="confirmed"
                    ),
                ],
            ),
            "rotation_succeeded",
            "completed in Sonarr",
        ),
        (
            ExecutionResult(
                credential="sonarr_api_key",
                attempt=1,
                failed="propagate:sonarr.indexers",
                detail="failed: HTTP 403 Forbidden",
            ),
            "rotation_failed",
            "failed: HTTP 403 Forbidden",
        ),
        (
            ExecutionResult(
                credential="sonarr_api_key",
                attempt=1,
                manual=["seerr.settings_json[sonarr]"],
            ),
            "rotation_manual",
            "manual steps outstanding: Seerr",
        ),
        (
            ExecutionResult(
                credential="sonarr_api_key",
                attempt=1,
                holders=[
                    HolderOutcome(
                        target="sonarr.indexers", label="Sonarr", outcome="written"
                    )
                ],
            ),
            "rotation_failed",
            "not confirmed: Sonarr",
        ),
        (
            ExecutionResult(
                credential="sonarr_api_key",
                attempt=1,
                manual=["homepage.label"],
                holders=[
                    HolderOutcome(
                        target="sonarr.indexers", label="Sonarr", outcome="written"
                    )
                ],
            ),
            "rotation_failed",
            "not confirmed: Sonarr",
        ),
    ],
)
def test_a_finished_manual_run_records_its_outcome(
    app, tmp_path, monkeypatch, result, kind, detail
) -> None:
    """Completed runs and runs that left the stack inconsistent are recorded
    with the engine's own answer, and are not silent: the operator has to look
    at them. The outcome is read off `execution_exit_code`, not off "nothing
    raised"."""
    monkeypatch.setattr(facade, "preflight", lambda **kwargs: [])
    monkeypatch.setattr(facade, "execute", lambda **kwargs: result)
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        wait_for_audit(client)
        assert client.post(
            "/api/v1/topology/import?confirm=replace", content=ROTATABLE_MANIFEST
        ).status_code == 200
        run = client.post(
            "/api/v1/credentials/sonarr_api_key/rotate",
            json={"confirm": "sonarr_api_key"},
        ).json()
        events = client.get("/api/v1/events").json()["events"]

    attempts = [event for event in events if event["kind"].startswith("rotation_")]
    assert [event["kind"] for event in attempts] == [kind]
    assert attempts[0]["credential"] == "sonarr_api_key"
    assert attempts[0]["detail"] == detail
    assert attempts[0]["silent"] is False
    # The answer to the caller is still the engine's document.
    assert run["exit_code"] == (0 if kind == "rotation_succeeded" else 1)
    assert run["run"] is not None


def test_moving_a_service_url_requires_the_stored_key_again(server, app) -> None:
    """A URL is a destination: the old key belongs to the old server."""
    with TestClient(server) as client:
        setup_admin(client)
        refused = client.patch(
            "/api/v1/services/seerr", json={"url": "http://elsewhere:5055"}
        )
        wrong = client.patch(
            "/api/v1/services/seerr",
            json={
                "url": "http://elsewhere:5055",
                "credential": "sonarr_api_key",
                "key": "wrong-holder-key-0123456789",
            },
        )
        moved = client.patch(
            "/api/v1/services/seerr",
            json={
                "url": "http://elsewhere:5055",
                "credential": "seerr_api_key",
                "key": "new-seerr-key-0123456789",
            },
        )
        retried = client.patch(
            "/api/v1/services/seerr",
            json={
                "url": "http://elsewhere:5055",
                "credential": "seerr_api_key",
                "key": "retry-seerr-key-0123456789",
            },
        )
        definitions = client.get(
            "/api/v1/services?observe=false"
        ).json()["definitions"]
    assert refused.status_code == 400
    assert "re-enter the API key" in refused.json()["detail"]
    assert wrong.status_code == 400
    assert "seerr_api_key" in wrong.json()["detail"]
    assert moved.status_code == 200, moved.text
    assert "new-seerr-key-0123456789" not in moved.text
    assert retried.status_code == 200, retried.text
    assert app.store.get_value("seerr_api_key").reveal() == (
        "retry-seerr-key-0123456789"
    )
    assert [s["url"] for s in definitions if s["name"] == "seerr"] == [
        "http://elsewhere:5055"
    ]


def test_a_url_move_refuses_a_parked_rotation_key(server, app) -> None:
    """A key chosen for the old destination must not be resumed at a new one."""
    with TestClient(server) as client:
        setup_admin(client)
        app.store.set_pending(
            "seerr_api_key", Secret("parked-for-the-old-destination-0123456789")
        )
        refused = client.patch(
            "/api/v1/services/seerr",
            json={
                "url": "http://elsewhere:5055",
                "credential": "seerr_api_key",
                "key": "new-seerr-key-0123456789",
            },
        )
    assert refused.status_code == 400
    assert "unfinished rotation" in refused.json()["detail"]
    assert "seerr_api_key" in refused.json()["detail"]


def test_configuration_writes_are_refused_while_a_rotation_holds_the_stack(
    app, tmp_path, monkeypatch
) -> None:
    """The race the stack lease closes, driven through the real HTTP routes.

    A rotation is blocked inside execute - after its stack lease is taken and
    before RECORD. Import, prune, delete, holder and URL edits must all answer
    409 instead of changing the topology under it. After release the parked
    value, canonical value and topology are exactly what they were, and the
    run minted once.
    """
    started = threading.Event()
    release = threading.Event()
    executed: list[str] = []
    journal = facade.journal_for(app.config)

    def blocking_execute(**kwargs):
        name = kwargs["credential"].name
        executed.append(name)
        attempt = journal.begin(name)
        journal.step_started(attempt, 0, "mint", "sonarr", "fake mint")
        started.set()
        assert release.wait(10), "the test never released the rotation"
        journal.step_finished(attempt, 0, "completed")
        journal.finish(attempt, "completed")
        return ExecutionResult(credential=name, attempt=attempt)

    monkeypatch.setattr(facade, "preflight", lambda **kwargs: [])
    monkeypatch.setattr(facade, "execute", blocking_execute)
    parked = Secret("parked-before-the-rotation-0123456789")
    app.store.set_pending("sonarr_api_key", parked)

    server = make_server(app, tmp_path)
    with TestClient(server) as client:
        setup_admin(client)
        wait_for_audit(client)
        assert client.post(
            "/api/v1/topology/import",
            params={"confirm": "replace"},
            content=ROTATABLE_MANIFEST,
        ).status_code == 200
        answer: dict = {}

        def rotate() -> None:
            answer["response"] = client.post(
                "/api/v1/credentials/sonarr_api_key/rotate",
                json={"confirm": "sonarr_api_key"},
            )

        runner = threading.Thread(target=rotate, daemon=True)
        runner.start()
        assert started.wait(10), "the rotation never reached execute"

        attempts = {
            "value": client.put(
                "/api/v1/credentials/sonarr_api_key/value",
                json={"value": "pasted-during-rotation-0123456789"},
            ),
            "delete": client.delete(
                "/api/v1/credentials/sonarr_api_key",
                params={"confirm": "sonarr_api_key"},
            ),
            "holders": client.put(
                "/api/v1/credentials/sonarr_api_key/holders",
                json={"consumers": [{"target": "radarr.indexers"}]},
            ),
            "url": client.patch(
                "/api/v1/services/seerr", json={"url": "http://elsewhere:5055"}
            ),
            "raw-import": client.post(
                "/api/v1/topology/import",
                params={"confirm": "replace"},
                content=NEW_MANIFEST,
            ),
            "prune": client.post(
                "/api/v1/topology/import",
                json={
                    "mode": "merge",
                    "prune": True,
                    "yaml": NEW_MANIFEST,
                    "confirm": "merge",
                },
            ),
        }
        for name, response in attempts.items():
            assert response.status_code == 409, (name, response.text)
            assert "in progress" in response.json()["detail"], (name, response.text)

        release.set()
        runner.join(timeout=10)
        assert not runner.is_alive()
        assert answer["response"].status_code == 200, answer["response"].text

        rows = client.get("/api/v1/credentials").json()["credentials"]
        services = client.get("/api/v1/services").json()["definitions"]

    assert executed == ["sonarr_api_key"], "the blocked run executed more than once"
    assert len(journal.steps(1)) == 1 and journal.steps(1)[0]["kind"] == "mint", (
        "the blocked topology produced a second attempt or mint"
    )
    row = next(row for row in rows if row["name"] == "sonarr_api_key")
    assert [holder["target"] for holder in row["consumers"]] == ["sonarr.indexers"]
    assert [service["url"] for service in services if service["name"] == "seerr"] == [
        app.settings_api.url
    ]
    assert app.store.get_value("sonarr_api_key").reveal() == SONARR_KEY
    assert app.store.get_pending("sonarr_api_key").reveal() == parked.reveal()


def test_a_preflight_problem_cannot_carry_a_value_into_activity(
    app, tmp_path, monkeypatch
) -> None:
    """Preflight builds its problems outside the executor's scrub boundary
    (`problems.append(str(exc))`), and recording an attempt is a new egress
    path for that text - to `app.db` and to every sink. The value must not
    follow it."""
    monkeypatch.setattr(
        facade,
        "preflight",
        lambda **kwargs: [f"sonarr: the service answered {SONARR_KEY}"],
    )
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        wait_for_audit(client)
        assert client.post(
            "/api/v1/topology/import?confirm=replace", content=ROTATABLE_MANIFEST
        ).status_code == 200
        client.post(
            "/api/v1/credentials/sonarr_api_key/rotate",
            json={"confirm": "sonarr_api_key"},
        )
        events = client.get("/api/v1/events").json()

    attempts = [
        event for event in events["events"] if event["kind"].startswith("rotation_")
    ]
    assert [event["kind"] for event in attempts] == ["rotation_failed"]
    assert SONARR_KEY not in attempts[0]["detail"]
    assert "[redacted]" in attempts[0]["detail"]


def test_the_plan_and_rotate_endpoints_hand_the_take_over_to_the_engine(
    app, tmp_path, monkeypatch
) -> None:
    """The console's resume path is a run instruction, not a client-side guess.

    Pinned on the seam between the BFF and the engine: with preflight and the
    run stubbed out, the only thing under test is the instruction that crosses.
    Both endpoints carry it, because the console plans and runs from the same
    answer, and the journal is untouched - closing a credential's steps is a
    run's act, under the lock, never a route's.
    """
    journal = facade.journal_for(app.config)
    attempt = journal.begin("sonarr_api_key")
    journal.step_started(attempt, 0, "mint", "sonarr", "POST /api/v3/command")

    seen: list[dict] = []

    def fake_preflight(**kwargs):
        seen.append(kwargs)
        return []

    def fake_execute(**kwargs):
        seen.append(kwargs)
        return ExecutionResult(credential=kwargs["credential"].name, attempt=1)

    monkeypatch.setattr(facade, "preflight", fake_preflight)
    monkeypatch.setattr(facade, "execute", fake_execute)

    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        wait_for_audit(client)
        assert client.post(
            "/api/v1/topology/import?confirm=replace", content=ROTATABLE_MANIFEST
        ).status_code == 200
        plan = client.post(
            "/api/v1/credentials/sonarr_api_key/plan", json={"take_over": True}
        ).json()
        run = client.post(
            "/api/v1/credentials/sonarr_api_key/rotate",
            json={"confirm": "sonarr_api_key", "take_over": True},
        ).json()

    # The stubbed preflight found nothing, so the console reads "ready" - which
    # is the answer the resume path is there to give.
    assert plan["exit_code"] == 0 and plan["run"] is None
    assert run["exit_code"] == 0 and run["run"] is not None
    assert [call["take_over"] for call in seen] == [True, True, True], seen
    assert all(call["journal"] is not None for call in seen), seen
    assert all(
        call["service_keys"]["sonarr"].reveal() == SONARR_KEY for call in seen
    ), "the BFF stopped reading the service key from the store"
    assert journal.pending(), "a route closed the steps instead of a run"


def test_a_takeover_inside_a_live_lease_is_refused_and_closes_nothing(
    app, tmp_path, monkeypatch
) -> None:
    """The fence the flag cannot open.

    `take_over` closes steps; it is not a way past a lease someone is still
    holding - pid and hostname are not identity, so an assertion nobody can
    check would start a second run over a live one. The console's resume path
    gets the engine's own 409, and the dead step is still there afterwards for
    the next attempt to take over. Only `preflight` is stubbed: the refusal
    this pins comes from the real lock, taken by the real `execute`.
    """
    journal = facade.journal_for(app.config)
    attempt = journal.begin("sonarr_api_key")
    journal.step_started(attempt, 0, "mint", "sonarr", "POST /api/v3/command")
    assert journal.try_acquire("sonarr_api_key", "the live one") is not None

    monkeypatch.setattr(facade, "preflight", lambda **kwargs: [])

    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        wait_for_audit(client)
        assert client.post(
            "/api/v1/topology/import?confirm=replace", content=ROTATABLE_MANIFEST
        ).status_code == 200
        answer = client.post(
            "/api/v1/credentials/sonarr_api_key/rotate",
            json={"confirm": "sonarr_api_key", "take_over": True},
        )
        events = client.get("/api/v1/events").json()["events"]

    assert answer.status_code == 409, answer.text
    assert "already being rotated" in answer.json()["detail"]
    # Refused before the journal: the dead step is still pending, unclaimed -
    # and nothing was attempted, so no rotation event was recorded.
    assert [step.credential for step in journal.pending()] == ["sonarr_api_key"]
    assert [event for event in events if event["kind"].startswith("rotation_")] == []


def test_a_preflight_that_cannot_finish_keeps_the_clis_exit_code(
    app, tmp_path, monkeypatch
) -> None:
    """A host the engine cannot even ask is exit 4, not 3.

    Preflight reports an unreachable *service* as its own problems; a transport
    failure raises before it can report at all, and the CLI returns that error's
    own code. The dry run and the run must name the same failure the same way -
    and the run must still start nothing."""
    def unreadable(**kwargs):
        raise TransportError("host 'local' cannot reach sonarr")

    monkeypatch.setattr(facade, "preflight", unreadable)
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        wait_for_audit(client)
        assert client.post(
            "/api/v1/topology/import?confirm=replace", content=ROTATABLE_MANIFEST
        ).status_code == 200
        plan = client.post("/api/v1/credentials/sonarr_api_key/plan").json()
        run = client.post(
            "/api/v1/credentials/sonarr_api_key/rotate",
            json={"confirm": "sonarr_api_key"},
        ).json()
    for body in (plan, run):
        assert body["refused"] is False and body["run"] is None
        assert body["exit_code"] == 4
        assert body["problems"] == [
            "host 'local' cannot reach sonarr"
        ]
    assert app.store.get_value("sonarr_api_key").reveal() == SONARR_KEY
    assert facade.journal_for(app.config).last_attempt("sonarr_api_key") is None


def test_services_answers_with_the_engines_document(server, monkeypatch) -> None:
    """The endpoint is a thin reader over the store, not a second report.

    `service_report` is monkeypatched at this boundary on purpose: the real one
    inspects containers and asks services, and this machine is not the subject.
    What is pinned is the payload the SPA reads, and the manifest behind it -
    the store's own, re-read per request."""
    seen: list[tuple[str, ...]] = []
    keys_seen: list[dict] = []

    def fake(manifest, config, *, service_keys=None, docker_url=None):
        seen.append(tuple(manifest.credentials))
        keys_seen.append(dict(service_keys or {}))
        return ServiceReport(
            services=(
                ServiceFacts(
                    system="sonarr",
                    host="local",
                    credentials=("sonarr_api_key",),
                    holders=(
                        HolderFacts(slot="indexers", write="servarr_api",
                                    managed=True, provenance=None),
                    ),
                    mint="reset",
                    url="http://127.0.0.1:8989",
                    provenance="measured against 4.0.5",
                    measured_version="4.0.5",
                    measured_image="sha256:" + "a" * 64,
                    observation=ServiceObservation(
                        system="sonarr",
                        host="local",
                        container="sonarr",
                        container_declared=True,
                        running_version="4.0.5",
                        version_note="",
                        image="sha256:" + "a" * 64,
                        image_digests=(),
                        image_note="",
                    ),
                    missing=("no url is declared for sonarr on local",),
                ),
            ),
        )

    monkeypatch.setattr("credarr_server.app.service_report", fake)
    with TestClient(server) as client:
        setup_admin(client)
        response = client.get("/api/v1/services")
    assert response.status_code == 200
    body = response.json()
    assert seen == [tuple(server.state.store.load_manifest().credentials)]
    assert isinstance(body["observed_at"], float)
    (service,) = body["services"]
    assert set(service) == {
        "system", "host", "credentials", "holders", "mint", "url",
        "provenance", "measured_version", "measured_image", "observation",
        "missing",
    }
    assert "sonarr" in keys_seen[0] and "seerr" in keys_seen[0]
    assert set(service["observation"]) == {
        "system", "host", "container", "container_declared", "running_version",
        "version_note", "image", "image_digests", "image_note",
    }
    assert service["holders"][0]["write"] == "servarr_api"
    assert service["missing"] == ["no url is declared for sonarr on local"]
    assert SONARR_KEY not in response.text


def test_services_can_return_definitions_without_probing(
    server, monkeypatch
) -> None:
    """The console only needs the saved URLs to draw Apps and the editor.

    Live version and image observations are a separate question, answered by
    the full report. Asking for definitions must not make the page wait on a
    service that is down.
    """
    def unexpected(*args, **kwargs):
        raise AssertionError("observe=false must not probe services")

    monkeypatch.setattr("credarr_server.app.service_report", unexpected)
    monkeypatch.setattr("credarr_server.app.stored_service_keys", unexpected)
    with TestClient(server) as client:
        setup_admin(client)
        response = client.get("/api/v1/services?observe=false")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["services"] == []
    assert body["observed_at"] is None
    seerr = next(row for row in body["definitions"] if row["name"] == "seerr")
    expected = server.state.config.host(
        server.state.config.default_host
    ).urls["seerr"]
    assert seerr["url"] == expected


def test_status_names_an_unfinished_rotation_and_when_it_can_resume(app, tmp_path) -> None:
    """The console's banner reads this: what started, on which credential, how
    long ago, and the age after which the engine takes over instead of
    refusing. Seeded through the journal's own API - the payload is what is
    being pinned, not a hand-written row."""
    journal = facade.journal_for(app.config)
    attempt = journal.begin("sonarr_api_key")
    journal.step_started(attempt, 0, "mint", "sonarr", "POST /api/v3/command")
    # Older than the liveness window: `pending()` would hide it, but
    # auto-rotation and the enable endpoint still refuse because of it.
    with sqlite3.connect(journal.path) as connection:
        connection.execute(
            "UPDATE steps SET started_at = ? WHERE attempt_id = ?",
            (time.time() - 10_000, attempt),
        )

    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        pending = client.get("/api/v1/status").json()["rotation"]
    assert pending["stale_after_seconds"] == 900.0
    (step,) = pending["pending"]
    assert step["credential"] == "sonarr_api_key"
    assert step["target"] == "sonarr" and step["kind"] == "mint"
    assert step["detail"] == "POST /api/v3/command"
    assert step["seconds_ago"] >= 10_000
    assert step["started_at"] > 0


def test_rotation_options_name_the_fallback_without_touching_the_stack(app, tmp_path) -> None:
    """The console's inference is a read-only answer.

    This fixture has no Sonarr URL, so both automatic paths honestly report
    unavailable and the manual mint is the recommendation. The endpoint must
    not fail because one method cannot be checked, and it must not need a
    second plan call.
    """
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        wait_for_audit(client)
        assert client.post(
            "/api/v1/topology/import?confirm=replace", content=ROTATABLE_MANIFEST
        ).status_code == 200
        response = client.get(
            "/api/v1/credentials/sonarr_api_key/rotation-options"
        )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["applicable"] is True
    assert body["selected"] == "backup_restore"
    assert body["recommended"] == "manual"
    assert body["methods"]["backup_restore"]["available"] is False
    assert body["methods"]["reconstruct"]["available"] is False
    assert body["methods"]["manual"] == {
        "available": True,
        "automatic": False,
        "reason": "You rotate the key in the service's own UI and paste it.",
    }
    assert "no url configured for 'sonarr'" in body["methods"]["backup_restore"]["reason"]
    assert "no url configured for 'sonarr'" in body["methods"]["reconstruct"]["reason"]
    assert SONARR_KEY not in response.text


def test_rotation_options_refuse_an_unstored_key_and_a_fixed_method(app, tmp_path) -> None:
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        wait_for_audit(client)
        fixed = client.get("/api/v1/credentials/seerr_api_key/rotation-options")
        assert fixed.status_code == 200
        assert fixed.json() == {
            "applicable": False,
            "service": "seerr",
            "reason": "this credential has no Servarr-style rotation",
        }

        assert client.post(
            "/api/v1/topology/import?confirm=replace", content=NEW_MANIFEST
        ).status_code == 200
        missing = client.get(
            "/api/v1/credentials/prowlarr_api_key/rotation-options"
        )
        assert missing.status_code == 409
        assert "store the key first" in missing.json()["detail"]


def test_an_unknown_credential_has_no_plan_or_run(server) -> None:
    with TestClient(server) as client:
        setup_admin(client)
        assert client.post("/api/v1/credentials/nope/plan").status_code == 404
        assert client.post(
            "/api/v1/credentials/nope/rotate", json={"confirm": "nope"}
        ).status_code == 404


MANUAL_MINT_MANIFEST = ROTATABLE_MANIFEST.replace(
    "write: {mechanism: servarr_command}",
    "write: {mechanism: servarr_command, manual_mint: true}",
)


def test_a_manual_mint_plan_is_marked_and_rotate_needs_the_key(app, tmp_path) -> None:
    """The console has to know to ask for a key, and the server is the boundary.

    A plan without the key is still ready: the key does not exist until the
    operator rotates it in the service's own UI. The rotate request without it
    is refused before any run starts; a supplied key on a plan that does not
    use the manual mint is refused rather than silently ignored.
    """
    with TestClient(make_server(app, tmp_path)) as client:
        setup_admin(client)
        wait_for_audit(client)
        assert client.post(
            "/api/v1/topology/import?confirm=replace", content=MANUAL_MINT_MANIFEST
        ).status_code == 200
        plan = client.post("/api/v1/credentials/sonarr_api_key/plan").json()
        assert plan["manual_mint"] is True
        assert plan["mint_via"] == "provided"
        assert plan["refused"] is False

        missing = client.post(
            "/api/v1/credentials/sonarr_api_key/rotate",
            json={"confirm": "sonarr_api_key"},
        )
        assert missing.status_code == 400
        assert "needs the key" in missing.json()["detail"]
        assert app.store.get_value("sonarr_api_key").reveal() == SONARR_KEY

        supplied = "manual-key-that-must-not-be-echoed"
        failed = client.post(
            "/api/v1/credentials/sonarr_api_key/rotate",
            json={"confirm": "sonarr_api_key", "manual_value": supplied},
        )
        assert failed.status_code == 200
        assert failed.json()["run"] is None
        assert supplied not in failed.text
        events = client.get("/api/v1/events").json()["events"]
        assert supplied not in str(events)

        assert client.post(
            "/api/v1/topology/import?confirm=replace", content=ROTATABLE_MANIFEST
        ).status_code == 200
        extra = client.post(
            "/api/v1/credentials/sonarr_api_key/rotate",
            json={
                "confirm": "sonarr_api_key",
                "manual_value": "a-key-this-plan-does-not-use",
            },
        )
        assert extra.status_code == 400
        assert "does not use a manual mint" in extra.json()["detail"]
        assert extra.json()["detail"].count("a-key-this-plan-does-not-use") == 0
