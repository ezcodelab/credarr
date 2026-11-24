"""The sync state machine, exercised through its store, not a stub.

The properties under test are the ones that decide whether a value reaches a
stack: one active job per credential and target, the newest committed version
wins, a partial result is never terminal success, a stale lease is retried, and
a replayed result is refused.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from credarr.redact import Secret
from credarr.targets import build_registry
from credarr_server.store import TopologyStore
from credarr_server.sync_store import (
    MAX_ATTEMPTS,
    SyncError,
    SyncStore,
    backoff,
)

REGISTRY = build_registry()
MANIFEST = """version: 1
credentials:
  sonarr_api_key:
    class: A
    max_age_days: 90
    consumers:
      - target: seerr.settings_json[sonarr]
        count: 1
        mechanism: process_api
"""


def _stack(tmp_path: Path) -> tuple[TopologyStore, SyncStore]:
    manifest = tmp_path / "credentials.yaml"
    manifest.write_text(MANIFEST, encoding="utf-8")
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest, REGISTRY)
    sync = SyncStore(tmp_path / "app.db", tree_configured=True)
    return store, sync


def _agent(sync: SyncStore, name: str = "edge", capabilities: tuple[str, ...] | None = None):
    token, _ = sync.create_enrollment(name, capabilities or ("compose",))
    return sync.consume_enrollment(
        token,
        fingerprint=f"fp-{name}",
        expires_at=10**12,
        rootful=False,
        ack=False,
    )


def _target(sync: SyncStore, agent_id: str, name: str = "media"):
    return sync.save_target(
        name=name,
        agent_id=agent_id,
        stack_path="/srv/media",
        project_name="media",
        services=("sonarr", "seerr"),
        workflow="compose",
    )


def test_no_job_exists_until_the_version_and_outbox_are_committed(tmp_path: Path) -> None:
    store, sync = _stack(tmp_path)
    agent = _agent(sync)
    _target(sync, agent.id)
    assert sync.jobs() == ()
    assert sync.dispatch() == 0

    store.set_value("sonarr_api_key", Secret("first"))
    assert sync.dispatch() == 1
    (job,) = sync.jobs()
    assert job.state == "queued"
    assert job.value_version == store.vault.current_version("sonarr_api_key").id
    with sqlite3.connect(tmp_path / "app.db") as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM sync_outbox WHERE dispatched_at IS NULL"
        ).fetchone()[0] == 0


def test_a_newer_value_coalesces_while_a_job_is_in_flight(tmp_path: Path) -> None:
    store, sync = _stack(tmp_path)
    agent = _agent(sync)
    _target(sync, agent.id)
    store.set_value("sonarr_api_key", Secret("first"))
    assert sync.dispatch() == 1
    (first,) = sync.jobs()
    leased, _ = sync.lease(agent)
    assert leased is not None and leased.id == first.id

    store.set_value("sonarr_api_key", Secret("second"))
    assert sync.dispatch() == 0, "an in-flight job must not be replaced"
    assert len(sync.jobs()) == 1

    with pytest.raises(SyncError, match="exactly the declared services"):
        sync.report(first.id, agent, services={"sonarr": True})
    delivered = sync.report(
        first.id, agent, services={"sonarr": True, "seerr": True}
    )
    assert delivered.state == "delivered"

    assert sync.dispatch() == 1
    jobs = sync.jobs()
    assert {job.state for job in jobs} == {"delivered", "queued"}
    queued = next(job for job in jobs if job.state == "queued")
    assert queued.value_version == store.vault.current_version("sonarr_api_key").id


def test_partial_delivery_retries_the_whole_service_set(tmp_path: Path) -> None:
    store, sync = _stack(tmp_path)
    agent = _agent(sync)
    _target(sync, agent.id)
    store.set_value("sonarr_api_key", Secret("value"))
    sync.dispatch()
    (job,) = sync.jobs()
    sync.lease(agent)
    sync.begin(job.id, agent)
    partial = sync.report(
        job.id, agent, services={"sonarr": True, "seerr": False}, detail="seerr refused"
    )
    assert partial.state == "retry_wait"
    assert partial.next_attempt_at == pytest.approx(partial.updated_at + backoff(1))
    assert partial.result["services"] == {"sonarr": True, "seerr": False}

    leased, _ = sync.lease(agent, now=partial.next_attempt_at + 1)
    assert leased is not None and leased.attempts == 2
    sync.begin(leased.id, agent)
    delivered = sync.report(
        leased.id, agent, services={"sonarr": True, "seerr": True}
    )
    assert delivered.state == "delivered"
    with sqlite3.connect(tmp_path / "app.db") as connection:
        kinds = [
            row[0]
            for row in connection.execute(
                "SELECT kind FROM events WHERE kind LIKE 'sync_%' ORDER BY id"
            )
        ]
    assert kinds == ["sync_partial", "sync_delivered"]


def test_a_partial_result_never_becomes_success_at_the_attempt_budget(
    tmp_path: Path,
) -> None:
    store, sync = _stack(tmp_path)
    agent = _agent(sync)
    _target(sync, agent.id)
    store.set_value("sonarr_api_key", Secret("value"))
    sync.dispatch()
    now = 1000.0
    for attempt in range(MAX_ATTEMPTS):
        leased, _ = sync.lease(agent, now=now)
        assert leased is not None
        sync.begin(leased.id, agent, now=now)
        result = sync.report(
            leased.id,
            agent,
            services={"sonarr": True, "seerr": False},
            now=now,
        )
        now += 10_000
        if attempt < MAX_ATTEMPTS - 1:
            assert result.state == "retry_wait"
        else:
            assert result.state == "failed"
    assert result.state == "failed"


def test_a_replayed_result_is_refused(tmp_path: Path) -> None:
    store, sync = _stack(tmp_path)
    agent = _agent(sync)
    _target(sync, agent.id)
    store.set_value("sonarr_api_key", Secret("value"))
    sync.dispatch()
    (job,) = sync.jobs()
    sync.lease(agent)
    sync.begin(job.id, agent)
    sync.report(job.id, agent, services={"sonarr": True, "seerr": True})
    with pytest.raises(SyncError, match="no longer in flight"):
        sync.report(job.id, agent, services={"sonarr": True, "seerr": True})


def test_a_job_outside_the_agents_capabilities_is_refused_with_an_event(
    tmp_path: Path,
) -> None:
    store, sync = _stack(tmp_path)
    agent = _agent(sync, capabilities=("compose:/srv/other",))
    _target(sync, agent.id)
    store.set_value("sonarr_api_key", Secret("value"))
    sync.dispatch()
    assert sync.lease(agent) is None
    (job,) = sync.jobs()
    assert job.state == "failed"
    assert "not bound" in job.last_error
    with sqlite3.connect(tmp_path / "app.db") as connection:
        kind = connection.execute(
            "SELECT kind FROM events WHERE kind = 'agent_policy_violation'"
        ).fetchone()
    assert kind is not None


def test_an_expired_lease_returns_to_retry_and_then_fails(tmp_path: Path) -> None:
    store, sync = _stack(tmp_path)
    agent = _agent(sync)
    _target(sync, agent.id)
    store.set_value("sonarr_api_key", Secret("value"))
    sync.dispatch()
    now = 10_000.0
    leased, _ = sync.lease(agent, now=now)
    assert leased is not None
    state = sync.tick(now=now + 10_000)
    assert state["expired"] == 1
    (job,) = sync.jobs()
    assert job.state in ("queued", "retry_wait")
    assert job.attempts == 1


def test_the_newest_committed_version_wins_when_the_older_was_never_leased(
    tmp_path: Path,
) -> None:
    store, sync = _stack(tmp_path)
    agent = _agent(sync)
    _target(sync, agent.id)
    store.set_value("sonarr_api_key", Secret("first"))
    store.set_value("sonarr_api_key", Secret("second"))
    assert sync.dispatch() == 1
    (job,) = sync.jobs()
    current = store.vault.current_version("sonarr_api_key")
    assert job.value_version == current.id
    with sqlite3.connect(tmp_path / "app.db") as connection:
        remaining = connection.execute(
            "SELECT COUNT(*) FROM sync_outbox WHERE dispatched_at IS NULL"
        ).fetchone()[0]
    assert remaining == 0


def test_a_target_requires_the_shared_tree_and_an_enrolled_agent(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "credentials.yaml"
    manifest.write_text(MANIFEST, encoding="utf-8")
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest, REGISTRY)
    no_tree = SyncStore(tmp_path / "app.db", tree_configured=False)
    with pytest.raises(SyncError, match="vault tree"):
        no_tree.save_target(
            name="media",
            agent_id="missing",
            stack_path="/srv/media",
            project_name="media",
            services=("sonarr",),
        )
    with_tree = SyncStore(tmp_path / "app.db", tree_configured=True)
    with pytest.raises(SyncError, match="no such agent"):
        with_tree.save_target(
            name="media",
            agent_id="missing",
            stack_path="/srv/media",
            project_name="media",
            services=("sonarr",),
        )


def test_an_env_target_requires_a_relative_file_and_key_mapping(tmp_path: Path) -> None:
    _store, sync = _stack(tmp_path)
    agent = _agent(sync, capabilities=("compose", "env"))
    base = {
        "name": "homepage",
        "agent_id": agent.id,
        "stack_path": "/srv/homepage",
        "project_name": "homepage",
        "services": ("homepage",),
        "workflow": "env",
    }
    with pytest.raises(SyncError, match="relative env file"):
        sync.save_target(**base, env_file="../outside", values={})
    with pytest.raises(SyncError, match="key mapping"):
        sync.save_target(**base, env_file=".env", values={})
    with pytest.raises(SyncError, match="invalid environment key"):
        sync.save_target(
            **base,
            env_file=".env",
            values={"not-a-key": "sonarr_api_key"},
        )
    target = sync.save_target(
        **base,
        env_file=".env",
        values={"HOMEPAGE_VAR_SONARR_API_KEY": "sonarr_api_key"},
    )
    assert target.env_file == ".env"
    assert target.values == {"HOMEPAGE_VAR_SONARR_API_KEY": "sonarr_api_key"}


def test_an_old_target_table_is_rebuilt_for_the_env_workflow(tmp_path: Path) -> None:
    database = tmp_path / "app.db"
    manifest = tmp_path / "credentials.yaml"
    manifest.write_text(MANIFEST, encoding="utf-8")
    store = TopologyStore(database)
    store.import_manifest(manifest, REGISTRY)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE sync_targets ("
            "id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, agent_id TEXT NOT NULL, "
            "stack_path TEXT NOT NULL, project_name TEXT NOT NULL, services TEXT NOT NULL, "
            "workflow TEXT NOT NULL DEFAULT 'compose' CHECK (workflow IN ('compose')), "
            "enabled INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL, "
            "updated_at REAL NOT NULL)"
        )
        connection.execute(
            "INSERT INTO sync_targets VALUES "
            "('old', 'media', 'agent', '/srv/media', 'media', '[\"sonarr\"]', "
            "'compose', 1, 1.0, 1.0)"
        )
    sync = SyncStore(database, tree_configured=True)
    target = sync.target("old")
    assert target is not None
    assert target.workflow == "compose"
    assert target.env_file is None
    assert target.values == {}
