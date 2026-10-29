"""The audit log: what survives a restart.

The claim these pin is the operational half of "the app remembers": stop the
app, start it again, and the drift state and holder ledger are still there. So
every read here goes through a fresh object, and the last test reads through a
fresh *process*.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from credarr import facade
from credarr.audit import AuditResult, ConsumerResult, CredentialResult, Status
from credarr.errors import ManifestError
from credarr.model import Consumer, Manifest, Target
from credarr.redact import Secret
from credarr.targets import build_registry
from credarr_server.audit_log import AuditLog
from credarr_server.source import StoreSource, runtime_manifest
from credarr_server.store import connect

REGISTRY = build_registry()

# What "the app after a restart" would do: open the database and prove the
# state is readable without anything the writing process still held.
CHILD = """
import sys

from credarr.audit import Status
from credarr_server.audit_log import AuditLog

state = AuditLog(sys.argv[1]).last_state()
assert state is not None, "no state after restart"
credential = next(c for c in state.credentials if c.credential == "sonarr_api_key")
assert state.last_run.exit_status is Status.MATCH, state.last_run
assert credential.credential == "sonarr_api_key", credential
assert credential.consumers[0].target == "seerr.settings_json[sonarr]", credential.consumers
print("match")
"""


def _audit(app) -> AuditResult:
    return facade.audit(app.config, runtime_manifest(app.store), StoreSource(app.store))


def test_a_recorded_audit_reads_back_with_its_holders(app) -> None:
    log = AuditLog(app.store.path)
    run_id = log.record(_audit(app), started_at=1_000.0)

    state = log.last_state()
    assert state is not None
    assert state.last_run.id == run_id
    assert state.last_run.exit_status is Status.MATCH
    assert state.last_run.exit_code == 0
    assert state.last_run.detail == ""
    assert state.last_run.started_at == 1_000.0
    assert state.last_run.finished_at >= state.last_run.started_at
    assert state.last_audit == state.last_run
    assert len(state.credentials) == 2
    credential = next(c for c in state.credentials if c.credential == "sonarr_api_key")
    assert credential.credential == "sonarr_api_key"
    assert credential.status is Status.MATCH
    assert [c.target for c in credential.consumers] == [
        "seerr.settings_json[sonarr]"
    ]
    assert credential.consumers[0].status is Status.MATCH


def test_history_uses_the_holder_sentence_when_the_credential_has_none(app) -> None:
    """A drift's reason lives on the holder row; the per-app history must not
    show a bare drift pill with an empty explanation."""
    log = AuditLog(app.store.path)
    with connect(log.path) as connection:
        cursor = connection.execute(
            "INSERT INTO audit_runs "
            "(started_at, finished_at, exit_code, exit_status, detail) "
            "VALUES (?, ?, ?, ?, '')",
            (100.0, 200.0, 1, "drift"),
        )
        run_id = cursor.lastrowid
        connection.execute(
            "INSERT INTO audit_credentials (run_id, credential, status, detail) "
            "VALUES (?, ?, ?, '')",
            (run_id, "sonarr_api_key", "drift"),
        )
        connection.execute(
            "INSERT INTO audit_consumers "
            "(run_id, credential, position, target, status, detail, observed_count) "
            "VALUES (?, ?, 0, ?, ?, ?, 1)",
            (
                run_id,
                "sonarr_api_key",
                "seerr.settings_json[sonarr]",
                "drift",
                "the live copy differs",
            ),
        )
    (check,) = log.checks("sonarr_api_key")
    assert check.status is Status.DRIFT
    assert check.source == "audit"
    assert check.detail == "seerr.settings_json[sonarr]: the live copy differs"


def test_history_uses_the_holder_sentence_for_unverifiable(app) -> None:
    """An unverifiable credential with an empty roll-up still gets its reason."""
    log = AuditLog(app.store.path)
    log.record(_unverifiable_holder_result(), started_at=1_000.0)

    (check,) = log.checks("prowlarr_api_key")
    assert check.status is Status.UNVERIFIABLE
    assert check.source == "audit"
    assert check.detail.startswith("sonarr.indexers: the holder's own test accepted")
    # The roll-up has no code of its own; the holder's code stands in beside
    # the holder's sentence.
    assert check.reason == "liveness_inconclusive"


def test_a_scoped_check_carries_the_unverifiable_holder_sentence(app) -> None:
    log = AuditLog(app.store.path)
    log.record_check(_unverifiable_holder_result().results[0], at=1_000.0)

    (check,) = log.checks("prowlarr_api_key")
    assert check.status is Status.UNVERIFIABLE
    assert check.source == "check"
    assert check.detail.startswith("sonarr.indexers: the holder's own test")
    assert check.reason == "liveness_inconclusive"


def test_an_unverifiable_event_carries_the_holder_sentence(app) -> None:
    log = AuditLog(app.store.path)
    log.record(
        AuditResult(
            results=[
                CredentialResult(
                    credential=SimpleNamespace(name="prowlarr_api_key"),
                    status=Status.LIVE,
                )
            ]
        ),
        started_at=1_000.0,
    )
    log.record(_unverifiable_holder_result(), started_at=2_000.0)

    (event,) = log.recent_events()
    assert event.kind == "unverifiable"
    assert event.detail.startswith("sonarr.indexers: the holder's own test")


def test_an_old_event_recovers_the_holder_sentence(app) -> None:
    """History written before the event fallback existed still explains itself."""
    log = AuditLog(app.store.path)
    with connect(log.path) as connection:
        cursor = connection.execute(
            "INSERT INTO audit_runs "
            "(started_at, finished_at, exit_code, exit_status, detail) "
            "VALUES (100.0, 200.0, 0, 'unverifiable', '')",
        )
        run_id = cursor.lastrowid
        connection.execute(
            "INSERT INTO audit_credentials (run_id, credential, status, detail) "
            "VALUES (?, 'prowlarr_api_key', 'unverifiable', '')",
            (run_id,),
        )
        connection.execute(
            "INSERT INTO audit_consumers "
            "(run_id, credential, position, target, status, detail, observed_count) "
            "VALUES (?, 'prowlarr_api_key', 0, 'sonarr.indexers', "
            "'unverifiable', 'row 1 timed out', NULL)",
            (run_id,),
        )
        connection.execute(
            "INSERT INTO events "
            "(at, kind, credential, previous_status, status, detail) "
            "VALUES (200.0, 'unverifiable', 'prowlarr_api_key', 'live', "
            "'unverifiable', '')",
        )

    (event,) = log.recent_events()
    assert event.detail == "sonarr.indexers: row 1 timed out"


def test_drift_reads_back_as_drift(app) -> None:
    app.store.set_value("sonarr_api_key", Secret("0" * 32))
    log = AuditLog(app.store.path)
    log.record(_audit(app), started_at=1_000.0)

    state = log.last_state()
    assert state is not None
    assert state.last_run.exit_status is Status.DRIFT
    assert state.last_run.exit_code == 1
    assert next(
        c for c in state.credentials if c.credential == "sonarr_api_key"
    ).status is Status.DRIFT


def _without_a_canonical(app) -> AuditResult:
    """The same stack with the credential declared but no value stored yet:
    the runtime manifest's `vault: None`, which the audit reports as
    unverifiable rather than as drift."""
    manifest = runtime_manifest(app.store)
    credential = manifest.credentials["sonarr_api_key"]
    return facade.audit(
        app.config,
        Manifest(
            version=manifest.version,
            credentials={**manifest.credentials, "sonarr_api_key": replace(credential, vault=None)},
        ),
        StoreSource(app.store),
    )


def _unverifiable_holder_result() -> AuditResult:
    """A credential whose reason exists only on its holder row.

    This is the Prowlarr shape: the roll-up is unverifiable, the credential
    detail is empty, and the useful sentence is on the indexer test.
    """
    return AuditResult(
        results=[
            CredentialResult(
                credential=SimpleNamespace(name="prowlarr_api_key"),
                status=Status.UNVERIFIABLE,
                consumers=(
                    ConsumerResult(
                        consumer=Consumer(target=Target("sonarr", "indexers")),
                        status=Status.UNVERIFIABLE,
                        detail="the holder's own test accepted 1 of 10 row(s); row 1 timed out",
                        reason="liveness_inconclusive",
                    ),
                ),
            )
        ]
    )


def test_a_status_change_records_one_event_carrying_both_statuses(app) -> None:
    """The unit a notification is built from: an edge, not a level.

    A credential that was already drifting is not news an hour later, so the
    ledger writes a row per *change* - and the row says what it changed from,
    because "drift" alone cannot tell a receiver whether this is a new problem
    or a recovery.
    """
    log = AuditLog(app.store.path)
    log.record(_audit(app), started_at=1_000.0)  # baseline: match, no event
    app.store.set_value("sonarr_api_key", Secret("0" * 32))
    log.record(_audit(app), started_at=2_000.0)  # match -> drift

    events = log.recent_events()
    assert len(events) == 1
    event = events[0]
    assert event.kind == "drift"
    assert event.credential == "sonarr_api_key"
    assert event.previous_status is Status.MATCH
    assert event.status is Status.DRIFT
    assert event.at == events[0].at
    # The credential's own detail is empty for a holder-level drift; the event
    # carries the holder's sentence instead, or the notification says nothing.
    assert event.detail.startswith("seerr.settings_json[sonarr]:")


def test_the_first_recorded_status_is_a_baseline(app) -> None:
    """A fresh install audits once and notifies nothing. The first status is
    what the operator just imported, not a change to wake anyone for."""
    app.store.set_value("sonarr_api_key", Secret("0" * 32))
    log = AuditLog(app.store.path)
    log.record(_audit(app), started_at=1_000.0)

    assert log.recent_events() == ()


def test_a_repeated_status_is_not_news(app) -> None:
    log = AuditLog(app.store.path)
    log.record(_audit(app), started_at=1_000.0)
    log.record(_audit(app), started_at=2_000.0)
    log.record(_audit(app), started_at=3_000.0)

    assert log.recent_events() == ()


def test_a_recovery_is_recorded_and_the_event_order_is_newest_first(app) -> None:
    log = AuditLog(app.store.path)
    original = app.store.get_value("sonarr_api_key")
    assert original is not None
    log.record(_audit(app), started_at=1_000.0)
    app.store.set_value("sonarr_api_key", Secret("0" * 32))
    log.record(_audit(app), started_at=2_000.0)
    app.store.set_value("sonarr_api_key", original)
    log.record(_audit(app), started_at=3_000.0)

    assert [event.kind for event in log.recent_events()] == ["recovered", "drift"]


def test_losing_and_regaining_a_canonical_is_told_apart_from_drift(app) -> None:
    """"Cannot tell" is the state that hides drift, so it gets its own kind,
    and leaving it is a recovery - an operator told about a blind spot has to
    be told when the tool can see again."""
    log = AuditLog(app.store.path)
    log.record(_audit(app), started_at=1_000.0)
    log.record(_without_a_canonical(app), started_at=2_000.0)
    log.record(_audit(app), started_at=3_000.0)

    assert [event.kind for event in log.recent_events()] == ["recovered", "unverifiable"]


def test_liveness_is_not_recorded_as_a_recovery(app) -> None:
    """"Live" is not equality, so leaving a blind spot for liveness must not
    emit the green "recovered" event a real match would."""
    log = AuditLog(app.store.path)
    log.record(_audit(app), started_at=1_000.0)
    unverifiable = _without_a_canonical(app)
    log.record(unverifiable, started_at=2_000.0)
    live = replace(
        unverifiable,
        results=[
            replace(unverifiable.results[0], status=Status.LIVE, consumers=())
        ],
    )
    log.record(live, started_at=3_000.0)

    assert [event.kind for event in log.recent_events()] == ["unverifiable"]


def test_live_after_drift_does_not_claim_the_drift_is_over(app) -> None:
    """Only a real comparison resolves a drift; liveness does not."""
    log = AuditLog(app.store.path)
    log.record(_audit(app), started_at=1_000.0)
    app.store.set_value("sonarr_api_key", Secret("0" * 32))
    drifted = _audit(app)
    log.record(drifted, started_at=2_000.0)
    live = replace(
        drifted,
        results=[replace(drifted.results[0], status=Status.LIVE, consumers=())],
    )
    log.record(live, started_at=3_000.0)

    assert [event.kind for event in log.recent_events()] == ["drift"]


def test_a_manual_rotation_attempt_is_an_action_not_a_transition(app) -> None:
    """The Activity trail's new rows: a click that never reached a measurement
    must not invent a "was" or an "is", and each vocabulary keeps its own
    allowlist so a caller cannot write the other one's kinds by accident."""
    import pytest

    log = AuditLog(app.store.path)
    event = log.record_rotation_event(
        "rotation_refused", "sonarr_api_key", "no rotation strategy"
    )
    assert event.previous_status is None and event.status is None
    assert log.recent_events()[0].kind == "rotation_refused"

    with pytest.raises(ValueError, match="manual rotation"):
        log.record_rotation_event("auto_blocked", "sonarr_api_key", "x")
    with pytest.raises(ValueError, match="auto-rotation"):
        log.record_auto_event("rotation_failed", "sonarr_api_key", "x")


def test_a_failed_run_records_no_transition(app) -> None:
    """A run that could not measure anything observed no change; writing an
    event for it would notify about a status nobody saw."""
    log = AuditLog(app.store.path)
    log.record(_audit(app), started_at=1_000.0)
    app.store.set_value("sonarr_api_key", Secret("0" * 32))
    log.record_failure("ManifestError: boom", started_at=2_000.0, exit_code=3)

    assert log.recent_events() == ()


def test_a_failed_run_keeps_the_last_audited_state(app) -> None:
    """The failure is recorded *and* the last known states survive it: a
    dashboard that empties itself on a bad minute is worse than useless."""
    log = AuditLog(app.store.path)
    log.record(_audit(app), started_at=1_000.0)
    log.record_failure(
        "ManifestError: boom", started_at=2_000.0, exit_code=ManifestError.exit_code
    )

    state = log.last_state()
    assert state is not None
    assert state.last_run.exit_status is None
    assert state.last_run.detail == "ManifestError: boom"
    assert state.last_run.exit_code == 3
    assert state.last_audit is not None
    assert state.last_audit.exit_status is Status.MATCH
    assert {c.credential for c in state.credentials} == {
        "sonarr_api_key", "seerr_api_key"
    }


def test_a_failure_without_an_exit_code_reads_back_as_none(app) -> None:
    log = AuditLog(app.store.path)
    log.record_failure("RuntimeError: bug", started_at=1.0)

    state = log.last_state()
    assert state is not None
    assert state.last_run.exit_code is None
    assert state.last_audit is None
    assert state.credentials == ()


def test_the_newest_completed_audit_wins(app) -> None:
    """With history longer than one run, "last state" must mean the newest
    completed audit - not the oldest, and not the failed attempt on top."""
    log = AuditLog(app.store.path)
    log.record(_audit(app), started_at=1_000.0)
    app.store.set_value("sonarr_api_key", Secret("0" * 32))
    log.record(_audit(app), started_at=2_000.0)
    log.record_failure("ManifestError: boom", started_at=3_000.0, exit_code=3)

    state = log.last_state()
    assert state is not None
    assert state.last_run.id == 3
    assert state.last_audit is not None and state.last_audit.id == 2
    assert state.last_audit.exit_status is Status.DRIFT
    assert next(
        c for c in state.credentials if c.credential == "sonarr_api_key"
    ).status is Status.DRIFT


def test_the_ledger_keeps_no_fingerprints(app) -> None:
    """The result carries fingerprints so a report can tell two values apart;
    the ledger is durable, and a fingerprint stored there is a durable
    pseudonym of a secret. Statuses and prose only - and there is prose."""
    app.store.set_value("sonarr_api_key", Secret("0" * 32))
    log = AuditLog(app.store.path)
    result = _audit(app)
    credential_result = result.results[0]
    assert credential_result.canonical_fingerprint is not None
    log.record(result, started_at=1_000.0)

    state = log.last_state()
    assert state is not None
    credential = next(
        c for c in state.credentials if c.credential == "sonarr_api_key"
    )
    printed = [
        credential_result.canonical_fingerprint,
        *credential_result.consumers[0].fingerprints,
    ]
    stored = [credential.detail, *(consumer.detail for consumer in credential.consumers)]
    assert all(fingerprint not in text for fingerprint in printed for text in stored)
    # The consumer detail is the sentence an operator reads; it must survive.
    assert credential.consumers[0].detail


def test_state_survives_a_new_instance(app) -> None:
    AuditLog(app.store.path).record(_audit(app), started_at=1.0)
    # A fresh object, fresh connections: nothing is cached in memory.
    state = AuditLog(app.store.path).last_state()
    assert state is not None
    assert state.last_run.exit_status is Status.MATCH
    # The live scope the audit saw travels with the holder, not only in prose.
    sonarr = next(c for c in state.credentials if c.credential == "sonarr_api_key")
    (consumer,) = sonarr.consumers
    assert consumer.observed_count == 1


def test_a_ledger_written_before_the_observed_count_migrates(app) -> None:
    """The column is additive and the migration is guarded: an app.db from
    before it keeps every run and holder, and reads `None` for the new field
    instead of failing to open."""
    AuditLog(app.store.path).record(_audit(app), started_at=1.0)
    with connect(app.store.path) as connection:
        connection.execute("ALTER TABLE audit_consumers DROP COLUMN observed_count")

    reopened = AuditLog(app.store.path)  # the migration adds the column back
    state = reopened.last_state()
    assert state is not None
    sonarr = next(c for c in state.credentials if c.credential == "sonarr_api_key")
    (consumer,) = sonarr.consumers
    assert consumer.observed_count is None

    with connect(app.store.path) as connection:
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(audit_consumers)")
        }
    assert "observed_count" in columns


def test_a_ledger_written_before_the_reason_column_migrates(app) -> None:
    """The code is additive: rows written before it keep their sentences and
    read an empty reason; a new run writes the code beside the sentence."""
    log = AuditLog(app.store.path)
    log.record(_unverifiable_holder_result(), started_at=1_000.0)
    log.record_check(_unverifiable_holder_result().results[0], at=2_000.0)
    with connect(app.store.path) as connection:
        for table in ("audit_credentials", "audit_consumers", "audit_checks"):
            connection.execute(f"ALTER TABLE {table} DROP COLUMN reason")

    reopened = AuditLog(app.store.path)  # the migration adds the column back
    state = reopened.last_state()
    assert state is not None
    prowlarr = next(
        c for c in state.credentials if c.credential == "prowlarr_api_key"
    )
    assert prowlarr.reason == ""
    assert prowlarr.consumers[0].reason == ""
    checks = reopened.checks("prowlarr_api_key")
    assert checks and all(check.reason == "" for check in checks)

    # And the reopened ledger writes the code for new rows.
    reopened.record(_unverifiable_holder_result(), started_at=3_000.0)
    latest = reopened.checks("prowlarr_api_key")[0]
    assert latest.reason == "liveness_inconclusive"


def test_an_event_ledger_written_before_the_sink_column_migrates(app) -> None:
    """The recipient is additive; history written before it stays readable."""
    log = AuditLog(app.store.path)
    log.record_test_event("hook")
    with connect(app.store.path) as connection:
        connection.execute("ALTER TABLE events DROP COLUMN sink")

    reopened = AuditLog(app.store.path)
    event, = reopened.recent_events()
    assert event.kind == "test"
    assert event.sink is None

    with connect(app.store.path) as connection:
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(events)")
        }
    assert "sink" in columns


def test_state_survives_a_new_process(app) -> None:
    AuditLog(app.store.path).record(_audit(app), started_at=1.0)
    source = Path(__file__).resolve().parents[2] / "src"
    child = subprocess.run(
        [sys.executable, "-c", CHILD, str(app.store.path)],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(source)},
    )
    assert child.returncode == 0, child.stderr
    assert child.stdout.strip() == "match"
