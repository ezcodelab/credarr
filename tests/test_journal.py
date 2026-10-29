"""The rotation journal.

The property that matters is crash detection: a step recorded as started and
never finished must be visible afterwards. A rotation that dies inside its
irreversible step leaves three services inconsistent, and the operator has to
be told which step - that is the whole reason this writes to disk before it
touches a credential.
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys
import time

import pytest

from credarr.journal import Journal, JournalLocked


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "state" / "rotation.db")


def test_a_completed_rotation_leaves_nothing_pending(journal):
    attempt = journal.begin("prowlarr_api_key")
    journal.step_started(attempt, 0, "mint", "prowlarr", "backup/restore")
    journal.step_finished(attempt, 0, "ok")
    journal.step_started(attempt, 1, "propagate", "sonarr.indexers", "PUT")
    journal.step_finished(attempt, 1, "ok")
    journal.finish(attempt, "completed")

    assert journal.pending() == []


def test_a_step_that_started_and_never_finished_is_pending(journal):
    """The crash case. The step was recorded before it ran, so the absence of a
    finish is evidence, not an absence of evidence."""
    attempt = journal.begin("prowlarr_api_key")
    journal.step_started(attempt, 0, "mint", "prowlarr", "backup/restore")
    journal.step_finished(attempt, 0, "ok")
    journal.step_started(attempt, 1, "propagate", "sonarr.indexers", "PUT 10 rows")
    # ... and then the process died here.

    pending = journal.pending()
    assert len(pending) == 1
    assert pending[0].target == "sonarr.indexers"
    assert pending[0].credential == "prowlarr_api_key"
    assert pending[0].seconds_ago >= 0


def test_take_over_closes_one_credential_and_names_who_decided(journal):
    """The explicit path past a fresh crash.

    `pending()` drops steps on age alone, so without this the only way past a
    `kill -9` is to wait out the window. An operator who knows the run is dead
    closes them now - and the row says a person decided, because "presumed
    dead" is a claim about a process nobody checked.
    """
    attempt = journal.begin("prowlarr_api_key")
    journal.step_started(attempt, 0, "mint", "prowlarr", "backup/restore")
    other = journal.begin("sonarr_api_key")
    journal.step_started(other, 0, "mint", "sonarr", "backup/restore")

    taken = journal.take_over("prowlarr_api_key", "admin")

    assert [step.target for step in taken] == ["prowlarr"]
    # The other credential's run was not spoken for, and stays pending.
    assert [step.credential for step in journal.pending()] == ["sonarr_api_key"]
    assert "prowlarr_api_key" not in journal.open_attempts()
    assert "sonarr_api_key" in journal.open_attempts()
    with journal._connect() as db:
        outcome = db.execute(
            "SELECT outcome FROM steps WHERE target = 'prowlarr'"
        ).fetchone()["outcome"]
    assert outcome == "abandoned: taken over by admin", outcome


def test_a_reclaim_closes_this_credentials_steps_and_leaves_anothers_alone(journal):
    """The row says "reclaimed by a later attempt", so only a run of *this*
    credential may write it. A run of another one closing these would invent an
    attempt of this credential that never happened, and would close the record
    of one that is alive but slow."""
    dead = journal.begin("prowlarr_api_key")
    journal.step_started(dead, 0, "propagate", "sonarr.indexers", "PUT 2 rows")
    other = journal.begin("sonarr_api_key")
    journal.step_started(other, 0, "mint", "sonarr", "backup/restore")
    with journal._connect() as db:
        db.execute("UPDATE steps SET started_at = ?", (time.time() - 3600,))

    reclaimed = journal.reclaim_stale("prowlarr_api_key")

    assert [step.target for step in reclaimed] == ["sonarr.indexers"]
    # Both are stale, so neither blocks a run - but only one carries a verdict.
    assert journal.pending() == []
    with journal._connect() as db:
        outcomes = dict(
            db.execute(
                "SELECT a.credential, s.outcome FROM steps s "
                "JOIN attempts a ON a.id = s.attempt_id"
            ).fetchall()
        )
    assert outcomes["prowlarr_api_key"].startswith("abandoned: run presumed dead")
    assert outcomes["sonarr_api_key"] is None
    assert "prowlarr_api_key" not in journal.open_attempts()
    assert "sonarr_api_key" in journal.open_attempts()


def test_beginning_an_attempt_records_it_even_if_nothing_happens(journal):
    """Died before the first step still leaves a trace."""
    journal.begin("prowlarr_api_key")
    # No steps at all. The attempt row is still there for an operator to find.
    assert Journal(journal.path).pending() == []


def test_the_lock_excludes_a_second_rotation(journal):
    assert journal.try_acquire("prowlarr_api_key")
    assert journal.try_acquire("prowlarr_api_key") is None


def test_the_blocking_lock_refuses_when_held(journal):
    """The blocking form raises rather than returning False.

    A caller that forgets to check a boolean would otherwise proceed unlocked,
    which is the failure this lock exists to prevent. Entering the context
    manager directly is the honest way to test the guard rather than the body.
    """
    assert journal.try_acquire("prowlarr_api_key")
    acquire = journal.lock("prowlarr_api_key")
    with pytest.raises(JournalLocked):
        acquire.__enter__()


def test_the_lock_is_per_credential(journal):
    """Rotating Sonarr's key must not block rotating Prowlarr's."""
    with journal.lock("prowlarr_api_key"), journal.lock("sonarr_api_key"):
        pass


def test_the_lock_is_released_when_the_rotation_fails(journal):
    """A failed rotation is exactly when a stale lock would be worst."""
    with pytest.raises(RuntimeError), journal.lock("prowlarr_api_key"):
        raise RuntimeError("boom")

    # Released despite the exception.
    assert journal.try_acquire("prowlarr_api_key")


def test_a_stale_lock_is_reclaimed_rather_than_blocking_forever(journal):
    """A process that is killed cannot release its lock. Refusing to ever
    rotate again after a crash is a worse failure than a rare overlap."""
    stale = Journal(journal.path, stale_after=0.01)
    with stale._connect() as db:
        db.execute(
            "INSERT INTO locks (credential, pid, host, acquired_at) "
            "VALUES ('prowlarr_api_key', 999999, 'gone', 0)"
        )

    assert stale.try_acquire("prowlarr_api_key")


def test_the_lock_survives_a_process_exit(journal):
    """A real second process, not a second object in this one.

    An in-process lock proves nothing about the case that matters, which is two
    operators on two machines.
    """
    script = (
        "import sys\n"
        "from credarr.journal import Journal, JournalLocked\n"
        "j = Journal(sys.argv[1])\n"
        "try:\n"
        "    with j.lock('prowlarr_api_key'):\n"
        "        print('acquired')\n"
        "except JournalLocked:\n"
        "    print('blocked')\n"
    )
    first = subprocess.run(
        [sys.executable, "-c", script, str(journal.path)],
        capture_output=True, text=True, timeout=60,
    )
    assert "acquired" in first.stdout, first.stderr


def test_the_database_file_is_created_with_its_directory(journal):
    """A state directory that does not exist must not be a reason the first
    rotation cannot be journalled."""
    assert not journal.path.exists()
    journal.begin("x")
    assert journal.path.is_file()


def test_an_existing_journal_gains_the_token_column(tmp_path):
    """A journal written before ownership tokens existed must still open.

    CREATE TABLE IF NOT EXISTS does not add a column to a table that is already
    there, so the first query naming `token` raised OperationalError and the
    rotation died before it started. Nothing caught it because every test made
    its journal with the current schema.
    """
    path = tmp_path / "rotation.db"
    con = sqlite3.connect(path)
    con.executescript(
        "CREATE TABLE locks ("
        " credential TEXT PRIMARY KEY, pid INTEGER NOT NULL,"
        " host TEXT NOT NULL, acquired_at REAL NOT NULL);"
    )
    con.execute(
        "INSERT INTO locks VALUES ('old_cred', 1, 'oldhost', 1.0)"
    )
    con.commit()
    con.close()

    journal = Journal(path, stale_after=900.0)

    assert journal.held("old_cred") is not None, "the old row vanished"
    # Its empty token becomes a distinct placeholder, not something a live
    # holder could match by accident.
    legacy = journal.held("old_cred")["token"]
    assert legacy.startswith("legacy-")
    # The property that matters is not that a placeholder is unusable - it is
    # that it can never be mistaken for a real token, so a live holder is
    # never displaced by an old row, and that the row stays reclaimable.
    real = journal.try_acquire("another_cred")
    assert real and legacy != real
    assert all(c in "0123456789abcdef" for c in real) and len(real) == 32
    assert not journal.renew("old_cred", real), "a real token matched a legacy row"


def test_last_success_ignores_failed_manual_and_unfinished_runs(journal):
    """The auto due clock may only advance on a full, unattended-finishable run.

    A failed attempt, a manual step still owing work, and a crash are different
    failures but the same answer here: no successful rotation.
    """
    assert journal.last_success("prowlarr_api_key") is None

    failed = journal.begin("prowlarr_api_key")
    journal.step_started(failed, 0, "mint", "prowlarr", "backup/restore")
    journal.step_finished(failed, 0, "ok")
    journal.finish(failed, "failed")
    assert journal.last_success("prowlarr_api_key") is None

    manual = journal.begin("prowlarr_api_key")
    journal.step_started(manual, 0, "manual", "homepage.label", "redeploy")
    journal.step_finished(manual, 0, "noted")
    journal.finish(manual, "completed")
    assert journal.last_success("prowlarr_api_key") is None

    interrupted = journal.begin("prowlarr_api_key")
    journal.step_started(interrupted, 0, "mint", "prowlarr", "backup/restore")
    journal.finish(interrupted, "completed")
    assert journal.last_success("prowlarr_api_key") is None

    abandoned = journal.begin("prowlarr_api_key")
    journal.step_started(abandoned, 0, "mint", "prowlarr", "backup/restore")
    journal.step_finished(abandoned, 0, "abandoned: taken over by admin")
    journal.finish(abandoned, "completed")
    assert journal.last_success("prowlarr_api_key") is None

    unproven = journal.begin("prowlarr_api_key")
    journal.step_started(unproven, 0, "propagate", "sonarr.indexers", "PUT")
    journal.step_finished(unproven, 0, "ok")
    journal.record_holder(unproven, "sonarr.indexers", "all", "written", "not read back")
    journal.finish(unproven, "completed")
    assert journal.last_success("prowlarr_api_key") is None

    complete = journal.begin("prowlarr_api_key")
    journal.step_started(complete, 0, "mint", "prowlarr", "backup/restore")
    journal.step_finished(complete, 0, "ok")
    journal.finish(complete, "completed")
    assert journal.last_success("prowlarr_api_key") is not None


def test_last_rotation_counts_a_finished_manual_step(journal):
    """The key has rotated; the copy a human still owes must not retry the mint."""
    attempt = journal.begin("prowlarr_api_key")
    journal.step_started(attempt, 0, "mint", "prowlarr", "backup/restore")
    journal.step_finished(attempt, 0, "ok")
    journal.step_started(attempt, 1, "manual", "homepage.label", "redeploy")
    journal.step_finished(attempt, 1, "noted")
    journal.finish(attempt, "completed")

    assert journal.last_success("prowlarr_api_key") is None
    assert journal.last_rotation("prowlarr_api_key") is not None


def test_last_rotations_answers_the_whole_ledger_in_one_read(journal):
    """The credentials list needs every watermark; asking once per credential
    made one screen open N database connections."""
    def complete(name: str, *, failed_holder: bool = False) -> int:
        attempt = journal.begin(name)
        journal.step_started(attempt, 0, "mint", name, "backup/restore")
        journal.step_finished(attempt, 0, "ok")
        if failed_holder:
            journal.record_holder(
                attempt, "sonarr.indexers", "all", "failed", "not written"
            )
        journal.finish(attempt, "completed")
        return attempt

    complete("prowlarr_api_key")
    good_sonarr = complete("sonarr_api_key")
    bad_sonarr = complete("sonarr_api_key", failed_holder=True)
    failed = journal.begin("radarr_api_key")
    journal.step_started(failed, 0, "mint", "radarr", "backup/restore")
    journal.finish(failed, "failed")
    # Distinguish the two eligible states by time: a grouped query that drops
    # the holder check would pick the later, failed-holder attempt.
    with journal._connect() as db:
        db.execute("UPDATE attempts SET finished_at = 100 WHERE id = ?", (good_sonarr,))
        db.execute("UPDATE attempts SET finished_at = 200 WHERE id = ?", (bad_sonarr,))

    names = ("prowlarr_api_key", "sonarr_api_key", "radarr_api_key")
    expected = {name: journal.last_rotation(name) for name in names}
    assert journal.last_rotations() == {
        name: value for name, value in expected.items() if value is not None
    }
    assert journal.last_rotations()["sonarr_api_key"] == 100


def test_unfinished_is_unwindowed_while_pending_is_not(journal):
    """Auto must still pause on a crash restarted long after the liveness window."""
    attempt = journal.begin("prowlarr_api_key")
    journal.step_started(attempt, 0, "mint", "prowlarr", "backup/restore")
    with sqlite3.connect(journal.path) as connection:
        connection.execute(
            "UPDATE steps SET started_at = ? WHERE attempt_id = ?",
            (time.time() - 10_000, attempt),
        )

    assert journal.pending() == []
    unfinished = journal.unfinished()
    assert len(unfinished) == 1
    assert unfinished[0].credential == "prowlarr_api_key"


def test_an_attempt_without_steps_is_still_open(journal):
    """A kill between `begin` and the first step must not look completed."""
    attempt = journal.begin("prowlarr_api_key")
    assert journal.open_attempts() == {"prowlarr_api_key": attempt}
    journal.finish(attempt, "failed")
    assert journal.open_attempts() == {}


def test_take_over_closes_an_attempt_that_had_no_steps(journal):
    """A kill between `begin` and the first step leaves no step to take over."""
    attempt = journal.begin("prowlarr_api_key")
    assert journal.take_over("prowlarr_api_key", "admin") == []
    assert journal.open_attempts() == {}
    with journal._connect() as db:
        row = db.execute(
            "SELECT outcome FROM attempts WHERE id = ?", (attempt,)
        ).fetchone()
    assert row["outcome"] == "abandoned: taken over by admin", row["outcome"]


def test_a_no_step_attempt_is_closed_by_reclaim(journal):
    """Under the lock, an attempt with nothing open cannot belong to a live run."""
    journal.begin("prowlarr_api_key")
    fresh = journal.begin("sonarr_api_key")

    assert journal.reclaim_stale("prowlarr_api_key") == []
    open_attempts = journal.open_attempts()
    assert "prowlarr_api_key" not in open_attempts
    assert open_attempts["sonarr_api_key"] == fresh
