"""Concurrency at the stale-lock boundary.

A fixed timeout cannot tell a dead process from a slow one. These tests pin the
behaviour at that boundary, because it is where two processes can end up
writing the same holders at once.

Properties covered:

  a live but slow holder keeps its lock, because it keeps renewing
  a stale token cannot release the lock that replaced it
  a stale token cannot renew the replacement's lease
  ownership is a token, not a pid - coincidental identity cannot pass
  a reclaimed holder stops before its next write
  the check-then-write gap is a known, demonstrated limitation
"""

from __future__ import annotations

import os
import time

import pytest

from credarr.executor import Executor, RotationContext
from credarr.journal import Journal, JournalLocked
from credarr.pending import FilePending
from test_executor import (
    HOST,
    OLD_KEY,
    FakeState,
    FakeTransport,
    _api_xml,
    _credential,
    _plan,
    _servarr_call,
)


def _reclaim_as(
    journal: Journal,
    credential: str,
    token: str | None = None,
    *,
    pid: int | None = None,
    host: str | None = None,
) -> None:
    """Simulate another process taking the lock over."""
    import secrets

    with journal._connect() as db:
        db.execute(
            "INSERT OR REPLACE INTO locks (credential, pid, host, acquired_at, token) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                credential,
                os.getpid() + 1 if pid is None else pid,
                "somewhere-else" if host is None else host,
                time.time(),
                secrets.token_hex(16) if token is None else token,
            ),
        )


def _age(journal: Journal, credential: str, seconds: float) -> None:
    """Move a lock's clock into the past, deterministically."""
    with journal._connect() as db:
        db.execute("UPDATE locks SET acquired_at = ? WHERE credential = ?",
                   (time.time() - seconds, credential))


def test_renewal_is_what_keeps_a_slow_holder_its_lock(tmp_path):
    """Deterministic: the clock is moved by writing to it, not by sleeping.

    Reclaiming a merely-slow holder is how two runs end up propagating to the
    same indexers. This shows that renewal is the thing preventing it - without
    the renewal the very same aged lock is reclaimable.
    """
    stale_after = 900.0
    renewed = Journal(tmp_path / "a.db", stale_after=stale_after)
    token = renewed.try_acquire("cred")
    _age(renewed, "cred", stale_after + 100)

    # Ageing alone is not enough - the heartbeat renews, which is the point.
    assert renewed.renew("cred", token)
    assert renewed.try_acquire("cred") is None, "a renewed lock was reclaimed"

    # The control: the same aged lock, with nobody renewing, is reclaimable.
    idle = Journal(tmp_path / "b.db", stale_after=stale_after)
    idle.try_acquire("cred")
    _age(idle, "cred", stale_after + 100)
    assert idle.try_acquire("cred") is not None, "an unrenewed lock was protected"


def test_the_heartbeat_renews_while_the_body_runs(tmp_path):
    """The renewal is a background thread, so this one does use the clock.

    Everything else is deterministic; this is the single place where the real
    mechanism has to be observed doing its job rather than simulated.
    """
    journal = Journal(tmp_path / "j.db", stale_after=0.3)
    with journal.lock("cred"):
        first = journal.held("cred")["acquired_at"]
        deadline = time.time() + 2.0
        while time.time() < deadline and journal.held("cred")["acquired_at"] == first:
            time.sleep(0.02)
        assert journal.held("cred")["acquired_at"] > first, (
            "the heartbeat did not renew the lease"
        )


def test_a_stale_token_cannot_release_the_lock_that_replaced_it(tmp_path):
    """The bug this closes is concrete and silent.

    A process whose lock was reclaimed comes back and releases on the way out.
    Releasing by credential or by pid alone would delete the *new* owner's lock
    while that process is still running, letting a third one in.
    """
    journal = Journal(tmp_path / "j.db", stale_after=0.2)
    stale = journal.try_acquire("cred")
    _reclaim_as(journal, "cred")

    journal.release("cred", stale)  # the stale process, on its way out

    assert journal.held("cred") is not None, (
        "a stale holder deleted the lock of the process that replaced it"
    )


def test_a_stale_token_cannot_renew_the_replacement_lease(tmp_path):
    """The same must hold for renewal, or a stale holder keeps the new one alive."""
    journal = Journal(tmp_path / "j.db", stale_after=900.0)
    stale = journal.try_acquire("cred")
    _reclaim_as(journal, "cred")

    assert not journal.renew("cred", stale), "a stale token renewed a lease it lost"
    assert journal.renew("cred", journal.held("cred")["token"]), (
        "the real owner cannot renew its own lease"
    )


def test_ownership_is_a_token_not_a_coincidental_identity(tmp_path):
    """pid and host can be reproduced; a random token cannot.

    Two containers can both be pid 1 on the same hostname. An ownership test
    built from pid and host would let one release or renew the other's lock.
    """
    journal = Journal(tmp_path / "j.db", stale_after=900.0)
    token = journal.try_acquire("cred")
    assert token and len(token) == 32

    # A replacement carrying the same pid and host: identical identity, and
    # still not the owner. This is the case pid+host cannot tell apart.
    mine = journal.held("cred")
    _reclaim_as(
        journal, "cred",
        token="not-the-original-token",
        pid=mine["pid"], host=mine["host"],
    )
    theirs = journal.held("cred")
    assert theirs["pid"] == mine["pid"] and theirs["host"] == mine["host"]
    assert theirs["token"] != mine["token"]
    assert not journal.renew("cred", token)
    # Release too: an identity built from pid and host would let this through,
    # and the holder would delete the lock of a process it has nothing to do
    # with. Both directions need covering, not just the one that is obvious.
    journal.release("cred", token)
    assert journal.held("cred") is not None, (
        "a coincidentally-identical holder released a lock it did not own"
    )

    # Two acquisitions never share a token.
    first = Journal(tmp_path / "a.db", stale_after=0.01).try_acquire("x")
    time.sleep(0.02)
    second = Journal(tmp_path / "a.db", stale_after=0.01).try_acquire("x")
    assert first != second


def test_a_reclaimed_holder_notices_before_its_next_write(tmp_path):
    journal = Journal(tmp_path / "j.db", stale_after=900.0)
    token = journal.try_acquire("cred")
    assert journal.renew("cred", token)

    _reclaim_as(journal, "cred")

    assert not journal.renew("cred", token), "a reclaimed holder still believes it holds"
    with pytest.raises(JournalLocked):
        journal.assert_held("cred", token)


def _lease_executor(journal: Journal, state: FakeState, token: str) -> Executor:
    transport = FakeTransport(state)
    ctx = RotationContext(
        credential=_credential(),
        host=HOST,
        transport=transport,
        journal=journal,
        # A real vault value, so the only thing that can stop this run is the
        # fence. With vault_value=None the mint guard refuses for an unrelated
        # reason and the test would pass without testing anything.
        vault_value=OLD_KEY,
        pending=FilePending(journal.path.with_name("pending.db")),
        lease_check=lambda: journal.assert_held("cred", token),
    )

    def backup(host, service, *, key, transport):
        state.backup_calls += 1
        return _api_xml(state.service_key[service]), "backup.zip"

    def restore(host, service, *, key, xml, transport):
        from credarr.executor import _config_xml_api_key
        state.service_key[service] = _config_xml_api_key(xml.decode())
        return 200, None

    return Executor(
        ctx,
        servarr_call=_servarr_call(state),
        servarr_backup=backup,
        servarr_restore=restore,
    )


def test_the_executor_stops_when_its_lease_is_gone(tmp_path):
    """The fence, wired through the executor rather than only the journal."""
    journal = Journal(tmp_path / "j.db", stale_after=900.0)
    token = journal.try_acquire("cred")
    state = FakeState()

    executor = _lease_executor(journal, state, token)
    _reclaim_as(journal, "cred")

    result = executor.execute(_plan())

    assert not result.ok
    assert state.backup_calls == 0, "kept going after losing the lock"
    assert state.api_writes == 0, "wrote to services it no longer owned"


def test_the_fence_is_invisible_when_the_lease_is_held(tmp_path):
    """It must not change behaviour when nothing is wrong with the lease."""
    journal = Journal(tmp_path / "j.db", stale_after=900.0)
    token = journal.try_acquire("cred")
    state = FakeState()

    result = _lease_executor(journal, state, token).execute(_plan())

    assert result.ok, result.detail
    assert state.backup_calls == 1


def test_CHARACTERISATION_the_check_does_not_fence_the_write_it_guards(tmp_path):
    """CHARACTERISATION TEST - THIS ASSERTS DEFECTIVE BEHAVIOUR ON PURPOSE.

    It is not evidence that the executor is safe, and it must never be quoted as
    such. Its only job is to pin the known limitation so it cannot be forgotten
    or deleted without someone noticing the window had closed. A real fencing
    implementation should replace this test, not leave it normalising the race.

    The lease is checked before each step, not atomically with the write it
    guards. Ownership can therefore change between the check and the write, and
    the write still happens. A true fix needs a fencing token carried in every
    write and rejected by the service, which is not built.

    If this test ever starts failing, the window has narrowed - good. If it is
    ever deleted, check that a real fence was built and not just removed.
    """
    journal = Journal(tmp_path / "j.db", stale_after=900.0)
    token = journal.try_acquire("cred")
    state = FakeState()

    executor = _lease_executor(journal, state, token)

    # Pass the check, then lose ownership before the step does its work.
    original = executor._lease_probe = journal.assert_held

    def lose_it_after_checking(credential: str, tok: str) -> None:
        original(credential, tok)
        _reclaim_as(journal, credential)

    executor._ctx.lease_check = lambda: lose_it_after_checking("cred", token)

    result = executor.execute(_plan())

    # The step whose lease was lost mid-flight still carried out its side
    # effect. That is the window. The *next* step's check is what stops the run,
    # so the mint happened and the propagation did not.
    assert state.backup_calls == 1, (
        "the unfenced write did not happen - if this is now refused the window "
        "has closed; update the README caveat rather than deleting the test"
    )
    assert not result.ok, "the run should have been stopped by the next check"
    assert state.api_writes == 0, "the later steps were correctly fenced off"


def test_the_lock_row_identifies_its_owner(tmp_path):
    """Ownership is recorded, and the pid is this process."""
    journal = Journal(tmp_path / "j.db", stale_after=900.0)
    journal.try_acquire("some-credential")
    held = journal.held("some-credential")
    assert held is not None
    assert held["pid"] == os.getpid()
    assert held["host"]
    assert len(held["token"]) == 32


def test_a_legacy_lock_is_reclaimed_not_adopted(tmp_path):
    """A journal written before tokens existed must not match a live holder."""
    journal = Journal(tmp_path / "j.db", stale_after=900.0)
    with journal._connect() as db:
        db.execute("INSERT INTO locks (credential, pid, host, acquired_at) "
                   "VALUES ('cred', 1, 'old', ?)", (time.time() - 10_000,))

    assert not journal.renew("cred", "anything"), "a legacy row matched a token"
    assert journal.try_acquire("cred"), "a legacy lock could not be reclaimed"


def test_concurrent_acquirers_get_exactly_one_winner(tmp_path):
    """The reclaim path is check, delete, insert - it must not interleave.

    Two processes both finding the lock stale must not both delete and both
    insert. The acquire runs inside an immediate transaction, so the losers see
    the winner's row and back off. Driven with a barrier so the threads really
    contend rather than happening to arrive in order.
    """
    import threading

    journal = Journal(tmp_path / "j.db", stale_after=900.0)
    journal.try_acquire("cred")
    # Age it so every thread takes the reclaim path, not the fast-fail path.
    _age(journal, "cred", 10_000)

    barrier = threading.Barrier(8)
    results: list[str | None] = []
    errors: list[str] = []
    guard = threading.Lock()

    def contend() -> None:
        # A barrier with a timeout, and every failure recorded. If a thread dies
        # before reaching the barrier the others must not hang the suite: they
        # time out, raise BrokenBarrierError, and it surfaces as a failed
        # assertion rather than as a stuck test.
        try:
            barrier.wait(timeout=10)
        except threading.BrokenBarrierError as exc:
            with guard:
                errors.append(f"BrokenBarrierError: {exc}")
            return
        try:
            got = journal.try_acquire("cred")
        except Exception as exc:
            with guard:
                errors.append(f"{type(exc).__name__}: {exc}")
            return
        with guard:
            results.append(got)

    threads = [threading.Thread(target=contend, daemon=True) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    assert not [t for t in threads if t.is_alive()], "a thread never finished"
    # Losing the race must be a clean refusal, not an exception. Without the
    # immediate transaction the losers collide on the primary key and surface
    # IntegrityError - which this test would otherwise miss, because it counts
    # winners and an exception means no winner was recorded.
    assert not errors, f"losers raised instead of backing off: {errors}"
    assert len(results) == 8, "a thread died before recording a result"
    winners = [r for r in results if r is not None]
    assert len(winners) == 1, f"{len(winners)} processes believe they hold the lock"
    assert len(set(winners)) == 1, "a token was issued twice"
    # And the surviving row is the winner's.
    assert journal.held("cred")["token"] == winners[0]


def test_tokens_are_distinct_and_unpredictable(tmp_path):
    """`secrets` not `random`: 128 bits from the OS, never a guessable sequence."""
    journal = Journal(tmp_path / "j.db", stale_after=0.01)
    seen = set()
    for i in range(50):
        token = journal.try_acquire(f"cred-{i}")
        assert token is not None
        seen.add(token)
    assert len(seen) == 50, "a token was reused"
    assert all(len(t) == 32 and all(c in "0123456789abcdef" for c in t) for t in seen)


def test_the_fence_is_per_row_not_per_step(tmp_path):
    """A propagation step writes many rows; each one is a protected action.

    Checking only at the step boundary would let a process that lost the lease
    keep writing for the rest of the step.
    """
    journal = Journal(tmp_path / "j.db", stale_after=900.0)
    token = journal.try_acquire("cred")
    state = FakeState()
    checks = {"n": 0}

    executor = _lease_executor(journal, state, token)
    original_check = executor._ctx.lease_check

    def counting() -> None:
        checks["n"] += 1
        original_check()

    executor._ctx.lease_check = counting
    executor.execute(_plan())

    assert state.api_writes == 3, "fixture changed; recount"
    # Steps: mint, sonarr propagate, radarr propagate. Writes: 3.
    # A per-step fence would give 3; per-row gives more.
    assert checks["n"] > len(_plan().steps), (
        f"only {checks['n']} checks for {len(_plan().steps)} steps - the fence "
        "is not covering every write"
    )


def test_ownership_check_is_read_only(tmp_path):
    """The check in front of a write must not itself extend the lease.

    Otherwise it doubles as a keep-alive, and a holder doing nothing but
    checking would never expire.
    """
    journal = Journal(tmp_path / "j.db", stale_after=900.0)
    token = journal.try_acquire("cred")
    before = journal.held("cred")["acquired_at"]

    time.sleep(0.05)
    assert journal.holds("cred", token)
    journal.assert_held("cred", token)

    assert journal.held("cred")["acquired_at"] == before, (
        "checking ownership renewed the lease"
    )


def test_concurrent_first_time_connections_are_safe(tmp_path):
    """Initialisation runs on every connection: schema, then the migration.

    Eight threads opening a brand-new journal at once must all succeed. The
    schema is IF NOT EXISTS throughout and the migration only writes when it
    finds an untokenised row, but "should be fine" is not what a concurrent
    first run looks like in practice.
    """
    import threading

    journal = Journal(tmp_path / "state" / "rotation.db", stale_after=900.0)
    errors: list[str] = []
    guard = threading.Lock()
    barrier = threading.Barrier(8)

    def open_and_write() -> None:
        try:
            barrier.wait(timeout=10)
            journal.try_acquire("cred")
            journal.renew("cred", journal.held("cred")["token"])
        except Exception as exc:
            with guard:
                errors.append(f"{type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=open_and_write, daemon=True) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    assert not [t for t in threads if t.is_alive()], "a thread never finished"
    assert not errors, f"concurrent initialisation failed: {errors}"


def test_container_names_survive_loading_the_configuration(tmp_path):
    """Read-only discovery still needs the operator's real container names.

    The loader used to ignore `containers`, so the image observation silently
    looked for a container named after the service. This pins the parsed
    mapping; no rotation acts on it.
    """
    from credarr.config import load_config

    path = tmp_path / "credarr.yaml"
    path.write_text(
        "version: 1\n"
        "default_host: media\n"
        "manifest: m.yml\n"
        "hosts:\n"
        "  media:\n"
        "    containers: {prowlarr: ct-prowlarr}\n"
    )

    config = load_config(path)

    assert config.host("media").containers["prowlarr"] == "ct-prowlarr"


@pytest.mark.parametrize("container", [7, "ct/prowlarr", "../prowlarr", "prowlarr "])
def test_a_malformed_container_name_is_a_configuration_error(tmp_path, container):
    """The name is an identity for discovery, so a typo must not become a match."""
    from credarr.config import ConfigError, load_config

    path = tmp_path / "credarr.yaml"
    path.write_text(
        "version: 1\n"
        "default_host: media\n"
        "manifest: m.yml\n"
        "hosts:\n"
        "  media:\n"
        f"    containers: {{prowlarr: {container!r}}}\n"
    )

    with pytest.raises(ConfigError, match=r"containers\.prowlarr"):
        load_config(path)


# -- actor: who is rotating, for display ---------------------------------------
#
# The token stays the ownership check. The actor is diagnostic only - it answers
# "rotation in progress by X" for a UI and nothing else, so it is never derived
# from pid or hostname: those are already recorded, they are not identity, and a
# coincidental match would display a confident wrong answer.


def test_the_actor_is_recorded_and_readable(tmp_path):
    journal = Journal(tmp_path / "j.db")
    assert journal.try_acquire("prowlarr_api_key", actor="alice@workstation") is not None

    held = journal.held("prowlarr_api_key")
    assert held is not None
    assert held["actor"] == "alice@workstation"


def test_no_actor_is_invented_when_none_is_given(tmp_path):
    """Absent stays absent.

    Deriving one from pid@host would look like identity and be wrong: two
    containers are both pid 1 on the same hostname, and a UI would show it as
    though it knew who was running.
    """
    journal = Journal(tmp_path / "j.db")
    journal.try_acquire("prowlarr_api_key")

    held = journal.held("prowlarr_api_key")
    assert held["actor"] is None
    # pid and host are still recorded, precisely because they are not identity.
    assert held["pid"] and held["host"]


def test_the_actor_does_not_grant_or_replace_ownership(tmp_path):
    """It is a label, not a capability.

    Ownership must still be provable only by the token, or the actor would
    become a second, guessable key to the same lock.
    """
    journal = Journal(tmp_path / "j.db")
    token = journal.try_acquire("prowlarr_api_key", actor="alice@workstation")

    assert journal.holds("prowlarr_api_key", token) is True
    assert journal.holds("prowlarr_api_key", "not-the-token") is False
    journal.release("prowlarr_api_key", "not-the-token")
    assert journal.holds("prowlarr_api_key", token) is True, (
        "a wrong actor was able to release another holder's lock"
    )


def test_lock_records_the_actor_it_was_given(tmp_path):
    journal = Journal(tmp_path / "j.db")
    with journal.lock("prowlarr_api_key", actor="bob@workstation"):
        assert journal.held("prowlarr_api_key")["actor"] == "bob@workstation"
    assert journal.held("prowlarr_api_key") is None


def test_a_journal_written_before_the_actor_column_still_works(tmp_path):
    """The migration has to run against a journal that already has rows.

    A fresh database takes the column from CREATE TABLE, so a test that only
    uses a new journal proves nothing about the ALTER path - which is the one
    that had previously worked on fresh journals only and broken on every real
    one.
    """
    import sqlite3

    path = tmp_path / "old.db"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE locks (credential TEXT PRIMARY KEY, pid INTEGER NOT NULL, "
        "host TEXT NOT NULL, acquired_at REAL NOT NULL, token TEXT NOT NULL DEFAULT '')"
    )
    connection.execute(
        "INSERT INTO locks VALUES ('prowlarr_api_key', 1, 'oldhost', 1.0, 'legacy-x')"
    )
    connection.commit()
    connection.close()

    journal = Journal(path)
    held = journal.held("prowlarr_api_key")
    assert held is not None, "the pre-existing row was lost"
    assert held["actor"] is None, "an actor was invented for a row written before the column"
    assert held["token"] == "legacy-x"

    with journal.lock("sonarr_api_key", actor="carol@workstation"):
        assert journal.held("sonarr_api_key")["actor"] == "carol@workstation"
