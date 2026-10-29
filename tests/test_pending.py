"""The pending-mint store: a credential that must survive the restart.

The CLI's canonical copy is a vault, but a backup/restore mint has a window where
the service is already on a value the vault does not hold yet. That value has to
live somewhere durable, private, and temporary. These tests pin the three
properties a crash depends on: it is written before anything reads it, it is
readable across processes, and it is removed when RECORD happens.
"""

from __future__ import annotations

import stat

from credarr.pending import FilePending
from credarr.redact import Secret


def test_a_dry_run_does_not_create_the_pending_file(tmp_path):
    pending = FilePending(tmp_path / "state" / "pending.db")

    assert pending.get("sonarr_api_key") is None
    assert not pending.path.exists()


def test_the_pending_value_survives_a_new_instance(tmp_path):
    path = tmp_path / "state" / "pending.db"
    FilePending(path).set("sonarr_api_key", Secret("candidate-value"))

    # A fresh object models the next process after a crash.
    assert FilePending(path).get("sonarr_api_key").reveal() == "candidate-value"


def test_the_pending_file_is_private_even_on_first_write(tmp_path):
    path = tmp_path / "state" / "pending.db"
    FilePending(path).set("sonarr_api_key", Secret("candidate-value"))

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    # WAL and shared-memory sidecars carry pages of the same value.
    for suffix in ("-wal", "-shm"):
        sidecar = path.with_name(path.name + suffix)
        if sidecar.exists():
            assert stat.S_IMODE(sidecar.stat().st_mode) == 0o600


def test_clear_removes_the_value_but_keeps_the_database(tmp_path):
    path = tmp_path / "state" / "pending.db"
    pending = FilePending(path)
    pending.set("sonarr_api_key", Secret("candidate-value"))

    pending.clear("sonarr_api_key")

    assert pending.get("sonarr_api_key") is None
    assert path.exists()


def test_clear_of_a_file_that_was_never_written_is_harmless(tmp_path):
    pending = FilePending(tmp_path / "state" / "pending.db")

    pending.clear("sonarr_api_key")

    assert not pending.path.exists()


def test_one_credential_does_not_clear_another(tmp_path):
    pending = FilePending(tmp_path / "state" / "pending.db")
    pending.set("sonarr_api_key", Secret("sonarr-candidate"))
    pending.set("prowlarr_api_key", Secret("prowlarr-candidate"))

    pending.clear("sonarr_api_key")

    assert pending.get("sonarr_api_key") is None
    assert pending.get("prowlarr_api_key").reveal() == "prowlarr-candidate"
