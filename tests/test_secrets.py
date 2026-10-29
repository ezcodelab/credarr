"""Secret handling.

The properties tested here are the ones whose failure is silent: a value that
gets printed once is a value that is in a log file, a CI artifact and someone's
scrollback for the rest of time.
"""

from __future__ import annotations

import copy
import json
import pickle
import threading
from pathlib import Path

import pytest

from credarr.errors import SecretSourceError
from credarr.fingerprint import Fingerprinter
from credarr.model import VaultRef
from credarr.redact import Secret, scrub, scrub_url_credentials
from credarr.secrets import StaticSource


def test_every_stringification_path_is_redacted():
    secret = Secret("hunter2-correct-horse")

    assert "hunter2" not in repr(secret)
    assert "hunter2" not in str(secret)
    assert "hunter2" not in f"{secret}"
    assert "hunter2" not in f"{secret}"
    assert "hunter2" not in f"{secret}"
    assert "hunter2" not in "%s" % (secret,)  # noqa: UP031 - the path under test
    assert "hunter2" not in f"{secret!r}"
    # The length is safe to show; it is what makes a report diagnosable.
    assert f"{len('hunter2-correct-horse')} chars" in repr(secret)


def test_a_secret_cannot_become_a_dict_key():
    """Otherwise it lands in a serialised report."""
    with pytest.raises(TypeError):
        {Secret("x"): 1}


# -- scrub: the boundary `Secret` cannot cover ---------------------------------
#
# A Service rejected the write by echoing the resource it was given, so the
# credential came back inside the refusal text. From there it reached an
# exception message, `log_line`, the journal and the operator's terminal - all of
# which `Secret` cannot protect, because the value has already been revealed into
# a plain string by the time the service responds.


def test_scrub_removes_a_revealed_credential_from_service_text():
    text = 'Invalid request: apiKey "the-real-key-000000000" was rejected'

    assert "the-real-key-000000000" not in scrub(text, "the-real-key-000000000")
    assert "rejected" in scrub(text, "the-real-key-000000000"), (
        "scrubbing must not destroy the diagnostic it was cleaning"
    )


def test_scrub_accepts_a_wrapped_secret_too():
    assert scrub("value was aaaaaaaaaaaa", Secret("aaaaaaaaaaaa")) == "value was [redacted]"


def test_scrub_catches_a_value_embedded_in_a_url():
    """Measured 2026-10-19: Sonarr's `indexer/test` failure text carries the
    stored credential inside the URL it reports (`...&apikey=<value>`). The
    scrub is a replacement, so the URL shape needs no special case - pinned
    because an exercise probe's failure is exactly this shape."""
    text = "GET at [http://prowlarr:9696/api/v1?t=caps&apikey=the-real-key-000000000]"

    scrubbed = scrub(text, "the-real-key-000000000")
    assert "the-real-key-000000000" not in scrubbed
    assert "apikey=[redacted]" in scrubbed


def test_scrub_redacts_unknown_query_credentials_by_shape():
    """A stale holder's key is not the canonical, so `scrub` cannot know it.

    The measured holder test embeds the stored value in a URL it reports. The
    shape-based backstop is what keeps that value out of the report even when
    the stored value and the canonical disagree.
    """
    text = "GET at [http://prowlarr:9696/api/v1?t=caps&apikey=stale-key-000000000]"

    scrubbed = scrub_url_credentials(text)
    assert "stale-key-000000000" not in scrubbed
    assert "apikey=[redacted]" in scrubbed
    assert "t=caps" in scrubbed


def test_scrub_ignores_values_too_short_to_be_credentials():
    """A one-character value appears in every message.

    Removing it would mangle the text it was meant to clean. Real credentials are
    far longer, so the floor costs nothing and is asserted here because it is the
    kind of limit that is easy to lower later without noticing.
    """
    assert scrub("abc def", "a") == "abc def"
    assert scrub("x" * 8, "x" * 8) == "[redacted]"


def test_scrub_leaves_unrelated_text_alone():
    assert scrub("nothing secret here", "a-different-value-00000") == "nothing secret here"


def test_scrub_with_no_values_is_a_no_op():
    """The common case must not cost a copy of the message."""
    assert scrub("untouched", None, 12345) == "untouched"


def test_a_secret_cannot_be_pickled():
    """Copy and multiprocessing both default to pickling."""
    with pytest.raises(TypeError):
        pickle.dumps(Secret("x"))
    with pytest.raises(TypeError):
        copy.deepcopy(Secret("x"))


def test_reveal_is_the_only_way_out():
    assert Secret("abc").reveal() == "abc"


def test_empty_secret_is_falsy_but_valid():
    assert not Secret("")
    assert Secret("x")


# --- fingerprints ------------------------------------------------------------


def test_fingerprints_are_stable_within_a_run():
    fp = Fingerprinter()
    assert fp.of(Secret("value")) == fp.of(Secret("value"))
    assert fp.of(Secret("value")) != fp.of(Secret("other"))


def test_fingerprints_differ_between_runs_by_default():
    """A leaked report must not become an oracle for guessing a password."""
    first = Fingerprinter().of(Secret("hunter2"))
    second = Fingerprinter().of(Secret("hunter2"))
    assert first != second


def test_pinning_the_salt_makes_them_stable_across_runs():
    salt = "ab" * 32
    first = Fingerprinter.from_config(salt).of(Secret("hunter2"))
    second = Fingerprinter.from_config(salt).of(Secret("hunter2"))
    assert first == second


def test_pinning_is_disclosed_to_the_operator():
    """A pinned salt is a real downgrade and the report says so."""
    assert Fingerprinter.from_config("ab" * 32).pinned is True
    assert Fingerprinter.from_config(None).pinned is False


def test_a_short_pinned_salt_is_refused():
    with pytest.raises(ValueError):
        Fingerprinter.from_config("abcd")


def test_a_non_hex_salt_is_refused():
    with pytest.raises(ValueError):
        Fingerprinter.from_config("not-hex-at-all-really-not")


# --- navigation --------------------------------------------------------------


def test_a_missing_path_is_none_not_an_empty_string():
    """These are different problems: one is a manifest that disagrees with
    reality, the other is a credential that is genuinely blank."""
    source = StaticSource({"a": {"b": "value"}})
    ref = VaultRef(backend="static", file="x", path=("a", "b"))
    assert source.get(ref).reveal() == "value"

    missing = VaultRef(backend="static", file="x", path=("a", "nope"))
    assert source.get(missing) is None


def test_a_non_string_value_is_an_error():
    source = StaticSource({"a": {"b": {"nested": "dict"}}})
    ref = VaultRef(backend="static", file="x", path=("a", "b"))
    with pytest.raises(SecretSourceError, match="not a string"):
        source.get(ref)


def test_navigation_stops_at_the_first_missing_segment():
    source = StaticSource({"a": "leaf"})
    ref = VaultRef(backend="static", file="x", path=("a", "b"))
    assert source.get(ref) is None


def test_a_list_value_is_not_silently_stringified():
    source = StaticSource({"a": ["one", "two"]})
    ref = VaultRef(backend="static", file="x", path=("a",))
    with pytest.raises(SecretSourceError):
        source.get(ref)


def test_json_output_of_a_probe_never_contains_a_value_typed_as_a_secret():
    """Belt and braces: the probe contract is plain JSON of strings, so the
    audit wraps them in Secret the moment they cross back."""
    payload = json.loads('{"observations": [{"target": "a.b", "label": "x", "value": "y"}]}')
    assert payload["observations"][0]["value"] == "y"
    wrapped = Secret(payload["observations"][0]["value"])
    assert "y" not in f"{wrapped}"


def test_a_manifest_is_self_contained(tmp_path):
    """A manifest declares where its values are, so it resolves them relative
    to itself.

    Resolving against wherever credarr happened to be installed meant that
    moving the tool silently broke every manifest pointing outside its own
    directory. Found by actually moving it.
    """
    from credarr.secrets import AnsibleVaultSource

    store = tmp_path / "manifest-dir"
    store.mkdir()
    source = AnsibleVaultSource(password_file=store / ".vault_pass", root=store)

    assert source._resolve("values.yml") == store / "values.yml"
    assert source._resolve("nested/values.yml") == store / "nested" / "values.yml"
    # Absolute paths are left alone, so a manifest may still point anywhere.
    absolute = tmp_path.parent / "elsewhere.yml"
    assert source._resolve(str(absolute)) == absolute


# --- the vault write -------------------------------------------------------
#
# A rotation that updates the services but not the vault leaves the canonical
# copy stale: the next redeploy puts the old key back and every drift check
# reports it again. Half a rotation is worse than none, so the write path is
# tested as carefully as the read path.

def test_the_vault_write_refuses_a_path_that_does_not_exist(tmp_path):
    from credarr.secrets import MutableAnsibleVaultSource

    store = tmp_path / "v.yml"
    store.write_text("a:\n  b: old\n")
    (tmp_path / ".vault_pass").write_text("x")
    source = MutableAnsibleVaultSource(
        password_file=tmp_path / ".vault_pass", root=tmp_path, binary="cat",
    )
    ref = VaultRef(backend="ansible-vault", file="v.yml", path=("a", "missing"))

    with pytest.raises(SecretSourceError):
        source.set(ref, Secret("new"))
    # Nothing was written.
    assert store.read_text() == "a:\n  b: old\n"


def test_a_tempfile_is_removed_even_when_encrypting_fails(tmp_path):
    """A failed rotation must not leave every credential in the homelab sitting
    in a temporary file on disk - and must leave the old vault alone."""
    from credarr.secrets import MutableAnsibleVaultSource

    store = tmp_path / "v.yml"
    store.write_text("a:\n  b: old\n")
    (tmp_path / ".vault_pass").write_text("x")
    source = MutableAnsibleVaultSource(
        password_file=tmp_path / ".vault_pass", root=tmp_path,
    )
    source._decrypt = lambda path: {"a": {"b": "old"}}

    def fail(source_path: Path, destination: Path) -> None:
        raise SecretSourceError("encryption failed")

    source._encrypt = fail
    ref = VaultRef(backend="ansible-vault", file="v.yml", path=("a", "b"))

    with pytest.raises(SecretSourceError):
        source.set(ref, Secret("new"))

    assert store.read_text() == "a:\n  b: old\n"
    assert list(tmp_path.glob("credarr-vault-*")) == [], "a plaintext temp file survived"


def test_a_successful_vault_write_replaces_the_file_from_private_plaintext(tmp_path):
    """The encrypted result is renamed into place, never written into the live
    vault, and the plaintext it came from is private and removed."""
    from credarr.secrets import MutableAnsibleVaultSource

    store = tmp_path / "v.yml"
    store.write_text("a:\n  b: old\n")
    source = MutableAnsibleVaultSource(password_file=tmp_path / ".vault_pass", root=tmp_path)
    source._decrypt = lambda path: {"a": {"b": "old"}}
    seen = {}

    def encrypt(source_path: Path, destination: Path) -> None:
        seen["file_mode"] = source_path.stat().st_mode & 0o777
        seen["dir_mode"] = source_path.parent.stat().st_mode & 0o777
        destination.write_bytes(b"encrypted")

    source._encrypt = encrypt
    ref = VaultRef(backend="ansible-vault", file="v.yml", path=("a", "b"))
    source.set(ref, Secret("new"))

    assert store.read_bytes() == b"encrypted"
    assert seen == {"file_mode": 0o600, "dir_mode": 0o700}
    assert list(tmp_path.glob("credarr-vault-*")) == []


def test_the_vault_write_lock_serialises_writers(tmp_path):
    from credarr.secrets import MutableAnsibleVaultSource

    store = tmp_path / "v.yml"
    store.write_text("a:\n  b: old\n")
    source = MutableAnsibleVaultSource(password_file=tmp_path / ".vault_pass", root=tmp_path)
    entered = threading.Event()

    def second_writer() -> None:
        with source._write_lock(store):
            entered.set()

    with source._write_lock(store):
        thread = threading.Thread(target=second_writer, daemon=True)
        thread.start()
        assert not entered.wait(0.2), "a second writer entered while the lock was held"

    assert entered.wait(20), "the lock was not released"
    thread.join(timeout=2)
