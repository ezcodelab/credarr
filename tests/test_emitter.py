"""The manifest emitter: the model back to YAML, and back again.

The store imports and exports manifests as text, so the contract these pin is
not "produces nice YAML" but "produces text that re-parses into the same model
through the same strict loader and target registry the audit uses". A field the
round trip drops is a field the store would silently lose, and an emitted file
that fails validation is one the operator cannot load.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from credarr.emitter import emit_manifest
from credarr.model import Manifest
from credarr.secrets import BACKENDS
from credarr.targets import build_registry

REGISTRY = build_registry()

# Every shape the parser accepts, in one manifest: a folded multi-paragraph
# description with quotes and an em-dash, `never_rotate` with and without an
# age, `provisioned: false`, a vault path that is a list with a dot in a
# segment, each qualifier form (a bare row, a row with a field, a row with a
# space and parentheses, a row with a backslash), a consumer with a host and a
# note, a consumer that declares nothing but its target, and free-form
# `canonical`/`write` values: booleans, numbers, null, a string that looks like
# a number, a quoted date-like string, an empty string, nested collections.
FULL = r"""
version: 1
credentials:
  sonarr_api_key:
    description: >-
      "The shared key." Rotated by command, never by PUT - see the note.

      Second paragraph - an em-dash, a colon: and a # sign, because folding
      must not eat any of them.
    class: A
    max_age_days: 90
    canonical:
      kind: servarr_api
      verified: true
      attempts: 3
      ratio: 1.0
      nothing: null
      revision: '007'
      cutoff: '2026-10-15'
      empty: ""
      nested: {attempts: [1, 5]}
    vault:
      backend: ansible-vault
      file: ../homelab-infrastructure/vault.yml
      path: [vault_env_secrets, sonarr, SONARR_API_KEY.v2]
    write:
      mechanism: servarr_command
      detail: >-
        Backup through the API, restore a config-only ZIP, then restart.
    consumers:
      - target: sonarr.indexers
      - target: seerr.settings_json[sonarr]
        count: 1
        mechanism: process_api
        host: nas
        note: read back from the running process
      - target: radarr.indexers[1337x (Prowlarr)]
        count: 2
  qbittorrent_api_key:
    class: B
    never_rotate: true
    provisioned: false
    canonical: {kind: qbittorrent_api}
    vault:
      backend: ansible-vault
      file: vault.yml
      path: [vault_env_secrets, qbittorrent, WEBUI_API_KEY]
    write: {mechanism: qbittorrent_rotate_api}
    consumers:
      - target: qui.instance
        count: 1
  legacy_credentials:
    class: B
    max_age_days: 365
    never_rotate: true
"""

ORIGIN = Path("manifest.yml")

# The live manifest is the one hand-written file the parser meets in
# production; a round trip that holds on a fixture but drops a field here is
# exactly the data loss this test exists to catch. Skipped when the sibling
# repository is not checked out beside this one.
LIVE = Path(__file__).resolve().parents[2] / "homelab-applications" / "credentials.yaml"


def parse(text: str, origin: Path = ORIGIN) -> Manifest:
    return Manifest.parse(
        text,
        origin=origin,
        known_targets=REGISTRY.known_targets(),
        known_backends=BACKENDS,
    )


def test_a_full_manifest_round_trips_exactly() -> None:
    first = parse(FULL)
    second = parse(emit_manifest(first))
    assert second == first


def test_emitting_the_same_model_twice_is_byte_identical() -> None:
    text = emit_manifest(parse(FULL))
    assert emit_manifest(parse(text)) == text


def test_defaults_are_omitted_but_class_is_always_written() -> None:
    minimal = "version: 1\ncredentials:\n  signing_key:\n    class: B\n    never_rotate: true\n"
    text = emit_manifest(parse(minimal))
    assert "class: B" in text
    assert "never_rotate: true" in text
    for absent in (
        "description",
        "max_age_days",
        "provisioned",
        "canonical",
        "vault",
        "write",
        "consumers",
    ):
        assert absent not in text


@pytest.mark.skipif(not LIVE.is_file(), reason="the live manifest repo is not checked out")
def test_the_live_manifest_round_trips_without_inventing_or_dropping_a_field() -> None:
    original = LIVE.read_text(encoding="utf-8")
    if "storage:" in original:
        pytest.skip(
            "the live manifest predates strict API-only and still declares "
            "the retired per-consumer storage field"
        )
    manifest = parse(original, origin=LIVE)
    emitted = emit_manifest(manifest)
    # The parse is the whole "nothing was ignored" guarantee: an unknown key is
    # an error now, so every field in the file is either in the model - and so
    # compared here - or the file does not load at all.
    assert parse(emitted, origin=LIVE) == manifest
    assert emit_manifest(parse(emitted, origin=LIVE)) == emitted
