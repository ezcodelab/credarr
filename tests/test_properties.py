"""Properties that must hold for every input, not just the examples.

The strict parser and the planner are the two places where "a typo is
indistinguishable from a check that passed" - exactly the class of bug a
hand-written example misses. These tests generate manifests and hostile text and
assert only public behaviour: `Manifest.parse`, `emit_manifest`, `plan_rotation`
and `scrub`.
"""

from __future__ import annotations

import contextlib

import yaml
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from credarr.config import HostConfig
from credarr.emitter import emit_manifest
from credarr.errors import ConfigError, ManifestError
from credarr.model import Manifest
from credarr.redact import REDACTED, Secret, scrub
from credarr.rotate import plan_rotation

SETTINGS = settings(max_examples=60, deadline=None)

NAMES = st.from_regex(r"[a-z][a-z0-9_]{0,20}", fullmatch=True)
SYSTEMS = st.sampled_from(["sonarr", "radarr", "prowlarr", "seerr"])
SLOTS = st.sampled_from(["indexers", "applications", "download_clients", "settings_json"])
CLASSES = st.sampled_from(["A", "A-unv", "B"])


@st.composite
def credential_specs(draw):
    name = draw(NAMES)
    consumers = st.lists(
        st.builds(
            lambda system, slot, count: {"target": f"{system}.{slot}", "count": count},
            SYSTEMS,
            SLOTS,
            st.integers(min_value=1, max_value=50),
        ),
        max_size=3,
        # A duplicate target inside one credential is refused by the parser, and
        # that refusal is asserted by its own test rather than assumed away here.
        unique_by=lambda consumer: consumer["target"],
    )
    spec = {
        "class": draw(CLASSES),
        "max_age_days": draw(st.integers(min_value=1, max_value=3650)),
        "consumers": draw(consumers),
    }
    return name, spec


@st.composite
def manifests(draw):
    credentials = {}
    for name, spec in draw(st.lists(credential_specs(), max_size=4)):
        credentials[name] = spec
    return {"version": 1, "credentials": credentials}


def _host() -> HostConfig:
    return HostConfig(name="probe", urls={}, containers={})


@SETTINGS
@given(manifests())
def test_a_manifest_survives_an_export_and_reimport(document):
    """Whatever parses must round-trip: export is the backup and migration door."""
    original = Manifest.parse(yaml.safe_dump(document))

    again = Manifest.parse(emit_manifest(original))

    assert again.credentials == original.credentials
    assert emit_manifest(again) == emit_manifest(original)


@SETTINGS
@given(manifests(), st.from_regex(r"[A-Za-z][A-Za-z0-9_]{0,12}", fullmatch=True))
def test_an_unknown_top_level_key_is_always_an_error(document, extra):
    """A typo must fail at load, never be silently ignored."""
    assume(extra not in document)
    document[extra] = 1

    try:
        Manifest.parse(yaml.safe_dump(document))
    except ManifestError:
        return
    raise AssertionError(f"unknown key {extra!r} was accepted")


@SETTINGS
@given(st.text(max_size=400))
def test_arbitrary_text_is_a_sentence_not_a_traceback(text):
    """Bad input raises the tool's own error, never KeyError/TypeError.

    A document that happens to be valid may parse; anything else must come back
    as the product's error. Either outcome is fine, any other exception fails
    the test by escaping it, which is the point.
    """
    # Anything outside this pair is a traceback the operator would see, so
    # letting it escape is the assertion.
    with contextlib.suppress(ManifestError, ConfigError):
        Manifest.parse(text)


@SETTINGS
@given(
    # Token-shaped values: hex, credential length. A value that is itself a
    # fragment of the replacement marker ("[redacte") cannot be asserted about -
    # the marker legitimately contains it - and a boundary-spanning match is
    # impossible when the secret contains no bracket the marker ends with.
    st.text(
        min_size=8,
        max_size=40,
        alphabet="0123456789abcdef",
    ),
    st.text(max_size=200),
)
def test_a_secret_never_survives_scrubbing(secret, harness_text):
    """Any text a service echoes back loses the value it was given."""
    assume(secret not in REDACTED)
    cleaned = scrub(harness_text + secret, secret)
    assert secret not in cleaned
    assert REDACTED in cleaned


@st.composite
def rotatable_credentials(draw):
    """Credentials shaped like the ones a real manifest declares.

    The bare `Credential()` default has no write mechanism, so the planner
    refuses it before it ever decides the ordering; a property over those would
    be vacuous. These draw a real mint and a writable holder target, so some
    generated plans are executable.
    """
    spec = {
        "class": draw(st.sampled_from(["A", "A-unv"])),
        "max_age_days": draw(st.integers(min_value=1, max_value=3650)),
        "vault": {
            "backend": "ansible-vault",
            "file": "vault.yml",
            "path": ["keys", "probe"],
        },
        "write": {"mechanism": draw(st.sampled_from(["servarr_command", ""]))},
        "consumers": draw(
            st.lists(
                st.builds(
                    lambda target, count: {"target": target, "count": count},
                    st.sampled_from(
                        [
                            "prowlarr.applications[Sonarr]",
                            "sonarr.indexers",
                            "seerr.settings_json[sonarr]",
                        ]
                    ),
                    st.integers(min_value=1, max_value=5),
                ),
                max_size=2,
                unique_by=lambda consumer: consumer["target"],
            )
        ),
    }
    document = {"version": 1, "credentials": {"sonarr_api_key": spec}}
    return Manifest.parse(yaml.safe_dump(document)).credentials["sonarr_api_key"]


@given(rotatable_credentials())
def test_a_revoke_window_is_only_claimed_for_an_executable_plan(credential):
    """`revokes_before_holders` describes a run that can happen."""
    plan = plan_rotation(credential, _host())

    if plan.revokes_before_holders:
        assert plan.executable, "a refused plan must not promise an ordering"


def test_an_executable_servarr_plan_does_state_the_window():
    """The property above is only meaningful if an executable case exists."""
    document = {
        "version": 1,
        "credentials": {
            "sonarr_api_key": {
                "class": "A",
                "max_age_days": 90,
                "vault": {
                    "backend": "ansible-vault",
                    "file": "vault.yml",
                    "path": ["keys", "sonarr_api_key"],
                },
                "write": {"mechanism": "servarr_command"},
                "consumers": [
                    {"target": "prowlarr.applications[Sonarr]", "count": 1},
                ],
            }
        },
    }
    credential = Manifest.parse(yaml.safe_dump(document)).credentials["sonarr_api_key"]

    plan = plan_rotation(credential, _host())

    assert plan.executable, plan.blocked_by
    assert plan.revokes_before_holders is True


@given(
    st.text(
        # A credential-shaped value: long enough that a hit inside the repr's
        # own prose ("Secret", "chars") is not a coincidence.
        min_size=12,
        max_size=60,
        alphabet=st.characters(whitelist_categories=("Ll", "Lu")),
    )
)
def test_repr_never_reveals_a_secret(value):
    assert value not in repr(Secret(value))
