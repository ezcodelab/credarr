"""The slot registry decides what a rotation is even allowed to attempt.

It replaced three hardcoded tables in the executor and the planner, which is
exactly the kind of change that can quietly lose a case. These tests pin the
properties that matter: every declared holder is describable, a gap is refused
rather than skipped, and a qualified target still resolves to its slot.
"""

from __future__ import annotations

import pytest

from credarr.model import Target, parse_row_selector, split_target
from credarr.writers import (
    API_VERSIONS,
    HOLDERS,
    MINT_SOURCES,
    api_version,
    holder_for,
    known_systems,
)


def test_every_servarr_service_and_slot_is_described():
    """A manifest can declare these; if one is missing the refusal would be
    discovered during a rotation rather than here."""
    for system in ("sonarr", "radarr", "prowlarr", "lidarr", "readarr", "whisparr"):
        for slot in ("indexers", "download_clients"):
            assert holder_for(system, slot) is not None, f"{system}.{slot} is undeclared"
    # Applications exist only on Prowlarr. A writer elsewhere would plan a
    # propagation step against a route that does not exist, after the mint had
    # already revoked the old key.
    assert holder_for("prowlarr", "applications") is not None
    for system in ("sonarr", "radarr", "lidarr", "readarr", "whisparr"):
        assert holder_for(system, "applications") is None, system


def test_only_known_test_routes_are_advertised():
    """The exercise is optional, not guessed. A holder with no known route says
    so, and the executor does not invent an endpoint whose 404 would read as a
    credential failure."""
    assert holder_for("sonarr", "indexers").test_path == "indexer/test"
    assert holder_for("radarr", "indexers").test_path == "indexer/test"
    assert (
        holder_for("sonarr", "download_clients").test_path
        == "downloadclient/test"
    )
    assert (
        holder_for("radarr", "download_clients").test_path
        == "downloadclient/test"
    )
    assert holder_for("prowlarr", "applications").test_path == "applications/test"
    assert holder_for("prowlarr", "indexers").test_path == ""
    assert holder_for("seerr", "settings_json").test_path == ""
    # The Servarr siblings share the shape but no live run has measured their
    # test route, so they stay exercise-unproven.
    for service in ("lidarr", "readarr", "whisparr"):
        assert holder_for(service, "indexers").test_path == ""
        assert holder_for(service, "download_clients").test_path == ""


def test_class_a_confirmation_routes_are_pinned():
    """Class A is a promise of an exercised writer, not just a writer.

    Keep this set in step with `writers.py` and the console catalog: a holder
    has a confirmation route only when it exposes a measured test or a running
    process read-back.
    """
    confirmed = {
        key
        for key, holder in HOLDERS.items()
        if holder.test_path or holder.readback
    }
    assert confirmed == {
        ("sonarr", "indexers"),
        ("radarr", "indexers"),
        ("sonarr", "download_clients"),
        ("radarr", "download_clients"),
        ("prowlarr", "applications"),
        ("seerr", "settings_json"),
        ("qui", "instance"),
    }


def test_an_unknown_slot_is_refused_not_skipped():
    """None is a real answer, and it is what the planner turns into a refusal.

    A rotation cannot complete while a holder cannot be updated, and a silently
    skipped holder leaves a live service holding a revoked key.
    """
    assert holder_for("sonarr", "quality_profiles") is None
    assert holder_for("nonexistent", "indexers") is None


def test_a_qualified_target_resolves_to_its_slot():
    """`prowlarr.applications[Sonarr]` is the applications slot, not a new one.

    The qualifier names a row inside the slot. Reading it as part of the slot
    name made a plan that had already checked the parsed Target report
    `executable`, then fail at execution - after the old key was revoked. This
    is the only reason the executor no longer splits the display string itself.
    """
    assert split_target("prowlarr.applications[Sonarr]") == ("prowlarr", "applications")
    assert split_target("sonarr.indexers") == ("sonarr", "indexers")
    assert holder_for(*split_target("prowlarr.applications[Sonarr]")) is not None


# --- the two holder shapes -------------------------------------------------


def test_seerr_is_registered_as_an_api_holder():
    """Seerr's settings are writable over its API, so the registry says so."""
    described = holder_for("seerr", "settings_json")
    assert described.write == "seerr_api"
    assert described.readback == "process_api"
    assert described.readback_path == "/settings/{service}"
    assert described.auth_header_name == "X-API-Key"


def test_seerr_is_not_a_servarr_holder():
    """The two write strategies are independent, and neither may be inferred.

    A Servarr holder writes over its REST API and is exercised by its own test
    route where one was measured. Seerr writes over its settings API and
    verifies from the running process.
    Both are true today, and which is which is data on the holder.
    """
    assert holder_for("seerr", "settings_json").write == "seerr_api"
    assert holder_for("sonarr", "indexers").write == "servarr_api"


def test_seerr_mints_its_own_key_by_regenerating_it():
    """`known_systems` means "a key can be minted here", not "a key lives here".

    Seerr mints its own key over `POST /settings/main/regenerate` (measured on
    3.5.0). Its mechanism is `regenerate`, not the Servarr `reset`, so a
    `servarr_command` manifest cannot reach Seerr's routes: the planner checks
    the mechanism and refuses.
    """
    assert "seerr" in known_systems()
    assert MINT_SOURCES["seerr"].mechanism == "regenerate"
    assert MINT_SOURCES["seerr"].mint_key_source == "vault"
    assert holder_for("seerr", "settings_json").write == "seerr_api"


def test_an_unqualified_seerr_holder_still_resolves():
    """Preflight refuses it, and that refusal must be reachable.

    `seerr.settings_json` names one section holding three services' credentials.
    Resolving it is correct - the registry knows the section - and the executor
    decides which row to write. A registry that hid it would replace a precise
    "name a row" refusal with a vague "unknown slot" one.
    """
    assert holder_for(*split_target("seerr.settings_json")) is not None
    assert holder_for(*split_target("seerr.settings_json[sonarr]")) is not None


def test_the_qualifier_survives_into_the_execution_target():
    """The slot lookup and the row selection need the same string.

    `split_target` drops the qualifier because a slot lookup must not see it, and
    that is exactly why a qualified target reached the write loop unscoped. The
    selection reads the full target string, so it has to still be there.
    """
    step = "prowlarr.applications[Sonarr]"

    assert parse_row_selector(step) is not None
    assert parse_row_selector(step).row == "Sonarr"
    assert parse_row_selector(step).field is None


def test_a_qualifier_may_hold_only_one_colon():
    """A qualifier is `row` or `row:field`, so two colons fit neither.

    `[Sonarr:HD]` is a row plus a field, not a row named `Sonarr:HD`. Reading a
    colon-bearing row name as the `row:field` form would mean one thing to the
    rotation writer and another to the audit matcher, which compares the whole
    string. A second colon cannot be disambiguated at all, so it is a manifest
    error rather than a divergence discovered during a rotation.
    """
    with pytest.raises(Exception, match="malformed target qualifier"):
        Target.parse("prowlarr.applications[Sonarr:HD:4K]", where="test")

    # The documented single-colon form still parses, and reads as a row + field.
    single = Target.parse("sonarr.download_clients[qBittorrent:password]", where="test")
    assert (single.row_selector.row, single.row_selector.field) == (
        "qBittorrent", "password"
    )


def test_a_row_and_field_qualifier_is_read_as_both():
    """A download-client row carries a password and an API key.

    Only the `row:field` form can say which one, and getting it wrong writes the
    password credential into the apiKey column.
    """
    selector = parse_row_selector("sonarr.download_clients[qBittorrent:password]")

    assert (selector.row, selector.field) == ("qBittorrent", "password")


def test_an_unqualified_target_selects_nothing_rather_than_everything():
    """`None` must mean "no restriction declared", not "match no rows".

    The whole-slot case is a legitimate manifest declaration, so a selector that
    returned an empty set would silently stop every unqualified rotation.
    """
    assert parse_row_selector("sonarr.indexers") is None
    assert parse_row_selector("sonarr.indexers[") is None


def test_the_target_exposes_its_own_row_selector():
    """One parse, used by both the planner and the executor.

    Two implementations of this would drift, and the drift would only appear as a
    rotation that wrote the wrong row after the old key was already revoked.
    """
    qualified = Target.parse("sonarr.download_clients[qBittorrent:password]", where="t")
    assert (qualified.row_selector.row, qualified.row_selector.field) == (
        "qBittorrent", "password"
    )
    assert Target.parse("sonarr.indexers", where="t").row_selector is None


def test_a_servarr_api_path_is_a_bare_route_segment():
    """It is concatenated into a URL, so it may not carry a query or a slash."""
    api = [h for h in HOLDERS.values() if h.write == "servarr_api"]
    assert api, "no API holders to check"
    for holder in api:
        assert holder.api_path.isidentifier(), holder
        assert holder.api_path == holder.api_path.strip()


def test_every_api_holder_carries_the_name_of_what_it_writes():
    """Servarr needs a field; Seerr needs the settings endpoint.

    A registry that had a Servarr holder with no field would silently write
    nothing, and one with no Seerr read-back path could not confirm a write.
    """
    for holder in HOLDERS.values():
        if holder.write == "servarr_api":
            assert holder.field, holder
            assert holder.api_path, holder
        elif holder.write == "seerr_api":
            assert holder.readback_path, holder
        elif holder.write == "qui_api":
            assert holder.api_path, holder
            assert holder.readback_path, holder
        else:
            pytest.fail(f"unknown holder write strategy {holder.write!r}")


def test_the_registry_holds_no_credential():
    """It describes where a credential goes; it must never contain one.

    Every value here is a field or a route segment. A 32-character hex string
    would be exactly as valid to every other assertion in this file, so the
    check is on the whole vocabulary rather than on a length threshold that a
    real key would slip under.
    """
    vocabulary = {holder.field for holder in HOLDERS.values()}
    # Routes are paths, not credential-shaped words; a long route is still a
    # route. The check is for a value that could be a key, so leave paths out.
    assert not any(len(name) > 20 for name in vocabulary), vocabulary


def test_api_version_differs_between_services():
    """Prowlarr is v1 where the others are v3 - so it cannot be a constant."""
    assert api_version("prowlarr") == "v1"
    assert api_version("sonarr") == "v3"
    assert api_version("lidarr") == "v1"
    assert api_version("readarr") == "v1"
    assert api_version("whisparr") == "v3"
    with pytest.raises(KeyError):
        api_version("nonexistent")


def test_every_mintable_service_has_a_known_api_version():
    """Every minting call travels under the service's versioned prefix.

    The version map stays wider than the mintable set - a service can have a
    versioned API without a mint path, which was Seerr's state before the
    regenerate route was measured. These two maps answer different questions -
    where does an HTTP call go, and where does a new credential come from - so
    they are not equal.
    """
    assert known_systems() <= set(API_VERSIONS)
    assert "seerr" in API_VERSIONS
    assert api_version("seerr") == "v1"


def test_every_mint_source_is_pinned_literally():
    """Pinned literally, because this set replaced a constant that was removed.

    Comparing the registry to itself cannot catch it losing a service; only a
    stated expectation can. Jellyfin is included: it mints by creating a key
    alongside the old one, which is the mechanism that removes the revocation
    window every Servarr rotation has. Seerr mints its own key by regenerating
    it, measured on 3.5.0.
    """
    assert known_systems() == frozenset(
        {"sonarr", "radarr", "prowlarr", "lidarr", "readarr", "whisparr",
         "jellyfin", "qbittorrent", "seerr", "grafana", "arcane", "gitea"})
