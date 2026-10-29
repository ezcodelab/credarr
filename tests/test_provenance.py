"""Capability provenance: the version a claim is measured against, or no claim.

Standing rule 6 reads "managed" as measured for a named service version. These
tests pin the three properties the plan asks for: every capability has decided its
provenance entry, the display text is generated from the metadata (there is
nothing for a template to retype), and an unrecorded version cannot produce a
managed badge.
"""

from __future__ import annotations

from credarr import provenance
from credarr.targets import build_registry
from credarr.writers import MINT_SOURCES


def test_every_measured_system_has_a_capability():
    """A new target or mint must record a version, or a stale entry is removed.

    Both directions, so a renamed system cannot leave a stale entry behind that
    makes the covered set look larger than it is.
    """
    targets = {key.split(".")[0] for key in build_registry().known_targets()}
    # Homepage and Profilarr have no reader or writer, so no capability version
    # exists to measure; they are declared-only or manual targets by design.
    systems = (targets | set(MINT_SOURCES)) - {"homepage", "profilarr"}
    assert set(provenance.MEASURED_VERSIONS) == systems


def test_the_versions_are_pinned():
    assert provenance.measured_version("prowlarr") == "2.6.5.5623"
    assert provenance.measured_version("seerr") == "3.5.0"
    assert provenance.measured_version("sonarr") == "4.0.20.3014"
    assert provenance.measured_version("radarr") == "6.4.4.10685"
    assert provenance.measured_version("lidarr") == "3.1.0.4875"
    assert provenance.measured_version("readarr") == "0.4.19.2811 nightly"
    assert provenance.measured_version("whisparr") == "2.2.0.231"
    assert provenance.measured_version("qbittorrent") == "5.3.0"
    assert provenance.measured_version("qui") == "1.33.0"
    assert provenance.measured_version("grafana") == "12.1.1"
    assert provenance.measured_version("arcane") == "2.17.0"
    assert provenance.measured_version("gitea") == "1.27.2"
    # No capability at all, which is a different state from an unrecorded version.
    assert provenance.measured_version("homepage") is None
    assert provenance.measured_version("profilarr") is None
    assert provenance.measured_version("no_such_service") is None


def test_the_images_are_pinned_only_where_a_live_run_recorded_one():
    """Deliberately partial: a service with no pinned image says so.

    An image nobody pinned is not a measurement; the Services view displays
    the recorded image next to the running one without asserting equality, and
    the absence is a state, not a failure.
    """
    assert provenance.measured_image("prowlarr").startswith("sha256:")
    assert provenance.measured_image("seerr").startswith("sha256:")
    assert provenance.measured_image("sonarr").startswith("sha256:")
    assert provenance.measured_image("radarr").startswith("sha256:")
    assert provenance.measured_image("qbittorrent").startswith("sha256:")
    assert provenance.measured_image("qui").startswith("sha256:")
    assert provenance.measured_image("lidarr").startswith("sha256:")
    assert provenance.measured_image("readarr").startswith("sha256:")
    assert provenance.measured_image("whisparr").startswith("sha256:")
    assert provenance.measured_image("grafana").startswith("sha256:")
    assert provenance.measured_image("jellyfin").startswith("sha256:")
    assert provenance.measured_image("gitea").startswith("sha256:")
    assert provenance.measured_image("arcane").startswith("sha256:")
    assert provenance.measured_image("homepage") is None
    assert provenance.measured_image("no_such_service") is None
    # Every pinned image belongs to a target or mint this build has, so a
    # renamed system cannot leave a stale image behind pretending to be
    # measured.
    targets = {key.split(".")[0] for key in build_registry().known_targets()}
    assert set(provenance.MEASURED_IMAGES) <= targets | set(MINT_SOURCES)


def test_the_text_is_generated_from_the_metadata(monkeypatch):
    monkeypatch.setitem(provenance.MEASURED_VERSIONS, "seerr", "9.9.9")
    assert provenance.provenance_text("seerr") == "measured against 9.9.9"
    monkeypatch.setitem(provenance.MEASURED_VERSIONS, "prowlarr", "")
    assert provenance.provenance_text("prowlarr") == "measured version unrecorded"
    # Declared-only: the caller's state, not a line about a measurement.
    assert provenance.provenance_text("homepage") is None


def test_a_recorded_version_with_a_writer_may_display_managed():
    assert provenance.managed("seerr", "settings_json")
    assert provenance.managed("prowlarr", "indexers")
    assert provenance.managed("sonarr", "indexers")
    assert provenance.managed("radarr", "indexers")


def test_an_unrecorded_version_cannot_display_managed(monkeypatch):
    """The acceptance for this slice: no recorded version, no managed badge.

    `seerr.settings_json` is the build's measured process readback, so it is the
    case the plan rule names, and the mutation is to its version rather than its writer.
    Radarr's holder keeps its writer and is still monitor-only once the version
    is unrecorded, which is the point: what is missing is the measurement, not
    the ability to write.
    """
    monkeypatch.setitem(provenance.MEASURED_VERSIONS, "radarr", "")
    assert not provenance.managed("radarr", "indexers")
    monkeypatch.setitem(provenance.MEASURED_VERSIONS, "seerr", "")
    assert not provenance.managed("seerr", "settings_json")


def test_no_writer_is_monitor_only_whatever_the_version_says(monkeypatch):
    monkeypatch.setitem(provenance.MEASURED_VERSIONS, "qbittorrent", "5.2.0")
    monkeypatch.setitem(provenance.MEASURED_VERSIONS, "homepage", "1.0")
    assert not provenance.managed("homepage", "label")


def test_servarr_siblings_are_managed_after_their_live_run():
    """Registration alone is not a measurement; a recorded run is.

    These three gained a writer and a version probe on 2026-10-21, and their
    versions were recorded only after the disposable e2e rotated each of them
    and confirmed the Prowlarr holder. Before that run the same test asserted
    the opposite, deliberately.
    """
    for service in ("lidarr", "readarr", "whisparr"):
        assert provenance.managed(service, "indexers")
