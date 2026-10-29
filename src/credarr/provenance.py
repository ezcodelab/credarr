"""The version each capability was measured against, and what may be claimed from it.

Standing rule 6: "managed" means measured for a named service version;
everything else is "monitor only". The live harness and the README record those
measurements in prose; this module is their machine-readable half, so a UI shows
the version and the badge from one source instead of retyping either.

An unrecorded version is a real answer, not a hole. The paths have usually been
exercised - Sonarr and Radarr are rotated in the live e2e - but no named build
is behind the result, and a claim with no version behind it is the assumption
the rule exists to refuse. Recording one is a deliberate act: a live run against
a pinned build.

Systems without a reader (Homepage and Profilarr) have nothing measured and no
entry here; they are declared-only or manual-copy targets, which the capability
checklist says separately. Every target or mint service that can be measured
does have an entry - pinned by test - so adding one forces the decision instead
of inheriting an accidental blank. `MEASURED_IMAGES`
is the same record for the image a measurement ran on, and is deliberately
partial: only a live run pins an image. A recorded image is displayed beside
the running one, not asserted equal; no comparison is enforced.
"""

from __future__ import annotations

from .writers import holder_for

# system -> the version its capability was last measured against; "" = unrecorded.
#
# The values are the runs recorded in docs/SERVICES.md,
# plus qBittorrent from the throwaway measurement cited there:
#   prowlarr     reset durability 3/3 and propagation, on 2.6.5.5623
#   seerr        process read-back and a full rotation, on 3.5.0
#   sonarr       full rotation, holder exercise and reset latency, 4.0.20.3014
#   radarr       indexer/test and reset latency on 6.4.4.10685 (2026-10-19);
#                holder propagation itself was exercised on an earlier,
#                unversioned disposable run
#   lidarr       full rotation and Prowlarr holder write on 3.1.0.4875
#   readarr      full rotation and Prowlarr holder write on 0.4.19.2811
#                (LinuxServer publishes this build as a nightly)
#   whisparr     full rotation and Prowlarr holder write on 2.2.0.231
#   qbittorrent  rotateAPIKey mint plus qui and download-client holders, 5.3.0
#   qui          instance write and its own connection test, 1.33.0
#   jellyfin     create/read-back mint, Seerr holder and revoke, 12.2.0; the
#                running deployment floats on `latest`, so the digest below is
#                the image the measurement ran on, not a running version pin
#   grafana      service-account token create, delete and liveness, 12.1.1
#   arcane       scoped key create and delete on 2.17.0, re-run 2026-10-24 on
#                the digest below (`arcane_api_key.py`); the tag still floats,
#                so the digest - not the tag - is the pin.
#   gitea        personal-access-token create, list and delete plus webhook
#                secret update, 1.27.2
MEASURED_VERSIONS: dict[str, str] = {
    "sonarr": "4.0.20.3014",
    "radarr": "6.4.4.10685",
    "prowlarr": "2.6.5.5623",
    "seerr": "3.5.0",
    "lidarr": "3.1.0.4875",
    "readarr": "0.4.19.2811 nightly",
    "whisparr": "2.2.0.231",
    "qbittorrent": "5.3.0",
    "qui": "1.33.0",
    "jellyfin": "12.2.0",
    "grafana": "12.1.1",
    "arcane": "2.17.0",
    "gitea": "1.27.2",
}

# The image each measurement above ran against, where the live run recorded
# one. Same deliberate act as a version, and no fallback: an image nobody
# pinned is not a measurement, so a service missing from here is "no measured
# image", which the console words as a state rather than a failure.
#
#   prowlarr  the full rotation, holder exercise and reset-latency demo ran on
#             this image; the separate durability harnesses pin the earlier
#             `cc10...` digest they were measured on
#   sonarr    this image carried the full rotation, exercise probe and
#             reset-latency run
#   radarr    the indexer/test route was measured on this image 2026-10-19;
#             reset latency was measured on the same digest
#   seerr     the pinned image of the adoption run, whose revision label the
#             harness asserts
#   lidarr    the pinned image the full disposable e2e rotated from
#   readarr   the nightly digest the full disposable e2e rotated from
#   whisparr  hotio publishes no version tag for this build; the digest is the
#             pin and the running app reports 2.2.0.231
MEASURED_IMAGES: dict[str, str] = {
    "sonarr": "sha256:0deb8db6c839ac475e9cd86277712772c40ba7f929a003d7e1de36c4b666bc13",
    "radarr": "sha256:cfbc4fa09dc9d78f7cedc898f4ec48c6277cacedc523c4e159db6ff1c741959c",
    "prowlarr": "sha256:f9151e5bc1025c6d0a630d503210cdcb6bb55a7cc098562609d96a408d838902",
    "seerr": "sha256:27602401178d54f1964442287b9f23f67a3fa2252645ee8065839ea1c3f69e45",
    "lidarr": "sha256:d8549ff9ea29b4015c32257360652c1000c31ea471a2b3f0835ae77292faf35b",
    "readarr": "sha256:4f291128d1a5538be73c2a30473d7cdd0820e223dc8b8533b0cbc5659000dcbe",
    "whisparr": "sha256:63ce52f78a6106c614aea455053da028255f84e4b9ee4235403cd8a111ec898e",
    "qbittorrent": "sha256:e887804fa9de4c60f5f0fb1f3a7e4febe40a8f69fe736f70c4e8589b1f868dab",
    "qui": "sha256:0348a74d25118969ed31baf5af922685ec03a0ef84af4e01d7c8441bc341d5b8",
    "grafana": "sha256:a1701c2180249361737a99a01bc770db39381640e4d631825d38ff4535efa47d",
    "jellyfin": "sha256:799509f8ef3be7037478699cc6fd14d19dd75faac5e474ed219e98ae78a5b3e4",
    "gitea": "sha256:c7953964c6e8fe532cf7fc3f3efdea1d0b161d7859c47e04f5e05489d494dea0",
    "arcane": "sha256:47af3e1aa8492eb17276d0dcc6c55fb1dfde98cfd928c12f2961023221891f5a",
}


def measured_version(system: str) -> str | None:
    """The version this build's capability for `system` was measured against.

    None means this build has no reader or mint for the system at all
    (declared-only, or unknown): there is no measured version to show. Empty
    string means the capability exists but no named build was recorded, which
    refuses the same claims None does - a caller showing manifest services
    draws its declared-only wording from the first case, not from
    `provenance_text`.
    """
    return MEASURED_VERSIONS.get(system)


def measured_image(system: str) -> str | None:
    """The image ID this build's capability for `system` was last measured on.

    None means no live run recorded one, which is the common case: the image of
    a running container is only a measurement when it was pinned for a run, and
    the Services view shows an unpinned service as "no measured image", never
    as an implicit match.
    """
    return MEASURED_IMAGES.get(system)


def provenance_text(system: str) -> str | None:
    """The measured-version line for a service, generated so nobody types it.

    None for a system with no reader or mint; the caller's declared-only state,
    not this text, is what such a service shows. Test with `is None`, not
    truthiness: an unrecorded capability and a missing one are different
    states.
    """
    version = measured_version(system)
    if version is None:
        return None
    return f"measured against {version}" if version else "measured version unrecorded"


def managed(system: str, slot: str) -> bool:
    """Whether a holder may display as managed; False is "monitor only".

    Two facts, both required: this build has a writer for the holder, and the
    service has a recorded measured version. The plan's per-claim gate is "a
    recorded live-fixture measurement for the named service version", so it
    applies to every holder - the item text singles out file/DB holders, and a
    rule that let an unmeasured service through because its holder happened to
    be API-shaped would be the weaker reading of the same gate.

    This gates what may be claimed, not what may run: rotation eligibility is
    the plan's and the class system's, and an unrecorded version does not block
    a rotation the plan allows.
    """
    return holder_for(system, slot) is not None and bool(measured_version(system))
