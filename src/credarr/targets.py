"""The targets this build knows, without any local read path.

A target is valid because a writer can update it, because it is rendered
elsewhere at deploy time, or because the operator updates it by hand. The last
case still has to be registered or a typo would silently look like a known
copy. Validation rejects a target this map does not name.

The Servarr API redacts a credential on read, so no adapter can read one back.
Strict API-only means the audit either asks the holder's own test to exercise
its stored value (`live`) or reports the copy unverifiable. There is no local
database or config file in this map.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

# Readable over the holder's API (or exercised by its own test route).
_SERVARR = {
    "indexers": "indexer rows over the Servarr API",
    "download_clients": "download-client rows over the Servarr API",
}

TARGETS: dict[str, str] = {}
for _system in ("sonarr", "radarr", "prowlarr", "lidarr", "readarr", "whisparr"):
    for _slot, _description in _SERVARR.items():
        TARGETS[f"{_system}.{_slot}"] = _description
TARGETS["prowlarr.applications"] = "application rows over the Prowlarr API"
TARGETS["seerr.settings_json"] = "settings API, read back from the running process"
TARGETS["qui.instance"] = "qBittorrent instance, confirmed by qui's connection test"

# Profilarr stores each Arr instance's API key in `arr_instances.api_key`. Its
# latest API v1 exposes only GET /api/v1/arr (secrets stripped); the update is
# a SvelteKit page action, and API-key auth is refused outside /api/v1. Until
# upstream adds a write route, this is a declared manual copy: the rotation
# names it, excludes it from the verdict, and never claims it was written.
TARGETS["profilarr.arr_config"] = (
    "Arr instance rows in Profilarr; no write/read API, update the copy by hand"
)

# Rendered from the canonical value at deploy time; there is no second copy to
# read back. Valid to declare, impossible to read.
DECLARED_ONLY = frozenset({"homepage.label"})


@dataclass(frozen=True)
class TargetRegistry:
    """The known-target set the manifest validator and the CLI use."""

    targets: Mapping[str, str] = field(default_factory=lambda: TARGETS)
    declared_only: frozenset[str] = DECLARED_ONLY

    def known_targets(self) -> frozenset[str]:
        return frozenset(self.targets) | self.declared_only

    def describe(self, key: str) -> str:
        if key in self.declared_only:
            return "rendered at deploy time; no read path"
        return self.targets.get(key, "unknown")


def build_registry() -> TargetRegistry:
    return TargetRegistry()
