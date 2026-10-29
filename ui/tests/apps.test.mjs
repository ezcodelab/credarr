import assert from "node:assert/strict";
import test from "node:test";

import {
  buildApps,
  copyNames,
  countProposals,
  dryRunSentence,
  isLoginBlock,
  manualCopyLabels,
  manualOnlyCopyLabels,
  manualTargets,
  missingCopyServices,
  ownerOfCredential,
  parseCopyCount,
  titleOfService,
  unprovenCopyLabels,
} from "../src/lib/apps.js";

const sonarr = {
  name: "sonarr_api_key",
  stored: true,
  status: "match",
  consumers: [
    { target: "prowlarr.applications[Sonarr]" },
    { target: "seerr.settings_json[sonarr]" },
  ],
};

const definitions = [
  { name: "sonarr", kind: "servarr", url: "http://sonarr:8989", declared: true },
  { name: "prowlarr", kind: "servarr", url: "http://prowlarr:9696", declared: true },
];

test("a credential joins its service by canonical, else by name", () => {
  assert.equal(ownerOfCredential(sonarr), "sonarr");
  assert.equal(
    ownerOfCredential({ name: "sonarr_api_key", canonical: { service: "radarr" } }),
    "radarr",
  );
  assert.equal(ownerOfCredential({ name: "onboarding_check" }), "");
});

test("buildApps joins cards and lists what has no key", () => {
  const { apps, unassigned, unconnected } = buildApps({
    credentials: [sonarr, { name: "mystery", stored: false, consumers: [] }],
    definitions,
  });
  assert.equal(apps.length, 1);
  assert.equal(apps[0].title, "Sonarr API Key");
  assert.equal(apps[0].url, "http://sonarr:8989");
  assert.equal(apps[0].stored, true);
  assert.equal(unassigned.length, 1);
  assert.equal(unconnected.length, 1);
  assert.equal(unconnected[0].id, "prowlarr");
});

test("a seeded but undeclared service is not a Not connected card", () => {
  const { unconnected } = buildApps({
    credentials: [],
    definitions: [
      {
        name: "jellyfin",
        kind: "jellyfin",
        url: "http://jellyfin:8096",
        declared: false,
      },
    ],
  });
  assert.deepEqual(unconnected, []);
});

test("copies read as service names, deduped", () => {
  assert.deepEqual(copyNames(sonarr), ["Prowlarr", "Seerr"]);
  assert.deepEqual(copyNames({ consumers: [] }), []);
});

test("a copy without a service definition is reported missing", () => {
  assert.deepEqual(missingCopyServices(sonarr, definitions), ["seerr"]);
  assert.deepEqual(missingCopyServices(sonarr, [...definitions, { name: "seerr" }]), []);
  assert.deepEqual(
    missingCopyServices(
      { consumers: [{ target: "homepage.label" }] },
      definitions,
    ),
    [],
    "Homepage is a holder, not an app that needs connecting",
  );
});

test("an app card can name its manual copies", () => {
  const { apps } = buildApps({
    credentials: [
      {
        name: "sonarr_api_key",
        stored: true,
        consumers: [
          { target: "homepage.label", manual: true, status: "indirect" },
        ],
      },
    ],
    definitions: [{ name: "sonarr", kind: "servarr", url: "http://sonarr:8989" }],
  });
  assert.deepEqual(apps[0].manualCopies, ["Homepage labels"]);
});

test("a holder-only service never asks to be connected", () => {
  const { unconnected } = buildApps({
    credentials: [],
    definitions: [
      { name: "homepage", kind: "other", url: "", declared: true },
      { name: "prowlarr", kind: "servarr", url: "http://prowlarr:9696", declared: true },
    ],
  });
  assert.deepEqual(unconnected.map((item) => item.id), ["prowlarr"]);
});

test("unknown services fall back to their id", () => {
  assert.equal(titleOfService("sonarr"), "Sonarr");
  assert.equal(titleOfService("no-such-app"), "no-such-app");
});

test("manual targets exclude a holder with a measured confirmation route", () => {
  assert.deepEqual(
    manualTargets({
      consumers: [
        { target: "seerr.settings_json[sonarr]", exercised: true },
        { target: "homepage.label", manual: true },
        { target: "sonarr.indexers" },
      ],
    }),
    ["homepage.label", "sonarr.indexers"],
  );
});

test("manual-copy labels name holders without a measured confirmation route", () => {
  assert.deepEqual(
    manualCopyLabels({
      consumers: [
        { target: "homepage.label" },
        { target: "seerr.settings_json[sonarr]", exercised: true },
      ],
    }),
    ["Homepage labels"],
  );
  assert.deepEqual(manualCopyLabels({ consumers: [] }), []);
});

test("unproven copies are described as automatic writes with manual proof", () => {
  const row = {
    consumers: [
      { target: "homepage.label", manual: true },
      { target: "lidarr.indexers", exercised: false },
      { target: "seerr.settings_json[sonarr]", exercised: true },
    ],
  };
  assert.deepEqual(manualOnlyCopyLabels(row), ["Homepage labels"]);
  assert.deepEqual(unprovenCopyLabels(row), ["Lidarr indexers"]);
});

test("a live count that disagrees is proposed, nothing else", () => {
  assert.deepEqual(
    countProposals([
      { target: "sonarr.indexers", count: 1, observed_count: 3 },
      { target: "radarr.indexers", count: 2, observed_count: 2 },
      { target: "prowlarr.applications[Sonarr]", count: 1, observed_count: null },
      { target: "seerr.settings_json[sonarr]", count: 1, observed_count: 0 },
    ]),
    [{ target: "sonarr.indexers", count: 1, observed: 3 }],
  );
  assert.deepEqual(countProposals(null), []);
});

test("a typed copy count is a whole number of at least one", () => {
  assert.equal(parseCopyCount("3"), 3);
  assert.equal(parseCopyCount(1), 1);
  assert.equal(parseCopyCount("0"), null);
  assert.equal(parseCopyCount("1.5"), null);
  assert.equal(parseCopyCount(""), null);
  assert.equal(parseCopyCount("many"), null);
});


test("a ready plan reads as the checks that passed", () => {
  assert.equal(
    dryRunSentence({
      refused: false,
      mint_via: "backup_restore",
      steps: [
        { kind: "mint", target: "sonarr_api_key" },
        { kind: "propagate", target: "prowlarr.applications[Sonarr]" },
        { kind: "propagate", target: "sonarr.indexers" },
      ],
    }),
    "Checks passed: sign-in works, the backup answers, 2 copies checked.",
  );
  assert.equal(
    dryRunSentence({
      refused: false,
      mint_via: "backup_restore",
      steps: [{ kind: "propagate", target: "sonarr.indexers" }],
    }),
    "Checks passed: sign-in works, the backup answers, 1 copy checked.",
  );
  assert.equal(
    dryRunSentence({
      refused: false,
      mint_via: "reconstructed",
      steps: [{ kind: "propagate", target: "sonarr.indexers" }],
    }),
    "Checks passed: sign-in works, the service reports SQLite, 1 copy checked.",
  );
  assert.equal(
    dryRunSentence({ refused: false, manual_mint: true, steps: [] }),
    "Checks passed: 0 copies declared; the key comes from you at run time.",
  );
  assert.equal(dryRunSentence({ refused: true, blocked_by: ["x"] }), "");
  assert.equal(dryRunSentence(null), "");
});

test("the UI-login block is recognised by the engine's own words", () => {
  assert.equal(
    isLoginBlock([
      "radarr: the backup download is behind the service's web UI login (HTTP 302); its API key cannot open that route",
    ]),
    true,
  );
  assert.equal(
    isLoginBlock(["write.ui_password must name a stored credential"]),
    true,
  );
  assert.equal(isLoginBlock(["no rotation strategy for write.mechanism ''"]), false);
  assert.equal(isLoginBlock([]), false);
  assert.equal(isLoginBlock(null), false);
});

test("a Profilarr Arr copy is named as a manual copy", () => {
  const row = {
    name: "sonarr_api_key",
    consumers: [
      { target: "profilarr.arr_config[Sonarr]", manual: true },
    ],
  };
  assert.deepEqual(manualOnlyCopyLabels(row), ["Profilarr Arr instances [Sonarr]"]);
  assert.deepEqual(manualTargets(row), ["profilarr.arr_config[Sonarr]"]);
  assert.deepEqual(unprovenCopyLabels(row), []);
});
