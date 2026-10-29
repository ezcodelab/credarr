import assert from "node:assert/strict";
import test from "node:test";

import {
  clearManualTracker,
  markManualDone,
  pruneManualTracker,
  readManualTracker,
  trackManual,
} from "../src/lib/manualTracker.js";

function storage() {
  const values = new Map();
  return {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
  };
}

test("a manual-copy reminder stores names and survives a reload", () => {
  const store = storage();
  assert.equal(readManualTracker("sonarr_api_key", store), null);

  const tracked = trackManual(
    "sonarr_api_key",
    7,
    ["homepage.label"],
    store,
  );
  assert.equal(tracked.attempt, 7);
  assert.equal(tracked.targets["homepage.label"].done, false);
  assert.deepEqual(readManualTracker("sonarr_api_key", store), tracked);

  const done = markManualDone("sonarr_api_key", "homepage.label", true, store);
  assert.equal(done.targets["homepage.label"].done, true);
  assert.equal(
    readManualTracker("sonarr_api_key", store).targets["homepage.label"].done,
    true,
  );

  assert.equal(clearManualTracker("sonarr_api_key", store), null);
  assert.equal(readManualTracker("sonarr_api_key", store), null);
});

test("a new attempt resets the reminder, and no targets clears it", () => {
  const store = storage();
  trackManual("sonarr_api_key", 7, ["homepage.label"], store);
  markManualDone("sonarr_api_key", "homepage.label", true, store);

  const next = trackManual(
    "sonarr_api_key",
    8,
    ["homepage.label", "jellyfin.label"],
    store,
  );
  assert.equal(next.attempt, 8);
  assert.equal(next.targets["homepage.label"].done, false);
  assert.equal(next.targets["jellyfin.label"].done, false);

  assert.equal(trackManual("sonarr_api_key", 9, [], store), null);
  assert.equal(readManualTracker("sonarr_api_key", store), null);
});

test("a reminder is pruned to targets still declared", () => {
  const store = storage();
  trackManual(
    "sonarr_api_key",
    7,
    ["homepage.label", "old.label"],
    store,
  );

  const kept = pruneManualTracker("sonarr_api_key", ["homepage.label"], store);
  assert.deepEqual(Object.keys(kept.targets), ["homepage.label"]);
  assert.equal(kept.attempt, 7);
  assert.deepEqual(
    Object.keys(readManualTracker("sonarr_api_key", store).targets),
    ["homepage.label"],
  );

  assert.equal(pruneManualTracker("sonarr_api_key", [], store), null);
  assert.equal(readManualTracker("sonarr_api_key", store), null);
  assert.equal(pruneManualTracker("missing", ["homepage.label"], store), null);
});

test("malformed local state is ignored rather than breaking the page", () => {
  const store = storage();
  store.setItem("credarr.manualFollowUp.v1", "{not json");
  assert.equal(readManualTracker("sonarr_api_key", store), null);

  store.setItem(
    "credarr.manualFollowUp.v1",
    JSON.stringify({ bad: { attempt: "7", targets: {} } }),
  );
  assert.equal(readManualTracker("sonarr_api_key", store), null);
});
