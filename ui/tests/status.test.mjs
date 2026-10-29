import assert from "node:assert/strict";
import test from "node:test";

import { checkStatus, eventInfo, fixHint, stackHealth, statusInfo, statusOf } from "../src/lib/status.js";

const audit = {
  topology: { imported: true },
  rotation: { pending: [] },
  last_audit: { exit_status: "match" },
};

function health(rows) {
  return stackHealth(audit, { credentials: rows, observed_run: {} });
}

test("a no-holder credential is not 'not audited yet'", () => {
  assert.equal(statusOf({ status: null, consumers: [] }), "no_holders");
  assert.equal(
    statusOf({ status: null, consumers: [{ target: "sonarr.indexers" }] }),
    "none",
  );
  assert.equal(statusOf({ status: "match", consumers: [] }), "match");
});

test("a manual copy reads as manual, not indirect", () => {
  assert.equal(statusInfo("indirect").label, "manual");
  assert.equal(statusInfo("manual").label, "manual");
  assert.equal(statusInfo("indirect").tone, "none");
});

test("a rotation with only manual copies reads as succeeded, not failed", () => {
  assert.deepEqual(eventInfo("rotation_manual"), {
    status: "enabled",
    label: "rotation succeeded",
  });
  assert.equal(eventInfo("rotation_failed").status, "error");
});

test("a manual-only stack is healthy without claiming every copy was compared", () => {
  const result = health([
    {
      name: "prowlarr_api_key",
      status: "match",
      consumers: [{ target: "homepage.label", manual: true }],
    },
  ]);

  assert.equal(result.tone, "ok");
  assert.equal(result.label, "all clear");
  assert.equal(result.title, "No findings");
  assert.match(result.why, /manual copies are not compared/i);
  assert.doesNotMatch(result.why, /app cards/i);
});

test("a no-holder credential does not make the stack incomplete", () => {
  const result = health([
    { name: "sonarr_api_key", status: "match", consumers: [{}] },
    { name: "seerr_api_key", status: null, consumers: [] },
  ]);

  assert.equal(result.tone, "ok");
  assert.equal(result.label, "all clear");
});

test("a credential with holders and no status still needs an audit", () => {
  const result = health([
    { name: "sonarr_api_key", status: null, consumers: [{}] },
  ]);

  assert.equal(result.tone, "warn");
  assert.equal(result.label, "coverage incomplete");
});

test("a missing value names the app page", () => {
  assert.match(
    fixHint({ stored: false, consumers: [{}], status: "unverifiable", detail: "" }),
    /app page/,
  );
});

test("a credential nothing holds says so", () => {
  assert.match(
    fixHint({ stored: false, consumers: [], status: "unverifiable", detail: "" }),
    /Nothing holds this key/,
  );
});

test("a missing holder row names the row's service", () => {
  assert.match(
    fixHint({
      stored: true,
      status: "unverifiable",
      detail: "the holder's API lists no row named 'Sonarr'; without a readable copy this is not a finding",
    }),
    /Add or rename that row/,
  );
});

test("an unreachable service names the URL", () => {
  assert.match(
    fixHint({
      stored: true,
      status: "unverifiable",
      detail: "the holder's API could not be read for a liveness test (connection refused)",
    }),
    /service's URL/,
  );
});

test("a compared row needs no hint", () => {
  assert.equal(fixHint({ stored: true, status: "match", detail: "" }), "");
});

test("a missing holder-service key names that service", () => {
  assert.match(
    fixHint({
      stored: true,
      status: "unverifiable",
      detail: "no stored key for seerr; store seerr's own key before declaring process_api; the running service's value is not confirmed",
    }),
    /Seerr's API key is not configured/,
  );
});

test("a stable reason names the fix when the sentence is empty", () => {
  assert.match(
    fixHint({ stored: true, status: "unverifiable", detail: "", reason: "row_missing" }),
    /Add or rename that row/,
  );
  assert.match(
    fixHint({ stored: true, status: "unverifiable", detail: "", reason: "no_readback" }),
    /cannot be read back/,
  );
  assert.match(
    fixHint({ stored: true, status: "unverifiable", detail: "", reason: "value_missing" }),
    /Add this key on its app page/,
  );
});

test("a live holder at its ceiling reads ok, not a gap", () => {
  assert.equal(statusInfo("live").label, "ok");
  assert.equal(statusInfo("live").tone, "ok");
  const result = health([
    { name: "sonarr_api_key", status: "live", consumers: [{}] },
    { name: "prowlarr_api_key", status: "live", consumers: [{}] },
  ]);
  assert.equal(result.tone, "ok");
  assert.equal(result.label, "all clear");
});

test("a live run is all clear, not a stack warning", () => {
  const liveAudit = {
    ...audit,
    last_audit: { exit_status: "live" },
  };
  const result = stackHealth(liveAudit, {
    credentials: [
      { name: "sonarr_api_key", status: "live", consumers: [{}] },
      { name: "seerr_api_key", status: "match", consumers: [{}] },
    ],
    observed_run: {},
  });
  assert.equal(result.tone, "ok");
  assert.equal(result.label, "all clear");
  assert.equal(result.title, "No findings");
  assert.match(result.why, /accepted by its service/i);
});

test("a live run with a manual copy is all clear and names manual coverage", () => {
  const liveAudit = {
    ...audit,
    last_audit: { exit_status: "live" },
  };
  const result = stackHealth(liveAudit, {
    credentials: [
      {
        name: "prowlarr_api_key",
        status: "live",
        consumers: [{ target: "homepage.label", manual: true }],
      },
    ],
    observed_run: {},
  });
  assert.equal(result.tone, "ok");
  assert.equal(result.label, "all clear");
  assert.equal(result.title, "No findings");
  assert.match(result.why, /manual copies are not compared/i);
  assert.doesNotMatch(result.why, /app cards/i);
});

test("a credential with no holders reads as no holders, not manual", () => {
  const row = { consumers: [] };
  assert.equal(checkStatus("indirect", row), "no_holders");
  assert.equal(checkStatus("manual", row), "no_holders");
});

test("a no-holder shape never hides a failed check", () => {
  const row = { consumers: [] };
  for (const status of ["error", "absent", "unverifiable"]) {
    assert.equal(checkStatus(status, row), status);
  }
});

test("a credential with holders keeps the check's own status", () => {
  const row = { consumers: [{ target: "seerr.settings_json[sonarr]" }] };
  assert.equal(checkStatus("drift", row), "drift");
  assert.equal(checkStatus("match", row), "match");
  assert.equal(checkStatus("indirect", null), "indirect");
});
