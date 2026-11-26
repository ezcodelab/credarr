import assert from "node:assert/strict";
import test from "node:test";

import {
  agentServerUrl,
  deliveryConfigured,
  listenerCopy,
} from "../src/lib/agents.js";

test("a disabled listener names the startup variable", () => {
  const state = listenerCopy({ enabled: false, port: 0, failure: null });

  assert.equal(state.off, true);
  assert.match(state.text, /CREDARR_AGENT_PORT/);
});

test("a failed listener keeps the server's failure sentence", () => {
  const state = listenerCopy({
    enabled: false,
    port: 8443,
    failure: "OSError: address already in use",
  });

  assert.equal(state.off, true);
  assert.equal(state.text, "OSError: address already in use");
});

test("a configured hostname becomes the exact agent URL", () => {
  assert.equal(
    agentServerUrl({ enabled: true, port: 9443, url: "https://credarr.test:9443" }),
    "https://credarr.test:9443",
  );
  assert.equal(
    agentServerUrl({ enabled: true, port: 9443, url: null }),
    "https://<credarr-host>:9443",
  );
});

test("delivery requires the shared tree", () => {
  assert.equal(deliveryConfigured({ tree_configured: true }), true);
  assert.equal(deliveryConfigured({ tree_configured: false }), false);
  assert.equal(deliveryConfigured(null), false);
});
