import assert from "node:assert/strict";
import test from "node:test";

import { deviceLabel } from "../src/lib/device.js";

test("a user agent becomes a browser and an operating system", () => {
  assert.equal(
    deviceLabel(
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    ),
    "Chrome 141 on Linux",
  );
  assert.equal(
    deviceLabel(
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    ),
    "Safari 17 on iOS",
  );
  assert.equal(deviceLabel("Firefox/120 on Linux"), "Firefox 120 on Linux");
});

test("an empty or non-browser label is not parsed as a user agent", () => {
  assert.equal(deviceLabel(""), "Unknown browser");
  assert.equal(deviceLabel("Chrome on Linux"), "Chrome on Linux");
  assert.equal(deviceLabel("curl/8.5.0"), "Unknown browser");
  assert.equal(
    deviceLabel(
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0 Mobile/15E148 Safari/604.1",
    ),
    "Chrome 120 on iOS",
  );
});
