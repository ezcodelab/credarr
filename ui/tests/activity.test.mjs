import assert from "node:assert/strict";
import test from "node:test";
import { get } from "svelte/store";

import { activity, beginActivity, endActivity } from "../src/lib/activity.js";

test("the in-flight count follows overlapping requests and never goes negative", () => {
  assert.equal(get(activity), 0);
  beginActivity();
  beginActivity();
  assert.equal(get(activity), 2);
  endActivity();
  assert.equal(get(activity), 1);
  endActivity();
  assert.equal(get(activity), 0);
  endActivity();
  assert.equal(get(activity), 0);
});
