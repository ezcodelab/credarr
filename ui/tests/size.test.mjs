import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

// A component that keeps growing is a screen nobody can review. The cap is a
// line count, not a style rule: it is cheap to check and it fails the moment a
// file crosses it, so the split happens while the file is still small enough
// to split.
const SOURCE = join(fileURLToPath(new URL("..", import.meta.url)), "src");
const LIMIT = 900;

// Files already over the cap when it went in. An entry may only shrink: it
// must stay above the cap (otherwise it belongs off this list, where the plain
// cap applies) and it must never grow past the number recorded here. The list
// itself may only shrink, so a new large component cannot be parked here.
const GRANDFATHERED = {
  "SetupWizard.svelte": 1720,
  "views/AppDetail.svelte": 1261,
  "lib/NotificationServices.svelte": 912,
};

function components(directory = SOURCE) {
  const found = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) found.push(...components(path));
    else if (entry.name.endsWith(".svelte")) found.push(path);
  }
  return found.sort();
}

function lines(path) {
  const text = readFileSync(path, "utf8");
  if (text === "") return 0;
  const split = text.split("\n");
  return text.endsWith("\n") ? split.length - 1 : split.length;
}

test("no component exceeds the line cap", () => {
  const over = components()
    .map((path) => ({ name: relative(SOURCE, path), count: lines(path) }))
    .filter((file) => file.count > LIMIT)
    .filter((file) => !(file.name in GRANDFATHERED));

  assert.deepEqual(
    over.map((file) => `${file.name} (${file.count} lines)`),
    [],
    "split these components, or make the case for the one you are adding:\n" +
      over.map((file) => `  ${file.name} is ${file.count} lines`).join("\n"),
  );
});

test("a grandfathered component only shrinks, and leaves the list once it fits", () => {
  const entries = Object.entries(GRANDFATHERED);
  const problems = [];

  if (entries.length > 3) {
    problems.push(
      `${entries.length} entries: the list may only shrink, never take a new file`,
    );
  }

  for (const [name, recorded] of entries) {
    let count;
    try {
      count = lines(join(SOURCE, name));
    } catch {
      problems.push(`${name} is listed but does not exist`);
      continue;
    }
    if (count > recorded) {
      problems.push(`${name} grew from ${recorded} to ${count} lines`);
    }
    if (count <= LIMIT) {
      problems.push(
        `${name} is ${count} lines: remove it, the plain cap now holds it`,
      );
    }
  }

  assert.deepEqual(problems, []);
});
