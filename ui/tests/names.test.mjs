import assert from "node:assert/strict";
import test from "node:test";

import { credentialSlug, credentialTitle, copyLabel, friendlyReason, importWarningLines, plainEngineText, reasonsForField, refusalLines, splitLoginWall, stripServicePrefix, bannerLine } from "../src/lib/names.js";

test("a catalog key reads as its service's API Key", () => {
  assert.equal(credentialTitle("sonarr_api_key"), "Sonarr API Key");
  assert.equal(credentialTitle("prowlarr_api_key"), "Prowlarr API Key");
  assert.equal(credentialTitle("qbittorrent_api_key"), "qBittorrent API Key");
});

test("other slugs fall back to title case", () => {
  assert.equal(credentialTitle("ui_created_key"), "UI Created Key");
  assert.equal(credentialTitle("my-custom-id"), "My Custom ID");
  assert.equal(credentialTitle(""), "Credential");
});

test("a typed title becomes the slug the manifest carries", () => {
  assert.equal(credentialSlug("Sonarr API Key"), "sonarr_api_key");
  assert.equal(credentialSlug("UI Created Key"), "ui_created_key");
  assert.equal(credentialSlug("my custom key"), "my_custom_key");
});

test("a title round-trips through its slug", () => {
  assert.equal(credentialTitle(credentialSlug("Sonarr API Key")), "Sonarr API Key");
  assert.equal(credentialTitle(credentialSlug("My Custom Key")), "My Custom Key");
});

test("a title with no usable characters has no slug", () => {
  // "API Key" alone has no service to name, so it keeps the generic slug.
  assert.equal(credentialSlug("API Key"), "api_key");
  assert.equal(credentialSlug("   "), "");
});

test("a target stub at the front of a reason reads as the copy's name", () => {
  assert.equal(
    friendlyReason(
      "sonarr.indexers: no rows to update, so a rotation would change nothing while still invalidating the old key",
    ),
    "Sonarr indexers: no rows to update, so a rotation would change nothing while still invalidating the old key",
  );
  assert.equal(
    friendlyReason("prowlarr.applications[Sonarr]: connection refused"),
    "Prowlarr applications [Sonarr]: connection refused",
  );
});

test("a reason without a known target keeps its words, sentence-cased", () => {
  assert.equal(
    friendlyReason("prowlarr: could not be reached during preflight"),
    "Prowlarr: could not be reached during preflight",
  );
  assert.equal(
    friendlyReason("credential is class A-unv: mintable, but unproven"),
    "Credential is class A-unv: mintable, but unproven",
  );
  assert.equal(
    friendlyReason("unknownsvc.slot: something failed"),
    "Unknownsvc.slot: something failed",
  );
});

test("a target stub reads as the copy's plain name", () => {
  assert.equal(copyLabel("sonarr.indexers"), "Sonarr indexers");
  assert.equal(copyLabel("prowlarr.applications[Sonarr]"), "Prowlarr applications [Sonarr]");
  assert.equal(copyLabel("prowlarr: could not be reached"), "prowlarr: could not be reached");
  assert.equal(copyLabel(null), "");
});

test("only the reasons naming a write field hang off it", () => {
  const reasons = [
    "write.token_name is required: Grafana never returns a token's value",
    "sonarr.indexers: no rows to update",
    "write.mint_with names 'x', which has no stored value in this run",
    "radarr: the backup download is behind the service's web UI login (HTTP 302); Declare write.ui_password, use write.manual_mint, or retry",
  ];
  assert.deepEqual(reasonsForField(reasons, "token_name"), [reasons[0]]);
  assert.deepEqual(reasonsForField(reasons, "mint_with"), [reasons[2]]);
  assert.deepEqual(reasonsForField(reasons, "repo"), []);
  assert.deepEqual(reasonsForField(null, "repo"), []);
  // The login wall names every option at once: it belongs to the panel and
  // the pane intro, not to one field — not even one it mentions.
  assert.deepEqual(reasonsForField(reasons, "ui_password"), []);
  assert.deepEqual(reasonsForField(reasons, "manual_mint"), []);
});

test("no dotted write field reaches the screen", () => {
  assert.equal(
    plainEngineText("write.token_name is required: Grafana never returns a token's value"),
    "Token name is required: Grafana never returns a token's value",
  );
  assert.equal(
    plainEngineText("no rotation strategy for write.mechanism ''"),
    "no rotation strategy for rotation method ''",
  );
  assert.equal(
    plainEngineText("Declare write.ui_password, use write.manual_mint, or retry"),
    "Declare UI password, use manual rotation, or retry",
  );
  assert.equal(
    plainEngineText("write.reconstruct_config cannot be combined with write.manual_mint"),
    "Config rebuild cannot be combined with manual rotation",
  );
  assert.equal(plainEngineText("write.mint_with names 'x'"), "Password credential names 'x'");
  assert.equal(plainEngineText("write.some_future_field broke"), "Some future field broke");
  assert.equal(plainEngineText("nothing to translate"), "nothing to translate");
  assert.equal(plainEngineText(null), "");
});

test("friendly reasons translate field paths too", () => {
  assert.equal(
    friendlyReason("write.token_name is required"),
    "Token name is required",
  );
});

test("the login wall splits off the listable problems", () => {
  const wall =
    "radarr: the backup download is behind the service's web UI login (HTTP 302)";
  const other = "radarr: /system/backup returned HTTP 500";
  assert.deepEqual(splitLoginWall([wall, other]), { wall: [wall], rest: [other] });
  assert.deepEqual(splitLoginWall([other]), { wall: [], rest: [other] });
  assert.deepEqual(splitLoginWall(null), { wall: [], rest: [] });
});

test("a banner line drops what the page already says", () => {
  assert.equal(
    bannerLine(
      "radarr: the stored key still authenticates; rotate the key first. Nothing has been changed.",
      ["radarr", "Radarr", "radarr_api_key"],
    ),
    "The stored key still authenticates; rotate the key first.",
  );
  assert.equal(
    bannerLine("prowlarr: could not be reached during preflight", ["prowlarr"]),
    "Could not be reached during preflight",
  );
  // Another service's prefix carries which copy failed, so it stays.
  assert.equal(
    bannerLine("prowlarr: could not be reached", ["radarr"]),
    "prowlarr: could not be reached",
  );
  assert.equal(bannerLine("no rotation strategy", ["radarr"]), "no rotation strategy");
  assert.equal(bannerLine(null, ["radarr"]), "");
});

test("an imported audit-only API key names the service that can rotate it", () => {
  assert.deepEqual(
    importWarningLines([{ credential: "seerr_api_key", service: "seerr" }]),
    [
      "Seerr API Key is marked audit-only, but Seerr supports rotation. Set its class to A if it should rotate.",
    ],
  );
  assert.deepEqual(importWarningLines([]), []);
  assert.deepEqual(importWarningLines(null), []);
});

test("a refusal says the outcome once, then only what can be acted on", () => {
  assert.deepEqual(
    refusalLines(
      [
        "credential is class B: no mechanism is not mintable by this tool, so there is nothing to rotate",
        "credential is marked never_rotate, which forbids rotation regardless of its class",
        "no rotation strategy for write.mechanism ''",
      ],
      ["seerr", "Seerr", "seerr_api_key"],
    ),
    ["This key is audit-only and has no usable rotation method."],
  );
  assert.deepEqual(
    refusalLines(["no rotation strategy for write.mechanism ''"]),
    ["This key has no rotation method."],
  );
  assert.deepEqual(
    refusalLines(["no rotation strategy for write.mechanism 'retired_method'"]),
    ["The declared rotation method is not supported by this build."],
  );
  assert.deepEqual(
    refusalLines(["credential is marked never_rotate, which forbids rotation"]),
    ["Rotation is turned off for this key."],
  );
  assert.deepEqual(
    refusalLines(["radarr: could not be reached during preflight"], ["radarr"]),
    ["Could not be reached during preflight"],
  );
});

test("only an own-service prefix is stripped", () => {
  assert.equal(stripServicePrefix("radarr: x", ["sonarr_api_key", "sonarr"]), "radarr: x");
  assert.equal(stripServicePrefix("sonarr_api_key: x", ["sonarr_api_key"]), "X");
  assert.equal(stripServicePrefix("Radarr: x", ["radarr"]), "X");
  assert.equal(stripServicePrefix("no prefix here", ["radarr"]), "no prefix here");
});
