import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import test from "node:test";

import { SERVICE_CATALOG, TARGETS, describeHolder, holderSuggestions, mechanismOptions, serviceById, targetByKey } from "../src/lib/setupCatalog.js";
import {
  DRAFT_KEY,
  clearDraft,
  credentialPayload,
  draftFromTopology,
  emptyDraft,
  holderField,
  isDraftOnlyCredential,
  loadDraft,
  mechanismOf,
  ensureService,
  newCredential,
  newHolder,
  normalizeDraft,
  prefillHolders,
  removeService,
  saveDraft,
  serviceFact,
  serviceKind,
  serviceUsage,
  suggestionsFor,
  toYaml,
  validateDraft,
  writeOf,
} from "../src/lib/setup.js";

const REPO = path.resolve(import.meta.dirname, "../..");
const PYTHON = process.env.CREDARR_PYTHON ?? path.join(REPO, ".venv", "bin", "python");
const hasPython = existsSync(PYTHON);

function fakeStorage() {
  const data = new Map();
  return {
    data,
    getItem(key) {
      return data.has(key) ? data.get(key) : null;
    },
    setItem(key, value) {
      data.set(key, String(value));
    },
    removeItem(key) {
      data.delete(key);
    },
  };
}

function validDraft() {
  const draft = emptyDraft();
  draft.services = ["sonarr", "prowlarr", "seerr"];
  for (const service of draft.services) {
    serviceFact(draft, service).url = `http://${service}:8989`;
  }
  const credential = newCredential(draft, "sonarr");
  credential.name = "sonarr_api_key";
  credential.description = "the key Sonarr serves";
  credential.class = "A";
  credential.max_age_days = 90;
  credential.never_rotate = false;
  credential.consumers = [
    newHolder("prowlarr", "applications", "Sonarr"),
    newHolder("seerr", "settings_json", "sonarr"),
  ];
  draft.credentials = [credential];
  return { draft, credential };
}

function parseWithEngine(yaml) {
  return execFileSync(
    PYTHON,
    [
      "-c",
      [
        "import sys",
        "from credarr.targets import build_registry",
        "from credarr.model import Manifest",
        "registry = build_registry()",
        "manifest = Manifest.parse(sys.stdin.read(), known_targets=registry.known_targets())",
        "print(len(manifest.credentials))",
      ].join("\n"),
    ],
    { cwd: REPO, encoding: "utf8", input: yaml },
  ).trim();
}

test("the catalog matches the build's target registry", { skip: !hasPython }, () => {
  const output = execFileSync(
    PYTHON,
    [
      "-c",
      "import json; from credarr.targets import build_registry; " +
        "from credarr.writers import holder_for; " +
        "targets = sorted(build_registry().known_targets()); " +
        "writers = {key: holder_for(*key.split('.', 1)) is not None for key in targets}; " +
        "print(json.dumps({'targets': targets, 'writers': writers}))",
    ],
    { cwd: REPO, encoding: "utf8" },
  );
  const registry = JSON.parse(output);
  assert.deepEqual(TARGETS.map((target) => target.key).sort(), registry.targets);
  // The catalog's writer flag is a second copy of holder_for; a key-only
  // comparison let it drift into offering a holder the planner would refuse.
  assert.deepEqual(
    Object.fromEntries(TARGETS.map((target) => [target.key, target.writer])),
    registry.writers,
  );
});

test("a valid draft emits a manifest the engine parses", { skip: !hasPython }, () => {
  const { draft } = validDraft();
  const validation = validateDraft(draft);
  assert.equal(validation.ok, true, JSON.stringify(validation.errors));
  const yaml = toYaml(validation.manifest);
  assert.match(yaml, /^version: 1$/m);
  assert.match(yaml, /class: A/);
  assert.match(yaml, /max_age_days: 90/);
  assert.match(yaml, /service: sonarr/);
  assert.match(yaml, /mechanism: servarr_command/);
  assert.match(yaml, /target: "prowlarr\.applications\[Sonarr\]"/);
  assert.match(yaml, /target: "seerr\.settings_json\[sonarr\]"/);
  assert.match(yaml, /mechanism: process_api/);

  assert.equal(parseWithEngine(yaml), "1");
});

test("a selected service without a usable http(s) URL is refused", () => {
  const { draft } = validDraft();
  delete draft.serviceFacts.sonarr;
  const missing = validateDraft(draft);
  assert.equal(missing.ok, false);
  assert.ok(missing.services.some((issue) => /Sonarr: Enter the service URL/.test(issue)));

  serviceFact(draft, "sonarr").url = "sonarr:8989";
  const malformed = validateDraft(draft);
  assert.equal(malformed.ok, false);
  assert.ok(
    malformed.services.some((issue) => /full http:\/\/ or https:\/\//.test(issue)),
  );
});

test("Homepage is a holder, not a connectable service", () => {
  assert.equal(serviceById("homepage").holderOnly, true);
  const draft = emptyDraft();
  assert.equal(ensureService(draft, "homepage"), false);
  assert.deepEqual(draft.services, []);
});

test("a Homepage copy needs no Homepage connection", () => {
  const { draft } = validDraft();
  draft.credentials[0].consumers.push(newHolder("homepage", "label"));
  const validation = validateDraft(draft);
  assert.equal(validation.ok, true, JSON.stringify(validation.errors));
  assert.ok(!draft.services.includes("homepage"));
  assert.match(toYaml(validation.manifest), /homepage\.label/);
});

test("a live topology becomes an editable draft without secrets", () => {
  const draft = draftFromTopology(
    [
      { name: "sonarr", declared: true, url: "http://sonarr:8989", path: "/mnt/sonarr" },
      { name: "prowlarr", declared: true, url: "http://prowlarr:9696", path: "/mnt/prowlarr" },
      { name: "not-in-catalog", declared: true, url: "http://other:1", path: "/mnt/other" },
    ],
    [
      {
        name: "sonarr_api_key",
        description: "issuer key",
        class: "A-unv",
        stored: true,
        max_age_days: 90,
        never_rotate: false,
        canonical: { service: "sonarr" },
        consumers: [
          { target: "prowlarr.applications[Sonarr]", count: 1, note: "indexer" },
          { target: "not-in-catalog.config_xml", count: 1 },
        ],
      },
    ],
  );
  assert.deepEqual(draft.services.sort(), ["prowlarr", "sonarr"]);
  assert.equal(draft.serviceFacts.sonarr.url, "http://sonarr:8989");
  assert.equal(draft.credentials.length, 1);
  assert.equal(draft.credentials[0].consumers.length, 1);
  assert.equal(draft.credentials[0].consumers[0].qualifier, "Sonarr");
  assert.equal(draft.credentials[0].stored, true);
  assert.equal(validateDraft(draft).ok, true);
});

test("a credential without canonical is owned by its name and keeps its holders", () => {
  // The fixture manifests in this repo declare consumers and no canonical;
  // the engine derives the service from the name. The wizard must read that
  // shape, or an edit would hide the credential and a same-named new one could
  // overwrite its declaration.
  const draft = draftFromTopology(
    [
      { name: "sonarr", declared: true, url: "http://sonarr:8989", path: "/mnt/sonarr" },
      { name: "prowlarr", declared: true, url: "http://prowlarr:9696", path: "/mnt/prowlarr" },
    ],
    [
      {
        name: "sonarr_api_key",
        description: "",
        class: "A",
        max_age_days: 90,
        never_rotate: false,
        provisioned: false,
        canonical: {},
        consumers: [
          {
            target: "prowlarr.applications[Sonarr]",
            count: 1,
            mechanism: "servarr_db_blob",
            note: "indexer",
          },
        ],
      },
    ],
  );
  assert.equal(draft.credentials.length, 1);
  const credential = draft.credentials[0];
  assert.equal(credential.owner, "sonarr");
  assert.notEqual(credential.base, null);
  const payload = credentialPayload(credential);
  assert.deepEqual(payload.canonical, { service: "sonarr" });
  assert.equal(payload.provisioned, false);
  assert.equal(payload.consumers[0].mechanism, "servarr_db_blob");
  assert.equal(payload.consumers[0].note, "indexer");
  assert.equal(validateDraft(draft).ok, true);
});

test("a credential whose declared owner is outside the catalog stays out", () => {
  const draft = draftFromTopology(
    [],
    [{ name: "sonarr_api_key", canonical: { service: "legacy-service" } }],
  );
  assert.equal(draft.credentials.length, 0);
});

test("an edit-mode save returns declared fields the wizard does not own", () => {
  const draft = draftFromTopology(
    [
      { name: "sonarr", declared: true, url: "http://sonarr:8989", path: "/mnt/sonarr" },
      { name: "prowlarr", declared: true, url: "http://prowlarr:9696", path: "/mnt/prowlarr" },
    ],
    [
      {
        name: "sonarr_api_key",
        description: "issuer key",
        class: "A",
        max_age_days: 90,
        never_rotate: false,
        provisioned: false,
        canonical: { service: "sonarr", note: "declared elsewhere" },
        write: { mechanism: "servarr_db_blob" },
        consumers: [
          {
            target: "prowlarr.applications[Sonarr]",
            count: 1,
            mechanism: "servarr_db_blob",
            host: "nas",
            note: "indexer",
          },
        ],
      },
    ],
  );
  const payload = credentialPayload(draft.credentials[0]);
  assert.equal(payload.provisioned, false);
  assert.deepEqual(payload.canonical, { service: "sonarr", note: "declared elsewhere" });
  assert.deepEqual(payload.write, { mechanism: "servarr_db_blob" });
  assert.deepEqual(payload.consumers[0], {
    target: "prowlarr.applications[Sonarr]",
    count: 1,
    mechanism: "servarr_db_blob",
    host: "nas",
    note: "indexer",
  });

  // Editing a field the wizard owns drops exactly that snapshot.
  draft.credentials[0].class = "B";
  const reclassed = credentialPayload(draft.credentials[0]);
  assert.deepEqual(reclassed.canonical, { service: "sonarr" });
  assert.deepEqual(reclassed.write, {});

  draft.credentials[0].consumers[0].slot = "config_xml";
  draft.credentials[0].consumers[0].qualifier = "";
  const retargeted = credentialPayload(draft.credentials[0]);
  assert.equal(retargeted.consumers[0].host, null);
  assert.equal(retargeted.consumers[0].mechanism, "");
});

test("a credential name YAML would resolve as a scalar is quoted", () => {
  const { draft, credential } = validDraft();
  credential.name = "true";
  credential.consumers = [];
  const validation = validateDraft(draft);
  assert.equal(validation.ok, true, JSON.stringify(validation.errors));
  const yaml = toYaml(validation.manifest);
  assert.match(yaml, /^  "true":$/m);
  if (hasPython) assert.equal(parseWithEngine(yaml), "1");
});

test("class A cannot be selected for a service with no mint source", () => {
  const draft = emptyDraft();
  draft.services = ["homepage"];
  const credential = newCredential(draft, "homepage");
  credential.name = "homepage_key";
  credential.class = "A";
  credential.max_age_days = 90;
  draft.credentials = [credential];
  const validation = validateDraft(draft);
  assert.equal(validation.ok, false);
  assert.match(
    validation.errors[`credential:${credential.id}:class`],
    /no mint source/,
  );
});

test("duplicate names, duplicate targets and malformed qualifiers are refused", () => {
  const { draft, credential } = validDraft();
  const second = newCredential(draft, "sonarr");
  second.name = "sonarr_api_key";
  second.consumers = [newHolder("prowlarr", "applications", "Sonarr")];
  draft.credentials.push(second);
  const validation = validateDraft(draft);
  assert.equal(validation.ok, false);
  assert.match(validation.errors[`credential:${second.id}:name`], /already uses/);
  assert.match(
    validation.errors[holderField(second, second.consumers[0], "target")],
    /already uses/,
  );

  credential.consumers[0].qualifier = "Sonarr:HD:extra";
  const malformed = validateDraft(draft);
  assert.match(
    malformed.errors[holderField(credential, credential.consumers[0], "qualifier")],
    /one colon/,
  );
});

test("an extra key does not prefill a copy another key already owns", () => {
  const draft = emptyDraft();
  draft.services = ["sonarr", "prowlarr", "seerr"];
  const first = newCredential(draft, "sonarr");
  draft.credentials = [first];
  prefillHolders(draft, first);
  assert.ok(first.consumers.length > 0);

  const second = newCredential(draft, "sonarr");
  draft.credentials.push(second);
  prefillHolders(draft, second);
  assert.deepEqual(second.consumers, []);

  const validation = validateDraft(draft);
  assert.equal(
    Object.keys(validation.errors).some((key) => key.endsWith(":target")),
    false,
  );
});

test("Homepage labels may be repeated across app credentials", () => {
  const draft = emptyDraft();
  draft.services = ["sonarr", "radarr", "homepage"];
  const sonarr = newCredential(draft, "sonarr");
  const radarr = newCredential(draft, "radarr");
  sonarr.consumers = [newHolder("homepage", "label")];
  radarr.consumers = [newHolder("homepage", "label")];
  draft.credentials = [sonarr, radarr];

  const validation = validateDraft(draft);
  assert.equal(
    Object.keys(validation.errors).some((key) => key.endsWith(":target")),
    false,
  );
});

test("class promises and counts are validated before import", () => {
  const { draft, credential } = validDraft();
  credential.class = "B";
  credential.max_age_days = null;
  credential.never_rotate = false;
  let validation = validateDraft(draft);
  assert.match(
    validation.errors[`credential:${credential.id}:max_age_days`],
    /warn-after age or to be marked never rotate/,
  );

  credential.never_rotate = true;
  credential.consumers[0].count = 0;
  validation = validateDraft(draft);
  assert.equal(validation.ok, false);
  assert.match(
    validation.errors[holderField(credential, credential.consumers[0], "count")],
    /positive whole number/,
  );

  credential.description = "bad\u0085description";
  validation = validateDraft(draft);
  assert.match(
    validation.errors[`credential:${credential.id}:description`],
    /NEL/,
  );
});

test("a draft with no holders is valid but warns, and unknown targets are dropped on load", () => {
  const { draft, credential } = validDraft();
  credential.consumers = [];
  const validation = validateDraft(draft);
  assert.equal(validation.ok, true);
  assert.match(
    validation.warnings[`credential:${credential.id}:holders`],
    /No holders/,
  );

  const raw = {
    version: 1,
    services: ["sonarr"],
    credentials: [
      {
        id: "cred-1",
        name: "sonarr_api_key",
        owner: "sonarr",
        class: "A-unv",
        max_age_days: 90,
        consumers: [
          { id: "holder-1", service: "sonarr", slot: "indexers", count: 1 },
          { id: "holder-2", service: "sonarr", slot: "not_a_slot", count: 1 },
        ],
      },
    ],
  };
  const normalized = normalizeDraft(raw);
  assert.equal(normalized.credentials[0].consumers.length, 1);
  assert.equal(normalized.credentials[0].consumers[0].slot, "indexers");
});

test("a process_api holder warns when its own service credential is absent", () => {
  const { draft } = validDraft();
  const holdersKey = `credential:${draft.credentials[0].id}:holders`;

  const missing = validateDraft(draft);
  assert.equal(missing.ok, true);
  assert.match(
    missing.warnings[holdersKey],
    /add Seerr as a credential and store its key/,
  );

  draft.credentials.push(newCredential(draft, "seerr"));
  const present = validateDraft(draft);
  assert.equal(present.warnings[holdersKey], undefined);
});

test("a Seerr credential is minted by regenerate and can be class A", { skip: !hasPython }, () => {
  const draft = emptyDraft();
  draft.services = ["seerr"];
  serviceFact(draft, "seerr").url = "http://seerr:5055";
  const credential = newCredential(draft, "seerr");
  credential.name = "seerr_api_key";
  credential.class = "A";
  credential.max_age_days = 90;
  draft.credentials = [credential];

  const validation = validateDraft(draft);
  assert.equal(validation.ok, true, JSON.stringify(validation.errors));
  const yaml = toYaml(validation.manifest);
  assert.match(yaml, /class: A/);
  assert.match(yaml, /mechanism: seerr_regenerate/);
  assert.equal(parseWithEngine(yaml), "1");
});

test("saving and loading keeps only non-secret draft data", () => {
  const { draft } = validDraft();
  const storage = fakeStorage();
  assert.equal(saveDraft(storage, draft, 2), true);
  const raw = storage.getItem(DRAFT_KEY);
  assert.ok(raw.includes("sonarr_api_key"));
  assert.ok(!raw.includes("credarr_"));
  assert.ok(!raw.toLowerCase().includes("secret"));
  const loaded = loadDraft(storage);
  assert.equal(loaded.step, 2);
  assert.deepEqual(loaded.draft, draft);
  clearDraft(storage);
  assert.equal(storage.getItem(DRAFT_KEY), null);
});

test("a key typed on the service card does not lock that service", () => {
  const draft = emptyDraft();
  draft.services = ["sonarr"];
  const credential = newCredential(draft, "sonarr");
  draft.credentials = [credential];
  assert.equal(isDraftOnlyCredential(credential), true);
  assert.equal(serviceUsage(draft, "sonarr"), 0);
  assert.equal(removeService(draft, "sonarr"), true);
  assert.deepEqual(draft.services, []);
  assert.deepEqual(draft.credentials, []);
});

test("a holder keeps the key credential and blocks removing the service", () => {
  const draft = emptyDraft();
  draft.services = ["sonarr"];
  const credential = newCredential(draft, "sonarr");
  credential.consumers = [newHolder("prowlarr", "applications", "Sonarr")];
  draft.credentials = [credential];
  assert.equal(isDraftOnlyCredential(credential), false);
  assert.equal(serviceUsage(draft, "sonarr"), 1);
  assert.equal(serviceUsage(draft, "prowlarr"), 1);
  assert.equal(removeService(draft, "sonarr"), false);
  assert.deepEqual(draft.services, ["sonarr"]);
  assert.equal(draft.credentials.length, 1);
});

test("a credential read from the live topology still blocks its service", () => {
  const draft = emptyDraft();
  draft.services = ["sonarr"];
  const credential = newCredential(draft, "sonarr");
  credential.base = { owner: "sonarr", class: "A", canonical: {}, write: {} };
  draft.credentials = [credential];
  assert.equal(isDraftOnlyCredential(credential), false);
  assert.equal(serviceUsage(draft, "sonarr"), 1);
  assert.equal(removeService(draft, "sonarr"), false);
});

test("a draft-only credential survives a reload without locking its service", () => {
  const storage = fakeStorage();
  const draft = emptyDraft();
  draft.services = ["sonarr"];
  draft.credentials = [newCredential(draft, "sonarr")];
  saveDraft(storage, draft, 1);
  const loaded = loadDraft(storage).draft;
  assert.equal(serviceUsage(loaded, "sonarr"), 0);
  assert.equal(removeService(loaded, "sonarr"), true);
  assert.deepEqual(loaded.credentials, []);
});

test("the YAML emitter is deterministic and quotes free text", () => {
  const { draft, credential } = validDraft();
  credential.description = 'a "quoted" value: [not yaml]';
  credential.consumers[0].note = "row note";
  const first = toYaml(validateDraft(draft).manifest);
  const second = toYaml(validateDraft(draft).manifest);
  assert.equal(first, second);
  assert.match(first, /description: "a \\"quoted\\" value: \[not yaml\]"/);
  assert.match(first, /note: "row note"/);
});

test("every holder suggestion is a real target", () => {
  for (const service of SERVICE_CATALOG) {
    const suggestions = suggestionsFor(service.id);
    assert.ok(suggestions.length > 0, `${service.id} has no suggestions`);
    for (const suggestion of suggestions) {
      assert.ok(targetByKey(suggestion.key), `${suggestion.key} is not a target`);
      assert.equal(suggestion.service, suggestion.key.split(".")[0]);
    }
  }
  const seerr = suggestionsFor("sonarr").find(
    (suggestion) => suggestion.key === "seerr.settings_json",
  );
  assert.equal(seerr?.qualifier, "sonarr");

  const lidarrProwlarr = suggestionsFor("lidarr").find(
    (suggestion) => suggestion.key === "prowlarr.applications",
  );
  assert.equal(lidarrProwlarr?.qualifier, "Lidarr");
  assert.equal(
    suggestionsFor("lidarr").some((suggestion) => suggestion.key === "seerr.settings_json"),
    false,
  );
  assert.ok(
    suggestionsFor("prowlarr").some((suggestion) => suggestion.key === "whisparr.indexers"),
  );
  assert.equal(targetByKey("sonarr.applications"), null);
  assert.equal(targetByKey("prowlarr.applications")?.writer, true);

  const qbit = suggestionsFor("qbittorrent").filter(
    (suggestion) => suggestion.key === "sonarr.download_clients",
  );
  assert.deepEqual(
    qbit.map((suggestion) => suggestion.qualifier),
    ["qBittorrent:apiKey"],
    "the API key belongs in apiKey, not also in the password field",
  );
  assert.equal(
    qbit[0]?.exercised,
    true,
    "Sonarr/Radarr downloadclient/test is measured",
  );
});

function giteaPair() {
  const draft = emptyDraft();
  draft.services = ["gitea"];
  serviceFact(draft, "gitea").url = "http://gitea:3000";
  const password = newCredential(draft, "gitea");
  password.name = "gitea_admin_password";
  password.class = "B";
  password.max_age_days = null;
  password.never_rotate = true;
  password.mechanism = "stored";
  const token = newCredential(draft, "gitea");
  token.name = "gitea_api_token";
  token.fields = { username: "admin", mint_with: "gitea_admin_password" };
  draft.credentials = [password, token];
  return { draft, password, token };
}

test("the catalog knows grafana, arcane and gitea as API services", () => {
  for (const id of ["grafana", "arcane", "gitea"]) {
    assert.ok(serviceById(id), `${id} is in the catalog`);
  }
  assert.equal(serviceKind("grafana"), "grafana");
  assert.equal(serviceKind("arcane"), "arcane");
  assert.equal(serviceKind("gitea"), "gitea");
});

test("the new services add no holder targets", () => {
  for (const id of ["grafana", "arcane", "gitea"]) {
    assert.deepEqual(serviceById(id).targets, []);
  }
});

test("only gitea offers a rotation-method choice", () => {
  assert.deepEqual(mechanismOptions("gitea"), ["gitea_token", "gitea_hook_secret", "stored"]);
  assert.deepEqual(mechanismOptions("grafana"), ["grafana_service_token"]);
  assert.deepEqual(mechanismOptions("sonarr"), ["servarr_command"]);
  assert.deepEqual(mechanismOptions("homepage"), []);
});

test("a grafana credential requires its token name", () => {
  const draft = emptyDraft();
  draft.services = ["grafana"];
  serviceFact(draft, "grafana").url = "http://grafana:3000";
  const credential = newCredential(draft, "grafana");
  credential.name = "grafana_api_token";
  draft.credentials = [credential];
  assert.equal(mechanismOf(credential), "grafana_service_token");
  const missing = validateDraft(draft);
  assert.equal(missing.ok, false);
  assert.match(
    missing.errors[`credential:${credential.id}:write.token_name`],
    /Token name is required/,
  );
  credential.fields = { token_name: "homelab-homepage" };
  const ready = validateDraft(draft);
  assert.equal(ready.ok, true, JSON.stringify(ready.errors));
  assert.deepEqual(ready.manifest.credentials.grafana_api_token.write, {
    mechanism: "grafana_service_token",
    token_name: "homelab-homepage",
  });
});

test("an arcane credential needs no fields", () => {
  const draft = emptyDraft();
  draft.services = ["arcane"];
  serviceFact(draft, "arcane").url = "http://arcane:3552";
  const credential = newCredential(draft, "arcane");
  credential.name = "arcane_api_key";
  draft.credentials = [credential];
  const validation = validateDraft(draft);
  assert.equal(validation.ok, true, JSON.stringify(validation.errors));
  assert.deepEqual(validation.manifest.credentials.arcane_api_key.write, {
    mechanism: "arcane_api_key",
  });
});

test("a gitea token mints with a stored password", () => {
  const { draft, token } = giteaPair();
  const validation = validateDraft(draft);
  assert.equal(validation.ok, true, JSON.stringify(validation.errors));
  assert.deepEqual(validation.manifest.credentials.gitea_api_token.write, {
    mechanism: "gitea_token",
    username: "admin",
    mint_with: "gitea_admin_password",
  });
  // The password itself exports no write block.
  assert.equal(
    validation.manifest.credentials.gitea_admin_password.write,
    undefined,
  );
  assert.equal(writeOf(token).mint_with, "gitea_admin_password");
});

test("mint_with must name a declared stored secret", () => {
  const { draft, token } = giteaPair();
  token.fields = { username: "admin", mint_with: "no-such-key" };
  const missing = validateDraft(draft);
  assert.equal(missing.ok, false);
  assert.match(
    missing.errors[`credential:${token.id}:write.mint_with`],
    /No credential named no-such-key/,
  );
  token.fields = { username: "admin", mint_with: "gitea_api_token" };
  const selfish = validateDraft(draft);
  assert.equal(selfish.ok, false);
  assert.match(
    selfish.errors[`credential:${token.id}:write.mint_with`],
    /No credential named gitea_api_token/,
  );
  const other = newCredential(draft, "gitea");
  other.name = "gitea_other_token";
  draft.credentials.push(other);
  token.fields = { username: "admin", mint_with: "gitea_other_token" };
  const rotating = validateDraft(draft);
  assert.equal(rotating.ok, false);
  assert.match(
    rotating.errors[`credential:${token.id}:write.mint_with`],
    /set to rotate; mint with a stored secret/,
  );
});

test("a hook secret mints with a gitea token, not a password", () => {
  const { draft } = giteaPair();
  const hook = newCredential(draft, "gitea");
  hook.name = "gitea_hook_secret";
  hook.mechanism = "gitea_hook_secret";
  hook.fields = {
    repo: "admin/fx-repo",
    hook_url: "https://deploy/hook",
    mint_with: "gitea_admin_password",
  };
  draft.credentials.push(hook);
  const wrong = validateDraft(draft);
  assert.equal(wrong.ok, false);
  assert.match(
    wrong.errors[`credential:${hook.id}:write.mint_with`],
    /not a Gitea API token/,
  );
  hook.fields.mint_with = "gitea_api_token";
  const ready = validateDraft(draft);
  assert.equal(ready.ok, true, JSON.stringify(ready.errors));
  assert.equal(
    ready.manifest.credentials.gitea_hook_secret.write.mint_with,
    "gitea_api_token",
  );
});

test("import-only overrides survive an untouched edit", () => {
  const { draft, token } = giteaPair();
  token.base = {
    owner: "gitea",
    class: "A-unv",
    canonical: { service: "gitea" },
    write: { mechanism: "gitea_token", scopes: ["read:user"] },
  };
  token.mechanism = "gitea_token";
  token.fields = { username: "admin", mint_with: "gitea_admin_password", scopes: ["read:user"] };
  const payload = credentialPayload(token);
  assert.deepEqual(payload.write, {
    mechanism: "gitea_token",
    username: "admin",
    mint_with: "gitea_admin_password",
    scopes: ["read:user"],
  });
});

test("a prowlarr key is never suggested in download-client rows", () => {
  // A download-client row authenticates to its download client; only indexer
  // rows can hold Prowlarr's key. Suggesting otherwise would write it where
  // it breaks logins.
  const slots = suggestionsFor("prowlarr").map((suggestion) => suggestion.key);
  assert.ok(slots.some((key) => key === "sonarr.indexers"));
  assert.equal(
    slots.some((key) => key.endsWith(".download_clients")),
    false,
  );
});

test("a copy is described in its settings screen's words", () => {
  assert.equal(
    describeHolder({ service: "prowlarr", slot: "applications", qualifier: "Sonarr" }, "Sonarr"),
    "A copy of Sonarr's key is in Prowlarr's Sonarr app.",
  );
  assert.equal(
    describeHolder({ service: "prowlarr", slot: "applications", qualifier: "" }, "Sonarr"),
    "A copy of Sonarr's key is in Prowlarr's Apps.",
  );
  assert.equal(
    describeHolder({ service: "radarr", slot: "indexers", qualifier: "" }, "Prowlarr"),
    "A copy of Prowlarr's key is in each of Radarr's indexers.",
  );
  assert.equal(
    describeHolder({ service: "sonarr", slot: "indexers", qualifier: "Prowlarr" }, "Prowlarr"),
    "A copy of Prowlarr's key is in Sonarr's Prowlarr indexer.",
  );
  assert.equal(
    describeHolder({ service: "sonarr", slot: "download_clients", qualifier: "qBittorrent:password" }, "qBittorrent"),
    "A copy of qBittorrent's key is in Sonarr's qBittorrent:password download client.",
  );
  assert.equal(
    describeHolder({ service: "seerr", slot: "settings_json", qualifier: "sonarr" }, "Sonarr"),
    "A copy of Sonarr's key is in Seerr's sonarr settings.",
  );
  assert.equal(
    describeHolder({ service: "homepage", slot: "label", qualifier: "" }, "Sonarr"),
    "A copy of Sonarr's key is rendered as a Homepage label when you deploy. It is not read back.",
  );
  assert.equal(
    describeHolder({ service: "qui", slot: "instance", qualifier: "qBittorrent" }, "qBittorrent"),
    "A copy of qBittorrent's key is in qui's qBittorrent instance.",
  );
  assert.equal(
    describeHolder({ service: "sonarr", slot: "nope", qualifier: "" }, "Sonarr"),
    "sonarr.nope",
  );
});

test("Profilarr is offered as a manual Arr copy, not a writer", () => {
  const suggestion = holderSuggestions("sonarr").find(
    (item) => item.service === "profilarr" && item.slot === "arr_config",
  );
  assert.ok(suggestion, "Profilarr must be suggested for a Sonarr key");
  assert.equal(suggestion.writer, false);
  assert.match(
    describeHolder(
      { service: "profilarr", slot: "arr_config", qualifier: "Sonarr" },
      "Sonarr",
    ),
    /update this copy by hand/,
  );
  assert.equal(serviceById("profilarr")?.holderOnly, true);
});
