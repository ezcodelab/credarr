// The setup draft and the manifest it produces. No Svelte here: the wizard
// renders this state, and the unit tests can exercise every rule without a
// browser. The draft never holds a credential value or an API key.
import {
  SERVICE_CATALOG,
  WRITE_MECHANISMS,
  defaultClass,
  defaultCredentialName,
  defaultMaxAge,
  defaultNeverRotate,
  holderSuggestions,
  serviceById,
  targetByKey,
  targetKey,
  targetString,
} from "./setupCatalog.js";
import { credentialTitle } from "./names.js";

export const DRAFT_VERSION = 1;
export const DRAFT_KEY = "credarr.setup.draft.v1";
export const NAME_RE = /^[a-z0-9][a-z0-9_-]*$/;

let idSequence = 0;

export function newId(prefix = "id") {
  if (globalThis.crypto?.randomUUID) return `${prefix}-${globalThis.crypto.randomUUID()}`;
  idSequence += 1;
  return `${prefix}-${Date.now()}-${idSequence}`;
}

export function emptyDraft() {
  const serviceFacts = {};
  for (const service of SERVICE_CATALOG) serviceFacts[service.id] = { url: "" };
  return { version: DRAFT_VERSION, services: [], serviceFacts, credentials: [] };
}

export function credentialField(credential, field) {
  return `credential:${credential.id}:${field}`;
}

export function holderField(credential, holder, field) {
  return `holder:${credential.id}:${holder.id}:${field}`;
}

export function holderMeta(holder) {
  return targetByKey(targetKey(holder.service, holder.slot)) ?? null;
}

export function holderTarget(holder) {
  return targetString(holder);
}

export function uniqueCredentialName(credentials, base) {
  const used = new Set(credentials.map((credential) => credential.name));
  if (!used.has(base)) return base;
  let suffix = 2;
  while (used.has(`${base}_${suffix}`)) suffix += 1;
  return `${base}_${suffix}`;
}

export function newCredential(draft, ownerId = "sonarr") {
  const owner = serviceById(ownerId) ?? SERVICE_CATALOG[0];
  return {
    id: newId("cred"),
    name: uniqueCredentialName(draft.credentials, defaultCredentialName(owner.id)),
    owner: owner.id,
    description: "",
    class: defaultClass(owner.id),
    max_age_days: defaultMaxAge(owner.id),
    never_rotate: defaultNeverRotate(owner.id),
    provisioned: true,
    // The rotation method and its fields. "" means the owner's default; the
    // wizard only offers a choice where an owner has several (Gitea). Fields
    // hold names and labels, never values.
    mechanism: "",
    fields: {},
    base: null,
    consumers: [],
  };
}

export function newHolder(service, slot, qualifier = "") {
  const target = targetByKey(targetKey(service, slot));
  if (!target) throw new Error(`unknown target ${service}.${slot}`);
  return {
    id: newId("holder"),
    service,
    slot,
    qualifier,
    count: 1,
    note: "",
    base: null,
  };
}

export function serviceFact(draft, serviceId) {
  if (!draft.serviceFacts || typeof draft.serviceFacts !== "object") draft.serviceFacts = {};
  const existing = draft.serviceFacts[serviceId];
  if (existing && typeof existing === "object") return existing;
  const fact = { url: "" };
  draft.serviceFacts[serviceId] = fact;
  return fact;
}

export function serviceFactValue(draft, serviceId) {
  const existing = draft.serviceFacts?.[serviceId];
  return existing && typeof existing === "object" ? existing : { url: "" };
}

// The API reaches every service over HTTP. Requiring the URL at the point the
// service is chosen keeps a typo out of the very first audit instead of
// surfacing it as an unexplained "host unreachable" later.
export function serviceUrlError(value) {
  const text = String(value ?? "").trim();
  if (!text) return "Enter the service URL.";
  try {
    const parsed = new URL(text);
    if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname) {
      return "Use a full http:// or https:// URL with a host.";
    }
  } catch {
    return "Use a full http:// or https:// URL with a host.";
  }
  return "";
}

export function parseHolderTarget(target) {
  const match = /^([^.]+)\.([^[]+)(?:\[(.*)\])?$/.exec(String(target ?? ""));
  if (!match) return null;
  const [, service, slot, qualifier = ""] = match;
  if (!targetByKey(targetKey(service, slot))) return null;
  return { service, slot, qualifier };
}

function plainMapping(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? { ...value } : {};
}

// Reopen setup starts from the live topology when the browser has no draft.
// Every field the wizard does not edit (`provisioned`, `canonical` extras,
// `write`, a holder's mechanism/host) is snapshotted on `base`, so an
// edit-mode save can leave declared state it does not own exactly as it was.
// Only changes to the fields the wizard does own (owner, class, target) drop
// the snapshot. Catalog services only; anything else is left untouched.
// The engine derives a credential's service from its name when `canonical` is
// absent (`rotate.service_for`), and a manifest without `canonical` is a
// supported shape. Read the same rule here, or a holder-only credential would
// vanish from an edit; an explicit non-catalog canonical still stays out.
function ownerForCredential(row) {
  const declared = row?.canonical?.service;
  if (declared !== undefined && declared !== null && declared !== "") {
    return serviceById(declared) ? declared : "";
  }
  const name = String(row?.name ?? "");
  return SERVICE_CATALOG.find((service) => name.startsWith(service.id))?.id ?? "";
}

export function draftFromTopology(serviceRows = [], credentialRows = []) {
  const draft = emptyDraft();
  for (const row of serviceRows) {
    if (!serviceById(row?.name)) continue;
    if (row.declared) ensureService(draft, row.name);
    const fact = serviceFact(draft, row.name);
    fact.url = typeof row.url === "string" ? row.url : "";
    fact.path = typeof row.path === "string" ? row.path : "";
  }
  for (const row of credentialRows) {
    const owner = ownerForCredential(row);
    if (!serviceById(owner)) continue;
    const credential = newCredential(draft, owner);
    credential.name = typeof row.name === "string" ? row.name : credential.name;
    credential.description =
      typeof row.description === "string" ? row.description : "";
    credential.class = ["A", "A-unv", "B"].includes(row.class)
      ? row.class
      : credential.class;
    credential.max_age_days =
      Number.isSafeInteger(row.max_age_days) && row.max_age_days >= 1
        ? row.max_age_days
        : null;
    credential.never_rotate = row.never_rotate === true;
    credential.provisioned = row.provisioned !== false;
    credential.stored = row.stored === true;
    credential.base = {
      owner,
      class: credential.class,
      canonical: plainMapping(row.canonical),
      write: plainMapping(row.write),
    };
    // The declared write path is editable state, not a snapshot: the wizard
    // owns the mechanism and its fields from here on.
    const declaredWrite = plainMapping(row.write);
    credential.mechanism =
      typeof declaredWrite.mechanism === "string" ? declaredWrite.mechanism : "";
    delete declaredWrite.mechanism;
    credential.fields = declaredWrite;
    credential.consumers = (Array.isArray(row.consumers) ? row.consumers : [])
      .map((consumer) => {
        const parsed = parseHolderTarget(consumer?.target);
        if (!parsed) return null;
        return {
          id: newId("holder"),
          ...parsed,
          count:
            Number.isSafeInteger(consumer.count) && consumer.count >= 1
              ? consumer.count
              : 1,
          note: typeof consumer.note === "string" ? consumer.note : "",
          base: {
            target: String(consumer.target ?? ""),
            mechanism: typeof consumer.mechanism === "string" ? consumer.mechanism : "",
            storage: typeof consumer.storage === "string" ? consumer.storage : "",
            host: typeof consumer.host === "string" ? consumer.host : null,
          },
        };
      })
      .filter(Boolean);
    draft.credentials.push(credential);
    ensureService(draft, owner);
    for (const holder of credential.consumers) ensureService(draft, holder.service);
  }
  return draft;
}

// The server body (POST or PATCH) for one authored credential. Kept here
// rather than in the component so the round trip - live topology in, body out -
// is testable without a browser.
export function credentialPayload(credential) {
  const sameShape =
    credential.base &&
    credential.base.owner === credential.owner &&
    credential.base.class === credential.class;
  const canonical =
    sameShape && Object.keys(credential.base.canonical).length
      ? { ...credential.base.canonical }
      : { service: credential.owner };
  return {
    name: credential.name,
    description: String(credential.description ?? "").trim(),
    class: credential.class,
    max_age_days: credential.max_age_days,
    never_rotate: credential.never_rotate,
    provisioned: credential.provisioned !== false,
    canonical,
    write: sameShape && sameWrite(credential) ? { ...credential.base.write } : writeOf(credential),
    consumers: credential.consumers.map((holder) => {
      const target = holderMeta(holder);
      const targetText = holderTarget(holder);
      const snapshot = holder.base?.target === targetText ? holder.base : null;
      return {
        target: targetText,
        count: holder.count,
        mechanism: snapshot ? snapshot.mechanism : target?.mechanism ?? "",
        host: snapshot ? snapshot.host : null,
        note: String(holder.note ?? "").trim(),
      };
    }),
  };
}

// The service kind the store expects. The wizard and the Apps view both
// create service definitions, so the mapping lives here rather than in a
// component.
export function serviceKind(id) {
  if (["sonarr", "radarr", "lidarr", "readarr", "prowlarr", "whisparr"].includes(id)) {
    return "servarr";
  }
  if (id === "jellyfin") return "jellyfin";
  if (["seerr", "overseerr"].includes(id)) return "seerr";
  if (id === "qbittorrent") return "qbittorrent";
  if (id === "qui") return "qui";
  if (id === "grafana") return "grafana";
  if (id === "arcane") return "arcane";
  if (id === "gitea") return "gitea";
  return "other";
}

export function ensureService(draft, serviceId) {
  if (!serviceById(serviceId) || serviceById(serviceId)?.holderOnly) return false;
  if (draft.services.includes(serviceId)) return false;
  draft.services = [...draft.services, serviceId];
  return true;
}

export function isDraftOnlyCredential(credential) {
  // No base means the credential exists only in this wizard draft; no holders
  // means nothing else names it. It can leave with its owner service.
  return credential.base == null && credential.consumers.length === 0;
}

export function serviceUsage(draft, serviceId) {
  let count = 0;
  for (const credential of draft.credentials) {
    // The key field creates its credential implicitly. It leaves with the
    // service, so it must not make the service look too referenced to remove.
    if (credential.owner === serviceId && !isDraftOnlyCredential(credential)) {
      count += 1;
    }
    for (const holder of credential.consumers) {
      if (holder.service === serviceId) count += 1;
    }
  }
  return count;
}

export function removeService(draft, serviceId) {
  if (serviceUsage(draft, serviceId) > 0) return false;
  draft.services = draft.services.filter((id) => id !== serviceId);
  draft.credentials = draft.credentials.filter(
    (credential) =>
      !(credential.owner === serviceId && isDraftOnlyCredential(credential)),
  );
  return true;
}

export function resetForOwner(credential, ownerId) {
  credential.owner = ownerId;
  credential.class = defaultClass(ownerId);
  credential.max_age_days = defaultMaxAge(ownerId);
  credential.never_rotate = defaultNeverRotate(ownerId);
  credential.mechanism = "";
  credential.fields = {};
}

// The rotation method a credential uses: the explicit choice, else an
// imported declaration, else the owner's default. "stored" is the wizard's
// marker for a class-B secret that never rotates; it exports no write block.
export function mechanismOf(credential) {
  if (credential.mechanism) return credential.mechanism;
  const baseMechanism = credential.base?.write?.mechanism;
  if (typeof baseMechanism === "string" && baseMechanism) return baseMechanism;
  if (credential.class === "B") return "stored";
  return serviceById(credential.owner)?.mint?.mechanism ?? "";
}

// The write block the manifest carries: the mechanism plus the non-blank
// fields. Class B never rotates, so it carries no block. Unknown keys ride
// along untouched so import-only overrides (`scopes`, `permissions`, …)
// survive an edit that leaves them alone.
export function writeOf(credential) {
  if (credential.class === "B") return {};
  const mechanism = mechanismOf(credential);
  if (!mechanism || mechanism === "stored") return {};
  const fields = {};
  for (const [key, value] of Object.entries(credential.fields ?? {})) {
    if (typeof value === "string") {
      if (value.trim()) fields[key] = value.trim();
    } else if (value !== null && value !== undefined) {
      fields[key] = value;
    }
  }
  return { mechanism, ...fields };
}

function sameWrite(credential) {
  const base = credential.base?.write ?? {};
  const current = writeOf(credential);
  const keys = new Set([...Object.keys(base), ...Object.keys(current)]);
  for (const key of keys) {
    if (JSON.stringify(base[key]) !== JSON.stringify(current[key])) return false;
  }
  return true;
}

export function suggestionsFor(ownerId) {
  return holderSuggestions(ownerId);
}

// A Homepage label is a deploy-time manual copy, not a writable slot: every
// key can render its own widget, so the same target is intentionally repeated
// across credentials. Other targets remain one-owner to catch copy-paste
// collisions between writable copies.
const REPEATABLE_TARGETS = new Set(["homepage.label"]);

export function targetIsRepeatable(target) {
  return REPEATABLE_TARGETS.has(String(target ?? ""));
}

// Fill the common copies for one credential, but never steal a writable copy
// another credential already declares. A repeatable manual target (Homepage
// labels) may still be proposed for every key.
export function prefillHolders(draft, credential) {
  const claimed = new Set(
    draft.credentials
      .filter((item) => item.id !== credential.id)
      .flatMap((item) => item.consumers.map((holder) => holderTarget(holder))),
  );
  for (const suggestion of suggestionsFor(credential.owner)) {
    if (!suggestion.writer) continue;
    if (!draft.services.includes(suggestion.service)) continue;
    const identity = targetString(suggestion);
    if (
      credential.consumers.some(
        (holder) => holderTarget(holder) === identity,
      )
    ) {
      continue;
    }
    if (claimed.has(identity) && !targetIsRepeatable(identity)) continue;
    credential.consumers = [
      ...credential.consumers,
      newHolder(suggestion.service, suggestion.slot, suggestion.qualifier ?? ""),
    ];
    claimed.add(identity);
  }
}

function normalizeHolderBase(raw) {
  if (!raw || typeof raw !== "object") return null;
  return {
    target: typeof raw.target === "string" ? raw.target : "",
    mechanism: typeof raw.mechanism === "string" ? raw.mechanism : "",
    storage: typeof raw.storage === "string" ? raw.storage : "",
    host: typeof raw.host === "string" ? raw.host : null,
  };
}

function normalizeCredentialBase(raw) {
  if (!raw || typeof raw !== "object") return null;
  return {
    owner: typeof raw.owner === "string" ? raw.owner : "",
    class: typeof raw.class === "string" ? raw.class : "",
    canonical: plainMapping(raw.canonical),
    write: plainMapping(raw.write),
  };
}

function normalizeHolder(raw) {
  if (!raw || typeof raw !== "object") return null;
  const service = typeof raw.service === "string" ? raw.service : "";
  const slot = typeof raw.slot === "string" ? raw.slot : "";
  if (!targetByKey(targetKey(service, slot))) return null;
  const count = Number.isSafeInteger(raw.count) && raw.count >= 1 ? raw.count : 1;
  return {
    id: typeof raw.id === "string" && raw.id ? raw.id : newId("holder"),
    service,
    slot,
    qualifier: typeof raw.qualifier === "string" ? raw.qualifier : "",
    count,
    note: typeof raw.note === "string" ? raw.note : "",
    base: normalizeHolderBase(raw.base),
  };
}

function normalizeCredential(raw) {
  if (!raw || typeof raw !== "object") return null;
  const owner = typeof raw.owner === "string" ? raw.owner : "";
  if (!serviceById(owner)) return null;
  const classValue = ["A", "A-unv", "B"].includes(raw.class) ? raw.class : defaultClass(owner);
  const maxAge =
    Number.isSafeInteger(raw.max_age_days) && raw.max_age_days >= 1
      ? raw.max_age_days
      : null;
  const fields = plainMapping(raw.fields);
  for (const [key, value] of Object.entries(fields)) {
    if (value === null || value === undefined) delete fields[key];
  }
  return {
    id: typeof raw.id === "string" && raw.id ? raw.id : newId("cred"),
    name: typeof raw.name === "string" ? raw.name : "",
    owner,
    description: typeof raw.description === "string" ? raw.description : "",
    class: classValue,
    max_age_days: maxAge,
    never_rotate: typeof raw.never_rotate === "boolean" ? raw.never_rotate : false,
    provisioned: raw.provisioned !== false,
    mechanism: typeof raw.mechanism === "string" ? raw.mechanism : "",
    fields,
    base: normalizeCredentialBase(raw.base),
    consumers: Array.isArray(raw.consumers)
      ? raw.consumers.map(normalizeHolder).filter(Boolean)
      : [],
  };
}

export function normalizeDraft(raw) {
  if (!raw || typeof raw !== "object" || raw.version !== DRAFT_VERSION) return null;
  const services = [];
  if (Array.isArray(raw.services)) {
    for (const id of raw.services) {
      if (serviceById(id)?.holderOnly) continue;
      if (serviceById(id) && !services.includes(id)) services.push(id);
    }
  }
  const serviceFacts = {};
  for (const service of SERVICE_CATALOG) serviceFacts[service.id] = { url: "" };
  if (raw.serviceFacts && typeof raw.serviceFacts === "object") {
    for (const [id, fact] of Object.entries(raw.serviceFacts)) {
      if (!serviceById(id) || !fact || typeof fact !== "object") continue;
      serviceFacts[id] = {
        url: typeof fact.url === "string" ? fact.url : "",
      };
    }
  }
  const credentials = Array.isArray(raw.credentials)
    ? raw.credentials.map(normalizeCredential).filter(Boolean)
    : [];
  for (const credential of credentials) {
    if (
      !serviceById(credential.owner)?.holderOnly &&
      !services.includes(credential.owner)
    ) {
      services.push(credential.owner);
    }
    for (const holder of credential.consumers) {
      if (serviceById(holder.service)?.holderOnly) continue;
      if (!services.includes(holder.service)) services.push(holder.service);
    }
  }
  for (const id of services) {
    if (!serviceFacts[id]) serviceFacts[id] = { url: "" };
  }
  return { version: DRAFT_VERSION, services, serviceFacts, credentials };
}

export function loadDraft(storage = globalThis.localStorage) {
  if (!storage) return null;
  try {
    const raw = JSON.parse(storage.getItem(DRAFT_KEY) ?? "null");
    if (!raw) return null;
    const draft = normalizeDraft(raw);
    if (!draft) return null;
    const step = Number.isInteger(raw.step) ? Math.min(3, Math.max(0, raw.step)) : 0;
    return { draft, step };
  } catch {
    return null;
  }
}

export function saveDraft(storage, draft, step) {
  if (!storage) return false;
  try {
    storage.setItem(
      DRAFT_KEY,
      JSON.stringify({
        version: DRAFT_VERSION,
        step: Math.min(3, Math.max(0, Number.isInteger(step) ? step : 0)),
        services: draft.services,
        serviceFacts: draft.serviceFacts,
        credentials: draft.credentials,
      }),
    );
    return true;
  } catch {
    return false;
  }
}

export function clearDraft(storage = globalThis.localStorage) {
  try {
    storage?.removeItem(DRAFT_KEY);
  } catch {
    // A browser that refuses storage has nothing to clear.
  }
}

export function storageAvailable(storage = globalThis.localStorage) {
  try {
    if (!storage) return false;
    const key = "credarr.setup.storage-test";
    storage.setItem(key, "1");
    storage.removeItem(key);
    return true;
  } catch {
    return false;
  }
}

function nel(text) {
  return String(text ?? "").includes("\u0085");
}

export function buildManifest(draft) {
  const manifest = { version: DRAFT_VERSION, credentials: {} };
  for (const credential of draft.credentials) {
    const entry = {};
    const description = String(credential.description ?? "").trim();
    if (description) entry.description = description;
    entry.class = credential.class;
    if (credential.class === "B" && credential.max_age_days == null) {
      entry.never_rotate = true;
    } else {
      entry.max_age_days = credential.max_age_days;
    }
    const sameShape =
      credential.base &&
      credential.base.owner === credential.owner &&
      credential.base.class === credential.class;
    entry.canonical =
      sameShape && Object.keys(credential.base.canonical).length
        ? { ...credential.base.canonical }
        : { service: credential.owner };
    if (credential.provisioned === false) entry.provisioned = false;
    if (sameShape && sameWrite(credential)) {
      if (Object.keys(credential.base.write).length) entry.write = { ...credential.base.write };
    } else {
      const explicit = writeOf(credential);
      if (Object.keys(explicit).length) entry.write = explicit;
    }
    if (credential.consumers.length > 0) {
      entry.consumers = credential.consumers.map((holder) => {
        const target = holderMeta(holder);
        const targetText = holderTarget(holder);
        const snapshot = holder.base?.target === targetText ? holder.base : null;
        const consumer = { target: targetText, count: holder.count };
        const mechanism = snapshot ? snapshot.mechanism : target?.mechanism ?? "";
        if (mechanism) consumer.mechanism = mechanism;
        if (snapshot?.host) consumer.host = snapshot.host;
        const note = String(holder.note ?? "").trim();
        if (note) consumer.note = note;
        return consumer;
      });
    }
    manifest.credentials[credential.name] = entry;
  }
  return manifest;
}

export function draftCounts(draft) {
  let holders = 0;
  let copies = 0;
  for (const credential of draft.credentials) {
    holders += credential.consumers.length;
    copies += credential.consumers.reduce((sum, holder) => sum + holder.count, 0);
  }
  return {
    credentials: draft.credentials.length,
    holders,
    copies,
    services: draft.services.length,
  };
}

export function validateDraft(draft) {
  const errors = {};
  const warnings = {};
  const serviceErrors = [];
  const credentialErrors = [];

  if (!draft || !Array.isArray(draft.services) || !Array.isArray(draft.credentials)) {
    return {
      ok: false,
      services: ["The saved draft is not readable; start a new one."],
      credentials: [],
      errors: {},
      warnings: {},
      manifest: null,
      counts: { credentials: 0, holders: 0, copies: 0, services: 0 },
    };
  }

  if (draft.services.length === 0) {
    serviceErrors.push("Choose at least one service. The catalog is what the credential editor offers.");
  }
  for (const id of draft.services) {
    if (!serviceById(id)) {
      serviceErrors.push(`The catalog does not know the service ${id}.`);
      continue;
    }
    const issue = serviceUrlError(serviceFactValue(draft, id).url);
    if (issue) {
      serviceErrors.push(`${serviceById(id).label}: ${issue}`);
    }
  }

  if (draft.credentials.length === 0) {
    credentialErrors.push("Add at least one credential. A topology with no credentials has nothing to audit.");
  }

  const names = new Map();
  const targetOwners = new Map();

  for (const credential of draft.credentials) {
    const name = String(credential.name ?? "");
    if (!name) {
      errors[credentialField(credential, "name")] = "Give this credential a name.";
    } else if (!NAME_RE.test(name)) {
      errors[credentialField(credential, "name")] =
        "Use lowercase letters, digits, underscores or dashes, starting with a letter or digit.";
    } else if (names.has(name)) {
      errors[credentialField(credential, "name")] =
        `Another credential already uses ${name}.`;
    } else {
      names.set(name, credential.id);
    }

    if (!serviceById(credential.owner)) {
      errors[credentialField(credential, "owner")] = "Choose the service that issues this credential.";
    } else if (!draft.services.includes(credential.owner)) {
      errors[credentialField(credential, "owner")] =
        "This service is not selected. Add it in Services.";
    }

    if (!["A", "A-unv", "B"].includes(credential.class)) {
      errors[credentialField(credential, "class")] = "Choose class A, A-unv or B.";
    } else if (credential.class === "A" || credential.class === "A-unv") {
      if (!serviceById(credential.owner)?.mint) {
        errors[credentialField(credential, "class")] =
          "This build has no mint source for this service; use class B.";
      }
      if (!Number.isSafeInteger(credential.max_age_days) || credential.max_age_days < 1) {
        errors[credentialField(credential, "max_age_days")] =
          "A key that can rotate needs a whole number of days to warn after.";
      }
      if (credential.never_rotate) {
        errors[credentialField(credential, "max_age_days")] =
          "A key that can rotate cannot also be marked never rotate.";
      }
    } else if (credential.class === "B") {
      if (credential.max_age_days == null) {
        if (!credential.never_rotate) {
          errors[credentialField(credential, "max_age_days")] =
            "An audit-only key needs either a warn-after age or to be marked never rotate.";
        }
      } else if (!Number.isSafeInteger(credential.max_age_days) || credential.max_age_days < 1) {
        errors[credentialField(credential, "max_age_days")] =
          "Warn after must be a whole number of days.";
      } else if (credential.never_rotate) {
        errors[credentialField(credential, "max_age_days")] =
          "Choose either a warn-after age or never rotate, not both.";
      }
    }

    if (nel(credential.description)) {
      errors[credentialField(credential, "description")] =
        "The manifest parser rejects the NEL control character; remove it.";
    }

    // Rotation methods with fields must name everything the engine refuses
    // without: the planner's own sentences say the rest at plan time.
    const mechanism = mechanismOf(credential);
    const spec = WRITE_MECHANISMS[mechanism];
    if (spec && credential.class !== "B") {
      for (const field of spec.fields) {
        const value = String(credential.fields?.[field.key] ?? "").trim();
        if (field.required && !value) {
          errors[credentialField(credential, `write.${field.key}`)] =
            `${field.label} is required for ${spec.label}.`;
        }
      }
      const mintField = spec.fields.find((field) => field.credential);
      const mintName = String(credential.fields?.[mintField?.key ?? ""] ?? "").trim();
      if (mintField && mintName) {
        const target = draft.credentials.find(
          (other) => other.id !== credential.id && other.name === mintName,
        );
        if (!target) {
          errors[credentialField(credential, `write.${mintField.key}`)] =
            `No credential named ${mintName} is declared. Add it first.`;
        } else if (mechanism === "gitea_token" && target.class !== "B") {
          errors[credentialField(credential, `write.${mintField.key}`)] =
            `${credentialTitle(target.name)} is set to rotate; mint with a stored secret instead.`;
        } else if (
          mechanism === "gitea_hook_secret" &&
          mechanismOf(target) !== "gitea_token"
        ) {
          errors[credentialField(credential, `write.${mintField.key}`)] =
            `${credentialTitle(target.name)} is not a Gitea API token; the hook API needs one with write:repository.`;
        }
      }
    }

    if (credential.consumers.length === 0) {
      warnings[credentialField(credential, "holders")] =
        "No holders. This credential will be declared, but there is no copy to compare.";
    }

    // A process_api holder is read through its own service's API, which needs
    // that service's own credential (and stored key). Say so before import:
    // otherwise the first audit correctly reports the holder unverifiable.
    const liveServices = [
      ...new Set(
        credential.consumers
          .filter((holder) => holderMeta(holder)?.mechanism === "process_api")
          .map((holder) => holder.service),
      ),
    ].filter(
      (service) =>
        !draft.credentials.some((entry) => entry.owner === service),
    );
    if (liveServices.length) {
      const names = liveServices
        .map((service) => serviceById(service)?.label ?? service)
        .join(" and ");
      warnings[credentialField(credential, "holders")] =
        `A process_api holder is read over ${names}'s running API; add ${names} as a credential and store its key, or that copy will be unverifiable.`;
    }

    const credentialTargets = new Set();

    for (const holder of credential.consumers) {
      const target = holderMeta(holder);
      if (!target) {
        errors[holderField(credential, holder, "target")] =
          "Choose a target this build can read.";
        continue;
      }
      if (
        !serviceById(holder.service)?.holderOnly &&
        !draft.services.includes(holder.service)
      ) {
        errors[holderField(credential, holder, "service")] =
          "This holder service is not selected. Add it in Services.";
      }

      const qualifier = String(holder.qualifier ?? "").trim();
      if (qualifier) {
        if (qualifier.includes("[") || qualifier.includes("]")) {
          errors[holderField(credential, holder, "qualifier")] =
            "A row or field name cannot contain brackets.";
        } else if ((qualifier.match(/:/g) ?? []).length > 1) {
          errors[holderField(credential, holder, "qualifier")] =
            "Use one colon at most: row or row:field.";
        } else if (nel(qualifier)) {
          errors[holderField(credential, holder, "qualifier")] =
            "The manifest parser rejects the NEL control character; remove it.";
        }
      }

      if (!Number.isSafeInteger(holder.count) || holder.count < 1) {
        errors[holderField(credential, holder, "count")] =
          "Count must be a positive whole number.";
      }
      if (nel(holder.note)) {
        errors[holderField(credential, holder, "note")] =
          "The manifest parser rejects the NEL control character; remove it.";
      }

      const text = targetString({ ...holder, qualifier });
      if (credentialTargets.has(text)) {
        errors[holderField(credential, holder, "target")] =
          "This credential already declares that exact target.";
      } else if (targetOwners.has(text) && !targetIsRepeatable(text)) {
        errors[holderField(credential, holder, "target")] =
          `${targetOwners.get(text)} already uses this copy. Pick a different row or field in Advanced.`;
      } else {
        credentialTargets.add(text);
        targetOwners.set(text, name || "another credential");
      }
    }

  }

  const ok =
    serviceErrors.length === 0 &&
    credentialErrors.length === 0 &&
    Object.keys(errors).length === 0;
  return {
    ok,
    services: serviceErrors,
    credentials: credentialErrors,
    errors,
    warnings,
    manifest: ok ? buildManifest(draft) : null,
    counts: draftCounts(draft),
  };
}

function scalar(value) {
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  throw new Error(`cannot emit ${typeof value} as a YAML scalar`);
}

function plainKey(value) {
  return /^[A-Za-z0-9_.-]+$/.test(value) ? value : scalar(value);
}

// The manifest emitter's output is deliberately plain: two-space indentation,
// one credential per mapping, and strings double-quoted so a description or a
// row selector cannot change the shape of the document.
export function toYaml(manifest) {
  const lines = [`version: ${manifest.version}`, "credentials:"];
  const names = Object.keys(manifest.credentials);
  if (names.length === 0) {
    lines[1] = "credentials: {}";
    return `${lines.join("\n")}\n`;
  }
  for (const name of names) {
    const credential = manifest.credentials[name];
    lines.push(`  ${scalar(name)}:`);
    if (credential.description) {
      lines.push(`    description: ${scalar(credential.description)}`);
    }
    lines.push(`    class: ${credential.class}`);
    if (credential.never_rotate) {
      lines.push("    never_rotate: true");
    } else {
      lines.push(`    max_age_days: ${credential.max_age_days}`);
    }
    lines.push("    canonical:");
    lines.push(`      service: ${plainKey(credential.canonical.service)}`);
    if (credential.write?.mechanism) {
      lines.push("    write:");
      lines.push(`      mechanism: ${plainKey(credential.write.mechanism)}`);
    }
    if (credential.consumers?.length) {
      lines.push("    consumers:");
      for (const consumer of credential.consumers) {
        lines.push(`      - target: ${scalar(consumer.target)}`);
        lines.push(`        count: ${consumer.count}`);
        if (consumer.mechanism) {
          lines.push(`        mechanism: ${plainKey(consumer.mechanism)}`);
        }
        if (consumer.note) {
          lines.push(`        note: ${scalar(consumer.note)}`);
        }
      }
    }
  }
  return `${lines.join("\n")}\n`;
}
