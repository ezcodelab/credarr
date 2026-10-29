// The Apps view joins the backend's two resources into the operator's one
// object: an app is a credential plus the service that issues it. No Svelte
// here, so the join is unit-testable without a browser.
import { SERVICE_CATALOG, serviceById } from "./setupCatalog.js";
import {
  copyLabel,
  credentialTitle,
  plainEngineText,
  stripServicePrefix,
} from "./names.js";
import { sentenceCase } from "./api.js";

// Which service a credential belongs to: the declared canonical service when
// there is one, else the service its name was generated from. "" means the
// console cannot place it; the view shows it under attention, never drops it.
export function ownerOfCredential(row) {
  const declared = row?.canonical?.service;
  if (typeof declared === "string" && declared !== "") return declared;
  const name = String(row?.name ?? "");
  const exact = SERVICE_CATALOG.find(
    (service) => name === `${service.id}_api_key` || name === service.id,
  );
  if (exact) return exact.id;
  const prefixed = SERVICE_CATALOG.filter((service) =>
    name.startsWith(service.id),
  ).sort((a, b) => b.id.length - a.id.length)[0];
  return prefixed?.id ?? "";
}

export function titleOfCredential(row) {
  return credentialTitle(row?.name ?? "");
}

export function titleOfService(id) {
  return serviceById(id)?.label ?? id;
}

// One card per credential, joined to its service definition. Services with no
// credential come back separately so the view can offer Connect instead of
// pretending they are healthy.
export function buildApps({ credentials = [], definitions = [] } = {}) {
  const byName = new Map(definitions.map((item) => [item?.name, item]));
  const apps = [];
  const unassigned = [];
  for (const row of credentials) {
    const owner = ownerOfCredential(row);
    if (!owner) {
      unassigned.push(row);
      continue;
    }
    apps.push({
      id: owner,
      name: row.name,
      title: titleOfCredential(row),
      row,
      definition: byName.get(owner) ?? null,
      url: byName.get(owner)?.url ?? "",
      stored: row.stored === true,
      manualCopies: [
        ...new Set(
          (row.consumers ?? [])
            .filter((consumer) => consumer.manual === true)
            .map((consumer) => copyLabel(consumer.target)),
        ),
      ],
    });
  }
  const keyed = new Set(apps.map((app) => app.id));
  const unconnected = definitions
    .filter(
      (item) =>
        item &&
        item.declared === true &&
        !keyed.has(item.name) &&
        !serviceById(item.name)?.holderOnly,
    )
    .map((item) => ({
      id: item.name,
      title: `${titleOfService(item.name)} API Key`,
      definition: item,
      url: item.url ?? "",
    }));
  apps.sort((a, b) => a.title.localeCompare(b.title));
  unconnected.sort((a, b) => a.title.localeCompare(b.title));
  return { apps, unassigned, unconnected };
}

// Copies whose live row count disagrees with the declaration. `null` means
// the run could not count the holder (never audited as declared, no answer),
// so the field stays hand-editable; 0 means the qualified row is missing,
// not that the copy should be declared absent — never offered.
export function countProposals(consumers) {
  return (consumers ?? [])
    .filter(
      (consumer) =>
        consumer?.observed_count != null &&
        consumer.observed_count !== consumer?.count &&
        consumer.observed_count > 0,
    )
    .map((consumer) => ({
      target: consumer.target,
      count: consumer.count,
      observed: consumer.observed_count,
    }));
}

// A typed copy count is a whole number >= 1; anything else is not a count.
export function parseCopyCount(value) {
  const count = Number(value);
  return Number.isSafeInteger(count) && count >= 1 ? count : null;
}

// What the dry run checked, in one past-tense sentence: the checks that
// passed, never what the run would do. Copies are propagate steps only, so
// the mint step's own target (a slug like `sonarr_api_key`, not a copy) can
// never leak into the count. Refused plans and empty answers get no
// sentence; their banner says why instead.
export function dryRunSentence(planPayload) {
  if (!planPayload || planPayload.refused) return "";
  const copies = (planPayload.steps ?? []).filter(
    (step) => step?.kind === "propagate",
  ).length;
  const units = copies === 1 ? "1 copy" : `${copies} copies`;
  if (planPayload.manual_mint === true)
    return `Checks passed: ${units} declared; the key comes from you at run time.`;
  if (planPayload.mint_via === "reconstructed")
    return `Checks passed: sign-in works, the service reports SQLite, ${units} checked.`;
  return `Checks passed: sign-in works, the backup answers, ${units} checked.`;
}

// Whether the plan is stuck at the service's UI login: the backup download
// answers with a login redirect the API key cannot open. The panel points at
// the UI-login section and the section offers the ways forward; the engine's
// own sentences stay beneath both.
export function isLoginBlock(reasons) {
  return (reasons ?? []).some((reason) =>
    /web UI login|write\.ui_password/.test(String(reason ?? "")),
  );
}

// A failed run's cause lines: the engine's "failed: ..." prefix goes away
// (the banner title already says it stopped) and an own-service prefix goes
// with it; the hint rides along, with write.* paths translated the way every
// rendered engine sentence is. A trailing "nothing has been changed" stays:
// a stopped run may be partial, so that sentence is load-bearing here.
export function failureLines(run, own = []) {
  const detail = String(
    run?.detail || (run?.failed ? `Stopped at ${run.failed}.` : ""),
  );
  return detail
    .replace(/^failed: /, "")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) =>
      sentenceCase(stripServicePrefix(plainEngineText(line), own)),
    );
}

// Targets whose write/confirmation route is not measured. Auto-rotation may
// leave them for a human, so the card warns and asks before enabling. The
// same set decides whether a saved reminder still describes this declaration.
export function manualTargets(row) {
  return [
    ...new Set(
      (row?.consumers ?? [])
        .filter(
          (consumer) => consumer.manual === true || !consumer.exercised,
        )
        .map((consumer) => consumer.target)
        .filter((target) => typeof target === "string" && target !== ""),
    ),
  ];
}

export function manualCopyLabels(row) {
  return [...new Set(manualTargets(row).map((target) => copyLabel(target)))];
}

// Copies the engine can write but cannot verify through a measured test or
// read-back. They are automatic writes with a manual proof, not manual writes.
export function unprovenCopyLabels(row) {
  return [
    ...new Set(
      (row?.consumers ?? [])
        .filter(
          (consumer) =>
            consumer.manual !== true && consumer.exercised !== true,
        )
        .map((consumer) => copyLabel(consumer.target)),
    ),
  ];
}

export function manualOnlyCopyLabels(row) {
  return [
    ...new Set(
      (row?.consumers ?? [])
        .filter((consumer) => consumer.manual === true)
        .map((consumer) => copyLabel(consumer.target)),
    ),
  ];
}

// Copies in operator words: the service names that hold this key.
export function copyNames(row) {
  const names = [];
  for (const consumer of row?.consumers ?? []) {
    const service = String(consumer?.target ?? "").split("[", 1)[0].split(".", 1)[0];
    names.push(titleOfService(service));
  }
  return [...new Set(names)];
}

// Holder services with no service definition behind them. The audit cannot
// look for those copies until the service exists.
export function missingCopyServices(row, definitions = []) {
  const known = new Set(definitions.map((item) => item?.name));
  const missing = new Set();
  for (const consumer of row?.consumers ?? []) {
    const service = String(consumer?.target ?? "").split("[", 1)[0].split(".", 1)[0];
    if (service && !known.has(service) && !serviceById(service)?.holderOnly) {
      missing.add(service);
    }
  }
  return [...missing];
}
