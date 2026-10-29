// A local reminder for copies Credarr cannot verify: a Homepage label, a
// deploy-time value, or a holder with no API. It stores names and checkboxes,
// never values, and never feeds the audit or an auto-rotation gate.
const KEY = "credarr.manualFollowUp.v1";

function defaultStorage() {
  try {
    return globalThis.localStorage;
  } catch {
    return null;
  }
}

function loadAll(storage) {
  try {
    const parsed = JSON.parse(storage?.getItem(KEY) ?? "null");
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const all = {};
    for (const [credential, entry] of Object.entries(parsed)) {
      if (!credential || !entry || typeof entry !== "object") continue;
      if (!Number.isSafeInteger(entry.attempt)) continue;
      const targets = {};
      for (const [target, state] of Object.entries(entry.targets ?? {})) {
        if (typeof target !== "string" || !target) continue;
        targets[target] = {
          done: state?.done === true,
          at: Number.isFinite(state?.at) ? state.at : 0,
        };
      }
      if (Object.keys(targets).length) {
        all[credential] = { attempt: entry.attempt, targets };
      }
    }
    return all;
  } catch {
    return {};
  }
}

function saveAll(storage, all) {
  try {
    storage?.setItem(KEY, JSON.stringify(all));
  } catch {
    // A blocked or full storage must not break the rotation result.
  }
}

export function readManualTracker(credential, storage = defaultStorage()) {
  return loadAll(storage)[credential] ?? null;
}

export function trackManual(
  credential,
  attempt,
  targets,
  storage = defaultStorage(),
) {
  const all = loadAll(storage);
  const wanted = [...new Set((targets ?? []).map(String).filter(Boolean))];
  if (!credential || !Number.isSafeInteger(attempt) || wanted.length === 0) {
    delete all[credential];
    saveAll(storage, all);
    return null;
  }
  const previous = all[credential];
  const sameAttempt = previous?.attempt === attempt;
  const at = Date.now();
  all[credential] = {
    attempt,
    targets: Object.fromEntries(
      wanted.map((target) => [
        target,
        {
          done: sameAttempt && previous.targets[target]?.done === true,
          at,
        },
      ]),
    ),
  };
  saveAll(storage, all);
  return all[credential];
}

// A reminder is only meaningful while the targets it names are still the
// current manual/unproven copies. A removed holder must not leave a stale
// "Manual rotation" card behind; the next rotation is the only thing that can
// create a new reminder.
export function pruneManualTracker(
  credential,
  currentTargets,
  storage = defaultStorage(),
) {
  const all = loadAll(storage);
  const entry = all[credential];
  if (!entry) return null;
  const wanted = new Set((currentTargets ?? []).map(String).filter(Boolean));
  const targets = Object.fromEntries(
    Object.entries(entry.targets).filter(([target]) => wanted.has(target)),
  );
  if (Object.keys(targets).length === 0) {
    delete all[credential];
    saveAll(storage, all);
    return null;
  }
  if (Object.keys(targets).length !== Object.keys(entry.targets).length) {
    all[credential] = { attempt: entry.attempt, targets };
    saveAll(storage, all);
    return all[credential];
  }
  return entry;
}

export function markManualDone(
  credential,
  target,
  done,
  storage = defaultStorage(),
) {
  const all = loadAll(storage);
  const entry = all[credential];
  if (!entry || !entry.targets[target]) return entry ?? null;
  entry.targets[target] = {
    done: done === true,
    at: Date.now(),
  };
  saveAll(storage, all);
  return entry;
}

export function clearManualTracker(credential, storage = defaultStorage()) {
  const all = loadAll(storage);
  delete all[credential];
  saveAll(storage, all);
  return null;
}
