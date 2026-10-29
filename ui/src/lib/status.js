// One vocabulary for every surface. The engine's status words are the labels;
// the glosses explain the word without inventing a softer state. A second map
// would let the hub and the app page disagree about the same run.
import { credentialTitle } from "./names.js";
import { serviceById } from "./setupCatalog.js";

export const STATUS = {
  match: {
    label: "match",
    tone: "ok",
    why: "The stored value and the observed copy agree.",
  },
  drift: {
    label: "drift",
    tone: "bad",
    why: "A holder holds a value that differs from the stored one.",
  },
  missing: {
    label: "missing",
    tone: "bad",
    why: "A declared holder is missing.",
  },
  error: {
    label: "error",
    tone: "bad",
    why: "The audit could not read this holder.",
  },
  absent: {
    label: "absent",
    tone: "warn",
    why: "No value is provisioned where one was expected.",
  },
  unverifiable: {
    label: "unverifiable",
    tone: "warn",
    why: "The audit could not compare a value. This is not a match.",
  },
  live: {
    label: "ok",
    tone: "ok",
    why: "Accepted by the service; equality can't be read back, so this is the full proof.",
  },
  indirect: {
    label: "manual",
    tone: "none",
    why: "A configured manual copy; Credarr does not read it back.",
  },
  manual: {
    label: "manual",
    tone: "none",
    why: "A configured manual copy; Credarr does not read it back.",
  },
  none: {
    label: "not audited yet",
    tone: "none",
    why: "No current status is recorded for this state.",
  },
  no_holders: {
    label: "no holders",
    tone: "none",
    why: "Nothing outside this app holds this value; there is no copy to compare.",
  },
  enabled: {
    label: "enabled",
    tone: "ok",
    why: "This policy can run without a click when its gate is met.",
  },
  off: {
    label: "off",
    tone: "none",
    why: "This policy is off.",
  },
  paused: {
    label: "paused",
    tone: "warn",
    why: "An unattended run did not finish; resolve it before re-enabling.",
  },
  ready: {
    label: "ready",
    tone: "ok",
    why: "The plan passed its checks.",
  },
  refused: {
    label: "refused",
    tone: "bad",
    why: "Credarr refused this rotation.",
  },
  preflight: {
    label: "checks failed",
    tone: "warn",
    why: "The plan could not be checked; this attempt started nothing.",
  },
  managed: {
    label: "managed",
    tone: "accent",
    why: "This build has a writer and a measured version for the holder.",
  },
  monitor: {
    label: "monitor only",
    tone: "monitor",
    why: "This holder is readable but has no measurement that allows a safe write.",
  },
  reset: {
    label: "reset",
    tone: "warn",
    why: "The mint invalidates the old key first.",
  },
  create: {
    label: "create",
    tone: "accent",
    why: "The new key is added alongside the old one.",
  },
  configured: {
    label: "configured",
    tone: "ok",
    why: "A sink is configured.",
  },
};

const STATUS_ORDER = {
  error: 0,
  drift: 1,
  missing: 2,
  absent: 3,
  unverifiable: 4,
  live: 5,
  indirect: 6,
  manual: 6,
  none: 8,
  no_holders: 9,
  match: 10,
};

export function statusInfo(status) {
  return STATUS[status] ?? STATUS.none;
}

// A credential with no holders is not waiting for an audit: there is no copy
// an audit could change. Keep that distinct from a null status that still has
// holders, which is a real "not measured" state.
export function statusOf(row) {
  if (row?.status) return row.status;
  if (row && (row.consumers?.length ?? 0) === 0) return "no_holders";
  return "none";
}

// A check of a credential with no holders is still a measurement of that one
// value; it must not read as the engine's "manual copy" status. The Apps card
// has always derived `no holders` from the declared shape, so the app history
// uses the same vocabulary for the same row.
export function checkStatus(status, row) {
  if (
    row &&
    (row.consumers?.length ?? 0) === 0 &&
    (status === "indirect" || status === "manual")
  ) {
    return "no_holders";
  }
  return status;
}

// A sorted table should put the worst finding first, not alphabetise "drift"
// past "match".
export function statusRank(status) {
  return STATUS_ORDER[status ?? "none"] ?? STATUS_ORDER.none;
}

export function runInfo(run) {
  if (!run) return { status: "none", label: "none yet", why: "No audit has run." };
  return {
    status: run.exit_status ?? "none",
    label: run.exit_status ?? "no result",
    why: run.detail || statusInfo(run.exit_status).why,
  };
}

// The most important sentence on the Overview. A green state is impossible
// while the store is empty, no audit has completed, or a rotation is open.
export function stackHealth(status, data) {
  const topology = status?.topology ?? {};
  const rows = data?.credentials ?? [];
  const pending = status?.rotation?.pending ?? [];
  const lastAudit = status?.last_audit ?? null;

  if (!topology.imported) {
    return {
      tone: "none",
      status: "none",
      label: "not imported",
      title: "Nothing has been measured",
      why: "No topology has been imported. An empty store is not a clean bill of health.",
    };
  }

  if (pending.length) {
    const names = [...new Set(pending.map((step) => credentialTitle(step.credential)))];
    return {
      tone: "bad",
      status: "error",
      label: "rotation interrupted",
      title: "A rotation did not finish",
      why: `${names.join(", ")} didn't finish. Resume it before relying on these copies; nothing retries automatically.`,
    };
  }

  if (!lastAudit) {
    return {
      tone: "warn",
      status: "none",
      label: "not audited yet",
      title: "Declared, not measured",
      why: "No audit has completed. Nothing below is a health verdict.",
    };
  }

  const attention = rows.filter((row) =>
    ["error", "drift", "missing"].includes(row.status),
  );
  if (attention.length) {
    return {
      tone: "bad",
      status: "drift",
      label: `${attention.length} need attention`,
      title: "Copies disagree",
      why: `${attention.map((row) => row.name).join(", ")} ${
        attention.length === 1 ? "has" : "have"
      } a current finding.`,
    };
  }

  // A credential that declares no holders has nothing to measure. Counting it
  // here made a finished setup look permanently incomplete.
  const unknown = rows.filter(
    (row) => !row.status && (row.consumers?.length ?? 0) > 0,
  );
  if (unknown.length) {
    return {
      tone: "warn",
      status: "unverifiable",
      label: "coverage incomplete",
      title: "Some credentials are unmeasured",
      why: `${unknown.length} declared ${
        unknown.length === 1 ? "credential has" : "credentials have"
      } no current status. Re-audit after the missing value or holder change.`,
    };
  }

  // Live is the ceiling for an exercised holder (the API can't show the
  // value back), so it is covered, not a gap: only unreadable copies ask
  // for another audit.
  const limited = rows.filter((row) =>
    ["unverifiable", "indirect", "absent"].includes(row.status),
  );
  if (limited.length) {
    // Name the apps, not a count: a number never says which key to open, and
    // the reason names the worst finding so mixed rows still read honestly.
    const names = [...new Set(limited.map((row) => credentialTitle(row.name)))];
    const reasons = {
      unverifiable: "the audit could not compare a value",
      indirect: "the comparison used a derived path",
      absent: "no value is provisioned where one was expected",
    };
    const worst = limited.reduce((a, b) =>
      (statusRank(a.status) ?? 9) < (statusRank(b.status) ?? 9) ? a : b,
    );
    return {
      tone: "warn",
      status: "unverifiable",
      label: "limited coverage",
      title: "No drift found, but not every copy was compared",
      why:
        `${names.join(", ")} ${names.length === 1 ? "was" : "were"} not ` +
        `fully compared: ${reasons[worst.status] ?? "no copy was compared"}.`,
    };
  }

  const manual = rows.filter((row) =>
    (row.consumers ?? []).some((consumer) => consumer.manual === true),
  );
  const manualNote = manual.length
    ? " Manual copies are not compared."
    : "";

  // `live` is a successful run: every holder was exercised and accepted its
  // value, but an API that redacts the value cannot prove equality. The app
  // cards show that as `ok`; the headline must not call it a warning.
  if (lastAudit.exit_status === "live" && rows.length > 0) {
    return {
      tone: "ok",
      status: "match",
      label: "all clear",
      title: "No findings",
      why:
        "No drift, missing or error. Every readable copy matched; every " +
        `exercised copy was accepted by its service.${manualNote}`,
    };
  }

  if (lastAudit.exit_status === "match" && rows.length > 0) {
    return {
      tone: "ok",
      status: "match",
      label: "all clear",
      title: manual.length ? "No findings" : "Every declared copy matches",
      why: manual.length
        ? "No drift, missing or error. Manual copies are not compared."
        : "Every declared credential was compared; no drift.",
    };
  }

  return {
    tone: "warn",
    status: lastAudit.exit_status ?? "none",
    label: lastAudit.exit_status ?? "audited",
    title: "Audit complete",
    why: "The last completed audit did not cover every credential.",
  };
}

// A null row status has three honest causes: nothing has run, the state the run
// measured is no longer declared, or there is no holder to compare.
export function credentialReason(row, observed) {
  if (row.status) return row.detail || statusInfo(row.status).why;
  if (row.consumers.length === 0)
    return "Declared with no holders; there is no copy to compare.";
  if (!observed)
    return row.stored
      ? "Waiting for the first audit; the stored value has not been measured."
      : "Waiting for a value and the first audit.";
  return "The value or holder set changed after the last audit. Re-audit to get a current status.";
}

export function autoInfo(policy = {}) {
  if (policy.paused) {
    return {
      status: "paused",
      label: "paused",
      why: policy.last_detail || "An unattended run did not finish.",
    };
  }
  if (policy.enabled) {
    return {
      status: "enabled",
      label: "enabled",
      why: "A fresh stack-wide audit can start a due rotation; manual copies are notified. It never resumes an interrupted run.",
    };
  }
  return {
    status: "off",
    label: "off",
    why: "Off by default. Nothing runs unattended.",
  };
}

const EVENT_KIND = {
  drift: "drift",
  unverifiable: "unverifiable",
  recovered: "match",
  test: "none",
  auto_blocked: "paused",
  auto_started: "enabled",
  auto_succeeded: "enabled",
  auto_manual: "unverifiable",
  auto_interrupted: "error",
  rotation_failed: "error",
  rotation_manual: "enabled",
  rotation_succeeded: "enabled",
};

const EVENT_LABEL = {
  auto_manual: "manual rotation",
  rotation_manual: "rotation succeeded",
};

export function eventInfo(kind) {
  return {
    status: EVENT_KIND[kind] ?? "none",
    label: EVENT_LABEL[kind] ?? kind.replaceAll("_", " "),
  };
}

// What the operator can do about the reason a row shows. The API's `detail` is
// deliberately a sentence; `reason` is the stable code beside it, so a row with
// no sentence still names the action instead of falling back to "unverifiable".
// The sentence patterns stay as a fallback for history written before codes.
const REASON_HINTS = {
  not_provisioned:
    "This key is not provisioned yet. Provision it, then run an audit again.",
  no_canonical:
    "No value is stored yet. Add this key on its app page, then run an audit again.",
  value_missing:
    "No value is stored yet. Add this key on its app page, then run an audit again.",
  no_service_key:
    "The copy's own service key is not configured. Add it on that app page, then audit again.",
  no_url:
    "The copy's service has no URL configured. Add it on that app page, then audit again.",
  row_missing:
    "The copy's service has no row with the declared name. Add or rename that row there, or remove this copy, then audit again.",
  unreachable:
    "Check the service's URL and that its API is answering, then audit again.",
  field_missing:
    "The copy's target does not expose the declared field. Check the copy's target on the credential, then audit again.",
  target_unqualified:
    "This copy needs a qualified target naming one row or section. Fix it on the credential, then audit again.",
  count_mismatch:
    "The live row count differs from the declared count. Set the copy's count to the live number, then audit again.",
  liveness_rejected:
    "The copy's service rejected the stored value. Rotate the key again to write the current value.",
  liveness_inconclusive:
    "The copy's service could not prove the stored value. Check the service, then audit again.",
  no_readback:
    "This copy cannot be read back by this build; update it by hand after a rotation.",
};

export function fixHint(row) {
  if (!row) return "";
  const detail = String(row.detail ?? "").toLowerCase();
  if (!row.stored) {
    if ((row.consumers?.length ?? 0) === 0) {
      return "Nothing holds this key yet, so there is nothing to compare. Add a copy if another app stores it.";
    }
    return "Add this key on its app page, then run an audit again.";
  }
  const missing = detail.match(/no stored key for ([a-z0-9_-]+)/);
  if (missing) {
    const label = serviceById(missing[1])?.label ?? missing[1];
    return `${label}'s API key is not configured. Add it on the ${label} app page, then audit again.`;
  }
  if (detail.includes("no row named")) {
    return "The copy's service has no row with the declared name. Add or rename that row there, or remove this copy, then audit again.";
  }
  if (
    detail.includes("could not be read") ||
    detail.includes("did not list its rows")
  ) {
    return "Check the service's URL and that its API is answering, then audit again.";
  }
  if (detail.includes("no rows carrying")) {
    return "The copy's target does not expose the declared field. Check the copy's target on the credential, then audit again.";
  }
  const reasonHint = REASON_HINTS[String(row.reason ?? "")];
  if (reasonHint) return reasonHint;
  if (row.status === "unverifiable") {
    return "Open the credential to see which copy could not be read; the copy names its own service.";
  }
  return "";
}
