// The one door to the BFF: /api/v1, same origin, session cookie.
//
// Errors carry the server's own sentence (`detail`), because the engine's
// messages are written to be read by an operator and the UI must not replace
// them with its own paraphrase.

// The session-bound CSRF token, kept in memory only. It arrives from
// `/auth/me` after sign-in and is sent on writes; it is not a credential and
// is never written to storage.
let csrfToken = "";

export function setCsrfToken(token) {
  csrfToken = typeof token === "string" ? token : "";
}

export function clearCsrfToken() {
  csrfToken = "";
}

// Our own HTTPExceptions carry a string; pydantic's 422s carry a list of
// {msg} - the setup password floor is one of those, and "HTTP 422" is not an
// answer an operator can act on.
function detailOf(payload) {
  const detail = payload?.detail;
  if (typeof detail === "string" && detail) return detail;
  if (Array.isArray(detail)) return detail.map((item) => item?.msg ?? "invalid request").join("; ");
  return "";
}

export class ApiError extends Error {
  constructor(status, detail) {
    super(detail || `HTTP ${status}`);
    this.status = status;
  }
}

const IDEMPOTENT = new Set(["GET", "HEAD"]);

export async function api(
  path,
  { method = "GET", body, type = "application/json", timeout, retried = false } = {},
) {
  const headers = body === undefined ? {} : { "content-type": type };
  if (!["GET", "HEAD", "OPTIONS"].includes(method) && csrfToken) {
    headers["x-csrf-token"] = csrfToken;
  }
  const response = await fetch(`/api/v1${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : type === "application/json" ? JSON.stringify(body) : body,
    credentials: "same-origin",
    // No default: a rotation or a live service scan can legitimately take
    // longer than a normal read. Full audits use the job helpers below.
    signal: timeout ? AbortSignal.timeout(timeout) : undefined,
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    // The password change rotates this session in one transaction, but a read
    // that left before the new cookie arrived can still be refused. Re-check
    // the session once and retry a read only: a write must never be replayed
    // behind the operator's back.
    if (response.status === 401 && !retried && IDEMPOTENT.has(method)) {
      const me = await fetch("/api/v1/auth/me", { credentials: "same-origin" });
      if (me.ok) {
        const state = await me.json().catch(() => null);
        setCsrfToken(state?.csrf ?? "");
        return api(path, { method, body, type, timeout, retried: true });
      }
    }
    throw new ApiError(response.status, detailOf(payload));
  }
  return payload;
}

// A full audit is a server-side job, not a request the browser holds open.
// Start it, then poll the job id; a dropped tunnel or proxy timeout no longer
// loses the run, and the console can resume polling when the path returns.
const AUDIT_START_TIMEOUT_MS = 15_000;
const AUDIT_POLL_TIMEOUT_MS = 10_000;
const AUDIT_POLL_MS = 1_000;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function startAuditJob() {
  let lastFailure;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      return await api("/audit?wait=false", {
        method: "POST",
        timeout: AUDIT_START_TIMEOUT_MS,
      });
    } catch (failure) {
      // A 4xx is a real refusal. A dropped connection may mean the server
      // accepted the start but the answer was lost; retrying attaches to the
      // active job, so the second request is safe.
      if (failure instanceof ApiError) throw failure;
      lastFailure = failure;
      if (attempt < 2) await sleep(1_000);
    }
  }
  throw lastFailure;
}

export async function waitForAudit(jobId, { onTrouble } = {}) {
  let delay = AUDIT_POLL_MS;
  let failures = 0;
  while (true) {
    let job;
    try {
      job = await api(`/audit/jobs/${encodeURIComponent(jobId)}`, {
        timeout: AUDIT_POLL_TIMEOUT_MS,
      });
    } catch (failure) {
      if (failure instanceof ApiError) {
        if (failure.status === 401) throw failure;
        if (failure.status === 404) {
          throw new Error(
            "the audit job is no longer available; reload to see the latest audit",
          );
        }
      }
      // A network drop, a proxy timeout or a transient 5xx: keep the audit
      // alive and reconnect instead of turning it into a failed run. Tell the
      // console after a few failures so it does not sit silently on
      // "Auditing…" with no message.
      failures += 1;
      if (failures === 3) onTrouble?.(failure);
      await sleep(delay);
      delay = Math.min(delay * 2, 5_000);
      continue;
    }
    if (failures > 0) onTrouble?.(null);
    failures = 0;
    if (job.status === "succeeded") return job.result;
    if (job.status === "failed") {
      throw new Error(job.error || "the audit failed");
    }
    await sleep(delay);
    delay = Math.min(delay * 2, 5_000);
  }
}

export async function auditStack({ onTrouble } = {}) {
  const job = await startAuditJob();
  if (!job?.job_id) {
    throw new Error("the server did not start an audit job");
  }
  return waitForAudit(job.job_id, { onTrouble });
}

// The saved service definitions, without asking the server to probe every
// service for a running version. Apps, the topology editor and the app detail
// page only render the URL/declared facts; the full report is for the
// observation API.
export async function serviceDefinitions({ timeout } = {}) {
  const data = await api("/services?observe=false", { timeout });
  return data?.definitions ?? [];
}

// Resources this page session created. A later write in the same draft may
// have failed, so a retry's 409 is ours to reconcile; a name this session did
// not create is a collision and must stay an error.
const createdHere = new Set();

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, stable(value[key])]),
    );
  }
  return value;
}

function sameJson(left, right) {
  return JSON.stringify(stable(left) ?? null) === JSON.stringify(stable(right) ?? null);
}

// Does the row already say exactly what this draft asked for? Compared field
// by field, so server-added status fields and ordering do not matter.
function sameDeclaration(path, existing, body) {
  if (path === "/services") {
    return Object.entries(body).every(
      ([key, value]) => key === "name" || sameJson(existing[key], value),
    );
  }
  return Object.entries(body).every(([key, value]) => {
    if (key === "name") return true;
    if (key !== "consumers") return sameJson(existing[key], value);
    const rows = existing.consumers ?? [];
    return (
      rows.length === value.length &&
      value.every((holder, index) =>
        ["target", "count", "mechanism", "host", "note"].every((field) =>
          sameJson(rows[index]?.[field], holder[field]),
        ),
      )
    );
  });
}

// Create a resource, or reconcile the one an interrupted earlier attempt
// already created. A retry may patch a row this page session created, because
// it owns that row. A name it did not create is only accepted when the saved
// declaration is already identical; anything else is a genuine collision and
// is never overwritten.
export async function createOrUpdate(path, body, { timeout } = {}) {
  const name = body?.name;
  const key = name ? `${path}/${name}` : "";
  try {
    const created = await api(path, { method: "POST", body, timeout });
    if (key) createdHere.add(key);
    return created;
  } catch (failure) {
    if (!(failure instanceof ApiError) || failure.status !== 409 || !name) {
      throw failure;
    }
    if (!createdHere.has(key)) {
      let existing;
      try {
        const answer = await api(path, { timeout });
        const rows =
          path === "/services" ? answer?.definitions ?? [] : answer?.credentials ?? [];
        existing = rows.find((row) => row.name === name);
      } catch {
        throw failure;
      }
      if (!existing || !sameDeclaration(path, existing, body)) throw failure;
      return existing;
    }
    const { name: _name, ...metadata } = body;
    return api(`${path}/${encodeURIComponent(name)}`, {
      method: "PATCH",
      body: metadata,
      timeout,
    });
  }
}

// The sentence a view shows when a call fails. Views keep their own 401 and
// timeout handling; this is only the shared fallback that used to be copied
// into every catch block.
export function errorText(failure) {
  if (failure?.name === "TimeoutError") {
    return sentenceCase("the server did not answer in time");
  }
  return sentenceCase(failure?.message ?? String(failure));
}

// Error details are sentences even when the server spells them lower-case.
// Brand names keep their own casing.
const LOWERCASE_STARTS = new Set([
  "qBittorrent",
  "qui",
  "ansible-vault",
  "chmod",
  "curl",
  "docker",
  "git",
  "sops",
  "sudo",
]);

export function sentenceCase(text) {
  const value = String(text ?? "");
  const firstWord = value.match(/^[^\s:]+/)?.[0] ?? "";
  if (LOWERCASE_STARTS.has(firstWord)) return value;
  return /^[a-z]/.test(value)
    ? value.charAt(0).toUpperCase() + value.slice(1)
    : value;
}

// The server's configured zone, not the browser's. A self-hosted console's
// audit timestamps should mean the same thing to every operator looking at the
// same deployment; the server reports TZ in /status.
let displayTimeZone = "";

export function setTimeZone(timezone) {
  displayTimeZone = typeof timezone === "string" ? timezone : "";
}

export function timestamp(seconds) {
  if (!seconds) return "—";
  const date = new Date(seconds * 1000);
  if (displayTimeZone) {
    try {
      return date.toLocaleString(undefined, { timeZone: displayTimeZone });
    } catch {
      // The server accepted a zone this browser's ICU does not know. Fall
      // back to UTC, not the browser: every viewer must still agree.
      return date.toLocaleString(undefined, { timeZone: "UTC" });
    }
  }
  return date.toLocaleString();
}

// A duration as the operator reads it: "45 seconds", "12 minutes".
export function elapsed(seconds) {
  const [count, unit] =
    seconds < 90
      ? [Math.round(seconds), "second"]
      : [Math.round(seconds / 60), "minute"];
  return `${count} ${unit}${count === 1 ? "" : "s"}`;
}
