// Retrying a half-written topology: an earlier attempt already created some
// rows, so the retry must patch them instead of failing on 409 forever.
import assert from "node:assert/strict";
import test from "node:test";

import {
  ApiError,
  api,
  auditStack,
  createOrUpdate,
  sentenceCase,
  serviceDefinitions,
  setTimeZone,
  timestamp,
} from "../src/lib/api.js";

function jsonResponse(status, payload) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload,
  };
}

function fakeApi({ failValueTimes = 0, failServiceCreate = false } = {}) {
  const state = {
    services: new Map(),
    credentials: new Map(),
    values: new Map(),
    valueAttempts: 0,
    calls: [],
  };

  async function fetchImpl(url, options = {}) {
    const path = url.replace("/api/v1", "");
    const method = options.method ?? "GET";
    const body = options.body ? JSON.parse(options.body) : undefined;
    state.calls.push({ method, path, body });

    if (path === "/services" && method === "GET") {
      return jsonResponse(200, { definitions: [...state.services.values()] });
    }
    if (path === "/credentials" && method === "GET") {
      return jsonResponse(200, { credentials: [...state.credentials.values()] });
    }

    const value = /^\/credentials\/([^/]+)\/value$/.exec(path);
    if (value && method === "PUT") {
      state.valueAttempts += 1;
      if (state.valueAttempts <= failValueTimes) {
        return jsonResponse(500, { detail: "the value write failed" });
      }
      state.values.set(decodeURIComponent(value[1]), body.value);
      return jsonResponse(200, { stored: true });
    }

    const one = /^\/(services|credentials)\/([^/]+)$/.exec(path);
    if (one && method === "PATCH") {
      const rows = state[one[1]];
      const name = decodeURIComponent(one[2]);
      if (!rows.has(name)) return jsonResponse(404, { detail: "not found" });
      rows.set(name, { ...rows.get(name), ...body });
      return jsonResponse(200, rows.get(name));
    }

    if (path === "/services" && method === "POST") {
      if (failServiceCreate) {
        return jsonResponse(500, { detail: "the store refused the write" });
      }
      if (state.services.has(body.name)) {
        return jsonResponse(409, { detail: "service already exists" });
      }
      state.services.set(body.name, { ...body });
      return jsonResponse(201, body);
    }

    if (path === "/credentials" && method === "POST") {
      if (state.credentials.has(body.name)) {
        return jsonResponse(409, { detail: "credential already exists" });
      }
      state.credentials.set(body.name, { ...body });
      return jsonResponse(201, body);
    }

    return jsonResponse(404, { detail: "not found" });
  }

  return { state, fetchImpl };
}

function useFetch(fetchImpl) {
  const original = globalThis.fetch;
  globalThis.fetch = fetchImpl;
  return () => {
    globalThis.fetch = original;
  };
}

// The wizard's order: service, credential, then the key value.
async function writeStack(url) {
  await createOrUpdate("/services", {
    name: "sonarr",
    kind: "servarr",
    url,
  });
  await createOrUpdate("/credentials", {
    name: "sonarr_api_key",
    class: "A",
    canonical: { service: "sonarr" },
  });
  await api("/credentials/sonarr_api_key/value", {
    method: "PUT",
    body: { value: "not-a-real-key" },
  });
}

test("the definitions read skips live service observations", async () => {
  const calls = [];
  const restore = useFetch(async (url) => {
    calls.push(url);
    return jsonResponse(200, {
      definitions: [{ name: "sonarr", url: "http://sonarr:8989" }],
    });
  });
  try {
    const rows = await serviceDefinitions();
    assert.deepEqual(rows, [{ name: "sonarr", url: "http://sonarr:8989" }]);
    assert.equal(calls.length, 1);
    assert.match(calls[0], /\/api\/v1\/services\?observe=false$/);
  } finally {
    restore();
  }
});

test("error sentences start with a capital and brands keep their casing", () => {
  assert.equal(
    sentenceCase("a service named jellyfin already exists"),
    "A service named jellyfin already exists",
  );
  assert.equal(sentenceCase("the server did not answer in time"), "The server did not answer in time");
  assert.equal(sentenceCase("qBittorrent refused the key"), "qBittorrent refused the key");
  assert.equal(sentenceCase("qui refused the key"), "qui refused the key");
  assert.equal(sentenceCase("chmod 600 the vault password file"), "chmod 600 the vault password file");
});

test("a retry patches the rows an earlier attempt created", async () => {
  const { state, fetchImpl } = fakeApi({ failValueTimes: 1 });
  const restore = useFetch(fetchImpl);
  try {
    // The first run dies at the last write, after both rows exist.
    await assert.rejects(writeStack("http://sonarr:8989"), ApiError);
    assert.equal(state.services.size, 1);
    assert.equal(state.credentials.size, 1);
    assert.equal(state.values.size, 0);
    state.calls.length = 0;

    // The retry posts the same names, gets 409, patches the current draft.
    await writeStack("http://sonarr:8990");

    assert.deepEqual(
      state.calls.map((call) => `${call.method} ${call.path}`),
      [
        "POST /services",
        "PATCH /services/sonarr",
        "POST /credentials",
        "PATCH /credentials/sonarr_api_key",
        "PUT /credentials/sonarr_api_key/value",
      ],
    );
    assert.equal(state.services.get("sonarr").url, "http://sonarr:8990");
    assert.deepEqual(state.credentials.get("sonarr_api_key").canonical, {
      service: "sonarr",
    });
    assert.equal(state.values.get("sonarr_api_key"), "not-a-real-key");
    // The name lives in the path, not in the patch body.
    assert.equal("name" in state.calls[1].body, false);
    assert.equal("name" in state.calls[3].body, false);
  } finally {
    restore();
  }
});

test("a failure that is not a duplicate still fails", async () => {
  const { state, fetchImpl } = fakeApi({ failServiceCreate: true });
  const restore = useFetch(fetchImpl);
  try {
    await assert.rejects(
      createOrUpdate("/services", {
        name: "sonarr",
        kind: "servarr",
        url: "http://sonarr:8989",
      }),
      (failure) =>
        failure instanceof ApiError && failure.status === 500,
    );
    assert.equal(state.services.size, 0);
    assert.equal(
      state.calls.some((call) => call.method === "PATCH"),
      false,
    );
  } finally {
    restore();
  }
});

test("a genuine name collision is never overwritten", async () => {
  const { state, fetchImpl } = fakeApi();
  const existing = {
    name: "radarr",
    kind: "servarr",
    url: "http://radarr:7878",
    notes: "the operator's own row",
  };
  state.services.set(existing.name, { ...existing });
  const restore = useFetch(fetchImpl);
  try {
    await assert.rejects(
      createOrUpdate("/services", {
        name: "radarr",
        kind: "servarr",
        url: "http://attacker:9999",
      }),
      (failure) => failure instanceof ApiError && failure.status === 409,
    );
    assert.deepEqual(state.services.get("radarr"), existing);
    assert.equal(
      state.calls.some((call) => call.method === "PATCH"),
      false,
      "a collision was patched over",
    );
  } finally {
    restore();
  }
});

test("an identical saved declaration is accepted without a write", async () => {
  const { state, fetchImpl } = fakeApi();
  const existing = {
    name: "jellyfin_api_key",
    class: "A",
    max_age_days: 90,
    never_rotate: false,
    provisioned: true,
    canonical: { service: "jellyfin" },
    write: { mechanism: "jellyfin_auth_keys" },
    consumers: [{ target: "seerr.settings_json[jellyfin]", count: 1, mechanism: "", host: null, note: "" }],
    status: "match",
  };
  state.credentials.set(existing.name, { ...existing });
  const restore = useFetch(fetchImpl);
  try {
    const result = await createOrUpdate("/credentials", {
      name: "jellyfin_api_key",
      class: "A",
      max_age_days: 90,
      never_rotate: false,
      provisioned: true,
      canonical: { service: "jellyfin" },
      write: { mechanism: "jellyfin_auth_keys" },
      consumers: [{ target: "seerr.settings_json[jellyfin]", count: 1, mechanism: "", host: null, note: "" }],
    });
    assert.equal(result.name, "jellyfin_api_key");
    assert.equal(
      state.calls.some((call) => call.method === "PATCH"),
      false,
      "an identical row was rewritten",
    );
    assert.deepEqual(state.credentials.get("jellyfin_api_key"), existing);
  } finally {
    restore();
  }
});

test("a reloaded retry with a changed draft stays a collision", async () => {
  const { state, fetchImpl } = fakeApi();
  const existing = {
    name: "prowlarr_api_key",
    class: "B",
    max_age_days: 30,
    canonical: { service: "prowlarr" },
    consumers: [],
  };
  state.credentials.set(existing.name, { ...existing });
  const restore = useFetch(fetchImpl);
  try {
    await assert.rejects(
      createOrUpdate("/credentials", {
        name: "prowlarr_api_key",
        class: "A",
        max_age_days: 90,
        canonical: { service: "prowlarr" },
        consumers: [],
      }),
      (failure) => failure instanceof ApiError && failure.status === 409,
    );
    assert.deepEqual(state.credentials.get("prowlarr_api_key"), existing);
    assert.equal(
      state.calls.some((call) => call.method === "PATCH"),
      false,
    );
  } finally {
    restore();
  }
});

test("timestamps render in the configured server timezone", () => {
  setTimeZone("America/New_York");
  try {
    const text = timestamp(Date.UTC(2026, 9, 27, 21, 44, 0) / 1000);
    assert.match(text, /(5:44|17:44)/);
  } finally {
    setTimeZone("");
  }
});

test("an unknown zone falls back to UTC, not the browser", () => {
  setTimeZone("Not/A_Zone");
  try {
    const seconds = Date.UTC(2026, 9, 27, 21, 44, 0) / 1000;
    assert.equal(
      timestamp(seconds),
      new Date(seconds * 1000).toLocaleString(undefined, { timeZone: "UTC" }),
    );
  } finally {
    setTimeZone("");
  }
});

test("a background audit polls its job and retries a dropped poll", async () => {
  const calls = [];
  let polls = 0;
  const restore = useFetch(async (url, options = {}) => {
    const path = url.replace("/api/v1", "");
    calls.push(`${options.method ?? "GET"} ${path}`);
    if (path === "/audit?wait=false") {
      return jsonResponse(202, { job_id: "job-1", status: "running" });
    }
    if (path === "/audit/jobs/job-1") {
      polls += 1;
      if (polls === 1) {
        return jsonResponse(200, { job_id: "job-1", status: "running" });
      }
      if (polls === 2) throw new TypeError("network down");
      return jsonResponse(200, {
        job_id: "job-1",
        status: "succeeded",
        result: { last_run: { id: 7 } },
      });
    }
    throw new Error(`unexpected path ${path}`);
  });
  try {
    const result = await auditStack();
    assert.equal(result.last_run.id, 7);
    assert.deepEqual(calls, [
      "POST /audit?wait=false",
      "GET /audit/jobs/job-1",
      "GET /audit/jobs/job-1",
      "GET /audit/jobs/job-1",
    ]);
  } finally {
    restore();
  }
});

test("a missing audit job is reported, not retried forever", async () => {
  const restore = useFetch(async (url) => {
    const path = url.replace("/api/v1", "");
    if (path === "/audit?wait=false") {
      return jsonResponse(202, { job_id: "job-3", status: "running" });
    }
    if (path === "/audit/jobs/job-3") {
      return jsonResponse(404, { detail: "no such audit job" });
    }
    throw new Error(`unexpected path ${path}`);
  });
  try {
    await assert.rejects(auditStack(), /no longer available/);
  } finally {
    restore();
  }
});

test("a failed background audit surfaces the job sentence", async () => {
  const restore = useFetch(async (url) => {
    const path = url.replace("/api/v1", "");
    if (path === "/audit?wait=false") {
      return jsonResponse(202, { job_id: "job-2", status: "running" });
    }
    if (path === "/audit/jobs/job-2") {
      return jsonResponse(200, {
        job_id: "job-2",
        status: "failed",
        error: "OperationalError: database is locked",
      });
    }
    throw new Error(`unexpected path ${path}`);
  });
  try {
    await assert.rejects(
      auditStack(),
      /OperationalError: database is locked/,
    );
  } finally {
    restore();
  }
});

// A password change rotates the session in one transaction, but a read that
// left before the new cookie arrived can still be refused. The retry is narrow
// on purpose: reads only, once, and only when the session is still alive.
test("a 401 on a read retries once after the rotated session checks out", async () => {
  const original = globalThis.fetch;
  const calls = [];
  let attempts = 0;
  globalThis.fetch = async (url, options = {}) => {
    const path = url.replace("/api/v1", "");
    calls.push({ method: options.method ?? "GET", path });
    if (path === "/status") {
      attempts += 1;
      if (attempts === 1) return jsonResponse(401, { detail: "authentication required" });
      return jsonResponse(200, { jobs: [] });
    }
    if (path === "/auth/me") return jsonResponse(200, { csrf: "fresh-token" });
    throw new Error(`unexpected path ${path}`);
  };
  try {
    const result = await api("/status");
    assert.equal(attempts, 2);
    assert.deepEqual(result, { jobs: [] });
    assert.deepEqual(
      calls.map((call) => call.path),
      ["/status", "/auth/me", "/status"],
    );
  } finally {
    globalThis.fetch = original;
  }
});

test("a 401 on a write is never retried", async () => {
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    return jsonResponse(401, { detail: "authentication required" });
  };
  try {
    await assert.rejects(
      api("/credentials", { method: "POST", body: { name: "x" } }),
      (failure) => failure instanceof ApiError && failure.status === 401,
    );
    assert.equal(calls, 1);
  } finally {
    globalThis.fetch = original;
  }
});

test("a 401 from a dead session still signs out", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (url.endsWith("/auth/me")) return jsonResponse(401, { detail: "authentication required" });
    return jsonResponse(401, { detail: "authentication required" });
  };
  try {
    await assert.rejects(
      api("/status"),
      (failure) => failure instanceof ApiError && failure.status === 401,
    );
  } finally {
    globalThis.fetch = original;
  }
});
