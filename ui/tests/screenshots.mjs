// Regenerate the README screenshots from the real console.
//
//   node ui/tests/screenshots.mjs
//
// Boots a real server over a disposable directory, a fake Seerr settings API
// and a fake Sonarr whose indexer test accepts the stored key, seeds a small
// synthetic topology through the public API, runs one audit, then captures
// Apps, App detail, Activity and Settings into .github/assets/.
//
// Everything in the images is fixture data: no production hostname, no real
// credential. The topology is deliberately honest - one readable match, one
// acceptance-only `live` copy, one manual Homepage copy, one key with no
// holders - because that is what the console actually says.

import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { chromium } from "playwright";

const REPO = path.resolve(import.meta.dirname, "../..");
const PYTHON = process.env.CREDARR_PYTHON ?? path.join(REPO, ".venv", "bin", "python");
const PORT = Number(process.env.CREDARR_SHOT_PORT ?? 8099);
const BASE = `http://127.0.0.1:${PORT}`;
const OUT = path.join(REPO, ".github", "assets");
const PASSWORD = "screenshots-only-0123456789"; // gitleaks:allow - a fixture
const SONARR_KEY = "95bcc02c859006271d31f6ba3a15cbdb"; // gitleaks:allow
const PROWLARR_KEY = "b32b53cb7fd1c3e7a1c9f0b2d4e6a8c1"; // gitleaks:allow
const SEERR_KEY = "e4a91c7d2b6f8053a1c9e7d5b3f10284"; // gitleaks:allow
// The key the Activity image rotates in: Sonarr accepts both so the holder test
// still answers, and the drift is the one Seerr's copy shows.
const DRIFT_KEY = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"; // gitleaks:allow

const MANIFEST = `version: 1
credentials:
  sonarr_api_key:
    description: the key Sonarr itself serves
    class: A
    max_age_days: 90
    write: {mechanism: servarr_command}
    consumers:
      - target: seerr.settings_json[sonarr]
        count: 1
        mechanism: process_api
      - target: homepage.label
        count: 1
        mechanism: redeploy
  prowlarr_api_key:
    description: the key Sonarr's indexers were given
    class: A
    max_age_days: 90
    write: {mechanism: servarr_command}
    consumers:
      - target: sonarr.indexers
        count: 2
  seerr_api_key:
    description: Seerr's own key
    class: B
    never_rotate: true
`;

// Seerr's measured settings API: it reports the Sonarr key it holds. That is
// the one holder the audit can compare for real (`match`).
async function startSeerr() {
  const server = createServer((request, response) => {
    if (request.headers["x-api-key"] !== SEERR_KEY) {
      response.writeHead(401);
      response.end();
      return;
    }
    if (!/^\/api\/v1\/settings\/sonarr$/.test(request.url ?? "")) {
      response.writeHead(404);
      response.end();
      return;
    }
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify([{ id: 1, name: "Sonarr", apiKey: SONARR_KEY }]));
  });
  // The published ports of the real services, so the captured URLs read like a
  // deployment instead of a test fixture. Fall back to a free port if taken.
  for (const port of [5055, 0]) {
    try {
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, "127.0.0.1", resolve);
      });
      break;
    } catch {
      continue;
    }
  }
  return {
    base: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

// Sonarr enough for the indexer liveness route and the rotation-method probes:
// list two rows, serve each row, accept its own `indexer/test`, and answer the
// backup/status/config routes so backup & restore is the recommended method.
// Acceptance is not equality, so the audit reports `live`.
async function startSonarr() {
  const rows = {
    1: { id: 1, name: "NZBgeek", apiKey: PROWLARR_KEY, enableRss: true },
    2: { id: 2, name: "DrunkenSlug", apiKey: PROWLARR_KEY, enableRss: true },
  };
  const host = {
    bindAddress: "*",
    port: 8989,
    sslPort: 9898,
    enableSsl: false,
    authenticationMethod: "forms",
    authenticationRequired: "enabled",
    urlBase: "",
    sslCertPath: "",
    sslCertPassword: "",
    instanceName: "Sonarr",
    updateMechanism: "docker",
    logLevel: "info",
    branch: "main",
    username: "admin",
  };
  const server = createServer((request, response) => {
    const url = request.url ?? "";
    if (url === "/backup/manual/__credarr_probe__.zip") {
      // A name that cannot exist: 404 is the healthy answer when the download
      // route is not behind a login.
      response.writeHead(404, { "content-type": "application/problem+json" });
      response.end('{"title":"Not Found"}');
      return;
    }
    if (request.headers["x-api-key"] !== SONARR_KEY
        && request.headers["x-api-key"] !== DRIFT_KEY) {
      response.writeHead(401, { "content-type": "application/json" });
      response.end('{"message":"unauthorized"}');
      return;
    }
    const one = /^\/api\/v3\/indexer\/(\d+)$/.exec(url);
    let body;
    if (url === "/api/v3/system/status") {
      body = { version: "4.0.20.3014", databaseType: "sqlite", isProduction: true };
    } else if (url === "/api/v3/config/host") body = host;
    else if (url === "/api/v3/system/backup") body = [];
    else if (url === "/api/v3/indexer") body = Object.values(rows);
    else if (one && rows[Number(one[1])]) body = rows[Number(one[1])];
    else if (request.method === "POST" && url === "/api/v3/indexer/test") body = {};
    else {
      response.writeHead(404, { "content-type": "application/json" });
      response.end('{"message":"not found"}');
      return;
    }
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify(body));
  });
  for (const port of [8989, 0]) {
    try {
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, "127.0.0.1", resolve);
      });
      break;
    } catch {
      continue;
    }
  }
  return {
    base: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

async function writeConfig(work, seerrBase, sonarrBase) {
  await writeFile(
    path.join(work, "credarr.yaml"),
    "version: 1\n" +
      "default_host: local\n" +
      "hosts:\n" +
      "  local:\n" +
      "    urls:\n" +
      `      seerr: ${seerrBase}\n` +
      `      sonarr: ${sonarrBase}\n` +
      "      prowlarr: http://127.0.0.1:9\n" +
      `manifest: ${path.join(work, "credentials.yaml")}\n`,
  );
  await writeFile(path.join(work, "credentials.yaml"), MANIFEST);
}

async function boot(config, work) {
  const server = spawn(
    PYTHON,
    ["-m", "credarr_server.app", "-c", config, "--config-dir", work,
     "--host", "127.0.0.1", "--port", String(PORT)],
    { cwd: REPO, stdio: ["ignore", "pipe", "pipe"] },
  );
  let log = "";
  server.stdout.on("data", (chunk) => (log += chunk));
  server.stderr.on("data", (chunk) => (log += chunk));
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (server.exitCode !== null) throw new Error(`the server exited:\n${log}`);
    const answer = await fetch(`${BASE}/api/v1/health`).catch(() => null);
    if (answer?.ok) return { server, kill: () => server.kill("SIGTERM") };
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`the server never answered on ${BASE}:\n${log}`);
}

// The console keeps its CSRF token in memory, so a direct write from the
// harness has to fetch the token the session cookie belongs to.
async function csrf(page) {
  const me = await page.request.get(`${BASE}/api/v1/auth/me`);
  return (await me.json()).csrf;
}

async function seed(context) {  const api = context.request;
  const setup = await api.post(`${BASE}/api/v1/auth/setup`, { data: { password: PASSWORD } });
  if (!setup.ok()) throw new Error(`setup: ${setup.status()} ${await setup.text()}`);
  const me = await api.get(`${BASE}/api/v1/auth/me`);
  const csrf = (await me.json()).csrf;
  const write = (url, data) =>
    api.post(url, { data, headers: { "X-CSRF-Token": csrf } });

  const imported = await write(`${BASE}/api/v1/topology/import`, {
    mode: "replace",
    prune: true,
    yaml: MANIFEST,
    confirm: "replace",
  });
  if (!imported.ok()) throw new Error(`import: ${imported.status()} ${await imported.text()}`);

  for (const [name, value] of [
    ["sonarr_api_key", SONARR_KEY],
    ["prowlarr_api_key", PROWLARR_KEY],
    ["seerr_api_key", SEERR_KEY],
  ]) {
    const stored = await api.put(`${BASE}/api/v1/credentials/${name}/value`, {
      data: { value },
      headers: { "X-CSRF-Token": csrf },
    });
    if (!stored.ok()) throw new Error(`value ${name}: ${stored.status()} ${await stored.text()}`);
  }

  const audit = await write(`${BASE}/api/v1/audit`, {});
  if (!audit.ok()) throw new Error(`audit: ${audit.status()} ${await audit.text()}`);
  await audit.json();
}

async function shot(page, name, { height, fullPage = false } = {}) {  const file = path.join(OUT, `${name}.png`);
  const clip = height
    ? { x: 0, y: 0, width: 1440, height: Math.ceil(height) }
    : undefined;
  await page.screenshot({ path: file, fullPage, clip });
  console.log(`wrote ${path.relative(REPO, file)}`);
}

async function main() {
  await mkdir(OUT, { recursive: true });
  const work = await mkdtemp(path.join(tmpdir(), "credarr-shots-"));
  const seerr = await startSeerr();
  const sonarr = await startSonarr();
  await writeConfig(work, seerr.base, sonarr.base);
  const { kill } = await boot(path.join(work, "credarr.yaml"), work);

  const browser = await chromium.launch();
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 2,
    // A headless UA would appear in Settings -> Active sessions; the image
    // should read as an ordinary browser, not as a test harness.
    userAgent:
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) " +
      "Chrome/141.0.0.0 Safari/537.36",
  });
  try {
    await seed(context);
    const page = await context.newPage();
    page.on("pageerror", (error) => console.error("PAGE ERROR:", String(error)));

    // Apps: the landing view, after a real audit.
    await page.goto(BASE, { waitUntil: "networkidle" });
    await page.getByRole("button", { name: "Apps", exact: true }).waitFor();
    await page.getByText("Sonarr API Key", { exact: false }).first().waitFor();
    await page.waitForTimeout(600);
    const grid = await page.locator(".apps-grid").boundingBox();
    await shot(page, "apps", { height: grid ? grid.y + grid.height + 40 : 640 });

    // App detail: connection, copies, check history and the rotation panel.
    await page.getByRole("link", { name: /Open Sonarr API Key/ }).click();
    await page.getByText("Used in", { exact: false }).first().waitFor();
    await page.waitForTimeout(800);
    // Tall enough for the copies table and the delete block; a clip past the
    // viewport is ignored, so this page is captured full-height instead.
    await shot(page, "app-detail", { fullPage: true });
    await page.getByRole("button", { name: "Apps", exact: true }).click();

    // A real drift, so Activity shows the ledger instead of the empty baseline:
    // the stored Sonarr key is replaced, and Seerr still holds the old one.
    const drifted = await page.request.put(`${BASE}/api/v1/credentials/sonarr_api_key/value`, {
      data: { value: DRIFT_KEY },
      headers: { "X-CSRF-Token": await csrf(page) },
    });
    if (!drifted.ok()) throw new Error(`drift seed: ${drifted.status()} ${await drifted.text()}`);
    const again = await page.request.post(`${BASE}/api/v1/audit`, {
      data: {},
      headers: { "X-CSRF-Token": await csrf(page) },
    });
    if (!again.ok()) throw new Error(`second audit: ${again.status()} ${await again.text()}`);
    await again.json();

    // Activity: the audit result plus the event ledger.
    await page.getByRole("button", { name: "Activity", exact: true }).click();
    await page.getByText("drift", { exact: false }).first().waitFor();
    await page.waitForTimeout(600);
    await shot(page, "activity", { height: 420 });

    // Settings: security and the audit schedule; the import/export blocks are
    // reference material, not the point of the image.
    await page.getByRole("button", { name: "Settings", exact: true }).click();
    await page.getByText("Audit schedule", { exact: false }).first().waitFor();
    await page.waitForTimeout(600);
    await shot(page, "settings", { height: 640 });
  } finally {
    await browser.close();
    kill();
    await seerr.close();
    await sonarr.close();
    await rm(work, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
