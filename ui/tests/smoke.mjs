// The committed live UI smoke: the built console, a real server, a real
// browser, a disposable directory. No NAS, no vault, no production credential -
// the stack it audits is built here from a fake Seerr settings API and the
// manifest the console imports. Every holder is read and written over a service
// API; there is no config file or database fixture.
//
//   make ui-smoke            (builds ui/dist into the package first)
//
// Needs the Playwright browser once: `cd ui && npx playwright install chromium`.
// Everything it asserts is a claim the UI makes: the empty state is not a clean
// bill of health, a missing key says "no key yet", a run with nothing to
// compare is not called "not audited yet", "monitor only" names the missing
// capability, a pasted value never reaches the DOM, a rotation refuses in the
// engine's own words, and an unfinished rotation is on screen before anything
// else can run. The Apps hub holds every claim to the same standard: a key is
// set, tested and opened per app, copies read as service names, and an
// observation that fails is a sentence. Notifications are held to it too: an
// event is a change and not a level, the test button reaches a real socket, a
// stored secret never comes back to the browser, and an event older than the
// sink it would go to says so instead of "queued".

import { execFileSync, spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { chromium } from "playwright";

const REPO = path.resolve(import.meta.dirname, "../..");
const PYTHON = process.env.CREDARR_PYTHON ?? path.join(REPO, ".venv", "bin", "python");
const PORT = Number(process.env.CREDARR_SMOKE_PORT ?? 8098);
const BASE = `http://127.0.0.1:${PORT}`;
const ARTIFACTS = path.join(import.meta.dirname, "..", "test-results");
const PASSWORD = "smoke-password-0123456789"; // gitleaks:allow - a fixture, not a secret
const NEW_PASSWORD = "smoke-password-9876543210"; // gitleaks:allow
const SONARR_KEY = "95bcc02c859006271d31f6ba3a15cbdb"; // gitleaks:allow
const PROWLARR_KEY = "b32b53cb7fd1c3e7a1c9f0b2d4e6a8c1"; // gitleaks:allow
const SEERR_KEY = "e4a91c7d2b6f8053a1c9e7d5b3f10284"; // gitleaks:allow
const WRONG_KEY = "deadbeefdeadbeefdeadbeefdeadbeef"; // gitleaks:allow
const STALE_KEY = "cafebabecafebabecafebabecafebabe"; // gitleaks:allow - a fixture, not a secret
const MANUAL_KEY = "00112233445566778899aabbccddeeff"; // gitleaks:allow - a fixture, not a secret
const UI_PASSWORD = "smoke-ui-password-44332211"; // gitleaks:allow - a fixture, not a secret

let passed = 0;
function check(label, condition, detail = "") {
  if (!condition) throw new Error(`FAILED: ${label} ${detail}`);
  passed += 1;
  console.log(`PASS: ${label}`);
}

const MANIFEST = `version: 1
credentials:
  sonarr_api_key:
    description: the key Sonarr itself serves
    class: A
    max_age_days: 90
    vault:
      backend: ansible-vault
      file: vault.yml
      path: [keys, sonarr_api_key]
    write: {mechanism: servarr_command}
    consumers:
      - target: seerr.settings_json[sonarr]
        count: 1
        mechanism: process_api
  prowlarr_api_key:
    description: 'the key Sonarr''s indexers were given <img src=x onerror="window.__pwned=1">'
    class: A
    max_age_days: 90
    write: {mechanism: servarr_command}
    consumers:
      - target: sonarr.indexers
        count: 2
  seerr_api_key:
    description: Seerr's own key, needed to read the settings row above
    class: B
    never_rotate: true
`;

// The fake Seerr API is the holder the audit reads. It answers only the
// measured settings route, requires the stored Seerr key, and reports the
// Sonarr key it holds; no config file is involved.
async function startSeerr() {
  const reported = { sonarr: SONARR_KEY };
  const server = createServer((request, response) => {
    if (request.headers["x-api-key"] !== SEERR_KEY) {
      response.writeHead(401);
      response.end();
      return;
    }
    const match = /^\/api\/v1\/settings\/(sonarr)$/.exec(request.url ?? "");
    if (!match) {
      response.writeHead(404);
      response.end();
      return;
    }
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify([{ id: 1, name: "Sonarr", apiKey: reported.sonarr }]));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    base: `http://127.0.0.1:${server.address().port}`,
    reported,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

// Sonarr's API and web login, enough for the inference probes: auth on, Forms
// login, SQLite, a healthy backup probe only after the login. Holder reads
// fail on purpose, so the fixture's Prowlarr indexer row stays a preflight
// sentence; this smoke never runs a holder write.
async function startSonarr() {
  const session = "sonarr-smoke-session";
  // The fixture drifts the stored value to WRONG_KEY; the service keeps
  // accepting it so the method probes can run against the key it actually
  // holds. SONARR_KEY is the value the Seerr copy still has.
  const accepted = new Set([SONARR_KEY, WRONG_KEY]);
  const server = createServer((request, response) => {
    const path = request.url ?? "";
    if (request.method === "POST" && path === "/login") {
      let body = "";
      request.on("data", (chunk) => (body += chunk));
      request.on("end", () => {
        const form = new URLSearchParams(body);
        const ok =
          form.get("username") === "admin" &&
          form.get("password") === UI_PASSWORD;
        response.writeHead(302, {
          Location: ok ? "/" : "/login?loginFailed=true",
          ...(ok ? { "Set-Cookie": `sonarr-auth=${session}; Path=/` } : {}),
        });
        response.end();
      });
      return;
    }
    if (path === "/backup/manual/__credarr_probe__.zip") {
      if ((request.headers.cookie ?? "").includes(`sonarr-auth=${session}`)) {
        response.writeHead(404, { "content-type": "application/problem+json" });
        response.end('{"title":"Not Found"}');
      } else {
        response.writeHead(302, { Location: "/login" });
        response.end();
      }
      return;
    }
    if (!accepted.has(request.headers["x-api-key"])) {
      response.writeHead(401, { "content-type": "application/json" });
      response.end('{"message":"unauthorized"}');
      return;
    }
    let body = "";
    let status = 200;
    if (path === "/api/v3/system/status") {
      body = JSON.stringify({
        version: "4.0.20.3014",
        databaseType: "sqlite",
        isProduction: true,
      });
    } else if (path === "/api/v3/config/host") {
      body = JSON.stringify({
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
      });
    } else if (path === "/api/v3/system/backup") {
      body = "[]";
    } else {
      status = 500;
      body = JSON.stringify({ message: "the smoke holds no rows" });
    }
    response.writeHead(status, { "content-type": "application/json" });
    response.end(body);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    base: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

async function writeConfig(work, seerrBase, sonarrBase) {
  const config = path.join(work, "credarr.yaml");
  // `prowlarr` is declared and points at nothing that exists. That is the
  // API-only preflight case: it has an API writer but no URL, and nothing asks
  // for a config bind. The container names are made up on purpose - this smoke
  // must never touch a real stack.
  await writeFile(
    config,
    "version: 1\n" +
      "default_host: local\n" +
      "hosts:\n" +
      "  local:\n" +
      "    urls:\n" +
      `      seerr: ${seerrBase}\n` +
      `      sonarr: ${sonarrBase}\n` +
      "      grafana: http://grafana:3000\n" +
      "    containers:\n" +
      "      sonarr: credarr-smoke-no-such-sonarr\n" +
      "      prowlarr: credarr-smoke-no-such-prowlarr\n" +
      `manifest: ${path.join(work, "credentials.yaml")}\n`,
  );
  await writeFile(path.join(work, "credentials.yaml"), MANIFEST);
  return { config };
}

async function boot(config, work) {
  const server = spawn(
    PYTHON,
    ["-m", "credarr_server.app", "-c", config, "--config-dir", work, "--host", "127.0.0.1", "--port", String(PORT)],
    { cwd: REPO, stdio: ["ignore", "pipe", "pipe"] },
  );
  let log = "";
  server.stdout.on("data", (chunk) => (log += chunk));
  server.stderr.on("data", (chunk) => (log += chunk));
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (server.exitCode !== null) throw new Error(`the server exited ${server.exitCode}:\n${log}`);
    const answer = await fetch(`${BASE}/api/v1/health`).catch(() => null);
    if (answer?.ok) return { server, kill: () => server.kill("SIGTERM"), log: () => log };
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`the server never answered on ${BASE}:\n${log}`);
}

// Write the journal row a killed run leaves behind, through the engine's own
// API rather than by hand: a step that started and never finished. The console
// must show it before it shows anything runnable.
function seedUnfinishedRotation(work) {
  const journal = path.join(work, "state", "rotation.db");
  execFileSync(
    PYTHON,
    ["-c", [
      "from credarr.journal import Journal",
      `journal = Journal(r"${journal}")`,
      'attempt = journal.begin("prowlarr_api_key")',
      'journal.step_started(attempt, 0, "mint", "prowlarr", "back up config over the API and restore a chosen key")',
    ].join("\n")],
    { cwd: REPO },
  );
}

async function main() {
  const work = await mkdtemp(path.join(tmpdir(), "credarr-ui-smoke-"));
  await mkdir(ARTIFACTS, { recursive: true });
  const seerr = await startSeerr();
  const sonarr = await startSonarr();
  const { config } = await writeConfig(work, seerr.base, sonarr.base);
  const booted = await boot(config, work);
  const { server, kill } = booted;
  globalThis.__smokeServerLog = booted.log;

  const browser = await chromium.launch();
  const page = await browser.newPage();
  // A CI runner can be several times slower than a laptop, and a plan runs
  // preflight probes before it renders. The assertions are unchanged; only the
  // patience is. Override with CREDARR_SMOKE_TIMEOUT on a slower machine.
  page.setDefaultTimeout(Number(process.env.CREDARR_SMOKE_TIMEOUT ?? 90_000));
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(String(error)));
  // A failed request or a 5xx is the common cause of "the state never
  // appeared": the UI is working, the answer never arrived. Printed where it
  // happens so a CI log names the cause instead of the symptom.
  page.on("requestfailed", (request) =>
    console.log(
      `DEBUG request failed: ${request.method()} ${request.url()} ${request.failure()?.errorText}`,
    ),
  );
  page.on("response", (response) => {
    const status = response.status();
    if (status >= 500) {
      console.log(
        `DEBUG http ${status}: ${response.request().method()} ${response.url()}`,
      );
    }
  });

  // The sidebar's parents toggle, so a check that wants a menu's children asks
  // whether it is open instead of clicking blind.
  const openMenu = async (label) => {
    const button = page.locator("aside nav > button").filter({ hasText: label });
    if ((await button.getAttribute("aria-expanded")) !== "true") await button.click();
  };

  // The console keeps its CSRF token in memory, so a direct write from the
  // harness has to fetch the token the session cookie belongs to. Fetched per
  // write: login and password change rotate it.
  const csrf = async () => {
    const me = await page.request.get(`${BASE}/api/v1/auth/me`);
    return (await me.json()).csrf;
  };

  const runAudit = async () => {
    const finished = page.waitForResponse((response) => {
      try {
        return (
          response.request().method() === "POST" &&
          new URL(response.url()).pathname.endsWith("/api/v1/audit")
        );
      } catch {
        return false;
      }
    });
    await page.getByRole("button", { name: "Run audit", exact: true }).click();
    await finished;
    // The POST only starts the job. Let Svelte apply the busy state before we
    // read the button again; otherwise a fast fixture can look finished while
    // the first poll is still in flight.
    await page.waitForTimeout(100);
    // The button stays "Auditing…" while the console polls; wait for the
    // polled result to put the button back.
    await page.getByRole("button", { name: "Run audit", exact: true }).waitFor();
  };

  try {
    // --- first run: setup, then an empty console ------------------------------
    await page.goto(BASE);
    await page.getByRole("button", { name: "Create the admin" }).waitFor();
    const favicon = await page.request.get(`${BASE}/favicon.svg`);
    check(
      "the tab has a shield-key favicon",
      (await page.locator('link[rel="icon"]').getAttribute("href")) === "/favicon.svg" &&
        favicon.ok() &&
        (await favicon.text()).includes('id="mdi-shield-key"'),
    );
    check("a fresh deployment asks for the admin password", true);

    await page.getByPlaceholder("new password").fill("short");
    await page.getByPlaceholder("repeat password").fill("short");
    await page.getByRole("button", { name: "Create the admin" }).click();
    await page.getByText(/at least 12 characters/).waitFor();
    check("a too-short password is refused in words, not a status code", true);

    await page.getByPlaceholder("new password").fill(PASSWORD);
    await page.getByPlaceholder("repeat password").fill(PASSWORD);
    await page.getByRole("button", { name: "Create the admin" }).click();
    await page.getByRole("heading", { name: "Set up your stack" }).waitFor();
    check("setup signs the admin in and opens the first-run wizard", true);
    check(
      "the wizard starts at Connect, with no automation-key step",
      await page.getByRole("heading", { name: "Connect", exact: true }).isVisible(),
    );
    check(
      "and the setup progress has no automation-key step",
      !(await page.getByText("Automation key", { exact: true }).isVisible()),
    );

    // --- skip is a real door out, and the empty Apps hub is still honest -----
    await page.getByRole("button", { name: "Skip for now" }).click();
    await page.getByRole("button", { name: "Apps" }).waitFor();
    check("skipping the wizard leaves the normal console reachable", true);
    check("an empty store is called what it is", await page.getByText("No apps yet").isVisible());
    check(
      "and its exit 0 is not painted as a health verdict",
      await page.getByText("Nothing has been measured").isVisible(),
    );
    check(
      "and it is not invited into an all-clean audit",
      await page.getByRole("button", { name: "Run audit", exact: true }).isDisabled(),
    );
    check(
      "the empty state offers the guided path again",
      await page.getByRole("button", { name: "Resume setup" }).isVisible(),
    );

    // --- resume: the saved draft opens at Connect ---------------------------
    await page.getByRole("button", { name: "Resume setup" }).click();
    await page.getByRole("heading", { name: "Connect", exact: true }).waitFor();
    check("Resume setup reopens the saved draft at Connect", true);

    // --- services: a read-only Docker scan does not create topology ----------
    await page
      .locator(".setup-service")
      .filter({ has: page.getByText("Sonarr", { exact: true }) })
      .getByRole("checkbox")
      .check();
    await page
      .locator(".setup-service")
      .filter({ has: page.getByText("Prowlarr", { exact: true }) })
      .getByRole("checkbox")
      .check();
    check(
      "the service step collects a deployment URL, not a config path",
      (await page.locator(".setup-service-facts").getByLabel(/URL/).count()) >= 2 &&
        (await page.locator(".setup-service-facts").getByLabel(/Config path/).count()) === 0,
    );
    // A selected service without a URL cannot leave the step: the click is
    // refused with the field's own error instead of advancing.
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.locator("#service-url-sonarr-error").waitFor();
    check(
      "a selected service without a URL blocks the step with its error",
      await page.getByRole("heading", { name: "Connect", exact: true }).isVisible(),
    );
    // The fixture stack is local-only, so the URL points at a closed port: the
    // Services view later shows the engine's own "could not be reached" sentence.
    await page.getByPlaceholder("http://sonarr:8989").fill(sonarr.base);
    await page.getByPlaceholder("http://prowlarr:8989").fill("http://127.0.0.1:9");
    await page.getByText("Docker discovery (optional, read-only)").click();
    await page.getByRole("button", { name: "Scan Docker" }).click();
    await page.getByText(/Docker discovery is off/).waitFor();
    check("Docker discovery is off by default and says so", true);
    check(
      "a Docker scan does not select a service",
      (await page.locator(".setup-services input[type=checkbox]:checked").count()) === 2,
    );
    // A selected service now needs its key, not only its URL.
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.getByText("Enter the API key for Sonarr.").first().waitFor();
    check("a selected service without a key blocks the step", true);
    // Typing a key creates its app key with the usual copies prefilled; the
    // fixture key is synthetic and disposable, so typing it here is the point.
    await page.locator(".setup-service-facts input[type=password]").first().fill(SONARR_KEY);
    await page.locator(".setup-service-facts input[type=password]").nth(1).fill(PROWLARR_KEY);
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.getByRole("heading", { name: "Copies", exact: true }).waitFor();

    // --- copies: the key arrived with its usual copies, no class picker ------
    const setupSonarrCard = page.locator(".setup-credential").first();
    await setupSonarrCard.locator(".setup-holder strong").first().waitFor();
    check(
      "a Sonarr key is prefilled with the selected stack's Prowlarr copy",
      (await setupSonarrCard.locator(".setup-holder").count()) === 1 &&
        (await setupSonarrCard.locator(".setup-holder strong").first().innerText()).includes("Prowlarr"),
    );
    check(
      "and no class picker or name field is asked for",
      (await page.getByLabel("Class", { exact: true }).count()) === 0 &&
        (await page.getByLabel("Name", { exact: true }).count()) === 0,
    );
    await page.getByRole("button", { name: "Review topology" }).click();
    await page.getByRole("heading", { name: "Review", exact: true }).waitFor();

    // --- review: the generated manifest, the replace warning, the acknowledgement
    await page.getByText("Manifest preview").click();
    const generated = await page.locator("pre.setup-yaml").innerText();
    check(
      "the review shows the generated manifest",
      generated.includes("version: 1") &&
        generated.includes("sonarr_api_key") &&
        generated.includes("class: A-unv") &&
        generated.includes("service: sonarr") &&
        generated.includes("prowlarr.applications[Sonarr]"),
    );
    check(
      "the review offers the direct API write",
      await page.getByRole("button", { name: "Save", exact: true }).isEnabled(),
    );
    let createAttempt = 0;
    await page.route("**/api/v1/credentials", async (route) => {
      if (route.request().method() !== "POST") return route.continue();
      createAttempt += 1;
      if (createAttempt === 1) {
        await new Promise((resolve) => setTimeout(resolve, 300));
        await route.fulfill({
          status: 400,
          contentType: "application/json",
          body: JSON.stringify({ detail: "the smoke server refused this credential" }),
        });
      } else {
        await route.continue();
      }
    });
    const createButton = page.getByRole("button", {
      name: "Save",
      exact: true,
    });
    await createButton.click();
    const creatingButton = page.getByRole("button", {
      name: "Saving…",
      exact: true,
    });
    await creatingButton.waitFor();
    check("the create control is disabled while the request is in flight", await creatingButton.isDisabled());
    await page.getByText("Setup did not finish.").waitFor();
    check(
      "a refused wizard write is shown in the server's words",
      await page.getByText("the smoke server refused this credential").isVisible(),
    );
    check(
      "a refused write keeps the browser draft",
      (await page.evaluate(() => localStorage.getItem("credarr.setup.draft.v1"))) !== null,
    );
    await createButton.click();
    await page.getByText("Topology created.").waitFor();
    await page.unroute("**/api/v1/credentials");
    check(
      "the completed write clears the browser draft",
      (await page.evaluate(() => localStorage.getItem("credarr.setup.draft.v1"))) === null,
    );

    // --- first audit: it runs by itself, and the why is on screen ------------
    await page.getByText(/Audit complete/).waitFor();
    check("the first audit runs by itself after creation", true);
    check(
      "the audit table has no stored column",
      (await page.locator("table thead").getByText("Stored", { exact: true }).count()) === 0,
    );
    check(
      "and the unreachable copy reads as unverifiable, not drift",
      await page.locator("table").getByText("unverifiable", { exact: true }).first().isVisible(),
    );
    await page.getByRole("button", { name: "Go to Apps", exact: true }).click();
    await page.getByRole("button", { name: "Apps" }).waitFor();
    check("the wizard hands the console to Apps", true);
    await page.locator(".app-card").getByText("Sonarr API Key").waitFor();
    check(
      "the new app names where its key is used",
      await page.getByText("Used in: Prowlarr").isVisible(),
    );

    // --- restore the committed smoke fixture through Settings -----------------
    await page.screenshot({ path: path.join(ARTIFACTS, "import.png"), fullPage: true });
    await page.getByRole("button", { name: "Settings", exact: true }).click();
    await openMenu("Settings");
    await page.locator("aside .nav-sub button").filter({ hasText: /^Import \/ Export$/ }).click();
    await page.locator("#settings-topology").waitFor();
    await page.getByLabel("Manifest YAML").fill(MANIFEST);
    await page.getByLabel("I understand this replaces the declared topology").check();
    await page.getByRole("button", { name: "Import", exact: true }).click();
    await page.getByText(/replace import: 3 credentials/).waitFor();
    await page.getByRole("button", { name: "Apps", exact: true }).click();
    await page.locator(".app-card").getByText("Sonarr API Key").waitFor();
    check("the console's own session imports the topology from the form", true);
    check(
      "the declared apps are listed as cards",
      (await page.locator(".app-card").count()) === 3,
    );
    // The wizard-typed key survives the import (values for kept names are
    // kept by design). Forget it so the fixture starts with no stored values.
    const forgotten = await page.request.delete(
      `${BASE}/api/v1/credentials/sonarr_api_key/value`,
      { headers: { "X-CSRF-Token": await csrf() } },
    );
    check("the wizard key can be forgotten before the fixture takes over", forgotten.ok());
    const forgottenProwlarr = await page.request.delete(
      `${BASE}/api/v1/credentials/prowlarr_api_key/value`,
      { headers: { "X-CSRF-Token": await csrf() } },
    );
    check("the second wizard key can be forgotten too", forgottenProwlarr.ok());
    await page.reload();
    await page.getByRole("button", { name: "Apps", exact: true }).click();
    await page.locator(".app-card").getByText("Sonarr API Key").waitFor();
    check(
      "no server string becomes markup anywhere",
      (await page.locator("img").count()) === 0 &&
        (await page.evaluate(() => window.__pwned)) === undefined,
    );
    check(
      "an app with no key says so, three times",
      (await page.getByText("no key yet", { exact: true }).count()) === 3,
    );
    const statusBeforeRun =
      (await page.getByText("not audited yet", { exact: true }).count()) +
      (await page.getByText("unverifiable", { exact: true }).count());
    check(
      "and the apps with copies carry a current status before a run",
      statusBeforeRun === 2,
    );
    check(
      "and the app that nothing holds says so",
      (await page.getByText("no holders", { exact: true }).count()) === 1,
    );
    check(
      "the hub has no duplicate rotate actions",
      (await page.getByRole("button", { name: /^Rotate( |$)/ }).count()) === 0,
    );

    // --- the search narrows what is declared ---------------------------------
    await page.getByLabel("Filter apps").fill("sonarr");
    check(
      "the filter narrows the app cards",
      (await page.locator(".app-card").count()) === 1,
    );
    await page.getByLabel("Filter apps").fill("");
    check(
      "clearing the filter restores every card",
      (await page.locator(".app-card").count()) === 3,
    );

    // --- a re-import warns what replace means --------------------------------
    await page.getByRole("button", { name: "Settings", exact: true }).click();
    await openMenu("Settings");
    await page.locator("aside .nav-sub button").filter({ hasText: /^Import \/ Export$/ }).click();
    await page.getByLabel("Manifest YAML").fill("version: 2\ncredentials: {}\n");
    await page.getByLabel("I understand this replaces the declared topology").check();
    await page.getByRole("button", { name: "Import", exact: true }).click();
    await page.getByText(/manifest version 2 is not supported/).waitFor();
    check("a refused manifest is refused in the server's words", true);

    // --- run an audit: the result and its date are visible -------------------
    await page.getByRole("button", { name: "Apps", exact: true }).click();
    await runAudit();
    check("the run reports its result and time", true);
    check(
      "the health pane carries the last run",
      await page.getByText(/Last run/).isVisible(),
    );
    // The notice and the per-card refresh are separate responses; wait for
    // both expected badges instead of racing the card re-render.
    const unverifiable = page.locator(".app-card").getByText("unverifiable", { exact: true });
    await unverifiable.nth(1).waitFor();
    await page.locator(".app-card").getByText("no holders", { exact: true }).waitFor();
    check(
      "a run with nothing to compare says so instead of 'not audited yet'",
      (await unverifiable.count()) === 2 &&
        (await page.locator(".app-card").getByText("no holders", { exact: true }).count()) === 1,
    );

    // --- Activity: a baseline is not a change --------------------------------
    await page.getByRole("button", { name: "Activity", exact: true }).click();
    await page.getByText("No changes yet").waitFor();
    check("the first status an audit records is a baseline, so Activity starts empty", true);
    check(
      "and the empty state says there is nowhere to send anything yet",
      await page.getByText(/No notification service is configured/).isVisible(),
    );
    check(
      "and the last audit is dated",
      await page.getByText(/Last audit finished/).isVisible(),
    );
    // --- the ledger shows the audit it ran -----------------------------------
    // Audits run from Apps; Activity always loads the latest ledger when it
    // opens, so there is no stale view to refresh into.
    await page.getByRole("button", { name: "Back to Apps" }).click();
    await runAudit();
    await page.getByRole("button", { name: "Activity", exact: true }).click();
    await page.getByText(/Last audit finished/).waitFor();
    check("returning to Activity shows the audit it ran", true);
    await page.getByRole("button", { name: "Back to Apps" }).click();
    await page.getByRole("button", { name: "Run audit", exact: true }).waitFor();
    check("its way back is Apps", true);

    // --- the app detail: the write-only paste path ---------------------------
    await page.getByRole("button", { name: "Apps", exact: true }).click();
    await page
      .locator(".app-card h3", { hasText: "Sonarr API Key" }).click();
    await page.getByRole("heading", { name: "Sonarr API Key" }).waitFor();
    check("the app detail names the selected app", true);
    check(
      "the key field is a password field, not a text field",
      (await page.getByLabel("API key").getAttribute("type")) === "password",
    );
    await page.getByLabel("API key").pressSequentially(SONARR_KEY);
    await page.locator("#connection").getByRole("button", { name: "Save", exact: true }).click();
    await page.locator(".toasts").getByText("Saved.").first().waitFor();
    check("the stored key is acknowledged with one dull toast", true);
    check(
      "the field is emptied once the key is stored",
      (await page.getByLabel("API key").inputValue()) === "",
    );
    check("the pasted key is not echoed back", !(await page.content()).includes(SONARR_KEY));
    await page.waitForFunction(() =>
      document.querySelector('[aria-label="API key"]')?.placeholder.includes("•••"),
    );
    check("the key state flips to stored", true);
    check(
      "a stored key reads back as redacted bullets, like the service's own field",
      (await page.getByLabel("API key").getAttribute("placeholder")) === "••••••••••••••••",
    );
    await page.getByLabel("API key").pressSequentially("unsaved-key");

    await openMenu("Apps");
    await page.locator("aside .nav-sub button").filter({ hasText: /^Prowlarr API Key$/ }).click();
    await page.getByRole("heading", { name: "Prowlarr API Key" }).waitFor();

    await openMenu("Apps");
    await page.locator("aside .nav-sub button").filter({ hasText: /^Sonarr API Key$/ }).click();
    await page.getByRole("heading", { name: "Sonarr API Key" }).waitFor();

    check(
      "an unsaved key does not follow the operator to another app",
      (await page.getByLabel("API key").inputValue()) === "",
    );

    // --- auto-rotation: off by default, pause and blocked copy ----------------
    await page.getByRole("heading", { name: "Auto-rotation" }).waitFor();
    check(
      "auto-rotation is off by default",
      await page.locator("section.auto-card").getByRole("button", { name: "Enable auto-rotation", exact: true }).isVisible(),
    );
    const autoDays = page.getByLabel("Days between automatic rotations");
    await autoDays.pressSequentially("30");
    await page.locator("section.auto-card").getByRole("button", { name: "Enable auto-rotation", exact: true }).click();
    await page.locator(".toasts").getByText("Saved.").first().waitFor();
    check("auto-rotation enables in one action", true);
    check(
      "one enabled pill, no metric grid",
      (await page.locator("section.auto-card .pill").count()) === 1 &&
        (await page.locator("section.auto-card .grid.stats").count()) === 0,
    );
    check(
      "the card names the next due time",
      await page.getByText("Next due").isVisible(),
    );
    await autoDays.fill("60");
    await page.locator("section.auto-card").getByRole("button", { name: "Save", exact: true }).click();
    await page.locator(".toasts").getByText("Saved.").first().waitFor();
    check(
      "the interval can be changed while enabled",
      (await autoDays.inputValue()) === "60",
    );

    // The server's audit loop can hold SQLite's writer; wait for it rather
    // than failing the harness with SQLITE_BUSY.
    const db = new DatabaseSync(path.join(work, "app.db"));
    db.exec("PRAGMA busy_timeout = 5000");
    const changed = db.prepare(
      "UPDATE auto_rotation SET paused = 1, last_outcome = 'interrupted', " +
        "last_detail = 'run did not finish' WHERE credential = ?",
    ).run("sonarr_api_key");
    const stored = db.prepare(
      "SELECT credential, enabled, paused FROM auto_rotation WHERE credential = ?",
    ).get("sonarr_api_key");
    db.close();
    console.log(
      `DEBUG pause write: changed=${changed.changes} row=${JSON.stringify(stored)}`,
    );
    await page.reload();
    await page.getByRole("button", { name: "Apps", exact: true }).click();
    await page
      .locator(".app-card h3", { hasText: "Sonarr API Key" }).click();
    try {
      await page.getByText("Auto-rotation is paused.").waitFor({ timeout: 15000 });
    } catch (failure) {
      const card = await page.locator("section.auto-card").innerText().catch(() => "(no card)");
      const api = await page.request
        .get(`${BASE}/api/v1/credentials/sonarr_api_key`)
        .then((r) => r.json())
        .catch((e) => `(api failed: ${e})`);
      console.log(`DEBUG auto card: ${card}`);
      console.log(`DEBUG api auto_rotation: ${JSON.stringify(api?.auto_rotation ?? api)}`);
      throw failure;
    }
    check(
      "a paused auto-rotation is shown as paused, not enabled",
      await page.getByText("run did not finish").isVisible(),
    );
    await page.locator("section.auto-card").getByRole("button", { name: "Enable auto-rotation", exact: true }).click();
    await page.locator(".toasts").getByText("Saved.").first().waitFor();
    check("re-enabling after a pause is an explicit action", true);

    const db2 = new DatabaseSync(path.join(work, "app.db"));
    db2.exec("PRAGMA busy_timeout = 5000");
    db2.prepare(
      "UPDATE auto_rotation SET paused = 0, last_outcome = 'blocked', " +
        "last_check_at = 1700000000, " +
        "last_detail = 'the last completed audit is stale' WHERE credential = ?",
    ).run("sonarr_api_key");
    db2.close();
    await page.reload();
    await page.getByRole("button", { name: "Apps", exact: true }).click();
    await page
      .locator(".app-card h3", { hasText: "Sonarr API Key" }).click();
    await page.getByText(/the last completed audit is stale/).waitFor();
    check("a blocked auto check names its reason on the card", true);
    await page.getByRole("button", { name: "Disable auto-rotation" }).click();
    await page.locator(".toasts").getByText("Saved.").first().waitFor();
    check(
      "disabling is a dull toast, not a banner",
      (await page.getByText("Auto-rotation disabled.").count()) === 0,
    );
    check("the operator can turn auto-rotation off without a typed name", true);

    await page.getByRole("button", { name: "Apps", exact: true }).click();

    // --- paste the right key: match; a wrong one: drift -----------------------
    const value = async (key, fallback) => {
      const token = await csrf();
      return page.request.put(`${BASE}/api/v1/credentials/${key}/value`, {
        data: { value: fallback ?? (key === "sonarr_api_key" ? SONARR_KEY : PROWLARR_KEY) },
        headers: { "X-CSRF-Token": token },
      });
    };
    check(
      "the Seerr own key is stored for the process read-back",
      (await value("seerr_api_key", SEERR_KEY)).ok(),
    );
    await page.getByRole("button", { name: "Apps", exact: true }).click();
    await runAudit();
    const sonarrCard = page.locator(".app-card", { hasText: "Sonarr API Key" });
    const prowlarrCard = page.locator(".app-card", { hasText: "Prowlarr API Key" });
    await sonarrCard.locator(".pill.match").waitFor();
    check("a matching value reads as match", true);
    check(
      "the other app says why it has no verdict",
      await prowlarrCard.locator(".pill.unverifiable").isVisible(),
    );

    check("the second paste is accepted", (await value("prowlarr_api_key")).ok());
    await runAudit();
    await prowlarrCard.locator(".pill.unverifiable").waitFor();
    check(
      "the API-only holder is measured and the unreadable one is still named",
      (await page.locator(".pill.match").count()) >= 1 &&
        (await prowlarrCard.locator(".pill.unverifiable").isVisible()),
    );

    const drifted = await page.request.put(`${BASE}/api/v1/credentials/sonarr_api_key/value`, {
      data: { value: WRONG_KEY },
      headers: { "X-CSRF-Token": await csrf() },
    });
    check("a wrong value can be pasted", drifted.ok());
    await runAudit();
    await sonarrCard.locator(".pill.drift").waitFor();
    check("drift is visible, in the engine's word", true);
    check("the pasted value is not in the DOM", !(await page.content()).includes(WRONG_KEY));

    // --- the copy editor proposes the live count, never a hand count -------
    // The audit already listed one row; the declaration is rewritten to say
    // two, and the next audit reports the mismatch with the live number
    // beside it.
    const credsBefore = await (await page.request.get(`${BASE}/api/v1/credentials`)).json();
    const sonarrRow = credsBefore.credentials.find((c) => c.name === "sonarr_api_key");
    const holdersPut = await page.request.put(`${BASE}/api/v1/credentials/sonarr_api_key/holders`, {
      data: {
        consumers: sonarrRow.consumers.map((c) => ({
          target: c.target,
          count: 2,
          mechanism: c.mechanism ?? "",
          host: c.host ?? null,
          note: c.note ?? "",
        })),
      },
      headers: { "X-CSRF-Token": await csrf() },
    });
    check("the stale count is written through the holders endpoint", holdersPut.ok());
    await runAudit();
    const credsAfter = await (await page.request.get(`${BASE}/api/v1/credentials`)).json();
    const seerrCopy = credsAfter.credentials
      .find((c) => c.name === "sonarr_api_key")
      .consumers.find((c) => c.target === "seerr.settings_json[sonarr]");
    check(
      "the audit reports the live row count beside the declaration",
      seerrCopy?.observed_count === 1,
      JSON.stringify(seerrCopy),
    );
    await page
      .locator(".app-card h3", { hasText: "Sonarr API Key" }).click();
    await page.getByRole("heading", { name: "Sonarr API Key" }).waitFor();
    await page.getByRole("heading", { name: "Connection", exact: true }).waitFor();
    await page.getByText(/the API lists 1 row/).waitFor();
    check("a stale count is offered the live number, not a counting job", true);
    await page.getByRole("button", { name: "Set count to 1" }).click();
    await page.locator(".toasts").getByText("Saved.").first().waitFor();
    await page.getByText(/the API lists 1 row/).waitFor({ state: "detached" });
    check("confirming the live count clears the proposal", true);

    // --- a scoped check is per-app history, not a stack audit ----------------
    const checked = page.waitForResponse(
      (response) =>
        response.url().includes("/api/v1/audit?only=sonarr_api_key") &&
        response.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Check", exact: true }).click();
    await checked;
    await page.getByRole("heading", { name: "Check history" }).waitFor();
    const checkHistory = page.locator("#check-history");
    await checkHistory.getByText("Check", { exact: true }).first().waitFor();
    await checkHistory.locator(".pill.drift").first().waitFor();
    check(
      "a scoped check shows its time and joins the full-audit history",
      (await checkHistory.locator("tbody tr").count()) >= 2,
    );

    // A hand-typed count is validated in place: zero or a fraction is refused
    // visibly and the field returns to the saved number instead of pretending.
    const countInput = page.locator("input.count-input").first();
    await countInput.fill("0");
    await countInput.press("Tab");
    await page.getByText(/whole number of at least one/).waitFor();
    check(
      "an invalid copy count is refused visibly and restored",
      (await countInput.inputValue()) === "1",
    );
    await countInput.fill("2");
    await countInput.press("Tab");
    await page.locator(".toasts").getByText("Saved.").first().waitFor();
    check("a whole copy count is written through", (await countInput.inputValue()) === "2");
    await countInput.fill("1");
    await countInput.press("Tab");
    await page.locator(".toasts").getByText("Saved.").first().waitFor();
    await page.getByRole("button", { name: "Apps", exact: true }).click();
    await page.locator(".app-card").nth(2).waitFor();

    check(
      "the hub cards are links with no Open buttons and no rotate actions",
      (await page.getByRole("button", { name: "Open", exact: true }).count()) === 0 &&
        (await page.getByRole("link", { name: /^Open / }).count()) === 3 &&
        (await page.getByRole("button", { name: /^Rotate( |$)/ }).count()) === 0,
    );

    // --- the sidebar's menus: a section opens, a child picks -------------------
    // The Apps menu lists the same apps the hub does, from the same payload,
    // and a name picked there opens it.
    await openMenu("Apps");
    const appMenu = await page.locator("aside .nav-sub button").allInnerTexts();
    check(
      "the Apps menu lists the declared apps",
      appMenu.includes("Sonarr API Key") && appMenu.includes("Prowlarr API Key"),
      JSON.stringify(appMenu),
    );
    await page.locator("aside .nav-sub button").filter({ hasText: /^Prowlarr API Key$/ }).click();
    await page.getByRole("heading", { name: "Prowlarr API Key" }).waitFor();
    check("a name in the menu opens that app", true);
    await page.getByRole("button", { name: "Apps", exact: true }).click();

    // --- the Used in table names services, not target strings -----------------
    // A reminder saved while a Homepage copy existed must not survive after
    // that holder is removed; the current declaration is Seerr-only.
    await page.evaluate(() => {
      const key = "credarr.manualFollowUp.v1";
      const all = JSON.parse(localStorage.getItem(key) ?? "{}");
      all.sonarr_api_key = {
        attempt: 1,
        targets: { "homepage.label": { done: false, at: 1 } },
      };
      localStorage.setItem(key, JSON.stringify(all));
    });
    await page
      .locator(".app-card h3", { hasText: "Sonarr API Key" }).click();
    await page.getByRole("heading", { name: "Sonarr API Key" }).waitFor();
    await page.waitForTimeout(100);
    const staleReminder = await page.evaluate(() => {
      const all = JSON.parse(
        localStorage.getItem("credarr.manualFollowUp.v1") ?? "{}",
      );
      return !all.sonarr_api_key;
    });
    check(
      "a stale manual reminder is dropped when its copy is gone",
      (await page.getByRole("heading", { name: "Manual rotation", exact: true }).count()) === 0 &&
        staleReminder,
    );
    check(
      "opening an app shows its copies by service",
      await page.getByText("Seerr", { exact: true }).first().isVisible(),
    );
    check(
      "and where the copy lives, in the settings screen's words",
      await page.getByText("A copy of Sonarr's key is in Seerr's sonarr settings.").isVisible(),
    );


    // --- the app detail: the menu and the last run's word -------------------
    await openMenu("Apps");
    await page.locator("aside .nav-sub button").filter({ hasText: /^Prowlarr API Key$/ }).click();
    await page.getByRole("heading", { name: "Prowlarr API Key" }).waitFor();
    check("the menu opens another app in its own view", true);
    check(
      "the hostile description is text on this view too",
      (await page.locator("img").count()) === 0 &&
        (await page.evaluate(() => window.__pwned)) === undefined &&
        (await page.getByText('<img src=x onerror="window.__pwned=1">').count()) === 1,
    );
    await openMenu("Apps");
    await page.locator("aside .nav-sub button").filter({ hasText: /^Sonarr API Key$/ }).click();
    await page.getByRole("heading", { name: "Sonarr API Key" }).waitFor();
    check("switching apps switches the page", true);
    await page.locator(".pill.drift").first().waitFor();
    check("the last run's word shows here too", true);
    await page.screenshot({ path: path.join(ARTIFACTS, "credential.png"), fullPage: true });

    // --- plan and run: a refusal, a failed preflight, armed consent --------
    // This fixture deliberately declares Seerr audit-only so the console must
    // collapse the engine's several reasons into one plain refusal. Seerr's
    // real regenerate path is covered by tests/test_rotate.py and the live
    // harness; it is not a capability limit.
    await page.getByRole("button", { name: "Apps", exact: true }).click();
    await page.locator(".app-card h3", { hasText: "Seerr API Key" }).click();
    await page.getByRole("heading", { name: "Seerr API Key" }).waitFor();
    // Plan / Check / Rotate live in the header; the panel below only reports.
    await page.getByRole("button", { name: "Rotate", exact: true }).waitFor();
    const headerActions = await page.locator(".page-actions button").allTextContents();
    check(
      "Check sits between Plan and Rotate, with Plan's secondary styling",
      headerActions.join("|") === "Plan|Check|Rotate" &&
        !(await page.locator(".page-actions button").nth(1).getAttribute("class") ?? "").includes("primary"),
    );
    check(
      "the header owns the rotation action",
      await page.getByRole("button", { name: "Rotate", exact: true }).isEnabled(),
    );
    await page.getByRole("button", { name: "Rotate", exact: true }).click();
    check(
      "the first press arms the rotation",
      await page.getByRole("button", { name: "Confirm rotation", exact: true }).isVisible(),
    );
    const scrollBeforeRotate = await page.evaluate(() => window.scrollY);
    await page.getByRole("button", { name: "Confirm rotation", exact: true }).click();
    await page.getByText("This key cannot be rotated yet.").waitFor();
    check(
      "confirming a rotation leaves the page in place",
      Math.abs((await page.evaluate(() => window.scrollY)) - scrollBeforeRotate) < 5,
    );
    check(
      "a refused run says why, without repeating itself",
      await page.getByText(/audit-only/).isVisible(),
    );
    check(
      "a refusal names its state without an exit code",
      (await page.getByText("This key cannot be rotated yet.").isVisible()) &&
        (await page.locator("#rotation-card").getByText(/exit \d/).count()) === 0,
    );
    check(
      "no manifest path leaks into the refusal",
      (await page.locator("#rotation-card").getByText(/write\.[a-z_]+/).count()) === 0,
    );
    check(
      "and the confirmation button is gone with nothing to run",
      (await page.getByRole("button", { name: "Confirm rotation", exact: true }).count()) === 0,
    );
    await page.getByRole("button", { name: "Plan", exact: true }).click();
    await page.getByText("This key cannot be rotated yet.").waitFor();
    check(
      "the plan reads the same answer as the run",
      await page.getByText(/audit-only/).isVisible(),
    );

    // --- the refused attempt is recorded, not notified ----------------------
    // A refusal answers one explicit click the panel already explained, so the
    // ledger keeps the trail while no sink ever hears about it.
    await page.getByRole("button", { name: "Activity", exact: true }).click();
    await page.getByRole("heading", { name: "Activity" }).waitFor();
    await page.locator("table.events-table tbody tr").first().waitFor();
    const refusedRow = page
      .locator("tbody tr", { hasText: "rotation refused" })
      .first();
    await refusedRow.waitFor();
    check(
      "a refused rotation is a row with the engine's blocker",
      await refusedRow.getByText(/[Cc]redential is class B/).isVisible(),
    );
    check(
      "a refusal carries no pending delivery count",
      (await refusedRow.getByText("pending").count()) === 0,
    );
    await page.getByRole("button", { name: "Apps", exact: true }).click();
    await page.locator(".app-card h3", { hasText: "Sonarr API Key" }).click();
    await page.getByRole("heading", { name: "Sonarr API Key" }).waitFor();

    // --- the method is inferred; only the fallback is shown -----------------
    // Sonarr's backup download is behind a UI login in this fixture. The
    // console must not make the operator decode a three-option form: one
    // fallback card, the password fix, the explicit rebuild, and the manual
    // path. A working UI password clears the card and the backup is the plan.
    await page.locator("#connection").waitFor();
    await page.getByText("Backup & restore isn't available.").waitFor();
    check(
      "a service whose backup needs a login shows the fallback, not a method picker",
      (await page.getByRole("radio", { name: /Backup & restore|Rebuild the config|rotate it in/ }).count()) === 0,
    );
    check(
      "and the reason names the UI login in plain words",
      await page.getByText(/asks for a UI sign-in before it will download a backup/).isVisible(),
    );
    await page.screenshot({ path: path.join(ARTIFACTS, "fallback.png"), fullPage: true });
    check(
      "the header is a warning banner, and it closes",
      (await page.locator(".banner-warn", { hasText: "Backup & restore isn't available." }).count()) === 1,
    );
    await page.locator(".banner-warn").getByRole("button", { name: "Close", exact: true }).click();
    await page.getByText("Backup & restore isn't available.").waitFor({ state: "detached" });
    check(
      "closing the warning keeps the fallback buttons",
      await page.locator(".confirm-box").getByRole("button", { name: "Save", exact: true }).isVisible(),
    );
    const sonarrPw = page.getByLabel("UI password", { exact: true });
    await sonarrPw.waitFor();
    check(
      "the fallback offers the UI password that restores backup & restore",
      await page.locator(".confirm-box").getByRole("button", { name: "Save", exact: true }).isVisible(),
    );
    await sonarrPw.pressSequentially(UI_PASSWORD);
    await page.locator(".confirm-box").getByRole("button", { name: "Save", exact: true }).click();
    await page.getByText("Backup & restore isn't available.").waitFor({ state: "detached" });
    check(
      "a working UI password clears the fallback and leaves no method picker",
      (await page.getByRole("radio").count()) === 0,
    );
    check(
      "the stored password is not in the DOM",
      !(await page.content()).includes(UI_PASSWORD),
    );
    await page.getByRole("button", { name: "Plan", exact: true }).click();
    await page.locator("#rotation-card").getByText(/Checks passed: sign-in works, the backup answers/).waitFor();
    check("the inferred backup path is the plan's method", true);

    // Cleanup: deleting the stored password makes the backup unavailable
    // again; the explicit rebuild choice clears the stale reference.
    await page.getByRole("button", { name: "Apps", exact: true }).click();
    await openMenu("Apps");
    await page.locator("aside .nav-sub button").filter({ hasText: /UI Password/ }).click();
    await page.getByRole("heading", { name: "Sonarr UI Password" }).waitFor();
    await page.getByRole("button", { name: "Delete this app key" }).click();
    await page.getByRole("button", { name: "Delete", exact: true }).click();
    await page.getByRole("heading", { name: "Sonarr API Key", exact: true }).waitFor();
    check("the stored password is removed again", true);
    await page.getByText("Backup & restore isn't available.").waitFor();
    await page.getByRole("button", { name: "Use config rebuild", exact: true }).click();
    // The toast can be its predecessor's; the blue disabled button is what
    // proves this save landed and rendered.
    await page.waitForFunction(
      () =>
        [...document.querySelectorAll("button")].some(
          (button) =>
            button.textContent === "Use config rebuild" &&
            button.disabled &&
            button.className.includes("primary"),
        ),
      { timeout: 60_000 },
    );
    check("the selection reads as blue, not as wording", true);
    check("the explicit rebuild choice clears the stale password reference", true);

    await openMenu("Apps");
    await page.locator("aside .nav-sub button").filter({ hasText: /^Prowlarr API Key$/ }).click();
    await page.getByRole("heading", { name: "Prowlarr API Key" }).waitFor();
    await page.getByRole("button", { name: "Plan", exact: true }).click();
    await page.getByText("The checks failed; nothing was changed.").waitFor();
    check("a plan that cannot be checked is not called ready", true);
    const preflightText = await page.locator("#rotation-card").innerText();
    check(
      "problems read as sentences with no own-service prefix",
      !preflightText.includes("prowlarr: could not be reached") &&
        preflightText.includes("Could not be reached during preflight") &&
        preflightText.includes("Sonarr indexers:"),
      preflightText.slice(0, 400),
    );
    check(
      "a failed preflight is a red banner, not a refusal and not an exit code",
      (await page.locator("#rotation-card .banner-danger", { hasText: "The checks failed" }).count()) === 1 &&
        (await page.locator("#rotation-card").getByText(/exit \d/).count()) === 0,
    );
    check(
      "and the header still offers the run: fixing the stack and retrying is the point",
      await page.getByRole("button", { name: "Rotate", exact: true }).isVisible(),
    );

    // --- manual mint: one press asks for the key ------------------------------
    // Prowlarr declares the servarr_command mint the opt-ins belong to. With
    // the manual opt-in saved, one press on Rotate opens the key field —
    // no arming, the form's own submit confirms. The server refuses an empty
    // submit, and a submitted key never reaches the page or the ledger again.
    // The opt-in is removed after, so the interrupted-run flow below meets
    // the fixture as declared.
    await page.locator("#connection").waitFor();
    await page.getByRole("button", { name: "Rotate the key myself", exact: true }).click();
    await page.waitForFunction(
      () =>
        [...document.querySelectorAll("button")].some(
          (button) =>
            button.textContent === "Rotate the key myself" &&
            button.disabled &&
            button.className.includes("primary"),
        ),
      { timeout: 60_000 },
    );
    const manualButton = page.getByRole("button", { name: "Rotate the key myself", exact: true });
    check(
      "the manual selection reads as blue, not as wording",
      ((await manualButton.getAttribute("class")) ?? "").includes("primary") &&
        (await manualButton.isDisabled()),
    );
    check(
      "the API key box locks while the key arrives by hand",
      await page.getByLabel("API key").isDisabled(),
    );
    await page.getByRole("button", { name: "Rotate", exact: true }).click();
    const manualField = page.getByLabel("Key from the service's Settings page");
    await manualField.waitFor();
    check(
      "one press opens the key field with no arming step",
      (await page.getByRole("button", { name: "Confirm rotation", exact: true }).count()) === 0,
    );
    const planned = page.waitForResponse(
      (response) =>
        response.url().includes("/credentials/prowlarr_api_key/plan") &&
        response.request().method() === "POST",
      { timeout: 60_000 },
    );
    await page.getByRole("button", { name: "Plan", exact: true }).click();
    await planned;
    // The answer lands a beat after the response; the panel shows one of the
    // plan states by then.
    await page.locator("#rotation-card").getByText(/Ready to rotate|refused|The checks failed|cannot complete/).first().waitFor();
    const panelText = await page.locator("#rotation-card").innerText();
    check(
      "the manual plan names its no-backup path or its blocker",
      panelText.includes("Checks passed") ||
        panelText.includes("This key cannot be rotated yet.") ||
        panelText.includes("The checks failed; nothing was changed."),
      panelText.slice(0, 400),
    );
    await page.getByRole("button", { name: "Rotate with this key", exact: true }).click();
    await page.getByText("the manual key is empty; nothing has been changed").waitFor();
    check(
      "submitting without a key is refused by the server with the form open",
      await manualField.isVisible(),
    );
    // `fill` does not stick on password inputs; type it the way a paste lands.
    await manualField.pressSequentially(MANUAL_KEY);
    const rotated = page.waitForResponse(
      (response) =>
        response.url().includes("/credentials/prowlarr_api_key/rotate") &&
        response.request().method() === "POST",
      { timeout: 120_000 },
    );
    await page.getByRole("button", { name: "Rotate with this key", exact: true }).click();
    await rotated;
    // The clear happens after the run's refresh lands, not on the response:
    // poll the field itself rather than racing it.
    await page.waitForFunction(
      () =>
        document.querySelector("#rotation-card input[type='password']")?.value === "",
      { timeout: 120_000 },
    );
    await page.getByText("The checks failed; nothing was changed.").waitFor();
    check(
      "the key field is cleared on submit",
      (await manualField.inputValue()) === "",
    );
    const afterManual = await page.content();
    check(
      "the submitted key is absent from the page",
      !afterManual.includes(MANUAL_KEY),
    );
    await page.getByRole("button", { name: "Activity", exact: true }).click();
    await page.getByRole("heading", { name: "Activity" }).waitFor();
    const manualRow = page.locator("tbody tr", { hasText: "rotation failed" }).first();
    await manualRow.waitFor();
    const manualRowText = await manualRow.innerText();
    check(
      "the ledger records the attempt without the key",
      manualRowText.includes("Prowlarr") && !manualRowText.includes(MANUAL_KEY),
      manualRowText.slice(0, 300),
    );
    await page.getByRole("button", { name: "Apps", exact: true }).click();
    await openMenu("Apps");
    await page.locator("aside .nav-sub button").filter({ hasText: /^Prowlarr API Key$/ }).click();
    await page.getByRole("heading", { name: "Prowlarr API Key" }).waitFor();
    // The fallback has no "none" choice when neither automatic path is
    // available. The fixture resets the declaration through the API it would
    // use anyway; the reload proves the UI read the new write block.
    const reset = await page.request.patch(
      `${BASE}/api/v1/credentials/prowlarr_api_key`,
      {
        data: { write: { mechanism: "servarr_command" } },
        headers: { "X-CSRF-Token": await csrf() },
      },
    );
    check("the manual opt-in is removed again", reset.ok());
    await page.reload();
    await page.getByRole("button", { name: "Apps" }).waitFor();
    await openMenu("Apps");
    await page.locator("aside .nav-sub button").filter({ hasText: /^Prowlarr API Key$/ }).click();
    await page.getByRole("heading", { name: "Prowlarr API Key" }).waitFor();
    check(
      "unsetting the opt-in closes the key field",
      (await manualField.count()) === 0,
    );
    check(
      "the API key box unlocks with it",
      await page.getByLabel("API key").isEnabled(),
    );

    // --- an interrupted rotation is visible before anything can run -----------
    seedUnfinishedRotation(work);
    await page.getByRole("button", { name: "Apps", exact: true }).click();
    await runAudit();
    await page.getByText("A rotation did not finish.").waitFor();
    check("an unfinished rotation is on screen before any run", true);
    const rotationBanner = await page
      .locator(".banner", { hasText: "A rotation did not finish." })
      .first()
      .innerText();
    check(
      "the banner says where the resume path is, and that a live run keeps the lock",
      rotationBanner.includes("Resume from the app page") &&
        rotationBanner.includes("keeps the lock"),
      rotationBanner,
    );
    check(
      "the interrupted credential is named",
      rotationBanner.includes("Prowlarr API Key stopped"),
      rotationBanner,
    );
    await page.getByRole("button", { name: "Resume Prowlarr API Key" }).click();
    await page.getByRole("heading", { name: "Prowlarr API Key" }).waitFor();
    check("it opens the credential that stopped", true);
    await page.waitForFunction(
      () => document.activeElement?.textContent?.includes("Resume rotation"),
    );
    check("and the banner's resume action lands on the rotation button", true);
    check(
      "the credential view names what stopped",
      await page.getByText("A rotation of this app did not finish.").isVisible(),
    );
    check(
      "the run affordance becomes the resume path",
      await page.getByRole("button", { name: "Resume rotation" }).isVisible(),
    );
    check(
      "and the view says what resuming takes over",
      await page.getByText("Continuing below takes those steps over").isVisible(),
    );
    // The fixture stack's prowlarr URL points at a closed port, so a resumed
    // run still cannot be checked. That refusal has to be the *stack's*: pressing
    // resume answers for the interrupted run and nothing else. Without
    // `take_over` the engine adds "a previous rotation of this credential is
    // unfinished" below the url problem, so this also proves the instruction
    // crossed.
    await page.getByRole("button", { name: "Resume rotation" }).click();
    await page.getByRole("button", { name: "Confirm rotation", exact: true }).click();
    // The button disarms when the answer arrives; the preflight text itself is
    // already on screen from the plan above.
    await page.getByRole("button", { name: "Resume rotation", exact: true }).waitFor();
    check(
      "a resume answers the unfinished step, not the stack's own gaps",
      await page.getByText("Could not be reached during preflight").first().isVisible(),
    );
    check(
      "and it does not re-refuse on the rotation it is taking over",
      (await page.getByText(/of this credential is unfinished/).count()) === 0,
    );
    check(
      "nothing was closed: the run never started",
      await page.getByText("A rotation of this app did not finish.").isVisible(),
    );

    await page.getByRole("button", { name: "Apps", exact: true }).click();

    // --- the detail Test button uses the stored key, and names a refusal -----
    // The key field is empty, so the probe runs with the stored key; the fake
    // Sonarr accepts it. A wrong key is rejected by the same probe, in words.
    await page.getByRole("button", { name: "Apps", exact: true }).click();
    await page
      .locator(".app-card h3", { hasText: "Sonarr API Key" }).click();
    await page.getByRole("heading", { name: "Sonarr API Key" }).waitFor();
    await page.getByRole("button", { name: "Test", exact: true }).click();
    await page.getByText(/Reached the service\. Version/).first().waitFor();
    check("Test with an empty field uses the stored key", true);
    await page.getByLabel("API key").pressSequentially(STALE_KEY);
    await page.getByRole("button", { name: "Test", exact: true }).click();
    await page.getByText(/The service did not answer as expected/).first().waitFor();
    check("the detail Test button shows the service's refusal in words", true);
    await page.screenshot({ path: path.join(ARTIFACTS, "apps.png"), fullPage: true });

    // --- Settings and Events: a sink proven end to end -----------------------
    // A local HTTP server stands in for ntfy, so what is checked is the whole
    // path the operator takes: type a URL, save, press the test button, see the
    // request arrive - with nothing but statuses in it.
    const notified = [];
    const sink = createServer((request, response) => {
      let body = "";
      request.on("data", (chunk) => (body += chunk));
      request.on("end", () => {
        notified.push({ path: request.url, headers: request.headers, body });
        response.writeHead(200);
        // Telegram's real API answers a 200 with `ok: true`; the other sinks
        // ignore the response body.
        response.end(request.url.startsWith("/bot") ? JSON.stringify({ ok: true }) : "ok");
      });
    });
    await new Promise((resolve) => sink.listen(0, "127.0.0.1", resolve));
    const sinkBase = `http://127.0.0.1:${sink.address().port}`;

    await page.getByRole("button", { name: "Settings", exact: true }).click();
    await page.getByRole("heading", { name: "Settings" }).waitFor();
    await openMenu("Settings");
    const settingsMenu = await page.locator("aside .nav-sub button").allInnerTexts();
    check(
      "the Settings menu names the page's sections",
      ["Security", "Audit schedule", "API keys", "Notifications", "Import / Export"].every(
        (label) => settingsMenu.includes(label),
      ),
      JSON.stringify(settingsMenu),
    );
    await page.locator("aside .nav-sub button").filter({ hasText: /^Notifications$/ }).click();
    check(
      "and a section in the menu lands on that section",
      await page.locator("#settings-notifications").isVisible(),
    );

    // --- Security: the session list, and a password change that rotates it ----
    await page.locator("aside .nav-sub button").filter({ hasText: /^Security$/ }).click();
    await page.locator("#settings-security").waitFor();
    check("the Security section is reachable from the Settings menu", true);
    check(
      "the browser that signed in is listed as this session",
      (await page.locator("#settings-security .session-row").count()) === 1 &&
        (await page.locator("#settings-security .session-row").getByText("this session").isVisible()),
    );
    await page.getByLabel("current password").fill(PASSWORD);
    await page.getByLabel("new password", { exact: true }).fill(NEW_PASSWORD);
    await page.getByLabel("confirm new password").fill(NEW_PASSWORD);
    await page.getByRole("button", { name: "Change password" }).click();
    await page.getByText("Password changed. Every other session is signed out.").waitFor();
    check("a password change keeps this session and says it signed the rest out", true);
    check(
      "and the new password satisfies the minimum while the fields are emptied",
      (await page.getByLabel("current password").inputValue()) === "",
    );

    // --- Audit schedule: persisted and applied without a restart -------------
    await openMenu("Settings");
    await page.locator("aside .nav-sub button").filter({ hasText: /^Audit schedule$/ }).click();
    await page.locator("#settings-audit").waitFor();
    const auditMinutes = page.getByLabel("Minutes between audits");
    const auditCard = page.locator("#settings-audit");
    const saveAudit = auditCard.getByRole("button", { name: "Save", exact: true });
    check("the audit schedule is reachable from Settings", true);
    check("the saved audit cadence loads", (await auditMinutes.inputValue()) === "60");
    await auditMinutes.fill("1.5");
    await saveAudit.click();
    await page.locator(".toasts").getByText("Saved.", { exact: true }).first().waitFor();
    check(
      "the audit cadence keeps fractional minutes",
      (await auditMinutes.inputValue()) === "1.5",
    );
    await auditCard.getByRole("button", { name: "Disable schedule" }).click();
    await auditCard.getByText("off", { exact: true }).waitFor();
    check("the audit schedule can be disabled", true);
    await auditMinutes.fill("2");
    await auditCard.getByRole("button", { name: "Enable schedule" }).click();
    await page.locator(".toasts").getByText("Saved.", { exact: true }).first().waitFor();
    await auditCard.getByText("enabled", { exact: true }).waitFor();
    check(
      "enabling the schedule uses the shown cadence",
      (await auditMinutes.inputValue()) === "2",
    );
    await auditMinutes.fill("60");
    await saveAudit.click();
    await page.locator(".toasts").getByText("Saved.", { exact: true }).first().waitFor();

    // --- API keys moved out of the wizard and into Settings ------------------
    await page.locator("aside .nav-sub button").filter({ hasText: /^API keys$/ }).click();
    await page.locator("#settings-keys").waitFor();
    check("the API keys section is reachable from the Settings menu", true);
    await page.locator("#settings-keys").getByRole("button", { name: "Create API key" }).click();
    const keyField = page.getByRole("textbox", { name: "New API key" });
    await keyField.waitFor();
    const apiKey = await keyField.inputValue();
    check("the one-time key is shown in Settings", apiKey.length > 20);
    const storageText = await page.evaluate(() =>
      JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }),
    );
    check("the one-time key is not persisted in browser storage", !storageText.includes(apiKey));
    check("the one-time key is not in the URL", !page.url().includes(apiKey));
    await page.locator("#settings-keys").getByRole("button", { name: "Done" }).click();
    const listed = await page.request.get(`${BASE}/api/v1/keys`);
    const listedKeys = await listed.json();
    const created = listedKeys.find((item) => item.prefix && apiKey.startsWith(item.prefix));
    check("the list names the key by prefix only, never the value", Boolean(created));
    await page
      .locator("#settings-keys li")
      .filter({ hasText: `${created.prefix}…` })
      .getByRole("button", { name: "Revoke" })
      .click();
    await page.getByRole("button", { name: "Confirm revoke" }).click();
    await page.waitForFunction(
      (prefix) => !document.querySelector("#settings-keys")?.innerText.includes(prefix),
      created.prefix,
    );
    check("an API key can be revoked from Settings", true);

    // The Profilarr pattern: a list with Add Service, then a form page with a
    // type dropdown and the fields that type needs.
    await page.locator("#settings-notifications").waitFor();
    check(
      "the Notifications list starts empty and offers Add Service",
      (await page.getByText(/No notification services configured/).isVisible()) &&
        (await page.getByRole("button", { name: "Add Service" }).isVisible()),
    );
    await page.getByRole("button", { name: "Add Service" }).click();
    await page.getByRole("heading", { name: "New Notification Service" }).waitFor();
    check("Add Service opens the new-service form", true);
    await page.getByLabel("Service Type").selectOption("email");
    await page.getByLabel("SMTP Host").waitFor();
    check(
      "the email service asks for SMTP settings",
      (await page.getByLabel("SMTP Port").inputValue()) === "587" &&
        (await page.getByLabel("SMTP TLS").inputValue()) === "starttls" &&
        (await page.getByLabel("SMTP Authentication").inputValue()) === "auto",
    );
    await page.getByLabel("Service Type").selectOption("ntfy");
    await page.getByLabel("Service Name").fill("ntfy");
    await page.getByLabel("Server URL").fill(sinkBase);
    await page.getByLabel("Topic").fill("credarr-smoke");
    await page.getByLabel("Access Token").fill("smoke-token");
    check(
      "the access token is a password field",
      (await page.getByLabel("Access Token").getAttribute("type")) === "password",
    );
    await page.getByRole("button", { name: "Test", exact: true }).click();
    await page.getByText("Test delivered.", { exact: true }).waitFor();
    check("an unsaved notification can be tested", notified.length === 1);
    await page
      .locator("#settings-notifications")
      .getByRole("button", { name: "Save", exact: true })
      .click();
    await page.locator(".toasts").getByText("Saved.").first().waitFor();
    check("a service is created from the form", true);
    check(
      "the typed secret never comes back to the browser",
      !(await page.content()).includes("smoke-token"),
    );
    await page.screenshot({ path: path.join(ARTIFACTS, "settings.png"), fullPage: true });

    await page
      .locator("#settings-notifications tr", { hasText: "ntfy" })
      .getByRole("button", { name: "Test" })
      .click();
    await page.getByText(/ntfy: accepted/).waitFor();
    check("the test button reaches the sink", notified.length === 2, JSON.stringify(notified));
    check(
      "as an ntfy POST to the topic, with the token the operator typed",
      notified[0].path === "/credarr-smoke" &&
        notified[0].headers.authorization === "Bearer smoke-token" &&
        notified[0].headers.title === "credarr: test notification",
      JSON.stringify(notified[0]),
    );
    check(
      "and nothing but statuses left the machine",
      !notified[0].body.includes(SONARR_KEY) && !notified[0].body.includes(PROWLARR_KEY),
    );

    // Discord and Telegram are added the same way. Telegram's API base is the
    // local stand-in so the request can be inspected without contacting Telegram.
    // Each service is tested on its own row: one test reaches one service.
    await page.getByRole("button", { name: "Add Service" }).click();
    await page.getByLabel("Service Name").fill("discord");
    await page.getByLabel("Service Type").selectOption("discord");
    await page.getByLabel("Webhook URL").fill(`${sinkBase}/discord`);
    const discordDraftTest = page
      .locator("#settings-notifications")
      .getByRole("button", { name: "Test", exact: true });
    check("Discord has Test before Save", await discordDraftTest.isEnabled());
    await discordDraftTest.click();
    await page.getByText("Test delivered.", { exact: true }).waitFor();
    await page
      .locator("#settings-notifications")
      .getByRole("button", { name: "Save", exact: true })
      .click();
    await page.locator(".toasts").getByText("Saved.").first().waitFor();
    await page.getByRole("button", { name: "Add Service" }).click();
    await page.getByLabel("Service Name").fill("telegram");
    await page.getByLabel("Service Type").selectOption("telegram");
    check(
      "Telegram defaults to the public Bot API",
      (await page.getByLabel("API Base").inputValue()) === "https://api.telegram.org",
    );
    await page.getByLabel("API Base").fill(sinkBase);
    await page.getByLabel("Chat ID").fill("4242");
    await page.getByLabel("Bot Token").fill("123:bot-token");
    const telegramDraftTest = page
      .locator("#settings-notifications")
      .getByRole("button", { name: "Test", exact: true });
    check("Telegram has Test before Save", await telegramDraftTest.isEnabled());
    await telegramDraftTest.click();
    await page.getByText("Test delivered.", { exact: true }).waitFor();
    await page
      .locator("#settings-notifications")
      .getByRole("button", { name: "Save", exact: true })
      .click();
    await page.locator(".toasts").getByText("Saved.").first().waitFor();
    check(
      "the bot token is write-only like every other sink secret",
      !(await page.content()).includes("123:bot-token"),
    );

    await page
      .locator("#settings-notifications tr", { hasText: "Discord" })
      .getByRole("button", { name: "Test" })
      .click();
    await page.getByText(/discord: accepted/).waitFor();
    await page
      .locator("#settings-notifications tr", { hasText: "Telegram" })
      .getByRole("button", { name: "Test" })
      .click();
    await page.getByText(/telegram: accepted/).waitFor();
    const later = notified.slice(2);
    const discordRequest = later.find((request) => request.path === "/discord");
    const telegramRequest = later.find(
      (request) => request.path === "/bot123:bot-token/sendMessage",
    );
    check(
      "Discord receives the scrubbed event and never pings a role",
      Boolean(discordRequest) &&
        JSON.parse(discordRequest.body).allowed_mentions.parse.length === 0 &&
        JSON.parse(discordRequest.body).content.includes("test notification"),
      JSON.stringify(later),
    );
    check(
      "Telegram receives the chat id, and its token stays in the path",
      Boolean(telegramRequest) &&
        JSON.parse(telegramRequest.body).chat_id === "4242" &&
        !telegramRequest.body.includes("bot-token"),
      JSON.stringify(later),
    );

    await page.getByRole("button", { name: "Activity", exact: true }).click();
    await page.getByRole("heading", { name: "Activity" }).waitFor();
    // The heading renders before the fetch returns; the table is the loaded state.
    await page.locator("table").waitFor();
    // The earlier refusal is still here, and now that sinks exist its silence
    // reads as recorded-only instead of queued-for-delivery.
    const refusedRowLate = page
      .locator("tbody tr", { hasText: "rotation refused" })
      .first();
    await refusedRowLate.waitFor();
    check(
      "a refusal counts as not sent, never pending",
      await refusedRowLate.getByText(/not sent/).isVisible() &&
        (await refusedRowLate.getByText(/pending|queued/).count()) === 0,
    );
    await refusedRowLate.locator("details.delivery summary").click();
    check(
      "and each sink says recorded only",
      await refusedRowLate.getByText("not notified: recorded only").first().isVisible(),
    );
    // Delivery is a compact count per row; the per-sink sentence is one
    // disclosure away, so a full ledger does not become a wall of sink names.
    // Each service is tested on its own row, so each test event names its own
    // delivery: the ntfy event's row is the one that says ntfy delivered.
    const testRow = page
      .locator("tbody tr", { hasText: "test notification from the console" })
      .filter({ hasText: "ntfy — delivered" })
      .first();
    check("the test event is in the ledger", await testRow.locator(".pill.none").isVisible());
    await testRow.locator("details.delivery summary").click();
    // The row was chosen by its ntfy delivery line; opening it must show that
    // line as delivered for the service whose Test button produced the event.
    check(
      "with what the sink did with it",
      await testRow.getByText(/ntfy — delivered/).isVisible(),
    );
    // A long pill or an unbroken filename must wrap inside its cell, never
    // paint over the next column: overflowing content is wider than its cell.
    // Runs on the full table, before the filter hides the longest rows.
    const spilling = await page.evaluate(() =>
      [...document.querySelectorAll("table.events-table tbody td")]
        .filter((cell) => cell.scrollWidth > cell.clientWidth + 1)
        .map((cell) => cell.innerText.slice(0, 60)),
    );
    check("table cells contain their text", spilling.length === 0, JSON.stringify(spilling));
    await page.getByLabel("Filter activity").fill("test notification");
    check(
      "the filter narrows the ledger",
      (await page.locator("table.events-table tbody tr").count()) > 0 &&
        (await page.locator("table.events-table .pill.drift").count()) === 0,
    );
    await page.getByLabel("Filter activity").fill("");
    await page.getByText("No change matches that filter").waitFor({ state: "detached" }).catch(() => {});
    await page.locator("table.events-table tbody tr").first().waitFor();
    const driftRow = page.locator("tr", { has: page.locator(".pill.drift") }).first();
    check(
      "a drift is one row: the kind and the audit's own sentence, under the copy's plain name",
      (await driftRow.getByText("drift", { exact: true }).count()) >= 1 &&
        (await driftRow.getByText("Seerr settings [sonarr]:").isVisible()),
    );
    await driftRow.locator("details.delivery summary").click();
    check(
      "an event from before the sink existed says never sent, not queued",
      await driftRow.getByText("not sent: the sink was configured later").first().isVisible(),
    );
    await page.screenshot({ path: path.join(ARTIFACTS, "events.png"), fullPage: true });
    await new Promise((resolve) => sink.close(resolve));

    // --- app URL editing ------------------------------------------------------
    // Hold the saved-definitions read open while typing, so the edit survives
    // the response that would otherwise replace it.
    await page.getByRole("button", { name: "Apps", exact: true }).click();
    await page
      .locator(".app-card h3", { hasText: "Sonarr API Key" })
      .waitFor();
    let releaseDefinitions;
    let definitionsStarted;
    const definitionsHeld = new Promise((resolve) => (releaseDefinitions = resolve));
    const definitionsSeen = new Promise((resolve) => (definitionsStarted = resolve));
    await page.route(/\/api\/v1\/services\?observe=false$/, async (route) => {
      definitionsStarted();
      await definitionsHeld;
      await route.continue();
    });
    const definitionsRead = page.waitForResponse(
      (response) =>
        response.url().includes("/api/v1/services?observe=false") &&
        response.request().method() === "GET",
    );
    await page
      .locator(".app-card h3", { hasText: "Sonarr API Key" }).click();
    await page.getByRole("heading", { name: "Sonarr API Key" }).waitFor();
    await definitionsSeen;
    await page.getByLabel("URL (required)").fill("http://typed-while-reading:8989");
    releaseDefinitions();
    await definitionsRead;
    await page.waitForFunction(
      () =>
        document.querySelector(
          '#connection input:not([type="password"])',
        )?.value === "http://typed-while-reading:8989",
    );
    check("a URL typed while the saved read is in flight survives", true);
    await page.unroute(/\/api\/v1\/services\?observe=false$/);

    // Let the saved-URL read land before editing; otherwise the read can
    // overwrite the typed value or leave Save enabled for the wrong reason.
    await page.waitForFunction(
      () =>
        document
          .querySelector('#connection input:not([type="password"])')
          ?.value.startsWith("http"),
      { timeout: 10_000 },
    );
    await page.getByLabel("URL (required)").fill("http://sonarr:8989");
    await page.locator("#connection").getByRole("button", { name: "Save", exact: true }).click();
    await page.getByText(/stored for the old URL/i).waitFor();
    check("moving a service URL asks for the key again", true);
    await page.locator("#connection-key").fill(SONARR_KEY);
    await page.locator("#connection").getByRole("button", { name: "Save", exact: true }).click();
    await page.locator(".toasts").getByText("Saved.").first().waitFor();
    check(
      "an app URL can be edited on its own page",
      (await page.getByLabel("URL (required)").inputValue()) === "http://sonarr:8989",
    );

    // --- app key create, copy and delete --------------------------------------
    // Keys are created by connecting an app, the wizard, or an import; the
    // detail page no longer carries its own blank-key form. The API call
    // below stands in for those paths so the copy, lift and delete UI keeps
    // live coverage.
    const createdKey = await page.request.post(`${BASE}/api/v1/credentials`, {
      data: {
        name: "ui_created_key",
        description: "",
        class: "A-unv",
        max_age_days: 90,
        never_rotate: false,
        provisioned: true,
        canonical: { service: "sonarr" },
        write: { mechanism: "servarr_command" },
      },
      headers: { "X-CSRF-Token": await csrf() },
    });
    check("an app key can be created through the console", createdKey.ok());
    await page.reload();
    await page.getByRole("heading", { name: "Apps" }).waitFor();
    await page.locator(".app-card h3", { hasText: "UI Created Key" }).click();
    await page.getByRole("heading", { name: "UI Created Key", exact: true }).waitFor();
    // A manual copy makes the class A promise false. Adding it must leave the
    // key rotatable by downgrading to A-unv, not by refusing every later plan.
    await page.getByRole("button", { name: "Add copy" }).click();
    await page.getByLabel("Service", { exact: true }).selectOption("homepage");
    await page.getByLabel("Copy").selectOption("homepage.label");
    await page.getByRole("button", { name: "Add copy" }).click();
    await page.locator(".toasts").getByText("Saved.").first().waitFor();
    const usedIn = page.locator("section", {
      has: page.getByRole("heading", { name: "Used in", exact: true }),
    });
    await usedIn.getByRole("cell", { name: "Homepage" }).waitFor();

    await page.getByRole("button", { name: "Apps", exact: true }).click();
    await page.locator(".app-card h3", { hasText: "UI Created Key" }).waitFor();
    check(
      "an app card marks its manual copy",
      (await page
        .locator(".app-card", { hasText: "UI Created Key" })
        .getByText("manual", { exact: true })
        .count()) === 1,
    );
    check(
      "Homepage is a holder, not an app to connect",
      (await page.getByRole("button", { name: /Connect Homepage/ }).count()) === 0 &&
        (await page.getByText("Homepage API Key", { exact: true }).count()) === 0,
    );
    await page.locator(".app-card h3", { hasText: "UI Created Key" }).click();
    await page.getByRole("heading", { name: "UI Created Key", exact: true }).waitFor();

    await usedIn.getByRole("button", { name: "Remove" }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Remove" }).click();
    await page.locator(".toasts").getByText("Saved.").first().waitFor();
    await usedIn.getByRole("cell", { name: "Homepage" }).waitFor({ state: "detached" });

    await page.getByRole("button", { name: "Add copy" }).click();
    await page.getByLabel("Service", { exact: true }).selectOption("prowlarr");
    await page.getByLabel("Copy").selectOption("prowlarr.applications[Sonarr]");
    await page.getByRole("button", { name: "Add copy" }).click();
    await page.locator(".toasts").getByText("Saved.").first().waitFor();
    await usedIn.getByRole("cell", { name: "Prowlarr" }).waitFor();
    check("a copy is added straight onto the one table", true);
    await usedIn.getByRole("button", { name: "Remove" }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Remove" }).click();
    await page.locator(".toasts").getByText("Saved.").first().waitFor();
    await usedIn.getByRole("cell", { name: "Prowlarr" }).waitFor({ state: "detached" });
    check("a copy is removed after confirmation", true);

    // --- a new rotation target connects like any other app -------------------
    // Grafana needs no holder slots; connecting it declares the service and
    // its credential, and the app page names the rotation method.
    await page.getByRole("button", { name: "Apps", exact: true }).click();
    await page.getByRole("button", { name: "Add app" }).click();
    await page.getByLabel("App", { exact: true }).selectOption("grafana");
    // Grafana is already a seeded service definition with no credential.
    // Connecting it must attach to that definition and patch the URL, not
    // POST the same name into a 409.
    await page.getByLabel("URL (required)").fill("http://grafana:3001");
    await page.getByRole("button", { name: "Connect", exact: true }).click();
    await page.locator(".toasts").getByText("Saved.").first().waitFor();
    await page.locator(".app-card h3", { hasText: "Grafana API Key" }).click();
    await page.getByRole("heading", { name: "Grafana API Key" }).waitFor();
    check(
      "the app page names the rotation method and its revoke-last promise",
      await page.getByText("Grafana service-account token.").isVisible() &&
        (await page.getByText(/revoked last/).count()) >= 1,
    );

    // --- a refusal hangs off the field that can fix it ---------------------
    // Lifting the class lets the plan run far enough to refuse on the missing
    // token name; the engine's sentence shows under Token name, verbatim.
    await page.getByRole("button", { name: "Plan", exact: true }).click();
    await page.getByText("This key cannot be rotated yet.").waitFor();
    check(
      "the refusal hangs off the token-name field it needs",
      await page.locator("#rotation-method").getByText("Token name is required").isVisible(),
    );
    await page.getByRole("button", { name: "Apps", exact: true }).click();
    await page.locator(".app-card h3", { hasText: "UI Created Key" }).click();
    await page.getByRole("heading", { name: "UI Created Key", exact: true }).waitFor();

    await page.getByRole("button", { name: "Delete this app key" }).click();
    await page.getByRole("button", { name: "Delete", exact: true }).click();
    await page.getByRole("heading", { name: "Sonarr API Key", exact: true }).waitFor();
    check(
      "an app key can be deleted after confirmation",
      (await page.getByText("UI Created Key").count()) === 0,
    );

    // --- import / export: merge keeps omitted names ----------------------------
    await page.getByRole("button", { name: "Settings", exact: true }).click();
    await openMenu("Settings");
    await page.locator("aside .nav-sub button").filter({ hasText: /^Import \/ Export$/ }).click();
    await page.locator("#settings-topology").waitFor();
    await page.waitForFunction(() =>
      document.querySelector('[aria-label="Exported manifest"]')?.value.includes("sonarr_api_key"),
    );
    check(
      "the export is the value-free manifest text",
      (await page.getByLabel("Exported manifest").inputValue()).includes("sonarr_api_key"),
    );
    await page
      .getByLabel("Manifest YAML")
      .fill("version: 1\ncredentials:\n  snapshot_probe_key:\n    class: B\n    never_rotate: true\n");
    await page.getByLabel("Import mode").selectOption("merge");
    await page.getByLabel("I understand this merges into the declared topology").check();
    await page.getByRole("button", { name: "Import", exact: true }).click();
    await page.getByText(/merge import: 1 credentials/).waitFor();
    await page.waitForFunction(() =>
      document.querySelector('[aria-label="Exported manifest"]')?.value.includes("snapshot_probe_key"),
    );
    check(
      "merge adds the new name and keeps the omitted ones",
      (await page.getByLabel("Exported manifest").inputValue()).includes("sonarr_api_key") &&
        (await page.getByLabel("Exported manifest").inputValue()).includes("snapshot_probe_key"),
    );

    // An imported API key that is audit-only despite a mint is a warning, not
    // a refusal: the import succeeds and names the declaration to reconsider.
    await page
      .getByLabel("Manifest YAML")
      .fill(
        "version: 1\ncredentials:\n  seerr_fixture_api_key:\n    class: B\n    max_age_days: 90\n    canonical: {service: seerr}\n",
      );
    await page.getByLabel("Import mode").selectOption("merge");
    await page.getByLabel("I understand this merges into the declared topology").check();
    await page.getByRole("button", { name: "Import", exact: true }).click();
    await page.getByText("Imported, but some keys are audit-only.").waitFor();
    check(
      "an audit-only API key on a mintable service is named after import",
      await page.getByText(/Seerr Fixture API Key is marked audit-only, but Seerr supports rotation/).isVisible(),
    );

    await page.getByRole("button", { name: "Apps", exact: true }).click();
    await page.locator(".app-card h3", { hasText: "Sonarr API Key" }).waitFor();
    check(
      "the merged app list keeps the existing names and adds the probe",
      (await page.locator(".app-card h3", { hasText: "Sonarr API Key" }).count()) === 1 &&
        (await page.getByText("Snapshot Probe Key", { exact: true }).count()) >= 1,
    );

    // --- sign out, and back in with a wrong password first --------------------
    await page.getByRole("button", { name: "Sign out" }).click();
    await page.getByRole("button", { name: "Sign in" }).waitFor();
    await page.getByPlaceholder("password").fill(PASSWORD);
    await page.getByRole("button", { name: "Sign in" }).click();
    await page.getByText("wrong password").waitFor();
    check("the password the admin changed away from is refused", true);
    await page.getByPlaceholder("password").fill(NEW_PASSWORD);
    await page.getByRole("button", { name: "Sign in" }).click();
    await page.getByRole("button", { name: "Apps" }).waitFor();
    check("the admin can sign back in with the new password", true);

    // --- Re-run opens the wizard at step 1, not where a draft was left -----
    await page.getByRole("button", { name: "Settings", exact: true }).click();
    await page.getByRole("heading", { name: "Settings" }).waitFor();
    await page.getByRole("button", { name: "Re-run Setup Wizard" }).click();
    await page.getByRole("heading", { name: "Connect", exact: true }).waitFor();
    check("re-running setup starts at Connect, not a saved step", true);
    await page.getByRole("button", { name: "Skip for now" }).click();
    await page.getByRole("button", { name: "Apps" }).waitFor();

    const shot = path.join(ARTIFACTS, "overview.png");
    await page.screenshot({ path: shot, fullPage: true });

    await page.setViewportSize({ width: 390, height: 844 });
    await page.getByRole("button", { name: "Open navigation" }).click();
    check(
      "the sidebar becomes a drawer below tablet width",
      await page.locator("aside.open").isVisible(),
    );
    await page.keyboard.press("Escape");
    check(
      "Escape closes the drawer",
      (await page.locator("aside.open").count()) === 0,
    );

    // --- Setup: reset asks once and lands on the first-run wizard ------------
    // Both live in the Settings header now; there is no Setup section left.
    await page.setViewportSize({ width: 1280, height: 720 });
    await page.getByRole("button", { name: "Settings", exact: true }).click();
    await page.getByRole("heading", { name: "Settings" }).waitFor();
    await page.getByRole("button", { name: "Reset", exact: true }).click();
    await page.getByRole("heading", { name: "Reset everything?", exact: true }).waitFor();
    check("reset asks once, naming what goes away", true);
    await page.getByRole("button", { name: "Reset everything", exact: true }).click();
    await page.getByRole("heading", { name: "Set up your stack" }).waitFor();
    check("the confirmed reset empties the topology and returns to the first-run wizard", true);

    check("the console raised no JavaScript errors", pageErrors.length === 0, pageErrors.join(" | "));

    console.log(`\n${passed} checks passed; screenshots in ${ARTIFACTS}`);
  } finally {
    await browser.close();
    kill();
    await seerr.close();
    await sonarr.close();
    // Let the server close its database before the directory goes; the
    // fixture admin digest, working copies and screenshots are evidence, not
    // litter: the screenshots are in ui/test-results, the rest goes.
    if (server.exitCode === null) await new Promise((resolve) => server.once("exit", resolve));
    await rm(work, { recursive: true, force: true });
  }
}

main().catch(async (error) => {
  console.error(`\n${error.message}`);
  // The server's own log is the other half of the story: a dead loop turns
  // every later request into a timeout.
  const serverLog =
    typeof globalThis.__smokeServerLog === "function"
      ? globalThis.__smokeServerLog()
      : "";
  if (serverLog) {
    console.error("\n--- server log (tail) ---\n" + serverLog.slice(-4000));
  }
  process.exit(1);
});
