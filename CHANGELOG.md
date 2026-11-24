# Changelog

###### 1.3.4 — 2026-11-24

- Ship the Docker CLI and compose plugin in the image so the separate agent
  stack can run its fixed `compose`/`env` workflows. The BFF still has no
  Docker socket and no compose privilege without one.
- The agent runs as the infra user with only the Docker group added; no root
  process in the container.

# 1.3.3 — 2026-11-24

- The agent gains a generic `env` workflow: allowlisted stack root, relative
  env file, declared `ENV_KEY -> credential` mapping, atomic `0600` rewrite,
  preserved comments/unrelated lines, and a compose recreate of the target
  services. No shell or user code.
- `sync_targets` carries `env_file` and `values`; an older target table is
  rebuilt for the new CHECK constraint.
- The signed `secret.current_changed` event is documented as the custom
  GitOps/Lambda trigger: credential, version and generation, never a value.
- Console target authoring accepts the `env` workflow and mapping.

# 1.3.2 — 2026-11-24

- Reveal is one press and an inline value beside the button; no dialog, stage
  picker or audit checkbox. The audit and the 30-second auto-clear remain.
- The soft-delete/recover/purge UI is gone. The visible action is Delete, which
  removes the Credarr record and stored copy only; the live service secret is
  untouched. The lifecycle API remains available for callers that need it.

# 1.3.1 — 2026-11-24

Fix the first-boot migration and tighten the two new console surfaces.

- A legacy database with plaintext `working_copies` and no KEK now bootstraps
  the key and migrates on first start. A database that already holds encrypted
  versions but has lost its KEK still fails closed.
- Expected value-store refusals answer 503/409 with a sentence, never a bare
  500; the rotation plan paths map `KekUnavailable` explicitly.
- Reveal is a compact anchored panel, not a full-screen dialog: short audit
  acknowledgment, one stage selector, value + copy/hide, 30-second clear.
- The lifecycle section is now "Delete or recover" with the same card, muted
  copy, field and toolbar pattern as the rest of the app detail.

# 1.3.0 — 2026-11-23

The next-generation value lifecycle: an encrypted version store, audited Reveal,
soft delete, adoption, durable sync jobs and an mTLS deploy agent.

### 🔐 Values

- `secret_versions` stores every value with AES-256-GCM under a unique DEK
  wrapped by a file KEK; AAD binds credential, version, stage and attempt id.
  A stage transition re-encrypts; a missing KEK fails every value operation
  closed while metadata stays readable.
- `working_copies` and the plaintext pending table are migrated and emptied;
  the database and WAL are scrubbed after migration.
- `credarr-kek status|init|rotate`; backup format 2 carries the KEK and the
  service keys, and a restore refuses an encrypted snapshot without one.
- `POST /credentials/{name}/reveal`: audited, rate-limited, no-store, 30-second
  UI TTL, CURRENT and PREVIOUS only.

### 🔁 Lifecycle

- Soft delete, restore and explicit purge; tombstoned credentials refuse
  reveal, rotate, adopt, paste and sync.
- Adoption with `verify=none` (unverified) or `verify=process_readback` (the
  engine audit must prove a match; otherwise nothing is stored).
- One CURRENT per credential, one PENDING, bounded retention for abandoned
  versions, one `secret.current_changed` per committed change.

### 📦 Sync and agent

- Commit-barrier outbox, per-target jobs, coalescing to the newest version,
  partial deploys as `retry_wait`, expiry/replay/clock-skew refusals.
- A separate TLS 1.3 mTLS control plane with one-time enrollment, one-day
  client certificates, renewal and immediate revocation.
- `credarr-agent` pulls, verifies the shared-tree generation, and runs the
  allowlisted compose workflow; Docker never enters the BFF.
- The listener tries the hybrid PQ group and records the classical fallback;
  no post-quantum claim is made until the real images exercise it.
- The console gains Reveal, Lifecycle and Agents & sync panels.

## 1.2.0 — 2026-11-07

A state-machine audit of the rotation engine, with the confirmed defects fixed,
an explicit way out of an interrupted run, and one recovery banner per page.

### 🔎 State audit

- `docs/STATE_MACHINES.md` inventories twelve explicit and implicit machines
  (lease, attempt, step, pending secret, holder outcome, executor recovery,
  auto policy, audit ledger, delivery, auth, topology and working copies, loop
  health) with their states, invariants, transitions and every reachable
  invalid state found.
- Ten findings are fixed with regression tests (SM-1…SM-10). SM-2c (a service
  that returns a secret once) and SM-9 (no fencing token at the service) are
  recorded as service-contract limits, not unhandled states.

### 🧩 Rotation

- A closed attempt is immutable: no new step or holder row, and a takeover or
  reclaim wins over a zombie's late finish.
- A crash after RECORD finishes from RECORD instead of minting a second key.
- Reissue mints park their value and record the created and predecessor row
  ids before RECORD, so a crash before or after it adopts the successor and
  revokes the predecessor by id.
- A run that loses the lease after its last step is not reported as success.
- Stored values, service URLs, holders, class, vault and mint mechanism are
  frozen while a run is unfinished; description and notes stay editable.

### 🚪 Recovery

- **Abandon** closes an unfinished rotation without minting or revoking:
  `POST /api/v1/credentials/{name}/rotation/abandon`,
  `credarr rotate <name> --abandon`, and **Abandon this run** in the console.
  It is the exit when the service is unreachable and no resume can run.
- The console shows one recovery banner per page: the page-level banner under
  the app header (Resume in the action bar, Abandon beside the explanation),
  and the stack-wide shell banner only on the other views. The no-step variant
  (every step finished, attempt open) is named too.

### 🐛 Fixes

- Every attempted holder has a row after retry exhaustion, including the one
  that failed.
- A blocked auto-rotation retries on the configured interval with scheduled
  audits off.
- A password change cannot race a sign-in that is verifying the old password.
- Import warns when a surviving name changes issuer but keeps the old stored
  value; the warning title no longer calls every warning audit-only.

### 📦 Ship

- Verified with 1004 Python tests, 220 console smoke checks, 4 container
  integration tests and `ruff`.
- Published as `ghcr.io/ezcodelab/credarr:1.2.0` and `:latest`; the test
  deployment pins `git.ezcloud.casa/admin/credarr:1.2.0`.

### 📖 Documentation

- `docs/STATE_MACHINES.md` added and linked from `docs/README.md`;
  `DECISIONS.md` 53, `LIMITATIONS.md`, `OPERATING.md`, `API.md` and
  `process-lessons.md` record the recovery contract.

## 1.1.0 — 2026-11-01

Graphite ledger console, and unattended rotation for every credential in the
setup wizard.

### 🚀 Features

- Console redesigned as a graphite ledger: quieter surfaces, one accent, dot
  status words, key tiles as the app identity.
- Apps becomes a ledger with a stack-health strip, one row per app and an open
  affordance; it stacks into cards below 960px.
- App detail gains a summary strip and sticky section index; Activity gains a
  three-part summary.
- Development-only design gallery at `/?design` (`npm run dev`), with axe-core
  WCAG scans in the browser smoke.

### 🧩 Rotation

- SABnzbd own key rotates via `set_apikey` and `mode=restart`; Sonarr's
  download-client test exercises it.
- Bazarr own key rotates via `settings-auth-apikey`; a rejected value is
  re-chosen up to three times, then fails closed.
- Every wizard mint has a server auto-rotation run: five Servarr apps,
  Jellyfin, qBittorrent, Seerr, Grafana, Arcane and Gitea.
- The audit exercises qui's connection test, so a qui-held qBittorrent key
  reports `live` instead of `unverifiable`.

### 🐛 Fixes

- `make ship` pushes the apps pin even when the compose pin already matches.
- The deploy report names the running image and detects same-name recreations.

### 📦 Ship

- `make ship` builds, pushes to the Gitea registry, pins
  `homelab-applications` and deploys through Arcane; a branch build tags
  `<branch>-<sha>` and leaves `:latest` on main.
- Published as `ghcr.io/ezcodelab/credarr:1.1.0` and `:latest`.

### 📖 Documentation

- `docs/ROTATION.md` adds the auto-e2e matrix; `SERVICES.md` and `TESTING.md`
  carry the measured versions and live harnesses.
- README rewritten; screenshots and logo regenerated from the shipped console.

## 1.0.0 — 2026-10-29

First public release: find out who holds each API key, whether the copies still
match, and what can be rotated.

### 🚀 Features

- Holder map and audit over each service's own API, reporting every copy as
  `match`, `live`, `drift`, `missing`, `unverifiable`, `absent` or `manual`.
- Plan, preflight, per-holder propagation with verification, durable journal,
  and resume or takeover of an interrupted run; the old key is revoked last.
- Console: Apps, per-app check history, rotation plans, auto-rotation,
  notifications and import/export; values are write-only.
- Opt-in auto-rotation gated on a clean audit; a human-only copy emits
  `auto_manual` naming the copy.
- Notifications to ntfy, an HMAC-signed webhook, Discord, Telegram and SMTP.
- AES-256-GCM backups with a verified restore; read-only Docker discovery, off
  by default.
- Measured services: six Servarr builds, Seerr, Jellyfin, qBittorrent, qui,
  Grafana, Arcane and Gitea; Homepage and Profilarr are manual, Plex and Jackett
  monitor-only.

### 🛡️ Security

- Values are write-only end to end: no response, event, log or validation error
  echoes one.
- One admin, argon2id, 12-character minimum, one generic failure sentence and a
  durable five-failure lockout.
- A password change rotates the caller's session and revokes every other one.
- Bounded responses, core dumps disabled, `X-Frame-Options: DENY`, path-safe
  archive restore.
- Topology replace requires `?confirm=replace`, because it prunes working
  copies and policy.

### 🐛 Fixes

- A rotation whose only remaining work is manual reports success plus `manual`,
  not failure.
- The Servarr backup reader waits for the archive to finish before downloading.
- A resumed run no longer claims no key was minted unless the service already
  held it.
- qBittorrent copies are confirmed with `downloadclient/test`.

### 🧭 Behaviour

- `LIVE` is acceptance by the service, never equality.
- Manual copies are neutral and do not change a credential verdict.
- Exit codes 0–5 are a public interface; 5 (refused) is not 3 (misconfigured).
- No Abandon action or snapshot undo; resume is the convergence path and the
  encrypted backup is the recovery story.
- One-sink-per-kind notification routes were removed before release, without
  aliases.

### ⚙️ CI

- GitHub Actions runs `check`, `container` and `smoke` on push and pull request;
  `smoke` drives the built console in Chromium.

### 📦 Release

- Published as `ghcr.io/ezcodelab/credarr:1.0.0` and `:latest`.

### ⚠️ Limits

- Basic UI login, Arcane beyond its pinned digest and the Lidarr, Readarr and
  Whisparr indexer rows were unproven at 1.0.0. See `docs/LIMITATIONS.md`.
