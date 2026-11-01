# Changelog

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
