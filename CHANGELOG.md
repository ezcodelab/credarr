# Changelog

## 1.1.0

The console becomes a graphite ledger, and every credential the setup wizard
offers now rotates unattended on a measured path.

### Rotation

- **SABnzbd's own key** rotates through `mode=config&name=set_apikey` and
  `mode=restart`: the old key answers 403, the new key 200, and Sonarr's
  SABnzbd download-client row is exercised by its own test.
- **Bazarr's own key** rotates through the measured `settings-auth-apikey`
  form write with no restart. A value the service rejects with 406/422 is
  re-chosen up to three times, after re-proving the old key live, and the run
  fails closed with nothing parked.
- **Every setup-wizard mint has a server auto-rotation run**: the five Servarr
  apps through backup/restore (Prowlarr application rows, Sonarr indexer rows),
  Jellyfin held by Seerr's settings section, qBittorrent held by qui's
  connection test, and Seerr, Grafana, Arcane and Gitea with a deploy-time
  Homepage copy recorded as `auto_manual`.
- The audit exercises a qui instance through qui's own connection test, so a
  qui-held qBittorrent key can reach `live` instead of `unverifiable`.

### Console

- Redesigned the console around a graphite ledger: quieter surfaces, one
  interaction accent, status words with dots instead of badge soup, and key
  tiles as the app identity anchor.
- Apps is now a ledger with a stack-health strip, one row per app, copies and
  an open affordance. It stacks into a card below 960px.
- App detail starts with a summary strip and a quiet sticky section index;
  Activity starts with a three-part summary. Settings keeps its anchored
  sections.
- Added `docs/UI_SYSTEM.md` and a development-only gallery at `/?design` under
  `npm run dev`, and axe-core WCAG scans in the browser smoke.
- Breakpoint, section-index and status-label polish after the first pass.

### Ship and packaging

- `make ship` builds the image, pushes it to the Gitea registry, pins the tag
  in `homelab-applications`, and deploys through Arcane. A branch checkout is
  tagged `<branch>-<sha>` and never moves `:latest`; the apps pin is pushed
  even when the compose file already names the tag, and the deploy report
  prints the running image.
- The package version is `1.1.0`.

### Docs

- README rewritten around the ledger screens, with the screenshots and logo
  regenerated from the shipped console.
- `docs/ROTATION.md` records auto-e2e coverage per mint; `docs/SERVICES.md`
  and `docs/TESTING.md` carry the measured versions and live-harness table.

### CI and release

- The image is published as `ghcr.io/ezcodelab/credarr:1.1.0` and `:latest`.

## 1.0.0

Credarr maps who holds each API key, audits every copy against the canonical
value, and rotates the keys it can prove. First public release.

### Features

- **Holder map and audit.** Every declared copy is compared over its service's
  own API and reported as `match`, `live`, `drift`, `missing`, `unverifiable`,
  `absent` or `manual`. Manual copies are never counted as drift.
- **Rotation.** Plan, preflight, per-holder propagation with verification,
  durable journal, and resume or takeover of an interrupted run. The old key is
  revoked last whenever the service allows it.
- **Console.** Apps, app detail with per-app Check, Activity, and Settings for
  security, audit schedule, API keys, notifications and import/export. Values
  are write-only in the browser.
- **Auto-rotation.** Opt-in per credential, gated on a fresh clean audit. A copy
  that needs a human rotates anyway and emits `auto_manual` naming the copy.
- **Notifications.** ntfy, webhook (HMAC-signed), Discord, Telegram and SMTP
  email. Events are status changes and never carry values.
- **Encrypted backups.** `credarr-backup` writes one AES-256-GCM file holding
  `app.db` and the config; `--restore` verifies before writing.
- **Optional Docker discovery.** Read-only, off by default, proposes services
  and never writes topology.
- **Services.** Servarr on six measured builds (backup/restore, reconstructed
  restore, manual mint, Forms UI login), Seerr, Jellyfin, qBittorrent, qui,
  Grafana, Arcane and Gitea. Homepage and Profilarr are manual copies; Plex and
  Jackett are monitor-only.

### Security

- Secrets are write-only end to end: no response, event, log or validation error
  echoes a value. Bounded responses, core dumps disabled on both entry points,
  `X-Frame-Options: DENY`, and path-safe archive restore.
- Changing the admin password rotates the caller's session in one transaction
  and revokes every other one, so the browser that made the change stays signed
  in.
- One admin, password only: argon2id with a 12-character minimum, one generic
  failure sentence, and a durable five-failure lockout.
- Raw YAML topology replace requires `?confirm=replace`, because it prunes
  working copies and policy.

### Fixes

- A rotation whose only remaining work is a manual copy is reported as
  "rotation succeeded" plus "manual", not as a failure.
- The Servarr backup reader waits for the Backup command to finish before
  downloading; Radarr lists the archive while it is still being written.
- A resumed run no longer claims no key was minted unless the service already
  held it.
- qBittorrent copies in Sonarr and Radarr are confirmed with
  `downloadclient/test`, so they no longer carry the unproven warning.
- Indexer tests distinguish a disabled upstream (`410`) or empty results from a
  rejected key, and keep the copy `live`.
- Holder tests get a 90 second budget, longer than a slow indexer test.
- Outbound calls identify as `credarr/<version>`, so a Cloudflare-fronted
  service does not reject Python's default user agent.
- Per-app Check runs one credential without touching the stack ledger, events or
  the auto-rotation gate.
- A saved URL that arrives late no longer overwrites what the operator typed.

### Behavior notes

- Classes: `A` and `A-unv` rotate and name a manual copy as a step; `B` and
  `never_rotate` refuse with exit code 5. There is no class switch in the UI.
- Auto-rotation accepts a fresh `MATCH` or `LIVE` audit with exact coverage.
  `LIVE` is acceptance by the service, never equality.
- Manual copies are named and neutral: they do not change the credential
  verdict, and an all-manual credential reports `match`.
- There is no Abandon action and no snapshot undo. Resume is the convergence
  path; the encrypted backup is the recovery story.
- The one-sink-per-kind notification routes were removed before release, with no
  aliases.

### CI and release

- GitHub Actions runs `check`, `container` and `smoke` on every push and pull
  request. `smoke` drives the built console in Chromium.
- The image is published as `ghcr.io/ezcodelab/credarr:1.0.0` and `:latest`.

### Limits

Basic UI login, Arcane beyond its pinned digest, and the Lidarr, Readarr and
Whisparr indexer rows remain unproven. See `docs/LIMITATIONS.md`.
