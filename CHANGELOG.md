# Changelog

## 1.0.0

- Notification services can be **Tested before saving**; the test uses the
  form's current values and writes no ledger row. An edit may reuse a stored
  secret only when the destination is unchanged; a changed URL or SMTP
  host/port requires the secret again. The button sits between Cancel and Save,
  and successful test results read `accepted` instead of repeating the delivery
  pill.
- Form actions use one **Save** label across the console; the audit schedule
  saves to `Saved.` without the old scheduler sentence.
- The audit schedule has an enabled/off switch, persisted and applied live.
  Off stops timed audits; manual and due auto-rotation audits still run. Off
  shows **Enable schedule**; on shows **Save** and **Disable schedule**.
  Auto-rotation uses the same primary-action shape.
- Setup accepts the intentional repeat of `homepage.label` across app
  credentials; duplicate writable copies are still refused.
- Confirming a rotation keeps the page in place; the header carries
  **Rotating…** and the panel status sits at the top.
- Setup's common-copy prefill skips a copy another key already owns, and a
  duplicate-copy error names the key and points at Advanced instead of the
  old target/selector wording.
- Telegram's form starts at the public Bot API base, so Chat ID and token are
  enough for a normal setup.
- Email notifications use Arcane's SMTP field model: host/port, username,
  write-only password, From, recipients, TLS mode and auth mode. Check history
  and Activity remain unchanged; email goes through the same retry ledger.
- Check history and Activity now explain non-success results with the
  holder-level sentence. `unverifiable` and `absent` were excluded from the
  previous fallback, so Prowlarr could show a bare pill with no reason; older
  events are filled from their run on read, without rewriting history.
- Stack health treats a successful `live` audit as **all clear** instead of
  falling through to “did not leave every credential with a full comparison.”
  A `live` holder is exercised and accepted by its service; the app card already
  says `ok`, and manual copies remain named without becoming warnings.
- Full audits run as a server-side job from the console:
  `POST /api/v1/audit?wait=false` answers 202 and the console polls
  `GET /api/v1/audit/jobs/{job_id}`. A dropped Cloudflare tunnel or proxy
  timeout no longer loses the audit or leaves the Run audit button wedged;
  `GET /api/v1/status` exposes the active job so a reload resumes polling. The
  synchronous default and scoped `only=` checks are unchanged for API clients.
- Per-app **Check**: `POST/GET /api/v1/audit?only=<credential>` runs a scoped
  engine audit, records separate `audit_checks` history, and leaves the stack
  ledger, events and auto-rotation freshness gate untouched. The app page adds
  Check between Plan and Rotate and lists the bounded history.
- Check history shows `no holders` for a credential with no consumers, instead
  of the engine's `manual` copy status.
- Profilarr Arr copies are a registered **manual** target
  (`profilarr.arr_config[<instance>]`). Latest API v1 has no Arr write/read
  route; no automatic holder rotation is advertised.
- Profilarr reviewed against source `797fb2b` / image v2.3.1, with a
  disposable-container probe.
- API-key `last_used_at` is throttled to once a minute, so automation polling
  does not turn every request into a SQLite write.
- Changing a service URL now re-enters its stored API key; the URL move and
  the key write commit together, and the console asks before redirecting the
  old key to a new destination.
- Console timestamps now use the server `TZ` (reported by `/status`) instead
  of the browser's timezone, so every operator and the container clock agree.

The public 1.0.0 release ships the full single-admin, single-process Credarr
console and engine.

### Shipped

- Apps / Activity / Settings console: setup wizard, app connection and key
  paste, holder map, on-demand and scheduled audit, event ledger, and a
  shield-key favicon.
- Settings → Audit schedule: the audit cadence is persisted in `app.db`,
  bounded to 1–10080 minutes, and applied to the running scheduler without a
  restart. The boot flag is only the initial default. A due auto-rotation now
  triggers its own audit first, so a long monitoring cadence cannot delay a
  scheduled rotation.
- Strict topology manifest import/export with replace, merge and prune.
- Plan, typed run, resume/takeover, journal and pending-value recovery.
- Named notifications: ntfy, generic webhook (HMAC-signed), Discord, Telegram,
  and SMTP email.
- Optional read-only Docker discovery, off by default.
- Opt-in auto-rotation with hard gates and a per-credential interval.
- Encrypted `credarr-backup` / `--restore` CLI.
- Servarr backup/restore mint (six measured SQLite builds), opt-in
  reconstructed restore, opt-in manual mint, and the Forms UI-login path.
- Jellyfin, Seerr, qBittorrent, qui, Grafana and Gitea rotation within their
  recorded versions; monitor-only rows for Gitea webhooks, Homepage, Plex,
  Jackett and profilarr.
- Local build image `credarr:local` and a five-minute compose quick start.
- First boot writes a minimal `credarr.yaml` and empty `credentials.yaml` if
  missing, so the console can be set up entirely in the UI; an existing config
  is never rewritten.

### Security fixes

- The admin login keeps its password-only form, with a durable
  five-failure/five-minute lockout, one generic failure sentence, and the
  existing 12-character argon2id minimum. Servarr's measured one-character
  minimum was deliberately not adopted for a console that stores every service
  key.

- A stored service key can only be used by `/services/test` at that service's
  saved URL; testing another URL requires a typed key.
- Raw YAML topology replace requires `?confirm=replace`, because it prunes
  working copies and policy.
- Configuration writes and rotations share a stack lease, so an import, delete,
  holder edit or URL change cannot race a run into pending-state loss or a
  second mint.
- Ordinary API responses are bounded; an oversized body is refused instead of
  buffered. Notification sink answers use the same bound.
- Validation errors name the rejected field and the fix, never the submitted
  value: a rejected password, API key or pasted credential is not echoed in the
  422 body.
- The server and backup entry points disable core dumps before reading a
  config, passphrase or working copy.
- The Servarr backup reader caps control responses, the full archive at 1 GiB
  and `config.xml` at 8 MiB; an oversized archive is still deleted from the
  service before the error.
- Responses carry `X-Frame-Options: DENY` and a `frame-ancestors 'none'` CSP.
- Restore rejects config names that are paths, `.` or `..`, and ignores extra
  archive members.

### Behavior changes

- Class A and A-unv both run and name a manual copy as a step; `B` and
  `never_rotate` still refuse. There is no user-facing class switch.
- Seerr's own key rotates with no holders: `class: A` plus
  `write.mechanism: seerr_regenerate` is the supported declaration. A
  `class: B` or `never_rotate` declaration is a deliberate audit-only choice,
  not a missing Seerr path.
- Auto-rotation accepts a fresh LIVE audit as well as MATCH, with exact
  coverage, stored-key preflight and old-key death still required. LIVE never
  becomes equality.
- Auto-rotation can run a plan with manual copies. The key and every writable
  copy rotate, an `auto_manual` event names the copy left for a human, the
  policy stays enabled, and the due clock advances from the completed mint.
  Real findings, a blocked plan, a failed preflight, a manual mint or an
  unfinished run still block. Enabling on such a credential requires
  `accept_manual` after an explicit console acknowledgement.
- A topology import warns when an `_api_key` credential is declared
  audit-only/`never_rotate` even though its service has a mint source. The
  import succeeds; the warning names the key and how to make it rotatable.
- Auto-rotation's "Rotate at most every" interval can be changed while enabled:
  the update keeps the existing due baseline and recalculates the next run.
- The Apps page has one Stack Health pane with the last run time; the separate
  Audit finished banner and its status pill are gone.
- Homepage is holder-only: it has no dashboard API key, so it is not offered as
  a connectable app. Homepage labels remain copy targets and are neutral in
  audit results. A manual copy is labelled `manual`, excluded from the
  credential verdict (an all-manual credential reports `match`), and marked on
  its app card. A manual copy is tracked by one Confirm rotation/Clear
  reminder card, not per-copy success pills.
- The app detail keeps a local, per-browser reminder checkbox for a manual copy
  left by a rotation. It is explicitly reminder-only and never feeds the audit
  or a rotation gate. A saved reminder is reconciled with the current manual
  targets, so removing a holder clears a stale card instead of leaving a
  Seerr-only app telling you to update a Homepage label.
- A manual copy (Homepage label, manual value, no-writer target) is a
  named manual step for both class A and A-unv. There is no user-facing class
  switch: the key rotates and the console asks you to confirm the manual
  copies.
- An all-unprovisioned audit summarizes as ABSENT instead of MATCH; exit stays
  0.
- The per-service notification Test reaches only that service. Its `test` event
  carries a recipient and is never broadcast on a later tick. The original
  one-sink-per-kind `/notifications` read/write and the all-sinks
  `/notifications/test` endpoint are removed before the first public release;
  there are no aliases or shims.
- Deleting a credential is refused with 409 while it has an unfinished rotation
  step or an open attempt. Resume or take it over first; deletion is not an
  Abandon action.
- A rotation whose only remaining work is a declared manual copy is recorded as
  `rotation_manual`; Activity shows green “rotation succeeded” plus a neutral
  “manual” pill instead of “rotation failed”. Real failed, unreached or
  unconfirmed holders stay red.
- The Apps page no longer shows a YAML-only service as **Not connected** unless
  the current topology declares it. A service deselected in setup can be added
  later through **Connect an app** without leaving a permanent gap card.
- The setup wizard suggests only `qBittorrent:apiKey` for a qBittorrent API key,
  not a duplicate password-field copy. The Used in table can remove one copy
  without changing its sibling or using a zero count.
- The wizard no longer labels the API key field “(required)” when URL has no
  such label, and the changed-URL test message now says to save the URL before
  testing with the stored key.
- Auto-rotation distinguishes a manual copy from a copy that is written
  automatically but cannot be verified automatically (for example *arr
  indexer rows with no measured test route).
- qBittorrent copies in Sonarr/Radarr download-client rows are now confirmed
  by the services' own `downloadclient/test` route. Measured 2026-10-26 on
  Sonarr 4.0.20.3014 and Radarr 6.4.4.10685: live key 200, revoked stored key
  400, rotated key 200. Those copies no longer carry the unproven warning.
- Indexer tests now distinguish a disabled upstream indexer (`410 Gone` after
  Prowlarr authentication) and `Query successful, but no results…` from a
  credential failure. Each keeps the copy `live`, preserves the service's
  explanation, and does not force the count down to the number of enabled rows.
- The Servarr backup reader now waits for the Backup command to complete before
  downloading. Radarr lists the ZIP while it is still being written, so the old
  reader could request it too early and receive HTTP 500 from the download
  route. A missing command id fails closed, transient post-completion 5xx
  downloads are retried, and the parent timeout has headroom for cleanup.
  Rendered errors also drop the literal `hint:` prefix; the corrective sentence
  follows directly.
- A retry that reused a parked candidate no longer claims “No new key was
  minted” unless the service already held that key; a real restore or regenerate
  is reported as the mint it was. The panel also stops showing “Rotating…” once
  the run result is on screen, during the post-run audit refresh.
- Adding an app now attaches to an existing seeded service definition and
  updates its URL instead of failing with a 409. Error sentences are
  rendered with a capital first letter; brand names such as qBittorrent
  and qui keep their case.
- Outbound service calls now identify as `credarr/<version>`. Cloudflare
  deployments that reject Python's default User-Agent can be reached
  over the public hostname without joining the service's Docker
  network; verified against `https://jellyfin.ezcloud.me`.
- Holder tests now have a 90-second transport budget instead of 25.
  Radarr's own indexer test can wait longer than that on a slow
  upstream; the old budget killed the local subprocess and reported
  `local API call timed out`. Inconclusive rows now name their index
  in the audit detail.
- The app page can **Check** one app without auditing the whole stack:
  `POST /api/v1/audit?only=<credential>` runs the scoped engine check, records
  it in separate `audit_checks` history, and leaves the stack ledger, events
  and auto-rotation freshness gate untouched. The header adds Check between
  Plan and Rotate, shows `Checked <timestamp>.`, and the page lists scoped
  checks beside full-audit rows.
- Apps, the setup editor and app detail read `/services?observe=false`
  instead of waiting for live version probes they never rendered. The full
  observation report now probes services in a bounded pool. Topology reads
  batch the working-copy and rotation-watermark queries, and the post-rotation
  audit runs after the result is shown instead of holding “Rotating…”.
- A saved URL read that lands after the operator starts editing no longer
  replaces the typed value; the first save wins the race instead of the stale
  response.
- Configuration and manifest parsing now reject unknown keys, repeated keys,
  non-integer versions and non-UTF-8 files with their normal configuration
  errors. A repeated consumer target is rejected; distinct qualified rows in
  one slot remain valid.
- `make check` now runs the UI unit tests as well as Python lint/tests.
- Version 1.0.0; the unused `itsdangerous` dependency is removed. The
  classifier is `5 - Production/Stable` for the public release.

### Demoted for v1

- Servarr Basic UI-password login is not a supported claim (Forms is measured;
  Basic remains unproven).
- Arcane's managed badge is bounded to the pinned `sha256:47af3e1a...` image
  that reported 2.17.0; an unpinned image remains monitor-only.
- Snapshot/restore undo was never implemented and is not advertised; use the
  encrypted backup CLI.

### Upgrade and backup

- Back up before upgrading (`credarr-backup --out ...` with the server
  stopped), deploy one pinned image, then verify health and run an audit.
  Schema upgrades are forward-only; there is no downgrade support.
- Existing beta `app.db` files are migrated in place by the guarded schema
  initialiser; a failed restore keeps `app.db.pre-restore` for recovery.
