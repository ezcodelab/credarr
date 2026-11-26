# Operating

## Configuration

- `credarr.yaml` holds hosts, service URLs, and the manifest path. It is gitignored: it names your hosts, which is reconnaissance. `credarr.example.yaml` is the committed template.
- The server audits the topology in `/config/app.db`, so a UI-only install needs no manifest file. `credentials.yaml` is the engine and CLI declaration and the value-free import/export format.
- First boot writes a minimal `credarr.yaml` and an empty manifest when none exist. Existing files are never overwritten.
- One process owns `/config`: the server, `--once`, `credarr-backup`, or a CLI apply. A second process exits 3 on `/config/app.lock`. `/config` must be a local filesystem. SQLite WAL and POSIX locks do not survive NFS or Unraid user shares. The app refuses those mounts at startup.
- Topology, value, service, policy, and import writes share one stack lease with every HTTP and auto rotation. A conflict answers 409. A killed process can fence writes for up to 15 minutes while the lease ages out.

## Audit

On demand (`POST /api/v1/audit`), on a persisted schedule (Settings, Audit schedule, 1 to 10080 minutes, applied live, can be switched off), or scoped to one credential (`?only=<name>`, recorded as a check, never as stack evidence). Manual audits and due auto-rotation audits still run with the schedule off. A full audit can run as a server-side job (`?wait=false` returns 202, poll by id) so a dropped proxy or tunnel does not lose it. Full audits have measured 103 seconds, so direct API callers should set a longer read timeout. Engine CLI: `credarr audit [--credential NAME]`.

## Rotation

`POST /credentials/{name}/plan` is the dry run. It returns the exit code and changes nothing. `POST /credentials/{name}/rotate` performs it with the typed credential name as confirmation. Every attempt lands in Activity as `rotation_refused` (exit 5, recorded but never notified), `rotation_failed`, `rotation_manual` (mint succeeded, named manual copies remain), or `rotation_succeeded`. Resume uses the same explicit takeover as the CLI `--take-over`. The journal's started-but-unfinished steps are the only safe guide. When the service is unreachable and no resume can run, `POST /credentials/{name}/rotation/abandon` (console: Abandon this run; CLI: `credarr rotate <name> --abandon`) closes the record without minting or revoking, leaving stored and parked values untouched; there is no snapshot undo. Resume is the convergence path, and the encrypted backup is the disaster recovery story. CLI: `credarr rotate <name> --dry-run` (default) or `--apply [--yes]`.

## Servarr own-key rotation

The only mint: the service backup API plus its own restart endpoint (`POST /api/<version>/system/restart`). That needs a supervisor that starts the app again (for example LinuxServer s6 images). Three routes, inferred by `GET /credentials/{name}/rotation-options`, in this order:

1. **Backup/restore** (default, automatic): download the backup, read `config.xml` out of it, restore a config-only ZIP with the chosen key, restart, then require the new key before touching holders. Destructive to the service `config.xml`. The temporary archive is a full database backup and is secret in full. The download is capped at 1 GiB, the extracted `config.xml` at 8 MiB.
2. **Reconstructed restore** (opt-in `write.reconstruct_config`, automatic): no backup download, no UI password, no auth change. It rebuilds `config.xml` from `GET /config/host`. It refuses PostgreSQL (or a missing `databaseType`) and a missing critical host field. Unexposed fields (theme, syslog, log rotation) may reset.
3. **Manual mint** (opt-in `write.manual_mint`): rotate in the service UI, supply the key (`manual_value` / `--manual-value-stdin`). The run proves the old key dead (HTTP 401 only) and the new one live. A 403 or unknown answer proceeds without exercise-only proof.

With UI authentication on, the backup download answers `302 /login` even though the API key works. In order, the fixes are: a stored UI credential (`write.ui_password`; Forms login measured on Sonarr only, Basic is wired but unproven and not a support claim, external/OIDC is refused), the reconstructed restore, the manual mint, or `Disabled for Local Addresses`. Only an old key answering **401** after the restart counts as proven dead.

## Auto-rotation

Off by default, per credential. Enabling requires the typed name plus `accept_manual` when a manual or unproven copy exists. Enabling from off or paused resets the baseline, so it never fires immediately. Due is `max(newest completed journal rotation, enabled_at) + every_days` (1 to 365; manual, CLI and console runs count, so a human renewal defers the clock). Every gate fails closed: supported mint, plan with no missing writer, fresh audit with exact credential and holder coverage (`MATCH` or `LIVE`, proven copies clean), no unfinished attempt or step anywhere (unwindowed, so a stale kill still blocks), not paused. A manual or unproven copy rotates with an `auto_manual` event naming the copy. The policy stays enabled and the due clock advances. A failure or interruption pauses. Only a human resume and abandon plus an explicit re-enable clears it. The audit-to-write window cannot be closed, and the console states it.

## Notifications

Named services (`ntfy`, `webhook`, Discord, Telegram, SMTP `email`). Each has its own enabled switch, event-kind selection, and delivery stats. Events are status changes (plus `test`, `auto_*`, `rotation_*`). They carry names, statuses, and the scrubbed audit sentence, never values. `ntfy` posts `match -> drift` with priority 4 on drift. `webhook` sends one JSON document per event, optionally HMAC-signed. Discord mentions stay off unless opted in. Telegram puts the bot token in the request path only. `email` follows the SMTP host, port, username, write-only password, From, recipients, TLS and auth model (STARTTLS, implicit TLS, `login` and `crammd5` remain unmeasured, so do not treat the field model as provider compatibility). Recorded-but-never-notified kinds are marked `silent`, not queued. Every form offers Test before Save without writing a ledger row. Reusing a stored secret requires an unchanged destination (URL, or SMTP host and port). Delivery is one ledger row per event and service, retried with capped backoff. One dead sink can delay others at one-admin load.

## Stored values and reveal

Values are encrypted with AES-256-GCM under a per-version data key wrapped by
`/config/kek.json`. The KEK is created on a fresh store and never recreated
after a value exists; a missing or unreadable KEK makes every value operation
answer 503 while metadata stays readable. `credarr-kek status` shows the key
path and how many versions are not under the active key; `credarr-kek rotate`
rewraps every DEK and keeps the old key in the keyring. Losing the KEK is
unrecoverable; the encrypted backup includes it.

`POST /credentials/{name}/reveal` is the only path that returns a value. It is
audited before the value is returned, limited to five per minute per actor and
per credential with a two-second cooldown, and the console clears the value
after 30 seconds. Soft-deleted credentials are not revealable.

## Sync and agents

A target is a stack path, project name and service set on one agent. The BFF
never runs Docker. The agent is the separate `credarr-agent` image on the
Docker host; it pulls over a TLS 1.3 mTLS listener on `CREDARR_AGENT_PORT`
(default 8443) and runs only the allowlisted `compose` or `env` workflow under
its `--allowed-root`. It reaches the Docker API through a LinuxServer socket
proxy (`DOCKER_HOST=tcp://socket-proxy:2375`) restricted to the endpoints
compose uses. The raw socket is a fallback with the full API. The console shows
the listener address and the exact agent URL in Settings -> Agents & sync. The
agent is the client: its `--server` URL must use the same host and port, and
the BFF never discovers an agent.

The shared vault tree is mandatory for a target: set `CREDARR_VAULT_TREE` and
`CREDARR_VAULT_TREE_KEY` before creating one. Audit and rotation still work
without a tree or an agent; the console disables target creation and says what
is missing. Delivery is advisory: a failed or pending job does not change a
rotation exit code. `retry_wait` is not success; a partial deploy re-runs the
whole service set. See `docs/SYNC.md` for the enrollment runbook and the state
machine.

## Backup and restore

```sh
install -m 600 /dev/null /config/backup.passphrase   # one line, owner-only
credarr-backup -c /config/credarr.yaml --config-dir /config \
  --out /config/backups/credarr-$(date +%F).backup \
  --passphrase-file /config/backup.passphrase        # stop the server first
```

One AES-256-GCM file holding `app.db`, the config, the KEK, the shared-tree key and the agent CA/server keys (never the rotation journal). A restore verifies before writing (decrypt, manifest shape, `PRAGMA integrity_check`), keeps `app.db.pre-restore`, and refuses hot sidecars, short passphrases, and group- or world-readable passphrase files. The passphrase is the only thing between the file and every stored value. Losing it, or losing the KEK carried inside, makes the archive unrecoverable; a restore without a KEK in the archive refuses an encrypted database rather than writing a half-recovered one.

## Discovery (optional)

Off unless `CREDARR_DOCKER_URL` names a Docker API (normally a read-only socket proxy: container reads only, no POST, `:ro` socket, unexposed port). One `GET /containers/json` per scan. It ignores environment and labels, proposes undeclared services with a guessed URL, and never writes topology or restarts anything.

## Console map

**Apps** (landing): a stack-health strip and a ledger with one row per app (key tile, title, state + why/fix, copies, open). **App detail**: a summary strip, a sticky section nav, connection, check history, copy editor, rotation plan, auto-rotation interval. **Activity**: a three-part summary and the event ledger. **Settings**: security, audit schedule, API keys, agents & sync, notifications, import/export, setup. Values are write-only except the audited Reveal dialog. No credential value is kept in local storage.
