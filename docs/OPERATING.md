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

`POST /credentials/{name}/plan` is the dry run. It returns the exit code and changes nothing. `POST /credentials/{name}/rotate` performs it with the typed credential name as confirmation. Every attempt lands in Activity as `rotation_refused` (exit 5, recorded but never notified), `rotation_failed`, `rotation_manual` (mint succeeded, named manual copies remain), or `rotation_succeeded`. Resume uses the same explicit takeover as the CLI `--take-over`. The journal's started-but-unfinished steps are the only safe guide. There is no Abandon button and no snapshot undo. Resume is the convergence path, and the encrypted backup is the disaster recovery story. CLI: `credarr rotate <name> --dry-run` (default) or `--apply [--yes]`.

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

## Backup and restore

```sh
install -m 600 /dev/null /config/backup.passphrase   # one line, owner-only
credarr-backup -c /config/credarr.yaml --config-dir /config \
  --out /config/backups/credarr-$(date +%F).backup \
  --passphrase-file /config/backup.passphrase        # stop the server first
```

One AES-256-GCM file holding `app.db` plus config (never the rotation journal). A restore verifies before writing (decrypt, manifest shape, `PRAGMA integrity_check`), keeps `app.db.pre-restore`, and refuses hot sidecars, short passphrases, and group- or world-readable passphrase files. The passphrase is the only thing between the file and every stored value. Losing it makes the archive unrecoverable.

## Discovery (optional)

Off unless `CREDARR_DOCKER_URL` names a Docker API (normally a read-only socket proxy: container reads only, no POST, `:ro` socket, unexposed port). One `GET /containers/json` per scan. It ignores environment and labels, proposes undeclared services with a guessed URL, and never writes topology or restarts anything.

## Console map

**Apps** (landing): one card per app with health, URL, stored-key state, copies, and Plan, Check, Rotate. **App detail**: connection, check history, copy editor, rotation plan, auto-rotation interval. **Activity**: last audit plus event ledger. **Settings**: security, audit schedule, API keys, notifications, import/export, setup. Values are write-only in the browser. No credential value is kept in local storage.
