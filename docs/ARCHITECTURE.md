# Architecture

Monorepo, one version, one Docker image: engine library + CLI, Python HTTP
server (BFF + scheduler), and a Svelte SPA served from the same origin by the
same process.

## Repository layout

The two projects this documentation follows are single-runtime applications:

- **Profilarr** is one SvelteKit app. `src/lib/server` and `src/lib/client`
  split the concern inside one package, one toolchain (Deno), one build.
- **Seerr** is one Next.js app. `src/` and `server/` are the two halves, again
  with one `package.json`, one runtime, one build.

Credarr is **two runtimes on purpose**, and the tree keeps them apart:

| Path | Runtime | Built by |
| --- | --- | --- |
| `src/credarr/` | Python engine library + CLI | the wheel |
| `src/credarr_server/` | Python BFF, scheduler, loops | the wheel |
| `ui/` | Node/Svelte SPA | Vite, then copied into `src/credarr_server/web` as package data |

The consequences that decide the layout:

1. **The SPA is a build artifact of a different toolchain.** `make web` runs
   Vite and copies `ui/dist` into the Python package; `pyproject.toml` ships it
   as `package-data`. Moving `ui/` under `src/` would not remove that step. It
   would only hide a Node build inside a Python source directory, where
   `setuptools` package discovery and `ruff` would both need exclusions.
2. **The image builds them in separate stages.** `Dockerfile` builds the SPA in
   a `node` stage and the wheel in a `python` stage; the runtime carries neither
   Node nor a source tree. One directory for both would still need two stages.
3. **Development loops differ.** `make serve` runs Python with no Node
   installed; `make ui-dev` runs Vite against the BFF. Neither path needs the
   other's toolchain.
4. **The API is the seam, and it is tested as one.** The SPA talks only to
   `/api/v1` on its own origin; the route set is pinned by tests. That contract
   is the integration point a merge would not improve.

**Recommendation: keep `src/` and `ui/` separate.** Merging would copy a
single-runtime convention from projects that have a single runtime, and would
add packaging and lint configuration to buy a directory name. If the two halves
ever share a language, revisit; until then the split is the honest shape.

## Modules

```
src/credarr/model.py        the manifest: declared state, parsed unforgivingly
src/credarr/rotate.py       the planner: refuses what cannot be delivered
src/credarr/executor.py     preflight, propagation, verification, restart
src/credarr/writers.py      holders: who can write a value into what
src/credarr/targets.py      the static target registry (no local read path)
src/credarr/provenance.py   the version each capability was measured against;
                            managed vs monitor-only; display claims only
src/credarr/transport.py    run_python(code); local subprocess for API calls
src/credarr/journal.py      SQLite: attempts, steps, locks, holders
src/credarr/audit.py        observed state (statuses + reason codes)
src/credarr/report.py       human + versioned JSON output
src/credarr_server/store.py the topology store: the manifest as rows, imported
                            and exported through the engine
src/credarr_server/app.py   the BFF: /api/v1 (pinned contract), the audit loop
                            thread, and the health signal when it dies
src/credarr_server/auth.py  single admin: argon2id password, lockout, hashed
                            server-side sessions, API keys stored hashed
src/credarr_server/{source,audit_log,scheduler}.py
                            the runtime seam (working copies), audit history,
                            and the audit loop
src/credarr_server/notifier.py
                            ntfy, webhook, Discord, Telegram and email delivery;
                            events are status changes, never values
src/credarr_server/discovery.py
                            optional read-only Docker scan; proposals and
                            capability diffs, never a topology write
ui/                         the SPA (Svelte + Vite); `make web` builds it into
                            src/credarr_server/web, which the BFF serves at "/"
```

## Stores

`/config/app.db` (SQLite/WAL) is the runtime source of record: topology,
working copies (the canonical values at runtime; a declared vault reference
is provenance and is never read), journal, audit ledger, event and delivery
rows, notification services, sessions, API-key hashes, auto-rotation policy.
`credentials.yaml` is the engine/CLI declaration and the value-free
import/export format. The journal is event-only: attempts, started-before-run
steps, locks, holders. No values, no fingerprint diffs, ever.

## Invariants

- **Strict API-only.** Every holder read and write goes over a service API.
  No service config path, no probe/adapter layer, no remote shell.
- **One implementation of plan/run/audit.** The product layer imports the
  engine; the CLI and the server produce the same blockers, ordering, and
  exit codes from the same code.
- **Secrets never reach output.** Values are wrapped; messages carry lengths
  and shapes, never values; `--json` emits JSON only.
- **Rotation order is the contract** (see `CONCEPTS.md`). Interrupted runs
  resume or are abandoned; never auto-rerun.
- **Classes are read, not decoration; exit codes 0–5 are a public interface.**
- **One process owns `/config`** (`app.lock`); one stack lease serialises
  topology/rotation mutations (conflict: 409).
- **Discovery is read-only and optional; restart is service-native**, never a
  Docker control surface.
- **Manifest validation stays unforgiving:** unknown target/key, duplicate
  keys, two credentials naming one vault entry, and broken class promises are
  all errors, never skips.
