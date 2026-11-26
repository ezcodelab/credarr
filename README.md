<p align="center">
  <img src=".github/assets/credarr-logo.png" alt="credarr" width="360">
</p>

---

**Find out which of your services hold each API key, whether the copies still match, and what can actually be rotated. Then rotate it.**

Credarr keeps a holder map, audits every readable copy against the canonical value, and rotates the keys it can prove.

## What it does

- **Audit** every declared credential against what its holders actually serve. Drift, unverifiable, absent and manual copies are reported in their own words. Never a silent skip.
- **Plan, then rotate.** A planner that refuses what it cannot deliver, preflight that fails before anything is minted, per-holder propagation with verification, and an encrypted journal so an interrupted run can be resumed. Never blindly re-run.
- **A console, not a CLI skin.** Apps, per-app check history, rotation plans, auto-rotation, notifications and import/export in one SPA over the same engine the CLI uses.
- **Opt-in auto-rotation** per credential, gated on a fresh clean audit. A copy that needs a human is named in an `auto_manual` notification instead of freezing the whole stack.
- **Notifications**: ntfy, webhook, Discord, Telegram and SMTP email. Events are status changes, never values.
- **Encrypted, versioned values.** AES-256-GCM under a per-version DEK wrapped by a file KEK; a stage change re-encrypts; a missing KEK fails closed.
- **Audited Reveal** for CURRENT and PREVIOUS, with a short UI TTL and a rate limit. No value in an event, log or job row.
- **Soft delete, recovery, adoption.** Tombstone a credential, restore it, or purge explicitly; adopt an external rotation only with engine proof or an honest `unverified`.
- **Durable sync and an mTLS agent.** Per-target jobs, partial deploys as `retry_wait`, and Docker only on the agent, never in the BFF.
- **Encrypted backups** of `app.db` and the KEK in one AES-256-GCM file.

## Requirements

- A Docker host (or any Linux host for the CLI) with network access to the services you want to audit.
- A URL and an API key per service. Credarr calls service APIs; it never reads a service's config file or data volume.
- Rotating a Servarr key asks the service to restart itself, so that service needs a supervisor that starts it again (for example the LinuxServer s6 images). A bare process without one is not supported.
- Optional Docker delivery: the `credarr-agent` image on each Docker host, with the shared vault tree and a restricted Docker socket proxy. Audit and rotation work without it.
- CLI only: Python 3.11+.
- Building the console from source: Node 24+.

## Quick start (Docker Compose)

```
services:
  credarr:
    image: ghcr.io/ezcodelab/credarr:latest
    container_name: credarr
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      PUID: "1000"
      PGID: "1000"
      TZ: Etc/UTC
      CREDARR_AUDIT_INTERVAL: "3600" # Initial seconds between audits. A value saved in Settings wins.
      # CREDARR_DOCKER_URL: "http://socket-proxy:2375" # Optional read-only Docker discovery.
    volumes:
      - ./config:/config
```

That stack is enough for audit and rotation. Add the agent listener port and
the shared tree only when you want Docker delivery; the agent section below
covers both.

### Docker settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `PUID` / `PGID` | `1000` | The uid/gid the app runs as. The entrypoint starts as root, aligns the app user and `/config`, then drops to it with `gosu`. Under `--user` they are ignored. |
| `TZ` | `Etc/UTC` | Timezone for server logs and every console timestamp (the browser's zone is not used). |
| `CREDARR_CONFIG_DIR` | `/config` | Where `app.db` lives. |
| `CREDARR_AUDIT_INTERVAL` | `3600` | Initial seconds between audits; a value saved in Settings wins. |
| `CREDARR_ALLOW_NETWORK_CONFIG` | unset | `1` accepts a network `/config`. This weakens SQLite locking and is not HA support. |
| `CREDARR_DOCKER_URL` | unset | Optional read-only Docker API for discovery, e.g. `http://socket-proxy:2375`. Never mount the raw socket. |
| `CREDARR_AGENT_PORT` | `8443` | The mTLS listener port for agents; `0` disables it. Publish and point the agent at the same port. |
| `CREDARR_AGENT_BIND` | `CREDARR_HOST` | Address for the agent listener. |
| `CREDARR_AGENT_HOSTNAME` | unset | DNS name or IP the agent puts in `--server`; added to the listener certificate SANs. Set it for every remote agent. |
| `CREDARR_VAULT_TREE` | unset | The shared delivery tree the agent reads. Required before a sync target can be created. |
| `CREDARR_VAULT_TREE_KEY` | `<config>/vault-tree.key` | Key file for the shared tree. Keep it outside the tree. |
| `CREDARR_SECURE_COOKIES` | unset | `1` marks the session cookie `Secure`. Set it behind HTTPS only. |
| `CREDARR_EXTERNAL_URL` | unset | The URL people reach the console on. `https` turns secure cookies on; a contradiction with the variable above refuses to start. |

Behind a TLS proxy set `CREDARR_EXTERNAL_URL=https://...`. Leave both unset for plain HTTP: a `Secure` cookie is dropped by the browser and sign-in fails. The server warns at startup when secure cookies are off and it binds a non-loopback address.

### Docker delivery agent (optional)

Audit and rotation work without an agent. The agent is only for delivery: update a stack's `.env` file or restart declared services after a rotation.

The agent is its own image, `ghcr.io/ezcodelab/credarr-agent`. It carries the Docker CLI, the compose plugin and the `credarr-agent` command, and no console process. The console image carries no Docker CLI and never receives the socket.

The console listens for agents on port `8443` by default. That port is startup configuration, not a console setting:

- `CREDARR_AGENT_PORT` changes it; `0` disables the listener.
- Publish the same port from the console container.
- Set `CREDARR_AGENT_HOSTNAME` to the DNS name or IP the agent uses. It is added to the listener certificate SANs.
- The agent is the client. It connects out to `--server https://<host>:<port>`. Credarr does not discover an agent, so the `--server` port must match `CREDARR_AGENT_PORT`.

Add the listener and shared tree to the console stack:

```yaml
services:
  credarr:
    image: ghcr.io/ezcodelab/credarr:latest
    restart: unless-stopped
    ports:
      - "8080:8080"
      - "8443:8443"
    environment:
      CREDARR_AGENT_HOSTNAME: credarr.example.com
      CREDARR_VAULT_TREE: /vault
      CREDARR_VAULT_TREE_KEY: /config/vault-tree.key
    volumes:
      - ./config:/config
      - ./vault:/vault
```

Restart the console. In **Settings -> Agents & sync**, the listener line shows the exact URL agents use. Download `agent-ca.crt`, then **Enroll agent** and copy the one-time token.

On the Docker host, keep the CA, the tree key and the agent state in one directory, mount the tree read-only, and mount only the stacks the agent may write. Put the Docker API behind the LinuxServer socket proxy:

```yaml
services:
  credarr-agent:
    image: ghcr.io/ezcodelab/credarr-agent:latest
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
    command:
      - --server
      - https://credarr.example.com:8443
      - --ca
      - /agent/agent-ca.crt
      - --vault-root
      - /vault
      - --vault-key
      - /agent/vault-tree.key
      - --allowed-root
      - /stacks
      - --state-dir
      - /agent/state
      - enroll
      - --name
      - media-host
      - --token-file
      - /agent/enroll.token
    environment:
      DOCKER_HOST: tcp://socket-proxy:2375
    depends_on:
      socket-proxy:
        condition: service_healthy
    networks:
      - internal_web
      - docker_api
    volumes:
      - ./agent:/agent
      - ./vault:/vault:ro
      - /srv/stacks:/stacks

  socket-proxy:
    image: lscr.io/linuxserver/socket-proxy:latest
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /run
    healthcheck:
      test: ["CMD-SHELL", "wget --no-verbose --tries=1 --spider http://localhost:2375/_ping || exit 1"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 10s
    networks:
      - docker_api
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - CONTAINERS=1
      - IMAGES=1
      - NETWORKS=1
      - VOLUMES=1
      - INFO=1
      - VERSION=1
      - PING=1
      - POST=1
      - ALLOW_START=1
      - ALLOW_STOP=1
      - ALLOW_ARCHIVE=0
      - ALLOW_CHANGES=0
      - ALLOW_EXPORT=0
      - ALLOW_LOGS=0
      - ALLOW_PAUSE=0
      - ALLOW_RESTARTS=0
      - ALLOW_TOP=0
      - ALLOW_UNPAUSE=0
      - AUTH=0
      - BUILD=0
      - COMMIT=0
      - CONFIGS=0
      - DISTRIBUTION=0
      - EVENTS=0
      - EXEC=0
      - NODES=0
      - PLUGINS=0
      - SECRETS=0
      - SERVICES=0
      - SESSION=0
      - SWARM=0
      - SYSTEM=0
      - TASKS=0
      - LIBPOD_CONTAINERS=0
      - LIBPOD_EVENTS=0
      - LIBPOD_EXEC=0
      - LIBPOD_GENERATE=0
      - LIBPOD_IMAGES=0
      - LIBPOD_INFO=0
      - LIBPOD_MANIFESTS=0
      - LIBPOD_NETWORKS=0
      - LIBPOD_PING=0
      - LIBPOD_PLAY=0
      - LIBPOD_PODS=0
      - LIBPOD_SECRETS=0
      - LIBPOD_SYSTEM=0
      - LIBPOD_VERSION=0
      - LIBPOD_VOLUMES=0

networks:
  internal_web:
    external: true
  docker_api:
    internal: true
```

The proxy allows the endpoints `docker compose up --force-recreate` uses: image and container inspection, network and volume listing, network creation, container create/start/stop/delete and rename. `ALLOW_START` and `ALLOW_STOP` are the only mutating verbs left enabled; exec, build, secrets, swarm and system access are refused. It still permits container creation and deletion, so a compromised agent can still control the containers it can reach. Rootless Docker remains the default, and a rootful daemon is root-equivalent even behind the proxy.

Mounting `/var/run/docker.sock` directly still works and is the fallback when the proxy is unavailable. That gives the agent the full Docker API, so use it only when you accept that.

Write the token to `./agent/enroll.token` before starting the container. After enrollment, replace `enroll ...` with `run`. The image entrypoint is `credarr-agent`, so an older compose command that starts with `credarr-agent` must drop that first item. The agent runs as its own non-root user; set `user:` to an id that can read `/agent`, `/vault` and the stacks. Rootless Docker is the default. A rootful daemon needs `--rootful --ack-rootful` and the stored acknowledgment.

If the listener is off, the console says so and no agent can connect. Existing audits and rotations keep working; a sync target cannot be created until `CREDARR_VAULT_TREE` is set.

### Run-once (cron)

```sh
credarr-server --once --config /config/credarr.yaml --config-dir /config --json
```

Audits the app's own store, prints the CLI's JSON document and exits with the CLI's code. It also ticks the notifier once, so a cron-only deployment is still a monitor.

## CLI

```sh
pip install .
# or, for development
pip install -e ".[dev]"

cp credarr.example.yaml credarr.yaml   # hosts, service URLs, manifest path
credarr targets                        # every target this build can read
credarr audit                          # check every declared credential
credarr rotate prowlarr_api_key        # plan only; nothing changes
credarr rotate prowlarr_api_key --apply  # typed confirmation, then run
```

## Documentation

| Page | What it is |
| --- | --- |
| [`docs/README.md`](docs/README.md) | Documentation index |
| [`docs/CONCEPTS.md`](docs/CONCEPTS.md) | Holder map, audit statuses and reason codes, classes, exit codes |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Engine / server / console layout and invariants |
| [`docs/OPERATING.md`](docs/OPERATING.md) | Audit, rotation, Servarr routes, auto-rotation, notifications, values, sync, backups, discovery |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Threat model, crypto inventory, KEK drills, reveal, TLS/PQ posture |
| [`docs/SYNC.md`](docs/SYNC.md) | Sync state machine, targets, shared tree, enrollment runbook, agent privilege |
| [`docs/SERVICES.md`](docs/SERVICES.md) | Per-service coverage and the measured versions |
| [`docs/API.md`](docs/API.md) | `/api/v1` reference (full contract: the live `/openapi.json`) |
| [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) | Known limits and troubleshooting |
| [`docs/TESTING.md`](docs/TESTING.md) | Test layers, gaps and the rules for new tests |
| [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) | Toolchain, checks, conventions |
| [`docs/ADDING_A_SERVICE.md`](docs/ADDING_A_SERVICE.md) | Lifecycle checklist for new service support |
| [`CHANGELOG.md`](CHANGELOG.md) | Release notes |

## License

Apache-2.0 (see [LICENSE](LICENSE)).
