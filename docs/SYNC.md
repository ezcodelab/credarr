# Sync and the agent

Sync is the delivery tracker for a committed value change. It is advisory in
v1: a failed or pending delivery never changes a rotation's exit code and never
causes a re-mint (decision 8). The audit verdict and the delivery state are two
different facts and the console shows them separately.

## States

A `sync_jobs` row moves through:

```
queued --lease--> leased --begin--> running --all services true--> delivered
   ^                  |                 |
   |                  |                 +--partial/failed--> retry_wait --+
   |                  +--lease expires-----------------------> retry_wait |
   +----------------------------------------------------------------------+
                                          retry_wait after max attempts -> failed
queued | leased | running | retry_wait --cancel/soft-delete/agent revoke--> cancelled
```

- At most one active job exists per `(credential, target)`; a unique partial
  index enforces it.
- A newer committed version for a target with an active job stays in the
  outbox until that job is terminal. The next dispatch makes the newer value a
  new job, so an older attempt cannot overwrite it.
- A partial result is `retry_wait`, never success. The next attempt re-runs the
  whole declared service set; a cached per-service success is not reused.
- `max_attempts` defaults to five. Backoff is 30 seconds doubling to one hour.
  A lease expires after 60 seconds; the tick returns it to `retry_wait` and
  spends one attempt. An agent that never returns cannot hold a job forever.
- Expired jobs, replayed results, results that do not name exactly the declared
  services, and results from an agent that does not own the lease are refused.

## Commit barrier

`VaultStore.set_current` writes the sealed tree value before the database
transaction. The transaction then writes the version flip, `vault_generations`,
`sync_outbox` and `secret.current_changed` together. The non-secret generation
marker is written only after COMMIT. A crash before the marker leaves the
shared tree ahead of what the database committed; the agent sees the marker
mismatch and refuses to deploy. A crash after COMMIT but before the marker is
the same fail-closed state and is repaired by the next committed change.

The dispatcher reads only committed outbox rows. A job cannot exist for a
version the transaction did not commit.

## Targets

A target is a compose identity:

```json
{
  "name": "media",
  "agent_id": "<agent>",
  "stack_path": "/srv/media",
  "project_name": "media",
  "services": ["sonarr", "seerr"],
  "workflow": "compose"
}
```

`stack_path` must be absolute and free of `..`. The agent resolves it and
requires it to be equal to or under one of its `--allowed-root` values. The
project name is lowercase letters, digits, `_` or `-`. Service names are
bounded to characters a compose file can name. A target cannot be created
without `CREDARR_VAULT_TREE`, because there would be no value source the agent
could use.

## The env workflow

`workflow: env` is the generic consumer-delivery adapter for Docker `.env`
files. It is not Homepage-specific; any compose stack with an env file can use
it.

```json
{
  "name": "homepage",
  "agent_id": "<agent>",
  "stack_path": "/stacks/homepage",
  "project_name": "homepage",
  "services": ["homepage"],
  "workflow": "env",
  "env_file": ".env",
  "values": {
    "HOMEPAGE_VAR_SONARR_API_KEY": "sonarr_api_key",
    "HOMEPAGE_VAR_RADARR_API_KEY": "radarr_api_key"
  }
}
```

The agent:

- resolves the stack under an `--allowed-root`;
- requires a relative env path without `..`, and resolves it under the stack;
- verifies the job's tree generation and reads only that credential's value;
- replaces only the env keys mapped to that credential, preserving comments
  and unrelated lines, removing duplicate declarations of a mapped key;
- writes a `0600` file atomically, fsyncs it, then runs the declared compose
  service set with `--force-recreate`;
- refuses a value that cannot be safely represented in an env line.

No shell, arbitrary command, or user script is involved. A key not mapped to
the job's credential is never touched. The lifecycle API remains available
outside the console; the visible app action is Delete, which removes the
Credarr record only.

### Homepage-style label consumers

Homepage discovers services from Docker labels. Each app compose carries
`homepage.widget.key=${HOMEPAGE_VAR_<SERVICE>...}`, and that variable is read
from **that app's own** `.env` at container creation. Homepage is not the
writer and does not need its own copies of the keys.

The env target is therefore one per app, not one for Homepage:

| Stack | Env key | Credential |
| --- | --- | --- |
| `sonarr` | `HOMEPAGE_VAR_SONARR_API_KEY` | `sonarr_api_key` |
| `radarr` | `HOMEPAGE_VAR_RADARR_API_KEY` | `radarr_api_key` |
| `prowlarr` | `HOMEPAGE_VAR_PROWLARR_API_KEY` | `prowlarr_api_key` |
| `seerr` | `HOMEPAGE_VAR_SEERR_API_KEY` | `seerr_api_key` |
| `jellyfin` | `HOMEPAGE_VAR_JELLYFIN_API_TOKEN` | `jellyfin_api_key` |
| `gluetun` (qBittorrent service) | `HOMEPAGE_VAR_QBITTORRENT_API_KEY` | `qbittorrent_api_key` |

The agent updates the app's `.env`, then recreates the declared app service.
Docker labels are fixed at container creation, so the app container must be
recreated for Homepage to see the new key. Homepage itself does not need a
restart: its dashboard cache is cleared by `POST /api/revalidate` (the refresh
icon), after which it reads the new labels. A live check returned
`{"revalidated":true}`. Without that cache invalidation, Homepage can keep
serving its previous dashboard data even though the label is current.

## Starting a custom workflow from an event

The existing signed notification webhook is the event trigger. Configure a
webhook sink with `secret.current_changed` in its kind selection (and optionally
a credential filter). Its payload is the same secret-free document as every
event:

```json
{
  "id": 42,
  "at": 1795480000.0,
  "kind": "secret.current_changed",
  "credential": "sonarr_api_key",
  "origin": "user",
  "data": {
    "version": "…",
    "previous_version": "…",
    "generation": 7,
    "verification": "verified"
  }
}
```

The receiver can start a Gitea/GitLab/GitHub workflow or a Lambda with the
credential name and version. The value is not in the event; the receiver uses
its own secret-store access or the shared tree key it already holds. A
webhook receiver is outside the verification boundary and cannot change the
credential verdict. See `OPERATING.md` for the sink configuration rules.

## Shared vault tree

The BFF writes one sealed value file per credential under
`$CREDARR_VAULT_TREE/values/` and a non-secret marker under
`$CREDARR_VAULT_TREE/generations/`. The key is a separate file
(`CREDARR_VAULT_TREE_KEY`, default `<config>/vault-tree.key`); it is never
inside the tree. A fresh clone of the tree without the key cannot open a value,
which is why a clone alone is not a valid agent value source.

The agent requires the marker for the credential, the marker's `value_version`
to equal the job's version, and the sealed value to decrypt under that version
before it starts Docker. A missing marker, a marker for another credential, an
unreadable file, or a mismatched version is `VaultError`; the agent reports all
services false with a short sentence and performs no Docker action.

## Images and listening address

The console and the agent are separate images with one version:

| Image | Role |
| --- | --- |
| `ghcr.io/ezcodelab/credarr` | Console and BFF. No Docker CLI, no Docker socket. |
| `ghcr.io/ezcodelab/credarr-agent` | Outbound agent. Docker CLI, compose plugin, no console. |

The BFF listens on `CREDARR_AGENT_PORT` (default `8443`) and
`CREDARR_AGENT_BIND` (default `CREDARR_HOST`). `CREDARR_AGENT_PORT=0` disables
the listener. `CREDARR_AGENT_HOSTNAME` is the DNS name or IP an agent puts in
its `--server` URL, and the listener certificate adds it to its SANs.

The port is boot configuration, not a database setting. The console shows the
listener state and the exact `https://<host>:<port>` URL in Settings -> Agents
& sync; changing the port means changing `CREDARR_AGENT_PORT`, the published
container port, and the agent's `--server` value together. The agent initiates
the connection, so the BFF never needs to discover an agent address.

## No agent configured

Audit and rotation do not need an agent. Without `CREDARR_VAULT_TREE` there is
no value source, so a sync target cannot be created; the console says that and
disables **New target**. With the tree but no enrolled agent, the console shows
how to run `credarr-agent` and keeps the rest of the app usable. A disabled or
failed listener is reported in the same panel, with the startup variable or
the listener failure named.

## Agent identity and enrollment

1. An admin creates a one-time token in Settings -> Agents & sync
   (`POST /api/v1/agents/enrollment`). The token is shown once and stored as a
   SHA-256 hash with a 10-minute default expiry.
2. Download `agent-ca.crt` from the same panel (`GET /api/v1/agents/ca`) and
   put it beside the agent state. The file is public; the CA private key stays
   in the BFF data directory.
3. On the agent host, generate a key and CSR and consume the token:

   ```sh
   credarr-agent --server https://credarr.example:8443 \
     --ca /etc/credarr/agent-ca.crt \
     --vault-root /srv/credarr-vault --vault-key /etc/credarr/vault-tree.key \
     --allowed-root /srv \
     enroll --name media-host --token-file /run/credarr/enroll.token
   ```

4. Run the agent under the Docker host's own service manager, or with the
   `credarr-agent` image. The image defaults to `run`; required runtime
   configuration is in the environment block:

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
       environment:
         CREDARR_AGENT_SERVER: https://credarr.example:8443
         CREDARR_AGENT_CA: /agent/agent-ca.crt
         CREDARR_AGENT_VAULT_ROOT: /vault
         CREDARR_AGENT_VAULT_KEY: /agent/vault-tree.key
         CREDARR_AGENT_ALLOWED_ROOT: /stacks
         CREDARR_AGENT_STATE: /agent/state
         CREDARR_AGENT_ROOTFUL: "1"
         CREDARR_AGENT_ACK_ROOTFUL: "1"
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

   networks:
     internal_web:
       external: true
     docker_api:
       internal: true
   ```

The image reads `CREDARR_AGENT_SERVER`, `CREDARR_AGENT_CA`,
`CREDARR_AGENT_VAULT_ROOT`, `CREDARR_AGENT_VAULT_KEY`,
`CREDARR_AGENT_ALLOWED_ROOT` (comma-separated for more than one),
`CREDARR_AGENT_STATE`, `CREDARR_AGENT_ROOTFUL`,
`CREDARR_AGENT_ACK_ROOTFUL` and `CREDARR_AGENT_POLL_SECONDS`. The equivalent
flags still work for a host install.

An older compose file that ran the console image with
`command: [credarr-agent, ...]` must remove the `command` block: the agent image
defaults to `run` and reads its required paths from the environment.

The client certificate is one day. Renewal is available at
`POST /v1/certificate/renew`; replacing the fingerprint makes the previous
certificate stop authenticating. Revocation is immediate.

## Privilege

The agent runs `docker compose` on its own host. It does not receive the BFF's
Docker socket; the BFF has none. The recommended deployment puts the Docker API
behind the LinuxServer socket proxy and sets `DOCKER_HOST` to it. The proxy
allows the operations `docker compose up --force-recreate` uses: inspect an
image, list containers, networks and volumes, create a network when the stack
needs one, create, start, stop, delete and rename containers. It refuses exec,
build, secrets, swarm, system, logs and archive access. `ALLOW_START` and
`ALLOW_STOP` are the only mutating verbs enabled; `POST=1` is required for
create and delete.

The proxy still permits container creation and deletion, so a compromised agent
can control the containers it can reach. Rootless Docker is the default. A
rootful daemon requires `--rootful --ack-rootful` or
`CREDARR_AGENT_ROOTFUL=1` and `CREDARR_AGENT_ACK_ROOTFUL=1`, which is stored on
the agent row and reported in the console, and remains root-equivalent even
behind the proxy. A job outside the bound workflow or path fails with
`agent_policy_violation` and no Docker action. The agent does not accept
arbitrary commands, shell, scripts, or environment from the BFF.

Mounting `/var/run/docker.sock` directly is the fallback when the proxy is not
available. It gives the agent the full Docker API and should be a deliberate
exception.

## Clock and expiry

Every control-plane request carries the agent's timestamp. The server refuses a
skew greater than five minutes. Leases are 60 seconds; an agent that stops
heartbeating for five minutes becomes `offline` and its active jobs are
cancelled by the next maintenance tick. Hosts must run NTP; a skewed clock fails
closed. This is the same class of assumption as the SQLite locking rule: the
system states it rather than pretending the environment guarantees it.

## Evidence

- Unit and API coverage: `tests/server/test_sync.py`,
  `tests/server/test_sync_api.py`, `tests/server/test_agent.py`.
- Disposable live flow: `python3 tests/live/agent_flow.py` starts the real
  control plane, enrolls the real agent, creates a job for a disposable compose
  stack, runs the agent once, and asserts `delivered`. It uses a unique project
  name and removes the stack; no production socket is involved.
- TLS 1.3 is enforced by the listener and by the agent client. The negotiated
  group is visible in `/api/v1/agents`; a classical fallback is recorded as
  `X25519`, never described as post-quantum.
