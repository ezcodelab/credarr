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

## Agent identity and enrollment

1. An admin creates a one-time token in Settings -> Agents & sync
   (`POST /api/v1/agents/enrollment`). The token is shown once and stored as a
   SHA-256 hash with a 10-minute default expiry.
2. Copy `agent-ca.crt` from the BFF data directory to the agent host.
3. On the agent host, generate a key and CSR and consume the token:

   ```sh
   credarr-agent --server https://credarr.example:8443 \
     --ca /etc/credarr/agent-ca.crt \
     --vault-root /srv/credarr-vault --vault-key /etc/credarr/vault-tree.key \
     --allowed-root /srv \
     enroll --name media-host --token-file /run/credarr/enroll.token
   ```

4. Run the agent under the Docker host's own service manager:

   ```sh
   credarr-agent --server https://credarr.example:8443 \
     --ca /etc/credarr/agent-ca.crt \
     --vault-root /srv/credarr-vault --vault-key /etc/credarr/vault-tree.key \
     --allowed-root /srv --state-dir /var/lib/credarr-agent \
     run
   ```

The client certificate is one day. Renewal is available at
`POST /v1/certificate/renew`; replacing the fingerprint makes the previous
certificate stop authenticating. Revocation is immediate.

## Privilege

The agent runs `docker compose` on its own host. It does not receive the BFF's
Docker socket; the BFF has none. Rootless Docker is the default. A rootful
daemon requires `--rootful --ack-rootful`, which is stored on the agent row and
reported in the console. A job outside the bound workflow or path fails with
`agent_policy_violation` and no Docker action. The agent does not accept
arbitrary commands, shell, scripts, or environment from the BFF.

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
