# Security model

This document is the threat model and crypto inventory for the next-generation
value lifecycle. It is binding alongside `DECISIONS.md` decision 54. Where a
property is not proven, it says so instead of claiming it.

## What protects what

| Asset | At rest | In transit | Who can read it |
| --- | --- | --- | --- |
| Stored credential version | AES-256-GCM under a unique DEK; DEK wrapped by the file KEK | never leaves the process except a reveal | the BFF process while it is running |
| Shared delivery tree | AES-256-GCM under a separate tree key | mounted filesystem | the agent host and anyone who can read its key file |
| KEK | `kek.json`, mode `0600`, outside `app.db` | never | the BFF host user |
| Agent certificate key | agent state directory, mode `0600` | mTLS client certificate | the agent host user |
| CA private key | BFF data directory, mode `0600` | never | the BFF host user |
| Backup | scrypt-derived AES-256-GCM archive | operator-controlled | anyone with the passphrase and the file |

AES-256-GCM is the only value cipher. There is no CBC, no unauthenticated
encryption, and no hand-rolled primitive. The AAD for a value is a
length-prefixed tuple `credential | version | stage | attempt_id | domain`.
Changing any field makes the ciphertext fail authentication; the store
therefore re-encrypts with a fresh DEK when a stage changes.

## Threats and boundaries

- **BFF process compromise exposes values in memory.** Encryption at rest does
  not mitigate it. A process that can decrypt CURRENT can read every value it
  serves, including a reveal. This is not claimed otherwise.
- **Local file KEK protects a stolen database or backup, not a live host.**
  Root on the BFF host can read `kek.json`. A managed KMS would move that
  boundary; this build does not claim equivalence to one.
- **Agent compromise in rootful Docker is root-equivalent.** Rootless is the
  default. Rootful needs `--rootful --ack-rootful`, is stored on the agent row,
  and produces a persistent warning. A policy violation disables the agent and
  emits `agent_policy_violation`.
- **The Docker API is behind a restricted proxy.** The recommended deployment
  sets `DOCKER_HOST` to the LinuxServer socket proxy. The proxy allows container
  create/start/stop/delete/rename, image inspection, network and volume listing
  and network creation, because `docker compose up --force-recreate` needs them.
  It refuses exec, build, secrets, swarm, system, logs and archive access. This
  reduces the API surface but does not make an agent compromise harmless: it can
  still replace or delete the containers it can reach. Mounting the raw socket
  is the fallback and gives the agent the full Docker API.
- **Shared tree compromise exposes the tree values.** The tree key is a file
  the agent host must hold. A clone of the tree without the key cannot read a
  value; a clone with the key is a copy of the delivery material. The tree is
  a delivery mirror, not a second independent key hierarchy.
- **Hooks and receivers are outside the verification boundary.** They never
  receive a value. A webhook body is HMAC-SHA256 signed with the receiver's
  configured secret; a receiver that ignores the signature is its own risk.
  Hook-origin events are excluded from sinks by default so a hook cannot feed
  its own reaction back into delivery.
- **Soft delete is a Credarr tombstone, not a remote wipe.** Remote holders keep
  their copies. That residual risk is explicit in decision 9 and remains an
  audit/holder problem unless a rotation strategy revokes them.
- **A compromised or lagging shared tree can produce stale deploy input.** The
  agent compares the job's value version with the tree marker and decrypts the
  sealed value under that version. A mismatch or unreadable file fails closed
  before Docker runs.
- **Clock skew can invalidate job expiry and nonce checks.** The agent sends a
  timestamp with every control-plane request; the server refuses a request more
  than five minutes from its clock. Job leases expire after 60 seconds and are
  retried. Hosts must run NTP; a skewed clock fails closed rather than
  deploying.

## KEK lifecycle

- On a fresh store, the first `TopologyStore` construction writes `kek.json`
  with one active 256-bit key and marks the store initialized. A store that has
  ever held a value never re-provisions a missing KEK automatically.
- Missing, unreadable, wrong-mode, malformed, or incomplete key material makes
  every value operation raise `KekUnavailable`. Metadata reads still work, so
  the console can show what is waiting for the key. The API answers 503.
- `credarr-kek status` prints the path, presence, active key id, version count
  and how many versions are not wrapped by the active key. It never prints a
  key or a value.
- `credarr-kek rotate` generates a new key, writes it into the keyring beside
  the old one, rewraps every version DEK and pending value DEK in one
  transaction, then makes the new key active. A crash before activation leaves
  both keys readable. Old keys are retained; `credarr-kek` never deletes key
  material automatically.
- Backup format 2 carries `keys/kek.json`, the delivery-tree key, and the agent
  CA/client keys. A restore without the KEK refuses to write when the snapshot
  holds encrypted versions. Losing the KEK is unrecoverable by design; the
  backup is the recovery path.

## Reveal

Reveal is the only browser path that returns a CURRENT or PREVIOUS value. It
is `POST /api/v1/credentials/{name}/reveal`, requires the admin session or an
API key, is limited to five per minute per actor and per credential with a
two-second cooldown, returns `Cache-Control: no-store`, and writes
`secret.revealed` before the value leaves the process. The event carries the
actor, credential, version and stage; it never carries the value. Soft-deleted
and purged versions are not revealable. The UI keeps the value in component
memory only, selects it on focus, and clears it when the 30-second TTL ends.

## Control plane transport

The agent control plane is a separate listener (`--agent-port`, default 8443).
It requires TLS 1.3 and a client certificate on every route except enrollment.
Enrollment tokens are one-time, 10-minute defaults, stored as SHA-256 hashes.
Client certificates are one day; renewal replaces the fingerprint, so the old
certificate stops authenticating. Revocation disables the agent immediately.
The listener prefers the `X25519MLKEM768` group and records the negotiated
choice in `/api/v1/agents`; where the linked OpenSSL does not expose it, it
uses `X25519` and the console says `group: X25519`. No post-quantum claim is
made for a classical fallback. TLS 1.0/1.1, cleartext, and a plain HTTP agent
URL are never fallbacks.

The main console listener is unchanged: it may sit behind the operator's TLS
proxy. That is a separate deployment surface from the agent control plane and
is not a claim that the console port itself terminates TLS.

## Residual risks accepted in this roadmap

- A BFF process compromise exposes the values it can decrypt.
- A rootful agent is root-equivalent on its Docker host.
- A tree copy plus its key file is a value copy.
- A soft-deleted credential may still exist in a remote holder.
- In-memory zeroization is best effort; Python strings and the cryptography
  library do not promise it.
- The event ledger and job rows are durable and secret-free, but their
  retention is an operator policy, not an automatic maximum.
