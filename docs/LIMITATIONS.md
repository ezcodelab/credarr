# Limitations & troubleshooting

Read before exposing the console or trusting a rotation. Each item is a known
v1 limit, not a roadmap promise.

- **Session cookies follow the scheme you declare.** Behind TLS set `CREDARR_EXTERNAL_URL=https://...` or
  `CREDARR_SECURE_COOKIES=1`. The scheme is not inferred from `X-Forwarded-Proto`: that header is client-supplied,
  and trusting it without a verified proxy would let a caller decide the cookie policy. A contradiction (an `https`
  URL with secure cookies off, or an `http` URL with them on) refuses to start.
- **What the KEK does and does not protect.** Credential values are AES-256-GCM
  under a per-version DEK wrapped by `kek.json` (mode `0600`); the database and
  WAL are scrubbed after migration. A stolen database or backup without the KEK
  is unreadable. A live BFF process compromise is not mitigated: it can decrypt
  CURRENT. The KEK file sits beside the database, so the same host compromise
  that reads the database usually reads the key. Do not claim HSM/KMS
  equivalence. Losing the KEK is unrecoverable; restore it from a format-2
  backup.
- **Agent and tree compromise.** Docker lives only in the agent. Rootless is
  the default; rootful is root-equivalent and needs an explicit acknowledgment.
  The shared tree key is a file on the agent host: a tree copy plus its key is
  a value copy. The BFF's own console port is still the operator's TLS-proxy
  surface; only the agent control plane terminates TLS itself. Default compose
  is HTTP. `--secure-cookies` is not TLS.
- **Hybrid PQ is not claimed.** The listener tries `X25519MLKEM768` and falls
  back to `X25519` when the linked OpenSSL does not expose it. No "post-quantum
  Credarr" wording is allowed until the real images exercise the hybrid group.
- **Sync is advisory.** A failed or pending delivery does not change a rotation
  exit code and does not remint. A partial deploy is `retry_wait`, never
  success. A soft-deleted or purged value is not remotely wiped from a holder
  that already received it.
- **Admin surface:** API keys are admin-equivalent, no scopes, no step-up, no
  email reset (operator recovery of `app.db` is the fallback). A proxy rate
  limit is still recommended in front of the public login.
- **Rotation hazards:** Servarr restore is destructive to `config.xml`; a
  crash can leave a temporary full-backup archive on the service (delete
  before retrying); a supervisor that restarts the service is required.
  Reconstructed restore may reset unexposed fields and refuses PostgreSQL.
  Reissue mints park the created value and its row ids before RECORD, so a
  later run adopts the successor instead of minting a third; a kill between
  the create response and that write can still leave a stray row, which the
  revoke's name sweep removes.
  `live` is not savability. A content-broken indexer row can pass its test
  yet refuse the holder save after revocation. Fix or remove that row before
  rotating the issuer.
- **Recovery posture:** no snapshots or undo. Resume is the convergence path.
  When the service is unreachable, Abandon (console, `POST
  /credentials/{name}/rotation/abandon`, `credarr rotate <name> --abandon`)
  closes the record without touching the service or the values. Deletion is
  refused while steps or attempts are open. The manual-copy reminder lives in
  per-browser localStorage and is never verification.
- **Unproven stays unproven:** no wording lifts Lidarr/Readarr/Whisparr
  indexer rows, Basic auth, the manual mint's full run, and SMTP TLS modes
  stay unproven. All remain `[T]`.
- **Timeouts:** full audits run as server-side jobs. Use `?wait=false`
  behind a proxy or tunnel (a 103-second synchronous audit will not survive a
  60/100-second proxy limit). One dead notification sink can delay others.
  Service observation is sequential. Console timestamps follow the server TZ.
- **Accepted residuals for 1.0.0:** the production read-only dry run was not
  repeated (operator accepted); auto-rotation keeps its audit-to-write
  window; one-admin load assumptions above.

One sentence from the CI probe: only this file changed.
