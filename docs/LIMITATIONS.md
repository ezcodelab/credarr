# Limitations & troubleshooting

Read before exposing the console or trusting a rotation. Each item is a known
v1 limit, not a roadmap promise.

- **Session cookies follow the scheme you declare.** Behind TLS set `CREDARR_EXTERNAL_URL=https://...` or
  `CREDARR_SECURE_COOKIES=1`. The scheme is not inferred from `X-Forwarded-Proto`: that header is client-supplied,
  and trusting it without a verified proxy would let a caller decide the cookie policy. A contradiction (an `https`
  URL with secure cookies off, or an `http` URL with them on) refuses to start.
- **Plaintext at rest:** working copies, digests, hashes and notification
  secrets live in one `0600` SQLite file. Full-host compromise is full
  credential compromise. Default compose is HTTP. Bind to localhost or use a
  trusted TLS proxy. `--secure-cookies` is not TLS.
- **Admin surface:** API keys are admin-equivalent, no scopes, no step-up, no
  email reset (operator recovery of `app.db` is the fallback). A proxy rate
  limit is still recommended in front of the public login.
- **Rotation hazards:** Servarr restore is destructive to `config.xml`; a
  crash can leave a temporary full-backup archive on the service (delete
  before retrying); a supervisor that restarts the service is required.
  Reconstructed restore may reset unexposed fields and refuses PostgreSQL.
  Reissue mints can leave residue on a crash (no pending-value coverage).
  `live` is not savability. A content-broken indexer row can pass its test
  yet refuse the holder save after revocation. Fix or remove that row before
  rotating the issuer.
- **Recovery posture:** no Abandon button and no snapshots. Resume is the
  convergence path. Deletion is refused while steps or attempts are open. The
  manual-copy reminder lives in per-browser localStorage and is never verification.
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
