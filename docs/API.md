# API reference

Seed for the generated reference. The full contract is the live
`/openapi.json`, and the pinned route set is covered by contract tests.

Base `/api/v1`. Public: `/health`, `/auth/state|setup|login|logout`.
Everything else needs the admin session (opaque `HttpOnly`/`SameSite=Strict`
cookie + CSRF token + Origin check; idle 30 min, absolute 12 h) or a Bearer
API key (shown once, stored hashed, admin-equivalent, no scopes). Five failed
sign-ins in fifteen minutes lock the single account for five minutes (`429` +
`Retry-After`). Changing the password revokes every other session and rotates
the caller's own in the same transaction, so the browser that made the change
stays signed in.

Groups: `/status`, `/services` (+ `/test`), `/credentials` (declare, holders,
value write-only, reveal, adopt, lifecycle, versions, strategy, plan,
rotation-options, auto-rotation, rotate, abandon), `/audit` (+ background jobs,
scoped checks), `/topology/export|import` (raw-YAML replace requires
`?confirm=replace`), `/notifications/services` (CRUD + per-service test, plus
a no-write draft `POST .../services/test`), `/sync/targets`, `/sync/jobs`,
`/agents` (listener facts, CA download, enrollment and revocation),
`/vault/status`, `/events`, `/settings/audit`, `/auth/sessions`, `/auth/me`,
`/discovery`.

`GET /agents` returns the enrolled agents, the sync counts, and a
`control_plane` object with `enabled`, `host`, `port`, `hostname`, `url`,
`tls`, `group`, `failure` and `ca`. The `url` is
`https://<hostname>:<port>` only when the listener is running, the hostname is
configured and the port is non-zero; the console does not guess it.
`GET /agents/ca` returns the public
agent CA certificate as `application/x-pem-file`; the private CA key never
leaves the data directory.

`POST /credentials/{name}/reveal` is the only read that returns a value. It
requires a confirmation in the UI, is audited before the value is returned,
carries `Cache-Control: no-store`, and is limited per actor and per credential.
`POST .../lifecycle` is soft-delete/restore/force-delete; `POST .../adopt` has
`verify=none` (unverified) or `verify=process_readback` (engine proof or 409).
`GET .../strategy` reports the create/set/test/finish view and its provenance.

An API key can be issued with `origin=hook`; mutations it makes are recorded
with `origin=hook`, which notification services exclude unless they opt in.

Audit and credential rows carry `status`, `detail` (operator sentence), and
`reason` (stable code, see `CONCEPTS.md`). Rotation attempts record
`rotation_refused` / `rotation_failed` / `rotation_manual` /
`rotation_succeeded` with plain service names in the detail.
