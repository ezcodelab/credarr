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
value write-only, plan, rotation-options, auto-rotation, rotate), `/audit`
(+ background jobs, scoped checks), `/topology/export|import` (raw-YAML
replace requires `?confirm=replace`), `/notifications/services` (CRUD +
per-service test, plus a no-write draft `POST .../services/test`),
`/events`, `/settings/audit`, `/auth/sessions`, `/auth/me`, `/discovery`.

Audit and credential rows carry `status`, `detail` (operator sentence), and
`reason` (stable code, see `CONCEPTS.md`). Rotation attempts record
`rotation_refused` / `rotation_failed` / `rotation_manual` /
`rotation_succeeded` with plain service names in the detail.
