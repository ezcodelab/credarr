"""Health, the overview status, and the audit ledger.

One domain because they answer the same question: is the process working,
what did the last run find, and may the operator start another."""

from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from credarr import __version__, facade
from credarr.model import NAME_RE
from credarr.services import declared_services
from credarr_server.api.context import ApiContext
from credarr_server.api.http import _actor, new_routers
from credarr_server.api.models import AuditIntervalBody
from credarr_server.api.payloads import _check_json, _run_json
from credarr_server.scheduler import (
    MAX_AUDIT_INTERVAL_SECONDS,
    MIN_AUDIT_INTERVAL_SECONDS,
)
from credarr_server.store import UnknownCredential


def routes(ctx: ApiContext) -> tuple[APIRouter, APIRouter]:
    """The domain's routes, over the one process context."""
    settings = ctx.settings
    store = ctx.store
    log = ctx.log
    audit_jobs = ctx.audit_jobs
    loop = ctx.loop
    auto = ctx.auto
    delivery = ctx.delivery
    config = ctx.config
    scheduler = ctx.scheduler
    stack_write = ctx.stack_write
    public, authed = new_routers()

    @public.get("/health")
    def health() -> JSONResponse:
        """Liveness for the container: degraded unless both loops are alive.

        A process whose loop died is not healthy even though it still answers
        requests, because everything it serves from that point is the past -
        and neither is one whose loop never started (a host run without the
        lifespan), because then there is no ledger at all. The delivery loop
        counts for the same reason: a console that records changes nobody hears
        about is a monitor that quietly stopped monitoring.
        """
        sync_loop = ctx.sync_loop
        for name, alive, failure in (
            ("scheduler", loop.running, loop.failure),
            ("notifier", delivery.running, delivery.failure),
            (
                "sync",
                True if sync_loop is None else sync_loop.running,
                None if sync_loop is None else sync_loop.failure,
            ),
            (
                "vault_maintenance",
                True if ctx.maintenance is None else ctx.maintenance.running,
                None if ctx.maintenance is None else ctx.maintenance.failure,
            ),
        ):
            if failure is not None:
                return JSONResponse({"status": "degraded", name: failure}, status_code=503)
            if not alive:
                return JSONResponse({"status": "degraded", name: "not running"}, status_code=503)
        if auto.failure is not None:
            return JSONResponse(
                {"status": "degraded", "auto_rotation": auto.failure}, status_code=503
            )
        if any(
            state.enabled for state in store.auto_rotations().values()
        ) and not auto.running:
            return JSONResponse(
                {"status": "degraded", "auto_rotation": "not running"}, status_code=503
            )
        return JSONResponse({"status": "ok"})

    def state_payload(*, include_job: bool = True) -> dict[str, Any]:
        """What Overview shows: the loop's health, the ledger, the counts.

        Statuses are the engine's vocabulary (`audit.Status`), and details are
        the strings the audit already writes to be safe in a log; nothing here
        has ever seen a value.

        `imported` is the honest half of the empty case: a store with no
        topology audits as exit 0 / match - the engine treats zero credentials
        as nothing wrong, and the CLI reads an empty manifest the same way - so
        the counts alone would let "never looked" read as "all clean". The flag
        says which one it is.

        `audit_job` is the running background full audit, if any. A reloaded
        console resumes polling it instead of showing the previous verdict as
        if nothing were happening.
        """
        manifest = store.load_manifest()
        state = log.last_state()
        journal = facade.journal_for(config)
        return {
            "version": __version__,
            "timezone": settings.timezone,
            "audit_job": audit_jobs.active() if include_job else None,
            "scheduler": {
                "running": loop.running,
                "failure": loop.failure,
                "interval_seconds": loop.scheduler.interval,
                "enabled": loop.scheduler.enabled,
            },
            "auto_rotation": {
                "running": auto.running,
                "failure": auto.failure,
                # "Enabled" is policy; eligible is whether a completed audit
                # can actually reach the worker right now.
                "eligible": loop.running
                and auto.running
                and loop.failure is None
                and auto.failure is None,
                "enabled": sum(
                    1 for state in store.auto_rotations().values() if state.enabled
                ),
            },
            "sync": ctx.sync.status() if ctx.sync is not None else None,
            "topology": {
                "imported": bool(manifest.credentials),
                "credentials": len(manifest.credentials),
                "holders": sum(len(c.consumers) for c in manifest.credentials.values()),
                # Names only, no probing: the console's menu and the Services
                # view must agree on which services exist before a host is
                # asked anything.
                "services": declared_services(manifest),
            },
            "last_run": _run_json(state.last_run) if state else None,
            "last_audit": (
                _run_json(state.last_audit) if state and state.last_audit is not None else None
            ),
            # An unfinished rotation is a state, not a history row: the console
            # has to show it before anything else can be run. This is the
            # unwindowed query on purpose - a crash older than `stale_after`
            # still blocks auto-rotation, so hiding it would leave the 409
            # pointing at a banner the operator cannot see. Continuing takes
            # over from the service's observed state rather than minting blind;
            # the lock still refuses a takeover while a live run holds it.
            "rotation": {
                "pending": [
                    {
                        "credential": step.credential,
                        "target": step.target,
                        "kind": step.kind,
                        "detail": step.detail,
                        "ordinal": step.ordinal,
                        "started_at": step.started_at,
                        "seconds_ago": step.seconds_ago,
                    }
                    for step in journal.unfinished()
                ],
                "stale_after_seconds": journal.stale_after,
                # An attempt can be open with every step finished: the kill
                # landed between the last step and `finish`. It blocks edits
                # the same way, so the console needs it to offer Abandon even
                # when no step is listed above.
                "open_attempts": [
                    {"credential": name, "attempt": attempt}
                    for name, attempt in journal.open_attempts().items()
                ],
            },
        }

    @authed.get("/status")
    def status() -> dict[str, Any]:
        """Overview's summary. The per-credential rows are `/credentials`."""
        return state_payload()

    @authed.get("/settings/audit")
    def get_audit_settings() -> dict[str, Any]:
        """The effective cadence and the bounds the UI may offer."""
        return {
            "interval_seconds": loop.scheduler.interval,
            "enabled": loop.scheduler.enabled,
            "minimum_seconds": MIN_AUDIT_INTERVAL_SECONDS,
            "maximum_seconds": MAX_AUDIT_INTERVAL_SECONDS,
            "boot_seconds": settings.audit_interval,
        }

    @authed.put("/settings/audit")
    def put_audit_settings(
        body: AuditIntervalBody, actor: str = Depends(_actor)
    ) -> dict[str, Any]:
        """Persist and apply a new cadence without restarting the process.

        The scheduler wake is part of the write: a change that only landed in
        the database would not take effect until the old interval elapsed.
        """
        with stack_write(actor):
            store.set_audit_interval(body.interval_seconds)
            loop.set_interval(body.interval_seconds)
            if body.enabled is not None:
                store.set_audit_enabled(body.enabled)
                loop.set_enabled(body.enabled)
        return get_audit_settings()

    @authed.get("/audit")
    def audit_history(only: str = "", limit: int = 20) -> dict[str, Any]:
        """The per-app history for one credential, newest first.

        A full audit's credential row and a scoped check are both history. The
        filter is the same `only` the run endpoint takes, so the history and
        the action name the same scope and cannot drift into two conventions.
        """
        name = only.strip()
        if not name:
            raise HTTPException(
                status_code=400,
                detail="only is required for per-app check history",
            )
        if not NAME_RE.fullmatch(name):
            raise HTTPException(status_code=400, detail="invalid credential name")
        if not 1 <= limit <= 100:
            raise HTTPException(
                status_code=400,
                detail="limit must be between 1 and 100",
            )
        if name not in store.load_manifest().credentials:
            raise HTTPException(status_code=404, detail=f"no credential named {name}")
        return {
            "credential": name,
            "checks": [
                {
                    "at": check.at,
                    "status": check.status.value,
                    "detail": check.detail,
                    "source": check.source,
                }
                for check in log.checks(name, limit=limit)
            ],
        }

    @authed.post(
        "/audit",
        responses={202: {"description": "audit started as a background job"}},
    )
    def run_audit(only: str | None = None, wait: bool = True) -> Any:
        """Audit now, and answer with the state that run produced.

        With `only=<credential>`, run the same engine audit for that credential
        alone and record it in per-app check history. That is a diagnostic, not
        a stack audit: it cannot satisfy auto-rotation's exact-coverage gate or
        replace `last_audit`.

        Without `only`, the default keeps the old synchronous contract and
        answers with the state the run produced. `wait=false` starts the same
        run in a background job and answers 202 immediately; the console polls
        `GET /audit/jobs/{job_id}` so a proxy or tunnel can drop without
        losing the server-side audit. A scoped check is deliberately not
        asynchronous: it is one bounded credential check, not a stack run.

        The only thing `Scheduler.once` lets escape is a ledger it cannot write
        (`sqlite3.Error`), which is the failure that ends the loop; that is the
        503, and the loop itself dies at its next tick. Anything else escaping
        is a bug, and a bug reported as "degraded" would be a lie with a
        status code in front of it, so it stays a 500. A background job records
        that same failure in its status instead of having a caller to raise to.
        """
        if only is not None:
            if not wait:
                raise HTTPException(
                    status_code=400,
                    detail="a scoped check is synchronous; omit wait=false",
                )
            name = only.strip()
            if not name or not NAME_RE.fullmatch(name):
                raise HTTPException(
                    status_code=400, detail="invalid credential name"
                )
            if name not in store.load_manifest().credentials:
                raise HTTPException(
                    status_code=404, detail=f"no credential named {name}"
                )
            try:
                checked_at, check = scheduler.check(name)
            except UnknownCredential:
                raise HTTPException(
                    status_code=404, detail=f"no credential named {name}"
                ) from None
            except sqlite3.Error as exc:
                raise HTTPException(
                    status_code=503,
                    detail=f"{type(exc).__name__}: {exc}",
                ) from None
            return {
                "checked_at": checked_at,
                "check": _check_json(check),
            }
        if wait:
            try:
                scheduler.once()
            except sqlite3.Error as exc:
                raise HTTPException(
                    status_code=503,
                    detail=f"{type(exc).__name__}: {exc}",
                ) from None
            return state_payload()

        def run() -> dict[str, Any]:
            if scheduler.once() is None:
                state = log.last_state()
                detail = (
                    state.last_run.detail
                    if state is not None and state.last_run is not None
                    else ""
                )
                raise RuntimeError(detail or "the audit did not complete; see the audit ledger")
            return state_payload(include_job=False)

        job = audit_jobs.start(run)
        return JSONResponse(
            status_code=202,
            content=audit_jobs.get(job.id) or {"job_id": job.id, "status": "running"},
        )

    @authed.get("/audit/jobs/{job_id}")
    def audit_job(job_id: str) -> dict[str, Any]:
        """One background audit's status and, when finished, its result."""
        job = audit_jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="no such audit job")
        return job

    return public, authed
