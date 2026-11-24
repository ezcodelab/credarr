"""Sync targets, jobs and agents.

This is the operator surface over the delivery subsystem. The job state machine
lives in `sync_store`; these routes validate the request, take the stack lease
for a target change, and return the store's own answers. No route sends a value
or accepts a value-shaped job result.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from credarr_server.api.context import ApiContext
from credarr_server.api.http import _actor, new_routers
from credarr_server.api.models import (
    AgentActionBody,
    EnrollmentBody,
    SyncTargetBody,
    SyncTargetPatch,
)
from credarr_server.sync_store import SyncError, SyncStore


def _sync(ctx: ApiContext) -> SyncStore:
    if ctx.sync is None:
        raise HTTPException(status_code=503, detail="the sync store is not running")
    return ctx.sync


def routes(ctx: ApiContext) -> tuple[APIRouter, APIRouter]:
    public, authed = new_routers()

    @authed.get("/sync/targets")
    def targets() -> dict[str, Any]:
        return {"targets": [target.as_json() for target in _sync(ctx).targets()]}

    @authed.post("/sync/targets")
    def create_target(body: SyncTargetBody, actor: str = Depends(_actor)) -> dict[str, Any]:
        with ctx.stack_write(actor):
            try:
                target = _sync(ctx).save_target(
                    name=body.name,
                    agent_id=body.agent_id,
                    stack_path=body.stack_path,
                    project_name=body.project_name,
                    services=tuple(body.services),
                    workflow=body.workflow,
                    env_file=body.env_file,
                    values=body.values,
                    enabled=body.enabled,
                )
            except SyncError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from None
        return {"ok": True, "target": target.as_json()}

    @authed.patch("/sync/targets/{target_id}")
    def update_target(
        target_id: str, body: SyncTargetPatch, actor: str = Depends(_actor)
    ) -> dict[str, Any]:
        store = _sync(ctx)
        existing = store.target(target_id)
        if existing is None:
            raise HTTPException(status_code=404, detail="no such sync target")
        with ctx.stack_write(actor):
            try:
                target = store.save_target(
                    name=body.name or existing.name,
                    agent_id=body.agent_id or existing.agent_id,
                    stack_path=body.stack_path or existing.stack_path,
                    project_name=body.project_name or existing.project_name,
                    services=tuple(body.services or existing.services),
                    workflow=body.workflow or existing.workflow,
                    env_file=(
                        existing.env_file if body.env_file is None else body.env_file
                    ),
                    values=(
                        existing.values if body.values is None else body.values
                    ),
                    enabled=existing.enabled if body.enabled is None else body.enabled,
                    identifier=existing.id,
                )
            except SyncError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from None
        return {"ok": True, "target": target.as_json()}

    @authed.delete("/sync/targets/{target_id}")
    def delete_target(target_id: str, actor: str = Depends(_actor)) -> dict[str, bool]:
        with ctx.stack_write(actor):
            if not _sync(ctx).delete_target(target_id):
                raise HTTPException(status_code=404, detail="no such sync target")
        return {"ok": True}

    @authed.get("/sync/jobs")
    def jobs(credential: str | None = None, limit: int = 100) -> dict[str, Any]:
        bounded = max(1, min(limit, 500))
        return {
            "jobs": [
                job.as_json()
                for job in _sync(ctx).jobs(credential=credential, limit=bounded)
            ]
        }

    @authed.post("/sync/jobs/{job_id}/retry")
    def retry_job(job_id: str, actor: str = Depends(_actor)) -> dict[str, Any]:
        job = _sync(ctx).retry(job_id, actor=actor)
        if job is None:
            raise HTTPException(
                status_code=409,
                detail="that job is not failed, cancelled or waiting; it cannot be retried",
            )
        return {"ok": True, "job": job.as_json()}

    @authed.post("/sync/jobs/{job_id}/cancel")
    def cancel_job(job_id: str, actor: str = Depends(_actor)) -> dict[str, Any]:
        job = _sync(ctx).cancel(job_id, actor=actor)
        if job is None:
            raise HTTPException(status_code=404, detail="no such sync job")
        return {"ok": True, "job": job.as_json()}

    @authed.get("/agents")
    def agents() -> dict[str, Any]:
        plane = ctx.agent_plane
        return {
            "agents": [agent.as_json() for agent in _sync(ctx).agents()],
            "sync": _sync(ctx).status(),
            "control_plane": (
                plane.info() if plane is not None else {"enabled": False}
            ),
        }

    @authed.post("/agents/enrollment")
    def enrollment(body: EnrollmentBody, actor: str = Depends(_actor)) -> dict[str, Any]:
        try:
            token, agent = _sync(ctx).create_enrollment(
                body.name, tuple(body.capabilities), ttl=float(body.ttl_seconds)
            )
        except SyncError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        # The token is returned exactly once; only its hash is stored.
        return {"ok": True, "token": token, "agent": agent.as_json()}

    @authed.delete("/agents/{agent_id}")
    def revoke_agent(agent_id: str) -> dict[str, bool]:
        if not _sync(ctx).revoke(agent_id):
            raise HTTPException(status_code=404, detail="no such agent")
        return {"ok": True}

    @authed.post("/agents/{agent_id}/disable")
    def disable_agent(
        agent_id: str, body: AgentActionBody, actor: str = Depends(_actor)
    ) -> dict[str, bool]:
        if not _sync(ctx).disable(agent_id, body.reason):
            raise HTTPException(status_code=404, detail="no such agent")
        return {"ok": True}

    return public, authed
