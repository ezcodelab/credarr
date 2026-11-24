"""The process state a router may use, and the guards shared by domains.

One `ApiContext` is built by `create_app` and handed to every router builder.
The guards are methods because the same lease and the same recovery rules must
hold on every write path; a domain never re-implements one."""

from __future__ import annotations

import contextlib
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from fastapi import HTTPException

from credarr import facade
from credarr.config import Config
from credarr.journal import STACK_LOCK, Journal, JournalLocked
from credarr.targets import TargetRegistry
from credarr_server import auto_rotation
from credarr_server.audit_jobs import AuditJobs
from credarr_server.audit_log import AuditLog
from credarr_server.auth import AdminAuth
from credarr_server.notifier import DeliveryLoop, Notifier
from credarr_server.reveal import RevealLimiter
from credarr_server.scheduler import Scheduler
from credarr_server.store import TopologyStore

if TYPE_CHECKING:
    from credarr_server.app import AuditLoop, ServerSettings
    from credarr_server.sync_store import SyncStore


@dataclass(slots=True)
class ApiContext:
    """The one process state every router reads, plus the write guards."""

    settings: ServerSettings
    store: TopologyStore
    auth: AdminAuth
    log: AuditLog
    audit_jobs: AuditJobs
    loop: AuditLoop
    auto: auto_rotation.AutoRotator
    notifier: Notifier
    delivery: DeliveryLoop
    config: Config
    scheduler: Scheduler
    registry: TargetRegistry
    reveal: RevealLimiter = field(default_factory=RevealLimiter)
    sync: SyncStore | None = None
    sync_loop: Any = None
    agent_plane: Any = None
    maintenance: Any = None

    def origin_for(self, actor: str) -> str:
        """Who caused a write: a browser admin or an automation key's origin."""
        if actor.startswith("key:"):
            try:
                return self.auth.key_origin(int(actor.split(":", 1)[1]))
            except (ValueError, TypeError):
                return "user"
        return "user"

    def unfinished_rotation(self, name: str, journal: Journal) -> str | None:
        """Why this credential cannot be edited yet, or None when it is clear."""
        unfinished = sorted(
            {step.target for step in journal.unfinished()
             if step.credential == name}
        )
        attempt = journal.open_attempts().get(name)
        if not unfinished and attempt is None:
            return None
        return (
            f"attempt {attempt} did not finish"
            if attempt is not None
            else "an unfinished step remains"
        )

    def value_change_guard(self, name: str, journal: Journal) -> None:
        """Refuse changing the recovery baseline while a run is unfinished.

        A stale lock lets a paste proceed even though the dead run's steps are
        still open. That can replace the canonical value the resume compares
        against, turning a mid-mint recovery into a second mint. The operator
        resumes or takes the run over first; the value is not the recovery
        mechanism.
        """
        detail = self.unfinished_rotation(name, journal)
        if detail is not None:
            raise HTTPException(
                status_code=409,
                detail=f"{name}: {detail}; resume, take it over or abandon it "
                "before changing the stored value",
            )

    def rotation_edit_guard(self, name: str, journal: Journal, action: str) -> None:
        """Refuse a change to the recovery plan while a run is unfinished.

        The value guard protects the baseline; holders, class, vault and the
        mint mechanism are the other half of the same plan. A resume reads them
        from the current declaration, so editing one mid-recovery changes what
        the parked value is delivered to. Metadata (description, notes) is not
        guarded because it changes no step.
        """
        detail = self.unfinished_rotation(name, journal)
        if detail is not None:
            raise HTTPException(
                status_code=409,
                detail=f"{name}: {detail}; resume, take it over or abandon it "
                f"before {action}",
            )

    @contextlib.contextmanager
    def stack_write(self, actor: str) -> Iterator[None]:
        """Keep topology, values and service URLs fixed for a whole rotation.

        The journal's reserved stack lease closes the check/write race: every
        server rotation takes it before planning, and every topology mutation
        takes it before reading candidate state. CLI apply cannot overlap the
        server because the instance owns `/config/app.lock`.

        Only the acquisition is translated. A credential lease conflict inside
        the body must keep the engine's own sentence, which names the holder
        and the age of the lock.
        """
        lease = facade.journal_for(self.config).lock(STACK_LOCK, actor)
        try:
            lease.__enter__()
        except JournalLocked:
            held = facade.journal_for(self.config).held(STACK_LOCK)
            detail = "a rotation or configuration change is in progress"
            if held is not None:
                changed = max(0, int(time.time() - held["acquired_at"]))
                who = held["actor"] or f"pid {held['pid']} on {held['host']}"
                detail = (
                    f"a rotation or configuration change is in progress "
                    f"({who}, {changed}s ago)"
                )
            raise HTTPException(
                status_code=409,
                detail=f"{detail}; retry after it finishes",
            ) from None
        try:
            yield
        finally:
            lease.__exit__(None, None, None)
