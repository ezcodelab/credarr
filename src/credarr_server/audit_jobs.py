"""Server-side job for one long audit.

The console cannot hold a request open for a full audit: a proxy or tunnel
will cut it, and the browser then reports a network error even though the
server is still working. This module owns one in-process audit thread and the
small amount of state the console needs to reconnect to it. It is deliberately
not durable: the audit ledger is the durable record, and a server restart
loses the waiter, not the audit.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

JobStatus = Literal["running", "succeeded", "failed"]

# Keep enough completed jobs for a reload to find its result, but do not grow
# without bound over a long-lived process.
MAX_JOBS = 20


@dataclass
class AuditJob:
    """One audit the console can poll."""

    id: str
    started_at: float
    status: JobStatus = "running"
    finished_at: float | None = None
    result: dict[str, Any] | None = None
    error: str | None = None


class AuditJobs:
    """One active audit and a bounded history of finished jobs."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, AuditJob] = {}
        self._active: AuditJob | None = None

    def start(self, run: Callable[[], dict[str, Any]]) -> AuditJob:
        """Start an audit, or return the one already running.

        A second click must not start a second stack audit. The scheduler's own
        lock serialises this thread against the interval loop; this lock only
        decides which job the console polls.
        """
        with self._lock:
            if self._active is not None:
                return self._active
            job = AuditJob(id=secrets.token_hex(16), started_at=time.time())
            self._jobs[job.id] = job
            self._active = job
            self._prune()
        thread = threading.Thread(
            target=self._run,
            args=(job, run),
            name=f"credarr-audit-{job.id[:8]}",
            daemon=True,
        )
        try:
            thread.start()
        except Exception as exc:
            # A failed thread start must not leave a dead job occupying the
            # one active slot forever.
            with self._lock:
                job.status = "failed"
                job.error = f"{type(exc).__name__}: {exc}"
                job.finished_at = time.time()
                if self._active is job:
                    self._active = None
            raise
        return job

    def active(self) -> dict[str, Any] | None:
        """The running job, for a reloaded console to resume polling it."""
        with self._lock:
            return self._payload(self._active) if self._active is not None else None

    def get(self, job_id: str) -> dict[str, Any] | None:
        """The JSON view of one job, or None when it is not in this process."""
        with self._lock:
            job = self._jobs.get(job_id)
            return self._payload(job) if job is not None else None

    def _run(self, job: AuditJob, run: Callable[[], dict[str, Any]]) -> None:
        result: dict[str, Any] | None = None
        error: str | None = None
        try:
            result = run()
        except Exception as exc:
            # The synchronous route lets a real bug escape as a 500. A
            # background job has no caller to raise to, so it records the same
            # class name and sentence for the polling route.
            error = f"{type(exc).__name__}: {exc}"
        finally:
            with self._lock:
                if error is None and result is None:
                    error = "the audit returned no result"
                job.result = result
                job.error = error
                job.status = "succeeded" if error is None else "failed"
                job.finished_at = time.time()
                if self._active is job:
                    self._active = None

    def _prune(self) -> None:
        """Drop the oldest completed jobs, never the active one."""
        finished = [job for job in self._jobs.values() if job.status != "running"]
        if len(finished) <= MAX_JOBS:
            return
        finished.sort(key=lambda job: job.finished_at or 0.0)
        for job in finished[: len(finished) - MAX_JOBS]:
            self._jobs.pop(job.id, None)

    @staticmethod
    def _payload(job: AuditJob) -> dict[str, Any]:
        return {
            "job_id": job.id,
            "status": job.status,
            "started_at": job.started_at,
            "finished_at": job.finished_at,
            "result": job.result,
            "error": job.error,
        }
