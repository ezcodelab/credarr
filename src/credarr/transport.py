"""Running the engine's stdlib-only API modules in a local subprocess.

Credarr is co-located with the stack it manages. Each service call is a real
Python program executed with stdin for its input and stdout for one JSON
answer: that keeps it importable, lintable and testable, and it means a crashed
call is a failed subprocess rather than a corrupted server process.

There is no remote transport and no local file read. Service API calls are
local to this deployment; the only Docker access is the optional read-only
discovery endpoint. A rotation asks each service to restart itself over its own
API.
"""

from __future__ import annotations

import subprocess
import sys
from typing import Protocol

from .errors import TransportError


class Transport(Protocol):
    """Runs a Python program locally and returns its stdout."""

    name: str

    def run_python(self, code: str, *, timeout: int | None = None) -> str:
        ...


class LocalTransport:
    """Runs the API module in a subprocess of this process's interpreter.

    Executing remote-shaped code by hand would mean emulating a process.
    Running a real subprocess keeps the contract identical: the module still
    only sees stdin and must still print JSON to stdout. It is the only
    transport this build has.
    """

    name = "local"

    def run_python(self, code: str, *, timeout: int | None = None) -> str:
        try:
            completed = subprocess.run(
                [sys.executable, "-"],
                input=code,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise TransportError("local API call timed out") from exc
        if completed.returncode != 0:
            raise TransportError(
                f"local API call failed (exit {completed.returncode}): {_tail(completed.stderr)}"
            )
        return completed.stdout


def _tail(stderr: str) -> str:
    """Last few lines of a module's stderr, bounded.

    The stderr can contain a fragment of a value if the module itself has a
    bug, so it is capped rather than passed through wholesale. This is a
    debugging aid for trusted operators, not a place to pass secrets.
    """
    lines = [line for line in stderr.strip().splitlines() if line.strip()]
    return " | ".join(lines[-3:])[:300] or "no output"
