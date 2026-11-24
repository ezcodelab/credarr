"""Reveal throttling, in process and deliberately small.

A reveal is the one path that returns a value to a browser. A stolen session
should not be able to enumerate every credential at wire speed, and an operator
should not be able to hold one value on screen through repeated requests. The
limit is two dimensions: a per-actor burst (five per minute), a short cooldown
between two reveals (two seconds), and a per-credential burst so one name does
not become a hot loop.

State is in memory on purpose. A restart clearing the counters is acceptable
for a single-admin homelab; persisting them would keep a value-adjacent event
in the database for a rate limit, which is the wrong trade.
"""

from __future__ import annotations

import threading
import time

MAX_PER_MINUTE = 5
COOLDOWN_SECONDS = 2.0
WINDOW_SECONDS = 60.0


class RevealLimiter:
    def __init__(
        self,
        *,
        max_per_minute: int = MAX_PER_MINUTE,
        cooldown: float = COOLDOWN_SECONDS,
        window: float = WINDOW_SECONDS,
    ) -> None:
        self.max_per_minute = max_per_minute
        self.cooldown = cooldown
        self.window = window
        self._lock = threading.Lock()
        self._by_actor: dict[str, list[float]] = {}
        self._by_credential: dict[str, list[float]] = {}
        self._last: dict[str, float] = {}

    def allow(self, actor: str, credential: str, *, now: float | None = None) -> str | None:
        """Record an attempt, or return why it is refused."""
        at = time.time() if now is None else now
        with self._lock:
            for table, key in ((self._by_actor, actor), (self._by_credential, credential)):
                recent = [stamp for stamp in table.get(key, []) if at - stamp < self.window]
                table[key] = recent
                if len(recent) >= self.max_per_minute:
                    return (
                        "too many reveals; wait before trying again"
                        if key == actor
                        else f"{credential} was revealed too often; wait before trying again"
                    )
            last = self._last.get(actor)
            if last is not None and at - last < self.cooldown:
                return "a reveal just happened; wait before revealing again"
            self._by_actor.setdefault(actor, []).append(at)
            self._by_credential.setdefault(credential, []).append(at)
            self._last[actor] = at
        return None
