"""The verify step drivers, behind `Executor`.

The methods are move-only from the executor; `self` is the same object, so
the journal, the bound transport and the rotation context are the ones the
orchestrator created.
"""

from __future__ import annotations

import time

from credarr.errors import RotationError, TransportError
from credarr.model import parse_row_selector, split_target
from credarr.redact import scrub
from credarr.rotate import Step
from credarr.writers import Holder, auth_kwargs, auth_shape, holder_for, readiness_path

from .support import READINESS_INTERVAL, exercise_holder, log_line
from .types import Verdict


class VerifySteps:
    def _checked_call(self, service: str, method: str, path: str,
                      **kwargs: object) -> tuple[int, object] | None:
        """One preflight API call, with an unreachable host reported not raised.

        Preflight's contract is that everything checkable is checked *before*
        the key is revoked, and that every reason is reported rather than the
        first one found. A `TransportError` escaping that contract breaks both
        halves: an unreachable host crashes the CLI with a traceback instead of
        reporting "nothing was changed", and it also short-circuits the checks
        after it, so a stack that is down *and* misconfigured reports only the
        first symptom.

        Returns None when the host could not be reached, which every caller
        turns into a problem and then moves past.
        """
        try:
            return self._call(self._ctx.host, service, method, path,
                              transport=self._ctx.transport, **kwargs)
        except TransportError as exc:
            # Reported by the caller as a problem, so a single unreachable host
            # never stops the remaining checks from running.
            self._ctx.preflight_notes.append(
                f"{service}: could not be reached during preflight ({exc})"
            )
            return None

    def _service_key(self, service: str) -> str | None:
        """The key that authorises calls to `service`.

        Distinct from the key being propagated. Rotating Prowlarr's key means
        writing it into Sonarr's indexer rows - but the PUT to Sonarr is
        authorised by Sonarr's own key. Conflating the two authenticates every
        write with the wrong credential, which fails with 401 at exactly the
        moment the old key has already been revoked.

        Resolution is the product's: the key this run minted for that service
        (a self-holder must see the new value), then the runtime store's copy of
        the service's own key. A missing source is not an error here; the
        caller reports what it could not prove. There is no local file fallback.
        """
        if self._ctx.minted is not None and self._ctx.minted_service == service:
            return self._ctx.minted.reveal()
        stored = self._ctx.service_keys.get(service)
        if stored is not None:
            return stored.reveal()
        return None

    def _authenticate(self, service: str, key: str | None) -> Verdict:
        """Ask the service whether `key` is a live credential.

        Three states, not two, because the middle one matters:

        live     the service accepted it.
        dead     the service refused it (401/403).
        unknown  the service could not be reached, or answered something that
                 is not a credential answer.

        `unknown` is deliberately distinct from `dead`. A service that is down
        says nothing about whether a key works, and collapsing the two is how a
        recovery ends up acting on a credential that was fine.
        """
        path = readiness_path(service)
        try:
            status, _ = self._call(
                self._ctx.host, service, "GET", path,
                transport=self._ctx.transport,
                **auth_kwargs(service, key),
            )
        except TransportError as exc:
            # A transport failure is an answer of its own: the service could
            # not be reached. Without this it escaped, which made the
            # "unknown" verdict unreachable and the retry that depends on it
            # dead code - a service restarting moments ago looked like a hard
            # failure rather than a temporary one.
            return Verdict("unknown", None, f"{type(exc).__name__}: {exc}")
        if 200 <= status < 300:
            return Verdict("live", status, f"HTTP {status}")
        if status in (401, 403):
            shape = auth_shape(service)
            if shape.live_on_403 and status == 403:
                # The service validates the token first and answers 403 when
                # the token lacks the route's scope, so the token is live and
                # the route is out of scope. A revoked token answers 401, so
                # the revoke check still sees dead.
                return Verdict("live", status, "HTTP 403")
            return Verdict("dead", status, f"HTTP {status}")
        return Verdict("unknown", status, f"HTTP {status}")

    def _authenticate_settled(self, service: str, key: str) -> Verdict:
        """Authenticate, tolerating a service that is still coming up.

        Only transport failures are retried. A 401 is an answer, and repeating
        a question that has already been answered only delays the report.
        """
        deadline = time.time() + self._ctx.settle_timeout
        verdict = self._authenticate(service, key)
        while verdict.state == "unknown" and time.time() < deadline:
            time.sleep(READINESS_INTERVAL)
            verdict = self._authenticate(service, key)
        return verdict

    def _confirm_old_key_dead(self, service: str, old_key: str) -> None:
        """Record whether the old key is dead at the issuer, without aborting.

        A still-live old key does not make the new key unusable, but it does
        break the exercise proof's equality reading: the holder could be
        carrying either value and the test would accept it. The writes still
        have to run (the reset may already have killed the old key), so this is
        a per-run fact used when a holder has no read-equal, not a refusal.
        """
        deadline = time.time() + self._ctx.settle_timeout
        while True:
            verdict = self._authenticate(service, old_key)
            # A bare 403 is not a credential verdict: an access layer refusing
            # the status route for a live key produces exactly that. The table
            # carries the measured answer for the services that use 403.
            dead_status = auth_shape(service).dead_status
            if verdict.state == "dead" and verdict.status == dead_status:
                self._ctx.old_key_dead = True
                return
            if time.time() >= deadline:
                self._ctx.old_key_dead = False
                if verdict.state == "dead":
                    state = f"was refused with {verdict.detail}, which is ambiguous"
                elif verdict.state == "live":
                    state = "still accepts it"
                else:
                    state = f"was {verdict.state}"
                log_line(
                    f"      {service}: could not confirm the old key is dead "
                    f"({state}); exercise-only confirmation will not be claimed"
                )
                return
            time.sleep(READINESS_INTERVAL)

    def _select_rows(self, target: str, rows: list) -> list:
        """Only the rows this target declared.

        A qualified target names one row; an unqualified one claims the whole
        slot and gets every row. Filtering here rather than at the call site
        means the write loop, the per-row comparison and the process read-back
        all see the same set - a check scoped more widely than the write would
        report success on a row the rotation never touched.
        """
        selector = parse_row_selector(target)
        if selector is None:
            return rows
        claimed = [
            row for row in rows
            if isinstance(row, dict) and str(row.get("name", "")) == selector.row
        ]
        if not claimed:
            raise RotationError(
                f"{target}: no row named {selector.row!r} exists to update",
                hint="the manifest names one row inside this slot. Writing every "
                "row instead would replace credentials this consumer never "
                "claimed, so the rotation stops here.",
            )
        return claimed

    def _row_name(self, target: str) -> str | None:
        """The row a qualified target names, for scoping an API row read."""
        selector = parse_row_selector(target)
        return selector.row if selector else None

    def _resolve_field(self, step: Step) -> str:
        """Which credential field in a row this step writes.

        A `row:field` qualifier selects it. Without that, a
        `download_clients[qBittorrent:password]` consumer would be written into
        the `apiKey` field, because the slot registry names one default field per
        slot and a download-client row carries more than one credential.
        """
        system, slot = split_target(step.target)
        described = holder_for(system, slot)
        if described is None:
            # A holder with no default field holds one credential per section
            # and its writer knows where each goes. Reaching here means a
            # caller asked a question this shape cannot answer, and returning
            # a Servarr default would be inventing one.
            raise RotationError(
                f"{step.target}: no default credential field for that holder",
                hint="this holder writes a named section, not a field",
            )
        selector = parse_row_selector(step.target)
        return selector.field if selector and selector.field else described.field

    def _exercise(self, holder: Holder, system: str, resource: dict) -> tuple[str, str]:
        """Ask the holder to use its stored value, returning a credential verdict.

        The body is the row exactly as the pre-write GET returned it, mask
        intact. Servarr treats the mask as "unchanged" and substitutes the
        stored value, so the test exercises the value the running process holds,
        not the one this run just wrote.

        `accepted` is liveness, not equality. `rejected` is ambiguous: a stale
        process, a blocked link and a 401 access layer are indistinguishable
        from a revoked key, which is why callers may not mint from it. Anything
        else, including a timeout, is inconclusive.
        """
        if not holder.test_path:
            return "unsupported", ""
        try:
            service_key = self._service_key(system)
        except (TransportError, RotationError) as exc:
            return "inconclusive", scrub(
                str(exc), self._ctx.minted, self._ctx.vault_value
            )
        if not service_key:
            return "inconclusive", "the holder's own API key is not readable"
        return exercise_holder(
            self._ctx.host,
            self._ctx.transport,
            holder,
            resource,
            service_key,
            call=self._call,
            timeout=self._ctx.exercise_timeout,
            secrets=(
                self._ctx.minted.reveal() if self._ctx.minted is not None else None,
                self._ctx.vault_value,
            ),
        )
