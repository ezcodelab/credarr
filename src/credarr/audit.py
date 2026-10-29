"""The audit: declared state on one side, observed state on the other.

Strict API-only. There is no local config or database read: a holder is either
read back through its own running API (Seerr's settings API) or exercised
through its measured test route (`live`), and a holder with neither is reported
unverifiable. The old file probes are gone, so a Servarr API's redacted read is
not worked around.

Matching. A consumer may name a whole slot ("sonarr.indexers" - every row) or
one specific row ("seerr.settings_json[sonarr]"). The distinction is not
cosmetic. Seerr holds *both* the Sonarr and the Radarr key, so matching a
consumer against its whole slot reports the other service's key as drift on a
perfectly healthy system. A checker that cries wolf gets ignored, and a checker
that gets ignored is worse than none.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import Enum

from .config import Config
from .errors import CredctlError
from .executor import (
    EXERCISE_TIMEOUT,
    _explain,
    _servarr_call,
    exercise_holder,
)
from .fingerprint import Fingerprinter
from .model import Consumer, Credential, Manifest, parse_row_selector
from .redact import Secret, scrub, scrub_url_credentials
from .rotate import service_for, ui_password_names
from .secrets import SecretSource
from .transport import LocalTransport, Transport
from .writers import holder_for


class Status(Enum):
    """Outcome for one credential or one consumer.

    Ordered from worst to best so a credential can take the worst of its
    consumers without a pile of comparisons.
    """

    ERROR = "error"
    DRIFT = "drift"
    MISSING = "missing"
    ABSENT = "absent"
    UNVERIFIABLE = "unverifiable"
    # The holder's own test accepted the value it stores, but the value was
    # not read back. It is liveness, not equality, so it can never be MATCH.
    LIVE = "live"
    INDIRECT = "indirect"
    MATCH = "match"

    @property
    def is_problem(self) -> bool:
        return self in (Status.ERROR, Status.DRIFT, Status.MISSING)


@dataclass(frozen=True, slots=True)
class Observation:
    """One value read back over a holder's API."""

    target: str
    label: str
    secret: Secret
    field: str = ""

    @property
    def qualified(self) -> str:
        return f"{self.label}:{self.field}" if self.field else self.label


@dataclass(frozen=True, slots=True)
class Mismatch:
    """One held value that is not the canonical one.

    Carries the row and field so a failure is actionable, and the fingerprints
    so the operator can tell the two values apart. Never the values themselves:
    a drift report gets pasted into tickets and CI logs, and a credential that
    appears in one is a credential that has to be rotated for a reason that did
    not previously exist.
    """

    label: str
    field: str
    fingerprint: str


@dataclass(frozen=True, slots=True)
class ConsumerResult:
    consumer: Consumer
    status: Status
    observed: tuple[Observation, ...] = ()
    fingerprints: tuple[str, ...] = ()
    detail: str = ""
    # A stable code beside the sentence. The console uses it to name the action
    # that fixes the row without parsing English; `detail` stays the operator's
    # explanation and is never replaced by it.
    reason: str = ""
    mismatched: tuple[Mismatch, ...] = ()
    # The number of live rows the holder's API listed for this copy, when the
    # list is trustworthy to count (see the audit paths that set it). None means
    # the holder was not asked, did not answer, or the answer cannot be counted.
    # `consumer.count` stays the declaration; this is what the stack reports, so
    # a console can offer "set the declared count to what the API lists".
    observed_count: int | None = None


@dataclass(frozen=True, slots=True)
class CredentialResult:
    credential: Credential
    status: Status
    canonical_fingerprint: str | None = None
    consumers: tuple[ConsumerResult, ...] = ()
    detail: str = ""
    # The worst consumer's code when the roll-up has no sentence of its own.
    reason: str = ""

    @property
    def observed_copies(self) -> int:
        return sum(len(c.observed) for c in self.consumers)


@dataclass
class AuditResult:
    results: list[CredentialResult] = field(default_factory=list)
    fingerprint_salt_pinned: bool = False

    @property
    def problems(self) -> list[CredentialResult]:
        return [r for r in self.results if r.status.is_problem]

    @property
    def exit_status(self) -> Status:
        if any(r.status is Status.ERROR for r in self.results):
            return Status.ERROR
        if any(r.status is Status.DRIFT for r in self.results):
            return Status.DRIFT
        if any(r.status is Status.MISSING for r in self.results):
            return Status.MISSING
        # Deliberately unprovisioned is not a comparison either. It remains
        # exit 0 (not drift), but an all-absent or partly absent stack is not MATCH.
        if any(r.status is Status.ABSENT for r in self.results):
            return Status.ABSENT
        # A run that compared nothing must not summarize as a match. The exit
        # code can still be 0 (no finding), but the status must say what the
        # coverage was: UNVERIFIABLE.
        if any(r.status is Status.UNVERIFIABLE for r in self.results):
            return Status.UNVERIFIABLE
        # Liveness is weaker than equality. A run that exercised every holder
        # but read none of them back must not summarize as a match.
        if any(r.status is Status.LIVE for r in self.results):
            return Status.LIVE
        return Status.MATCH

    def counts(self) -> Mapping[Status, int]:
        tally: dict[Status, int] = {}
        for result in self.results:
            tally[result.status] = tally.get(result.status, 0) + 1
        return tally


def build_transport() -> Transport:
    """The transport for service API calls, run in this process's interpreter."""
    return LocalTransport()


class Auditor:
    """Runs the declared manifest against reality."""

    def __init__(
        self,
        *,
        manifest: Manifest,
        config: Config,
        secrets: SecretSource,
        fingerprinter: Fingerprinter,
    ) -> None:
        self._manifest = manifest
        self._config = config
        self._secrets = secrets
        self._fp = fingerprinter
        self._service_keys: dict[str, Secret | None] = {}

    def run(self, *, only: set[str] | None = None) -> AuditResult:
        credentials = [
            c for c in self._manifest.credentials.values()
            if only is None or c.name in only
        ]
        results = [self._evaluate(c) for c in credentials]
        return AuditResult(
            results=results, fingerprint_salt_pinned=self._fp.pinned
        )

    # -- evaluation ---------------------------------------------------------

    def _host_of(self, consumer: Consumer) -> str:
        """A consumer that does not name a host belongs to the configured
        default, resolved here rather than baked into the model."""
        return consumer.host or self._config.default_host

    def _service_key(self, service: str) -> Secret | None:
        """The holder's own key, read from the same canonical source.

        A service key is a normal credential. The runtime manifest has already
        re-anchored stored credentials to the app's database, so this asks the
        same source the audit uses for every other value. An unreadable
        unrelated credential is skipped rather than aborting the audit.
        """
        if service in self._service_keys:
            return self._service_keys[service]
        found: Secret | None = None
        # Manifest order and `setdefault` semantics match the runtime store's
        # resolver. The CLI additionally filters by vault backend; the audit
        # already reads through the source it was given. A declared UI
        # password is never the service's API key, even when its name starts
        # with the service name.
        passwords = ui_password_names(self._manifest, service)
        for credential in self._manifest.credentials.values():
            if credential.name in passwords:
                continue
            if not credential.provisioned or credential.vault is None:
                continue
            if service_for(credential) != service:
                continue
            try:
                found = self._secrets.get(credential.vault)
            except CredctlError:
                # One unreadable credential must not make every holder using
                # this service unverifiable; try the next candidate.
                continue
            if found is not None:
                break
        self._service_keys[service] = found
        return found

    def _live_alternative(
        self, consumer: Consumer, canonical: Secret
    ) -> tuple[ConsumerResult | None, str]:
        """Ask the holder's own test to exercise its stored value.

        This proves the holder accepts the value it holds; it does not read that
        value, so it cannot prove equality with the canonical one. It is the
        ceiling for a holder whose API redacts the value. Returning None means
        the preconditions were absent and the caller reports unverifiable; the
        second item is the stable code for why they were absent.
        """
        holder = holder_for(consumer.target.system, consumer.target.slot)
        if holder is None or not holder.test_path or not holder.api_path:
            return None, "no_readback"
        service = consumer.target.system
        host = self._config.host(self._host_of(consumer))
        if service not in host.urls:
            return None, "no_url"
        key = self._service_key(service)
        if key is None:
            return None, "no_service_key"
        secret = key.reveal()
        transport = build_transport()
        try:
            status, rows = _servarr_call(
                host, service, "GET", f"/{holder.api_path.strip('/')}",
                key=secret, transport=transport, timeout=EXERCISE_TIMEOUT,
            )
        except CredctlError as exc:
            return ConsumerResult(
                consumer, Status.UNVERIFIABLE,
                detail=scrub_url_credentials(scrub(
                    f"the holder's API could not be read for a liveness test "
                    f"({exc}); this copy was not compared",
                    secret, canonical,
                )),
                reason="unreachable",
            ), ""
        if status != 200 or not isinstance(rows, list):
            reason = scrub_url_credentials(
                scrub(_explain(rows), secret, canonical)
            ) or f"HTTP {status}"
            return ConsumerResult(
                consumer, Status.UNVERIFIABLE,
                detail=f"the holder's API did not list its rows for a liveness "
                f"test ({reason}); this copy was not compared",
                reason="unreachable",
            ), ""

        rows = [row for row in rows if isinstance(row, dict)]
        selector = parse_row_selector(str(consumer.target))
        if selector is not None:
            rows = [
                row for row in rows
                if str(row.get("name", "")) == selector.row
            ]
            if not rows:
                # A filtered list can look like an absent row. Without a
                # readable copy this is not a finding.
                return ConsumerResult(
                    consumer, Status.UNVERIFIABLE,
                    detail=f"the holder's API lists no row named "
                    f"{selector.row!r}; without a readable copy this is not a "
                    "finding",
                    reason="row_missing",
                    observed_count=0,
                ), ""
            if len(rows) != consumer.count:
                return ConsumerResult(
                    consumer, Status.UNVERIFIABLE,
                    detail=f"declared {consumer.count} cop"
                    f"{'y' if consumer.count == 1 else 'ies'}, the holder's "
                    f"API lists {len(rows)} row(s) named {selector.row!r}; "
                    "liveness cannot confirm the declared copies",
                    reason="count_mismatch",
                    observed_count=len(rows),
                ), ""
        else:
            rows = [row for row in rows if _has_field(row, holder.field)]
            if not rows:
                # List endpoints can omit fields; an empty filtered list is not
                # proof that the copy is gone, because the value is not
                # readable through the API.
                return ConsumerResult(
                    consumer, Status.UNVERIFIABLE,
                    detail=f"the holder's API lists no rows carrying "
                    f"{holder.field!r}; declared {consumer.count}, but "
                    "without a readable copy this is not a finding",
                    reason="field_missing",
                ), ""
            if len(rows) != consumer.count:
                return ConsumerResult(
                    consumer, Status.UNVERIFIABLE,
                    detail=f"declared {consumer.count} cop"
                    f"{'y' if consumer.count == 1 else 'ies'}, the holder's "
                    f"API lists {len(rows)} rows carrying {holder.field!r}; "
                    "liveness cannot say which row belongs to this credential",
                    reason="count_mismatch",
                    observed_count=len(rows),
                ), ""

        accepted = 0
        functional: list[str] = []
        rejected: list[str] = []
        inconclusive: list[str] = []
        for row in rows:
            row_id = row.get("id")
            if not isinstance(row_id, int):
                inconclusive.append("a row has no id")
                continue
            try:
                got, resource = _servarr_call(
                    host, service, "GET",
                    f"/{holder.api_path.strip('/')}/{row_id}",
                    key=secret, transport=transport, timeout=EXERCISE_TIMEOUT,
                )
            except CredctlError as exc:
                inconclusive.append(f"row {row_id}: " + scrub_url_credentials(
                    scrub(str(exc), secret, canonical)
                ))
                continue
            if got != 200 or not isinstance(resource, dict):
                inconclusive.append(f"row {row_id}: " + (
                    scrub_url_credentials(
                        scrub(_explain(resource), secret, canonical)
                    ) or f"HTTP {got}"
                ))
                continue
            verdict, note = exercise_holder(
                host, transport, holder, resource, secret,
                timeout=EXERCISE_TIMEOUT,
                secrets=(canonical,),
            )
            if verdict == "accepted":
                accepted += 1
                if note:
                    functional.append(scrub_url_credentials(
                        scrub(note, secret, canonical)
                    ))
            elif verdict == "rejected":
                rejected.append(scrub_url_credentials(
                    scrub(note, secret, canonical)
                ))
            else:
                inconclusive.append(f"row {row_id}: " + (
                    scrub_url_credentials(
                        scrub(note, secret, canonical)
                    ) or verdict
                ))

        if rejected:
            return ConsumerResult(
                consumer, Status.UNVERIFIABLE,
                detail=f"the holder's own test rejected the stored value for "
                f"{len(rejected)} of {len(rows)} row(s) ({rejected[0]}); this "
                "is not proof of drift - a stale process or an access layer "
                "looks the same, and the value was not read back",
                reason="liveness_rejected",
                observed_count=len(rows),
            ), ""
        if inconclusive or accepted != len(rows):
            reason = inconclusive[0] if inconclusive else "no verdict"
            return ConsumerResult(
                consumer, Status.UNVERIFIABLE,
                detail=f"the holder's own test accepted {accepted} of "
                f"{len(rows)} row(s); {reason}; this copy was not confirmed",
                reason="liveness_inconclusive",
                observed_count=len(rows),
            ), ""
        note = ""
        if functional:
            note = (
                f"; {len(functional)} row(s) reported a non-credential "
                f"condition ({functional[0]})"
            )
        return ConsumerResult(
            consumer, Status.LIVE,
            detail=f"the holder's own test accepted the stored value for "
            f"{accepted} row(s); the value was not read back, so equality "
            f"with the saved value is not proven{note}",
            reason="live",
            observed_count=len(rows),
        ), ""

    def _process_readback(
        self, consumer: Consumer, canonical: Secret, want: str
    ) -> ConsumerResult:
        """Read the value the holder's running process reports.

        `mechanism: process_api` promises that the holder must answer over its
        own API, authenticated with the holder's own key. Seerr's settings API
        does exactly that. Only an equal live value earns MATCH; a readable
        live value that differs is a finding, and a read that cannot be made
        stays unconfirmed rather than claiming a weaker answer.
        """
        def unconfirmed(text: str, code: str) -> ConsumerResult:
            return ConsumerResult(
                consumer, Status.UNVERIFIABLE,
                detail=f"{text}; the running service's value is not confirmed",
                reason=code,
            )

        holder = holder_for(consumer.target.system, consumer.target.slot)
        if (
            holder is None
            or holder.readback != "process_api"
            or not holder.readback_path
        ):
            return unconfirmed(
                f"this build has no process readback for {consumer.target}",
                "no_readback",
            )
        selector = parse_row_selector(str(consumer.target))
        if selector is None:
            return unconfirmed(
                "a process readback needs a qualified target naming one "
                "section, like seerr.settings_json[sonarr]",
                "target_unqualified",
            )
        service = holder.system
        host = self._config.host(self._host_of(consumer))
        if service not in host.urls:
            return unconfirmed(f"no URL for {service}", "no_url")
        key = self._service_key(service)
        if key is None:
            return unconfirmed(
                f"no stored key for {service}; store {service}'s own key "
                "before declaring process_api",
                "no_service_key",
            )
        secret = key.reveal()
        try:
            path = holder.readback_path.format(service=selector.row)
        except (KeyError, IndexError):
            return unconfirmed(
                f"the {service} readback path has no service placeholder",
                "no_readback",
            )
        transport = build_transport()
        try:
            status, body = _servarr_call(
                host, service, "GET", path,
                key=secret, transport=transport,
                auth_header=holder.auth_header_name,
                auth_transport=holder.auth_transport,
                timeout=EXERCISE_TIMEOUT,
            )
        except CredctlError as exc:
            return unconfirmed(scrub_url_credentials(scrub(
                f"the {service} settings API could not be read ({exc})",
                secret, canonical,
            )), "unreachable")
        if status != 200:
            reason = scrub_url_credentials(
                scrub(_explain(body), secret, canonical)
            ) or f"HTTP {status}"
            return unconfirmed(
                f"the {service} settings API did not answer ({reason})",
                "unreachable",
            )

        items = [body] if isinstance(body, dict) else body
        if not isinstance(items, list):
            return unconfirmed(
                f"the {service} settings API returned an unexpected shape",
                "unreachable",
            )
        rows = [item for item in items if isinstance(item, dict)]
        if not rows:
            # A valid empty section is the live truth: nothing holds this key
            # in the running service.
            return ConsumerResult(
                consumer, Status.MISSING,
                detail=f"the running service reports no {selector.row!r} "
                "entry carrying an API key",
                reason="row_missing",
                observed_count=0,
            )
        # shortcut: the measured process_api holder (Seerr) reports `apiKey`;
        # a second holder with another field needs that field on Holder.
        values = [
            item.get("apiKey") for item in rows
        ]
        values = [
            value for value in values
            if isinstance(value, str) and value and set(value) != {"*"}
        ]
        if not values:
            return unconfirmed(
                f"the {service} settings API returned no readable API key",
                "no_readback",
            )

        observations = tuple(
            Observation(
                target=consumer.target.key,
                label=selector.row,
                secret=Secret(value),
                field="apiKey",
            )
            for value in values
        )
        fingerprints = tuple(self._fp.of(o.secret) for o in observations)
        if len(values) != consumer.count:
            return ConsumerResult(
                consumer, Status.DRIFT, observations, fingerprints,
                detail=f"the running service reports {len(values)} "
                f"{selector.row!r} entr{'y' if len(values) == 1 else 'ies'} "
                f"where {consumer.count} cop"
                f"{'y' if consumer.count == 1 else 'ies'} were declared",
                reason="count_mismatch",
                observed_count=len(values),
            )
        offending = tuple(
            Mismatch(label=selector.row, field="apiKey", fingerprint=fp)
            for fp in fingerprints if fp != want
        )
        if offending:
            return ConsumerResult(
                consumer, Status.DRIFT, observations, fingerprints,
                detail=f"{len(offending)} of {len(observations)} live cop"
                f"{'y' if len(observations) == 1 else 'ies'} differ from the "
                "saved value",
                reason="value_drift",
                mismatched=offending,
                observed_count=len(values),
            )
        return ConsumerResult(
            consumer, Status.MATCH, observations, fingerprints,
            detail=f"the running {service} process reports the saved value",
            reason="match",
            observed_count=len(values),
        )

    def _evaluate(self, credential: Credential) -> CredentialResult:
        if not credential.provisioned:
            return CredentialResult(
                credential, Status.ABSENT,
                detail="declared but not provisioned yet",
                reason="not_provisioned",
            )

        if credential.vault is None:
            return CredentialResult(
                credential, Status.UNVERIFIABLE,
                detail="no canonical reference in the manifest",
                reason="no_canonical",
            )

        canonical = self._secrets.get(credential.vault)
        if canonical is None:
            return CredentialResult(
                credential, Status.ERROR,
                detail=f"no value at {'.'.join(credential.vault.path)} "
                f"in {credential.vault.file}",
                reason="value_missing",
            )

        want = self._fp.of(canonical)
        consumer_results = [
            self._evaluate_consumer(consumer, want, canonical)
            for consumer in credential.consumers
        ]
        # A failed API call's message can echo a fragment of what it was
        # reading, and the message reaches reports and the app's audit log. The
        # engine's own messages never name a value; this is the one path that
        # can.
        consumer_results = [
            replace(result, detail=scrub(result.detail, canonical))
            for result in consumer_results
        ]

        detail = ""
        reason = ""
        if not consumer_results:
            status = Status.INDIRECT
            reason = "no_holders"
        else:
            # A configured manual copy is not an anomaly and has nothing to
            # compare. It is displayed as `manual`; it does not pull the
            # credential's verdict away from the copies that were measured.
            comparable = [
                result
                for result in consumer_results
                if result.status is not Status.INDIRECT
            ]
            if comparable:
                worst = min(comparable, key=lambda result: _severity(result.status))
                status = worst.status
                reason = worst.reason
            else:
                status = Status.MATCH
                detail = (
                    "configured manual copies only; no API read-back to compare"
                )
                reason = "manual_only"

        return CredentialResult(
            credential, status, want, tuple(consumer_results), detail=detail,
            reason=reason,
        )

    def _evaluate_consumer(
        self,
        consumer: Consumer,
        want: str,
        canonical: Secret,
    ) -> ConsumerResult:
        if consumer.indirect:
            return ConsumerResult(consumer, Status.INDIRECT, reason="manual_copy")

        if consumer.process_readback:
            # The manifest asked for the running process. There is no local
            # file to fall back to, so this is the whole evaluation.
            return self._process_readback(consumer, canonical, want)

        holder = holder_for(consumer.target.system, consumer.target.slot)
        if holder is None:
            # Known and valid to declare, but nothing can read it back: a
            # manual copy by design. It is shown as `manual` and does not make
            # an otherwise measured credential look unhealthy.
            return ConsumerResult(consumer, Status.INDIRECT, reason="manual_copy")

        missing = "no_readback"
        if holder.test_path:
            live, missing = self._live_alternative(consumer, canonical)
            if live is not None:
                return live

        return ConsumerResult(
            consumer, Status.UNVERIFIABLE,
            detail="the holder's API does not expose a readable copy, so this "
            "copy was not compared; this is not a match",
            reason=missing,
        )


def _has_field(row: dict, name: str) -> bool:
    """Whether a Servarr resource row carries a named credential field."""
    if name in row:
        return True
    fields = row.get("fields")
    return isinstance(fields, list) and any(
        isinstance(field, dict) and field.get("name") == name for field in fields
    )


# Worst to best for comparable consumers. INDIRECT (manual) and ABSENT are not
# observations: they are kept here for the coverage test and must not be fed to
# the credential reduction. A manual copy is excluded rather than ranked.
_SEVERITY = {
      Status.ERROR: 0,
      Status.DRIFT: 1,
      Status.MISSING: 2,
      Status.UNVERIFIABLE: 3,
      # Liveness is a real observation, but it is not equality: the holder was
      # asked to use its stored value and accepted it.
      Status.LIVE: 4,
      Status.MATCH: 5,
      Status.INDIRECT: 6,
      Status.ABSENT: 7,
}


def _severity(status: Status) -> int:
    return _SEVERITY[status]


__all__ = [
    "AuditResult",
    "Auditor",
    "ConsumerResult",
    "CredentialResult",
    "Mismatch",
    "Observation",
    "Secret",
    "Status",
    "build_transport",
]
