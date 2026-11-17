"""The executor's inputs, outcomes, and the frozen verdict of an auth probe.

These are shared by the orchestrator and the step-kind mixins, so they live
below both. A value that crosses a step boundary is defined here once.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from credarr.config import HostConfig
from credarr.executor_steps.support import EXERCISE_TIMEOUT
from credarr.journal import Journal
from credarr.model import Credential
from credarr.pending import PendingSecrets
from credarr.redact import Secret
from credarr.transport import Transport


@dataclass(frozen=True, slots=True)
class HolderOutcome:
    """What happened to one specific holder.

    Reported per holder rather than per step, because "propagate failed" does
    not tell an operator which of sixteen indexers now hold a dead key. That
    list is the difference between a rotation that was interrupted and one that
    left the stack broken.
    """

    target: str
    label: str
    # written        - the write landed, nothing has read it back yet. Transient
    #                  on the way to "confirmed": *arr answers 202 before the
    #                  row has necessarily changed, and the holder's own test
    #                  has not accepted it yet. It can survive a failure
    #                  mid-slot, so it must not be read as an outcome in its own
    #                  right.
    # confirmed      - the holder's own API confirmed the value: its measured
    #                  test route accepted the stored value for a Servarr row,
    #                  or the running process reported it for a Seerr holder.
    # A level above "confirmed" - the consumer actually searched with it - is
    # deliberately absent. Nothing produces it, and a state no run can reach is
    # a promise the report cannot keep.
    # already-current| the holder already held the new key; nothing written.
    # failed         - the write was refused, or did not take.
    # not-reached    - a step before this one failed, so this was never tried.
    outcome: str
    detail: str = ""
    # The proof that supported a confirmation: "read-equal" when the running
    # process returned the value, "exercised" when the holder's own test route
    # or connection test accepted it. Empty when nothing confirmed the row.
    # Never set on a tripwire: the detail says what disagreed instead.
    method: str = ""


@dataclass
class ExecutionResult:
    credential: str
    attempt: int
    completed: list[str] = field(default_factory=list)
    failed: str | None = None
    detail: str = ""
    manual: list[str] = field(default_factory=list)
    holders: list[HolderOutcome] = field(default_factory=list)
    preflight: list[str] = field(default_factory=list)
    # True when this run continued an earlier mint rather than making one.
    resumed: bool = False
    # Steps this run took over from a run presumed dead. Recorded rather than
    # silently aged out, so an operator can see a takeover happened.
    reclaimed: list[tuple[str, str]] = field(default_factory=list)
    # False when the source supports deferred revocation (Jellyfin create).
    revokes_before_holders: bool = True
    # True only when this run's RECORD step completed. The CLI's "the vault now
    # holds the new key" sentence reads this, rather than matching a word in a
    # step target.
    vault_written: bool = False

    @property
    def ok(self) -> bool:
        """True when no step raised. **Not** a delivery signal.

        A run holding a `written` holder raises nothing and is
        still undelivered, so this returns True for exactly the state `clean`
        exists to catch. Anything deciding whether a rotation succeeded must read
        `clean`, or read the holders themselves.
        """
        return self.failed is None

    @property
    def clean(self) -> bool:
        """True only when nothing failed and nothing was left unproven.

        `ok` asks whether a step raised. `clean` asks whether the stack is
        consistent, which is the question a scheduled job needs answered: a
        holder that was never reached is as broken as one that failed, and
        reporting success because nothing threw would be worse than useless.

        "written" counts against it. It is a transient state on the way to
        "confirmed" — the API accepted the request, and *arr answers 202 before
        the row has necessarily changed — so seeing one at the end means the
        promotion did not happen. A stack is not in a known state when
        something is unproven.

        A manual step counts too: the tool could not update that holder, so it
        still holds the key that was just revoked. That is the same condition
        `audit` reports as drift, and the reason `execution_exit_code` returns
        1 for it - a result that read `clean` here would say a rotation landed
        when a consumer is holding a dead key.
        """
        return (
            self.failed is None
            and not self.manual
            and not any(
                h.outcome in ("failed", "not-reached", "written")
                for h in self.holders
            )
        )

    def summary(self) -> str:
        counts: dict[str, int] = {}
        for holder in self.holders:
            counts[holder.outcome] = counts.get(holder.outcome, 0) + 1
        return ", ".join(f"{n} {k}" for k, n in sorted(counts.items()))


@dataclass
class RotationContext:
    """Everything an executor needs that is not the plan."""

    credential: Credential
    host: HostConfig
    transport: Transport
    journal: Journal
    # Minted value, held for the run so a consumer write never re-reads it and
    # never has to carry it through a plan.
    minted: Secret | None = None
    # The canonical value from the vault. Needed before minting so a resumed run
    # can tell "already rotated" from "first attempt".
    vault_value: str | None = None
    # A key the operator rotated in the service's own UI and supplied to this
    # run. Only the explicit `write.manual_mint` path uses it; it is verified
    # before any holder is written and never crosses the journal or a message.
    provided: str | None = None
    # The runtime store's copies of each service's own API key, keyed by
    # service: the app's working copies, or the CLI's vault. A holder call uses
    # these; there is no local config fallback.
    service_keys: Mapping[str, Secret] = field(default_factory=dict)
    # The service whose key this run minted. A holder of that same service must
    # use the new value, not the store's copy, which is written at RECORD.
    minted_service: str | None = None
    # The service-side identifier of the credential this run minted, for a
    # mechanism whose revoke cannot match by value (Grafana lists token names,
    # never secrets; Arcane lists key ids). Empty when the mechanism does not
    # need one.
    minted_handle: str = ""
    # Stored values of other credentials a mint may authenticate with, keyed by
    # credential name (write.mint_with). Empty when this credential rotates
    # itself.
    mint_values: Mapping[str, Secret] = field(default_factory=dict)
    # Writes the minted value back to the canonical store. None for a run that
    # must not write, such as a dry preflight.
    vault_setter: Callable[[Secret], None] | None = None
    # Where an API-only mint parks the value it chose before restoring the
    # service's config. None means this run cannot offer that mechanism; the
    # preflight reports it before anything is changed.
    pending: PendingSecrets | None = None
    # Per-run record of what happened to each individual holder.
    holders: list[HolderOutcome] = field(default_factory=list)
    # Set once the run has an attempt id, so holder state can be journalled.
    attempt: int | None = None
    # Set before the first step when the previous attempt reached RECORD but
    # never finished. The run completes from RECORD instead of minting again.
    prior_record: bool = False
    prior_attempt: int | None = None
    # The handle a dead run's reissue mint recorded before it died. When the
    # value it created is still parked, the mint adopts that row instead of
    # creating a third secret.
    prior_mint_handle: str = ""
    # The ordinal of the step being dispatched, for a mint that must record its
    # handle before the step itself finishes.
    current_ordinal: int = -1
    # Called after the attempt row exists; a scheduler uses it to record a
    # truthful "started" event, never one with a fake status transition.
    on_started: Callable[[int], None] | None = None
    # Observations gathered during preflight that are not failures of their own
    # but explain why a check could not run. Kept on the context because
    # `_checked_call` has no `problems` list of its own to append to.
    preflight_notes: list[str] = field(default_factory=list)
    # True when the run continued an earlier mint rather than making one. Kept
    # here because that is what decides it, and reported because the difference
    # is the whole of whether a rerun was safe.
    resumed: bool = False
    # How long to keep retrying a *transport* failure while deciding whether a
    # key is live. Short by design: this covers a service that was just
    # restarted and is still accepting connections, not an outage. A genuine
    # outage still refuses, it just refuses after genuinely trying.
    settle_timeout: float = 20.0
    # Bound on one holder test call. Expiry is inconclusive; a hang must not
    # become the rotation's own runtime.
    exercise_timeout: float = EXERCISE_TIMEOUT
    # True when the issuer no longer accepts the old key, False when it still
    # does or could not be asked, None when no reset mint ran. Exercise-only
    # confirmation requires True (protocol 1 and 2 of the proof contract).
    old_key_dead: bool | None = None
    # Base backoff between holder-write attempts. Injectable so tests prove the
    # retry logic without spending the time.
    write_backoff: float = 5.0
    # Seconds to wait between holder writes.
    #
    # Every write makes the *arr app validate the indexer against its upstream,
    # so a rotation adds a burst of requests to an upstream that is also being
    # hammered by the app's own background sync. This paces that burst.
    #
    # It reduces the load this tool contributes; it cannot remove the load the
    # service generates itself, and it is not what guarantees convergence - the
    # retry is. A default of zero would be a silent promise that the problem
    # does not exist, so the default is a real interval and every pause is
    # logged rather than hidden.
    write_interval: float = 2.0
    # Asserts the rotation lock is still ours. Set when the caller holds one.
    # Without it a reclaimed run cannot tell it was overtaken, and keeps writing
    # to services another rotation now owns.
    lease_check: Callable[[], None] | None = None
    # The operator has said the run that left unfinished steps behind is not
    # coming back: the run takes those steps over now instead of waiting out the
    # staleness window. It closes the *record*; what makes it safe is the lock
    # (taken before this run began) and the mint re-deriving from the service's
    # own state.
    take_over: bool = False
    # Who asked, for the journal row that records the takeover. The console
    # sends `admin` or `key:<id>`; the CLI sends whatever `--actor` names, and
    # nothing when it was not given.
    actor: str | None = None


@dataclass(frozen=True, slots=True)
class BackupProbe:
    """The backup-download verdict plus what the console needs to explain it.

    `problem` is the engine sentence (None when the download is usable).
    `login_required` is the measured 302; `auth_method`/`can_help` say whether
    a stored UI password is a possible fix. These are facts from a read-only
    probe, not a second copy of the planner.
    """

    problem: str | None
    login_required: bool = False
    auth_method: str = ""
    ui_password_configured: bool = False
    ui_password_can_help: bool = False


@dataclass(frozen=True, slots=True)
class Verdict:
    """What a service answered about a key, in fields rather than prose.

    `state` is the credential answer, `status` the HTTP code when there was one
    (`None` when the service could not be reached), and `detail` the sentence a
    human reads. The split is the point: control flow reads `state` and
    `status`, so rewording `detail` - "HTTP 401" today, a sentence that quotes
    the service tomorrow - cannot change whether a mint refuses.

    A caller with no value to ask about uses `state="absent"`, which is not a
    service answer: it never counts as `live` or `dead`, and callers that need
    "could not check" test it separately from `unknown`.
    """

    state: str
    status: int | None
    detail: str
