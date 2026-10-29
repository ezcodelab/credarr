"""Executing a rotation.

The plan says what will happen. This makes it happen, and it is the only module
that writes anything anywhere.

Four properties, all of which exist because the alternative is a rotation that
leaves the stack broken in a way nobody can see:

- **Idempotent where the service allows it.** A reset mint compares the
  service's current key with the vault's, so a previous attempt's key resumes
  propagation instead of minting again. Jellyfin's create mint has nothing to
  compare against: a resume mints a fresh key and takes the newest, so a run
  interrupted between its mint and its revoke always leaves one key live - the
  one it minted if it died before the vault write, the one it was replacing if
  it died after. The revoke sweeps every key carrying the name credarr mints
  under, so its own leftovers do not accumulate; the residue it cannot claim
  is a key credarr never minted - an adopted predecessor - which stays an
  operator step.

- **Verified by the holder's own test, not a local store.** The *arr indexer
  endpoint redacts `apiKey` as `********` on read, so it cannot confirm its own
  write by equality. Strict API-only has no local database readback: the
  holder app's measured test endpoint is asked to use its stored value against
  the counterpart, and an accepted value counts as equal only when the issuer
  no longer accepts the old key. Exercise alone is never enough. A holder with
  no measured test route is reported as written-but-unproven, not confirmed.

- **Journaled before, not after.** Each step is recorded as started before it
  runs. A start with no finish is the evidence that survives a crash.

- **Stops at the first failure.** Continuing after a failed write means later
  writes land against a half-propagated value, and the rollback is harder to
  reason about than the failure.
"""

from __future__ import annotations

import base64
import copy
import io
import json
import re
import sys
import time
import urllib.parse
import zipfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from secrets import token_hex
from xml.sax.saxutils import escape as _xml_escape

from . import __version__
from .config import HostConfig
from .errors import ConfigError, CredctlError, RotationError, TransportError
from .journal import Journal
from .model import Credential, parse_row_selector, split_target
from .pending import PendingSecrets
from .redact import Secret, scrub, scrub_url_credentials
from .rotate import RotationPlan, Step, StepKind, service_for
from .transport import Transport
from .writers import (
    MINT_SOURCES,
    REISSUERS,
    Holder,
    Reissue,
    api_version,
    holder_for,
    known_systems,
    readiness_path,
)

# How long to wait for a service to answer after a restart. Restarting Prowlarr
# and immediately hammering its API produces a burst of connection refusals that
# looks like a failure and is not.
READINESS_TIMEOUT = 180
READINESS_INTERVAL = 3
# Identify the client at the HTTP boundary. Cloudflare deployments can reject
# Python's default User-Agent with a 1010 WAF response even though the host is
# reachable; a stable product UA is not a credential and makes that distinction
# visible to the deployment's owner.
USER_AGENT = f"credarr/{__version__}"
# Seerr's settings API updates the running process synchronously, but the
# read-back is a separate request and a slow process may not answer at once.
SEERR_READBACK_TIMEOUT = 30
SEERR_READBACK_INTERVAL = 0.5
# A holder write is validated by the *arr app against its upstream, so one
# write can fail for reasons that have nothing to do with the request. Bounded
# attempts with backoff, because giving up immediately turned a rate limit into
# a thirty-minute outage.
WRITE_ATTEMPTS = 4
WRITE_BACKOFF = 5
# Ceiling on the pacing interval. Bounded because an escalating delay that never
# resets would turn a slow rotation into a stalled one.
MAX_WRITE_INTERVAL = 30.0

# Sonarr validates an indexer while saving it, which can involve contacting it.
# Three of ten took over five seconds and some exceeded thirty, so a short
# timeout turns a successful write into an apparent failure - and a rotation
# that reports failure for a write that landed is worse than one that is slow.
API_TIMEOUT = 180
# Ordinary API answers are JSON documents; a service or a proxy that streams
# without end must not be read into memory. Full database backups are the one
# deliberate exception: they go to an unlinked temporary file in the service
# host's process, never through this buffer (see _servarr_backup_config). They
# still have a ceiling, and only config.xml is extracted from the archive.
MAX_JSON_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_BACKUP_BYTES = 1024 * 1024 * 1024
MAX_CONFIG_XML_BYTES = 8 * 1024 * 1024
# Reading config.xml through the service's own backup API is a multi-step
# operation: ask, wait for the Backup command to complete, download the archive,
# extract the one small file, and delete the archive. The backup command and
# file waits alone can consume 300s; the parent budget must also cover the
# download and ZIP extraction, or the child is killed before it can delete the
# archive and report the real cause.
CONFIG_READ_TIMEOUT = 420
# The same, for the restore upload. The file is tiny; the service can still take
# a while to accept it.
CONFIG_RESTORE_TIMEOUT = 180
# The holder's own test is a second call after a successful write, not a save
# validation. A real Radarr indexer test can exceed 30s while it waits on its
# upstream; 25s cut the local subprocess before Radarr could return its own
# result. The transport still bounds a hang, but it must not be shorter than
# the service's own test. Expiry is inconclusive, never a credential verdict.
EXERCISE_TIMEOUT = 90
# Only these texts name the credential (measured on the pinned *arr pair). The
# status is identical to a 500 or a DNS failure, and a 401 from a proxy or
# allowlist in front of a healthy app produces the same words as a stale key -
# which is why a rejection is ambiguous, not drift. A bare "Apikey" is not a
# marker: the measured 429 body embeds `apikey=` in the request URL while saying
# nothing about the credential.
CREDENTIAL_MARKERS = ("invalid credentials", "api key is invalid")

# These are indexer test failures that happen after the credential was accepted.
# Sonarr/Radarr report a disabled upstream Prowlarr indexer as a 400 carrying
# `[410:Gone]`; Prowlarr itself answers 410 only after API-key authentication.
# A "query successful" with no category results is also a content result, not
# a rejected key. Treating either as a credential failure makes a healthy copy
# look unverifiable.
INDEXER_FUNCTIONAL_MARKERS = (
    "no results in the configured categories",
    "[410:gone]",
)


def _names_credential(text: str) -> bool:
    """Whether a failure's own words name the credential (measured shapes)."""
    normalized = " ".join(text.lower().split())
    return any(marker in normalized for marker in CREDENTIAL_MARKERS)


def _indexer_functional_failure(text: str) -> bool:
    """Whether an indexer test failed after the key was accepted."""
    normalized = " ".join(text.lower().split())
    if any(marker in normalized for marker in INDEXER_FUNCTIONAL_MARKERS):
        return True
    # Prowlarr's XML body names the disabled indexer but Sonarr may only retain
    # the status line. Require both facts: a bare "disabled" can be a temporary
    # 429 and must stay inconclusive.
    return "410" in normalized and "indexer is disabled" in normalized

# Slot name -> the API path segment that addresses it.
#
# They are not the same word. The manifest says "indexers" because that is the
# table and the noun an operator uses; the API says /indexer. Guessing the path
# from the slot name produces a 404 for every row - after the key was revoked.
# Verified against the running services rather than inferred: sonarr serves
# /api/v3/indexer and /api/v3/downloadclient, prowlarr serves
# /api/v1/applications, and none of them serve the plural forms.
# Upstream trouble that a retry can fix, as opposed to a request this tool got
# wrong. Both reach us as the same status: Sonarr and Radarr each validate an
# indexer by calling Prowlarr live during the save, so Prowlarr rate-limiting or
# timing out surfaces as a 400 from the app holding the row. The status is
# Prowlarr's problem wearing Sonarr's status code, and the body text is the
# only thing that distinguishes the two.
TRANSIENT_MARKERS = (
    "too many requests", "429", "rate limit", "timed out", "timeout",
    "unable to connect", "connection refused", "server is unavailable",
    "temporarily unavailable", "no route to host", "try again later",
    "service unavailable", "gateway timeout",
)
# A verdict about the indexer itself. Retrying these forever is pointless: the
# indexer has no content in the categories it is configured for.
PERMANENT_MARKERS = (
    "no results in the configured categories", "could not be converted",
    "is required", "is invalid", "not a valid",
)
TRANSIENT_STATUS = {408, 425, 429, 500, 502, 503, 504}


def log_line(message: str) -> None:
    """Progress during a run, on stderr so the report stays machine-readable."""
    print(message, file=sys.stderr)


def classify_refusal(status: int, payload: object) -> tuple[str, str]:
    """`(verdict, reason)` for a non-2xx holder write.

    transient  - upstream is unwell or busy; the same request may succeed later.
    permanent  - this request cannot succeed as sent, and probably never will.
    unknown    - no body to judge by; worth one retry, then surface it.
    """
    if status in TRANSIENT_STATUS:
        return "transient", f"HTTP {status}"
    text = _explain(payload).lower()
    if any(marker in text for marker in PERMANENT_MARKERS):
        return "permanent", _explain(payload)
    if any(marker in text for marker in TRANSIENT_MARKERS):
        return "transient", _explain(payload)
    if not text:
        return "unknown", f"HTTP {status} with no explanation"
    return "permanent", _explain(payload)


def _explain(payload: object) -> str:
    """One line saying why a service refused something, or nothing.

    Both halves matter. Servarr's problem+json puts the generic summary in
    `title` ("Invalid request Validation failed") and the actual cause in
    `errors` ("Unable to connect to indexer: [429:TooManyRequests]"). Returning
    only the title reproduces the uselessness this is meant to remove.
    """
    if isinstance(payload, dict):
        parts: list[str] = []
        for key in ("title", "message", "detail", "errorMessage"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                parts.append(value.strip())
                break
        errors = payload.get("errors")
        if isinstance(errors, dict) and errors:
            for field, messages in errors.items():
                text = (str(messages[0]) if isinstance(messages, list)
                        and messages else str(messages))
                text = text.strip()
                if text and text not in parts:
                    # "--" is Servarr's placeholder field for a whole-resource
                    # validation failure; it names nothing and only adds noise.
                    parts.append(text if field == "--" else f"{field}: {text}")
                break
        if parts:
            return ": ".join(parts)[:400]
    if isinstance(payload, list):
        # The measured Servarr holder test routes answer with a list of problem
        # objects, not problem+json. Their `errorMessage` is the sentence that
        # says whether this was a credential refusal or a network failure.
        for item in payload:
            if not isinstance(item, dict):
                continue
            for key in ("errorMessage", "message", "detail", "title"):
                value = item.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()[:400]
    if isinstance(payload, str) and payload.strip():
        return payload.strip()[:400]
    return ""


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


class Executor:
    def __init__(
        self,
        ctx: RotationContext,
        *,
        servarr_call: Callable | None = None,
        servarr_backup: Callable | None = None,
        servarr_restore: Callable | None = None,
        servarr_login: Callable | None = None,
    ) -> None:
        self._ctx = ctx
        self._call = servarr_call or _servarr_call
        self._backup_config = servarr_backup or _servarr_backup_config
        self._restore_config = servarr_restore or _servarr_restore_config
        self._login = servarr_login or _servarr_login

    def preflight(self, plan: RotationPlan) -> list[str]:
        """Everything that can be checked before the key is revoked.

        The old key dies at the restart that lands the restored config - there
        is no overlap window to hold it open, because Servarr keeps exactly one
        API key. So the only lever is to fail *before* that point rather than
        after it. Every problem this reports is one that would otherwise be
        discovered halfway through, with the credential already invalidated.
        """
        problems: list[str] = []
        services = {step.target for step in plan.steps if step.kind is StepKind.MINT}

        # 1. The mint target must answer, and must have a key to authenticate
        #    the command with. A service that is down or has no key cannot be
        #    rotated at all.
        for service in sorted(services):
            answered = self._checked_call(
                service, "GET", readiness_path(service),
                **self._auth_kwargs(service, self._ctx.vault_value))
            if answered is None:
                continue
            status, _ = answered
            if status not in (200, 401, 403):
                problems.append(
                    f"{service}: {readiness_path(service)} returned HTTP "
                    f"{status}; it must answer before its key can be rotated"
                )
            source = MINT_SOURCES.get(service)
            if source is not None and source.mechanism in ("rotate", "regenerate"):
                # These responses carry the only copy of the new key, and the
                # old one is already revoked when they arrive, so a crash
                # between the response and the store write loses it. The
                # pending store is the only place that can park it first.
                if self._ctx.pending is None:
                    problems.append(
                        f"{service}: no pending-secret store is available, so "
                        f"the {source.mechanism} mint cannot survive a crash "
                        "after the old key is revoked"
                    )
                if self._ctx.vault_value is None:
                    problems.append(
                        f"{service}: the store holds no value for this "
                        "credential, so the mint cannot authenticate"
                    )
                continue
            if source is not None and source.mechanism == "reset":
                if self._reconstruct_config():
                    problems.extend(self._reconstruct_preflight(service))
                    continue
                if self._manual_mint():
                    problems.extend(self._manual_preflight(service))
                    if (
                        self._ctx.vault_value is not None
                        and self._ctx.provided is not None
                    ):
                        problems.extend(
                            self._manual_mint_problems(
                                service, self._ctx.vault_value,
                                self._ctx.provided,
                            )
                        )
                    continue
                problems.extend(self._backup_preflight(service)[0])
                continue
            # A reissue mint's own preconditions, checked read-only so the
            # dry run does not promise a plan whose first step is a 403. The
            # per-service differences come from the registry row.
            write_mechanism = str(
                self._ctx.credential.write.get("mechanism") or ""
            )
            if (
                source is not None
                and source.system in REISSUERS
                and REISSUERS[source.system].mechanism == write_mechanism
            ):
                spec = REISSUERS[source.system]
                if self._ctx.vault_value is None:
                    problems.append(
                        f"{service}: the vault holds no value for this "
                        "credential, and the mint authenticates with it"
                    )
                else:
                    write = self._ctx.credential.write
                    try:
                        kwargs, raw, rotator = self._reissue_call_kwargs(
                            service, spec
                        )
                        account = self._reissue_account(service, spec, raw)
                        username = str(write.get("username") or "")
                        rows = self._reissue_rows(
                            service, spec, kwargs, account=account,
                            username=username,
                        )
                        current = self._reissue_current(
                            service, spec, rows, self._ctx.vault_value, write
                        )
                    except (RotationError, TransportError) as exc:
                        problems.append(str(exc))
                    else:
                        declared = (
                            str(write.get(spec.declared_name_field) or "")
                            if spec.declared_name_field else ""
                        )
                        base = (
                            re.sub(r"\.credarr\.\d+$", "",
                                   str(current.get("name") or ""))
                            if current else ""
                        )
                        if current is None:
                            problems.append(
                                f"{service}: the stored value is not in the "
                                f"{spec.list_label}"
                            )
                        elif any(current.get(field)
                                 for field in spec.protected_fields):
                            problems.append(
                                f"{service}: {current.get('name')!r} is "
                                f"protected from deletion "
                                f"({spec.protected_hint})"
                            )
                        elif declared and declared != base:
                            problems.append(
                                f"{service}: write.{spec.declared_name_field} "
                                f"is {declared!r} but the credential in use is "
                                f"named {base!r}"
                            )
                        if (
                            spec.system == "arcane"
                            and rotator
                            and current is not None
                        ):
                            rotator_row = self._reissue_current(
                                service, spec, rows, raw, write
                            )
                            if rotator_row is None:
                                problems.append(
                                    f"{service}: rotator {rotator!r} is not "
                                    f"in the {spec.list_label}"
                                )
                            else:
                                have = {
                                    grant.get("permission")
                                    for grant in rotator_row.get(
                                        "permissions") or []
                                    if isinstance(grant, dict)
                                }
                                missing = {
                                    "apikeys:list", "apikeys:create",
                                    "apikeys:delete",
                                } - have
                                if missing:
                                    problems.append(
                                        f"{service}: rotator {rotator!r} "
                                        f"lacks {', '.join(sorted(missing))}"
                                    )
                                declared_values = write.get(
                                    spec.declared_values_field
                                )
                                if (isinstance(declared_values, list)
                                        and declared_values):
                                    wanted = {
                                        str(item) for item in declared_values
                                    }
                                else:
                                    wanted = {
                                        grant.get("permission")
                                        for grant in current.get(
                                            "permissions") or []
                                        if isinstance(grant, dict)
                                    }
                                over = {
                                    item for item in wanted if item
                                } - have
                                if over:
                                    problems.append(
                                        f"{service}: rotator {rotator!r} "
                                        f"cannot grant "
                                        f"{', '.join(sorted(over))}"
                                    )
                continue
            if write_mechanism == "gitea_hook_secret":
                try:
                    self._gitea_hook(service)
                except (RotationError, TransportError) as exc:
                    problems.append(str(exc))
                continue
            # Jellyfin's create mint, and every other non-reset source,
            # authenticate with the stored credential itself.
            if source is None:
                problems.append(
                    f"{service}: no mint source is registered for this service"
                )
            elif self._ctx.vault_value is None:
                problems.append(
                    f"{service}: the vault holds no value for this credential, "
                    "and the mint authenticates with it"
                )

        # 2. Every consumer must be reachable and listable with the CURRENT
        #    key. A consumer that cannot be listed cannot be written either.
        for step in plan.steps:
            if step.kind is not StepKind.PROPAGATE:
                continue
            system, slot = split_target(step.target)
            described = holder_for(system, slot)
            if described is None:
                problems.append(
                    f"{step.target}: no writer known for that slot, so this build "
                    "cannot update the holder at all"
                )
                continue
            if described.write == "qui_api":
                row = self._row_name(step.target)
                if row is None:
                    problems.append(
                        f"{step.target}: does not name which qui instance to "
                        "write"
                    )
                    continue
                try:
                    api_key = self._service_key(system)
                except (ConfigError, TransportError) as exc:
                    problems.append(
                        f"{step.target}: cannot read {system}'s own API key "
                        f"({exc}), so no write to it could be authenticated"
                    )
                    continue
                if not api_key:
                    problems.append(
                        f"{step.target}: no API key for {system!r}; store "
                        f"{system}'s own key before rotating a credential it holds"
                    )
                    continue
                answered = self._checked_call(
                    system, "GET", described.api_path, key=api_key,
                    auth_header=described.auth_header_name,
                    auth_transport=described.auth_transport,
                )
                if answered is None:
                    problems.append(
                        f"{step.target}: {system} was unreachable during "
                        "preflight; the write could not be confirmed"
                    )
                    continue
                status, body = answered
                if status != 200 or not isinstance(body, list):
                    problems.append(
                        f"{step.target}: cannot list {system} instances "
                        f"(HTTP {status}); the write would fail after the key "
                        "was already revoked"
                    )
                    continue
                matches = [
                    item for item in body
                    if isinstance(item, dict) and item.get("name") == row
                ]
                if not matches:
                    problems.append(
                        f"{step.target}: no {system} instance named {row!r} "
                        "exists to update"
                    )
                elif len(matches) > 1:
                    problems.append(
                        f"{step.target}: {len(matches)} {system} instances are "
                        f"named {row!r}; which one holds this credential is "
                        "ambiguous"
                    )
                continue
            if described.write == "seerr_api":
                row = self._row_name(step.target)
                if row is None:
                    problems.append(
                        f"{step.target}: does not name which holder to write"
                    )
                    continue
                try:
                    url = self._ctx.host.url(system)
                except ConfigError:
                    problems.append(f"{step.target}: no URL for {system}")
                    continue
                if url is None:
                    problems.append(f"{step.target}: no URL for {system}")
                    continue
                try:
                    api_key = self._service_key(system)
                except (ConfigError, TransportError) as exc:
                    problems.append(
                        f"{step.target}: cannot read {system}'s own API key "
                        f"({exc}), so no write to it could be authenticated"
                    )
                    continue
                if not api_key:
                    problems.append(
                        f"{step.target}: no API key for {system!r}; store "
                        f"{system}'s own key before rotating a credential it holds"
                    )
                    continue
                answered = self._checked_call(
                    system, "GET", described.readback_path.format(service=row),
                    key=api_key,
                    auth_header=described.auth_header_name,
                    auth_transport=described.auth_transport,
                )
                if answered is None:
                    problems.append(
                        f"{step.target}: {system} was unreachable during preflight; "
                        "the write could not be confirmed"
                    )
                else:
                    status, body = answered
                    if status != 200:
                        problems.append(
                            f"{step.target}: the read-back that would confirm this "
                            f"write returned HTTP {status}; the write would succeed "
                            "but could not be confirmed"
                        )
                    elif row == "jellyfin":
                        if not isinstance(body, dict) or not body:
                            problems.append(
                                f"{step.target}: {system} has no Jellyfin "
                                "settings object, so a rotation would revoke the "
                                "old key and update nothing"
                            )
                    elif not isinstance(body, list):
                        problems.append(
                            f"{step.target}: {system} returned an unexpected "
                            f"settings shape for {row!r}; refusing a write that "
                            "could not be confirmed"
                        )
                    elif not body:
                        problems.append(
                            f"{step.target}: the settings section holds no "
                            f"{row} instances, so a rotation would revoke the "
                            "old key and update nothing"
                        )
                    elif len(body) > 1:
                        problems.append(
                            f"{step.target}: the settings section holds "
                            f"{len(body)} {row} instances and this build can "
                            "update exactly one; which instance holds this "
                            "credential is not in the manifest, so the write is "
                            "refused rather than made into the wrong one"
                        )
                continue
            try:
                self._resolve_field(step)
            except RotationError as exc:
                problems.append(str(exc))
                continue
            try:
                holder_key = self._service_key(system)
            except TransportError as exc:
                problems.append(
                    f"{step.target}: cannot read the holder's own API key "
                    f"({exc}), so no write to it could be authenticated"
                )
                continue
            if not holder_key:
                problems.append(
                    f"{step.target}: no API key for the holder service "
                    f"{system!r}; nothing could authenticate a write to it"
                )
                continue
            answered = self._checked_call(system, "GET", f"/{described.api_path}",
                                          key=holder_key)
            if answered is None:
                continue
            status, rows = answered
            if status != 200 or not isinstance(rows, list):
                problems.append(
                    f"{step.target}: cannot list rows (HTTP {status}); the "
                    f"write would fail after the key was already revoked"
                )
                continue
            try:
                selected = self._select_rows(step.target, rows)
            except RotationError as exc:
                problems.append(str(exc))
                continue
            if not selected:
                problems.append(
                    f"{step.target}: no rows to update, so a rotation would "
                    f"change nothing while still invalidating the old key"
                )

        # Notes are appended, not pre-pended: they explain a check that could
        # not run, and they must not crowd out a reason that says why to stop.
        for note in self._ctx.preflight_notes:
            if note.split(":")[0] not in {p.split(":")[0] for p in problems}:
                problems.append(note)

        # 3. A rotation must not start while a previous one is unfinished.
        # This credential's own steps are exactly what `take_over` is for, so
        # with it they are simply not a problem - the run closes them and
        # re-derives from the service's own state. Another credential's are
        # not: they say the stack's state is unresolved somewhere this run
        # cannot see, and no instruction about *this* credential changes that.
        outstanding = self._ctx.journal.pending()
        mine = [p for p in outstanding if p.credential == self._ctx.credential.name]
        others = [p for p in outstanding if p.credential != self._ctx.credential.name]
        if others:
            listed = ", ".join(sorted({f"{p.credential}:{p.target}" for p in others}))
            problems.append(
                f"an unfinished rotation of another credential ({listed}) leaves "
                f"the stack's state unknown; take over that credential's rotation "
                f"or let it age out"
            )
        if mine and not self._ctx.take_over:
            listed = ", ".join(sorted({p.target for p in mine}))
            minutes = round(self._ctx.journal.stale_after / 60)
            problems.append(
                f"a previous rotation of this credential is unfinished "
                f"({listed}); take it over with --take-over, or wait "
                f"{minutes} minutes for it to age out"
            )
        return problems

    def _journal_holders(self) -> None:
        """Mirror the in-run holder state into the journal.

        The database is the authority on what a holder holds now; this is the
        controller's record of what it did, which is the only thing available if
        the run dies before the database is consulted again.
        """
        if self._ctx.attempt is None:
            return
        for holder in self._ctx.holders:
            self._ctx.journal.record_holder(
                self._ctx.attempt, holder.target, holder.label,
                holder.outcome, holder.detail,
            )

    def _mark_unreached(self, plan: RotationPlan, failed_at: int) -> None:
        """Every holder in a step that never ran is recorded as not-reached.

        Silence about them would be the most damaging thing this could do: an
        operator reading "failed at sonarr.indexers" cannot tell which of the
        sixteen indexers are dead and which were never touched.
        """
        reached = {h.target for h in self._ctx.holders}
        for step in plan.steps[failed_at:]:
            if step.kind is not StepKind.PROPAGATE or step.target in reached:
                continue
            self._ctx.holders.append(
                HolderOutcome(step.target, "all", "not-reached",
                              "the step before this one failed")
            )

    def execute(self, plan: RotationPlan) -> ExecutionResult:
        # The plan chose the mint mechanism; the executor must not guess a
        # different one after approval.
        # The engine repeats the refusal the CLI already makes. That guard lives
        # in the presentation layer, so anything else calling here - a wrapper, a
        # test harness, a future scheduler - would otherwise mint a key it already
        # knows it cannot deliver, which is the one outcome this tool exists to
        # prevent. It is checked before reclaim_stale() and journal.begin() too:
        # opening an attempt for a plan that cannot run is itself a side effect.
        if not plan.executable:
            raise RotationError(
                f"{plan.credential.name}: refusing to start a rotation that "
                "cannot complete",
                hint="; ".join(plan.blocked_by)
                or "the plan has no steps, so there is nothing to do",
            )

        # This credential's own steps left by a dead run are closed out here,
        # before this run's first step, so the journal says a takeover happened
        # instead of the old steps quietly ageing out of a query. The takeover
        # does not by itself authorise the mint - the backup/restore mint
        # re-derives from the pending store and the vault whether a restore
        # already happened, and resumes it if so.
        reclaimed = self._ctx.journal.reclaim_stale(plan.credential.name)
        if self._ctx.take_over:
            # Under the lock, so the run that left these behind is not holding
            # it any more; the row still says who decided, because "presumed
            # dead" is a claim about a process, and this one is about a person.
            reclaimed += self._ctx.journal.take_over(
                plan.credential.name, self._ctx.actor
            )
        result = ExecutionResult(credential=plan.credential.name, attempt=0)
        result.reclaimed = [(p.target, p.detail) for p in reclaimed]
        result.attempt = self._ctx.journal.begin(plan.credential.name)
        if self._ctx.on_started is not None:
            self._ctx.on_started(result.attempt)
        result.revokes_before_holders = plan.revokes_before_holders
        self._ctx.attempt = result.attempt

        for ordinal, step in enumerate(plan.steps):
            self._ctx.journal.step_started(
                result.attempt, ordinal, step.kind.value, step.target, step.detail
            )
            try:
                # The fence, inside the try so losing the lease is reported as a
                # failed run rather than escaping as a traceback. If the lock was
                # reclaimed while this run was slow, the work below belongs to
                # whoever took over. Checking once per step is not atomic with
                # the writes, but it stops a reclaimed process before its next
                # write instead of letting it run to the end and report success
                # for work that was overtaken.
                if self._ctx.lease_check is not None:
                    self._ctx.lease_check()
                detail = self._dispatch(step)
            except Exception as exc:  # the reason is recorded in the journal
                # Scrubbed at the one place every failure passes through. The
                # message can contain the credential: a service that echoes the
                # resource it was refused hands it straight back, and from here
                # it reaches the journal, the report and the operator's terminal.
                #
                # The hint is carried, not dropped. A `RotationError` says what
                # failed and its hint says what to do about it - and this tool's
                # hints are written to be read ("nothing was recorded in the
                # vault", "check the service's log"). Building `detail` from the
                # message alone threw them away, so every failure reached the
                # operator as a bare HTTP status.
                detail = scrub(f"failed: {exc}", self._ctx.minted,
                               self._ctx.vault_value)
                # getattr, not `exc.hint`: only CredctlError defines one, and a
                # plain bug raised inside a step must surface as a reported
                # failure, not an escaping traceback from this handler.
                hint = getattr(exc, "hint", None)
                if hint:
                    detail += "\n  " + scrub(hint, self._ctx.minted,
                                               self._ctx.vault_value)
                self._ctx.journal.step_finished(result.attempt, ordinal, detail)
                result.failed = step.target
                result.detail = detail
                self._ctx.journal.finish(result.attempt, "failed")
                self._mark_unreached(plan, ordinal)
                # Holders live on the context; the result is what
                # the report reads. Copied on every exit path, because a
                # report rendering no holders is indistinguishable from a
                # rotation that touched none - the exact confusion this
                # per-holder reporting exists to remove.
                result.holders = list(self._ctx.holders)
                self._journal_holders()
                return result

            self._ctx.journal.step_finished(result.attempt, ordinal, detail)
            if step.kind is StepKind.MANUAL:
                result.manual.append(step.target)
            else:
                result.completed.append(step.target)
                if step.kind is StepKind.RECORD:
                    result.vault_written = True

        result.resumed = self._ctx.resumed
        self._ctx.journal.finish(result.attempt, "completed")
        # As the failure path does, so the record shows what the run achieved
        # and not only what it ran; INSERT OR REPLACE just rewrites what the
        # API path already journalled.
        self._journal_holders()
        result.holders = list(self._ctx.holders)
        return result

    def _dispatch(self, step: Step) -> str:
        if step.kind is StepKind.MANUAL:
            return "noted"
        if step.kind is StepKind.MINT:
            if step.target in MINT_SOURCES:
                return self._mint_for(step)
            raise RotationError(
                f"{step.target}: no mint source is registered for this service"
            )
        if step.kind is StepKind.REVOKE:
            return self._revoke_for(step)
        if step.kind is StepKind.PROPAGATE:
            return self._propagate(step)
        if step.kind is StepKind.RECORD:
            return self._record()
        raise RotationError(f"no executor for step kind {step.kind}")

    # -- steps --------------------------------------------------------------

    def _mint_for(self, step: Step) -> str:
        """Dispatch a mint to the implementation its source names.

        The reissue services share one driver and are keyed by their registry
        row; everything else is one function per mechanism. A new mint source
        is a row in `MINT_SOURCES` plus, for a reissue service, a `REISSUERS`
        row.
        """
        if str(self._ctx.credential.write.get("mechanism") or "") == (
            "gitea_hook_secret"
        ):
            return self._mint_gitea_hook(step)
        if step.target in REISSUERS:
            return self._reissue_mint(step)
        mechanism = MINT_SOURCES[step.target].mechanism
        if mechanism == "reset":
            if self._manual_mint():
                return self._mint_provided(step)
            return self._mint_api(step)
        if mechanism == "create":
            return self._mint_jellyfin(step)
        if mechanism == "rotate":
            return self._mint_qbittorrent(step)
        if mechanism == "regenerate":
            return self._mint_seerr(step)
        raise RotationError(
            f"{step.target}: no mint implementation for mechanism {mechanism!r}",
            hint="the mint source is registered, but nothing here can run it",
        )

    def _revoke_for(self, step: Step) -> str:
        """Dispatch the revoke step to the mechanism that planned it."""
        if step.target in REISSUERS:
            return self._reissue_revoke(step)
        mechanism = MINT_SOURCES[step.target].mechanism
        if mechanism == "create":
            return self._revoke_jellyfin(step)
        raise RotationError(
            f"{step.target}: no revoke implementation for mechanism {mechanism!r}",
            hint="the plan added a revoke step this build cannot run; nothing "
            "was changed by it",
        )

    def _manual_mint(self) -> bool:
        """The explicit no-backup/restore path for a Servarr credential."""
        return self._ctx.credential.write.get("manual_mint") is True

    def _reconstruct_config(self) -> bool:
        """The automatic no-backup path: rebuild config.xml from the API."""
        return self._ctx.credential.write.get("reconstruct_config") is True

    def _reconstruct_config_problems(self, service: str) -> list[str]:
        """Read-only checks for the reconstructed config path.

        The API must answer with the current key, report SQLite, and expose every
        config field that decides reachability and authentication. A Postgres
        deployment is refused because the API does not expose its connection
        settings; a rebuilt config could reset them and lose the database.
        """
        problems: list[str] = []
        answered = self._checked_call(
            service, "GET", readiness_path(service),
            key=self._ctx.vault_value,
        )
        if answered is None:
            return []
        status, payload = answered
        if status in (401, 403):
            # A crash after the restore's restart leaves the service on the
            # parked key with the stored one dead. That is the resumable state:
            # the mint's candidate-live branch continues without rebuilding.
            pending = (
                self._ctx.pending.get(self._ctx.credential.name)
                if self._ctx.pending is not None
                else None
            )
            if pending is not None:
                verdict, _ = self._authenticate_settled(
                    service, pending.reveal()
                )
                if verdict == "live":
                    return []
            return [
                f"{service}: the stored key does not authenticate; the "
                "reconstructed config cannot be built"
            ]
        if status != 200 or not isinstance(payload, dict):
            return [
                f"{service}: {readiness_path(service)} returned HTTP {status}; "
                "the reconstructed config cannot be built"
            ]
        database = str(payload.get("databaseType") or "").strip().lower()
        if not database:
            return [
                f"{service}: /system/status did not report databaseType; this "
                "path cannot prove the service is SQLite, and a rebuilt "
                "config.xml would omit the Postgres settings. Use "
                "write.ui_password or write.manual_mint."
            ]
        if "postgres" in database:
            return [
                f"{service}: /system/status reports {database!r}; the rebuilt "
                "config.xml does not carry the Postgres connection settings "
                "(the API does not expose them), so this path is refused. Use "
                "write.ui_password or write.manual_mint."
            ]
        answered = self._checked_call(
            service, "GET", "/config/host", key=self._ctx.vault_value
        )
        if answered is None:
            return []
        status, host_config = answered
        if status in (401, 403):
            return [
                f"{service}: the stored key does not authorize /config/host; "
                "the reconstructed config cannot be built"
            ]
        if status != 200 or not isinstance(host_config, dict):
            return [
                f"{service}: /config/host returned HTTP {status}; the "
                "reconstructed config cannot be built"
            ]
        missing = sorted(
            key for key in _CRITICAL_CONFIG_FIELDS
            if host_config.get(key) is None
        )
        if missing:
            problems.append(
                f"{service}: /config/host did not expose the fields a rebuilt "
                "config.xml needs: " + ", ".join(missing) + "; they would reset "
                "on restore"
            )
        return problems

    def _reconstruct_preflight(self, service: str) -> list[str]:
        """Shared by the plan's selected path and the read-only options check."""
        problems: list[str] = []
        if self._ctx.pending is None:
            problems.append(
                f"{service}: no pending-secret store is available, "
                "so the reconstructed mint cannot survive a crash "
                "after the restore"
            )
        if self._ctx.vault_value is None:
            problems.append(
                f"{service}: the store holds no value for this "
                "credential, so the config cannot be read and the "
                "old key cannot be proven live"
            )
        else:
            problems.extend(self._reconstruct_config_problems(service))
        return problems

    def _manual_preflight(self, service: str) -> list[str]:
        """Shared by the plan's selected path and the read-only options check."""
        problems: list[str] = []
        if self._ctx.pending is None:
            problems.append(
                f"{service}: no pending-secret store is available, "
                "so the manual mint cannot survive a crash after a "
                "holder is written"
            )
        if self._ctx.vault_value is None:
            problems.append(
                f"{service}: the store holds no value for this "
                "credential, so the manual mint has no old key to "
                "prove dead"
            )
        return problems

    def _backup_preflight(
        self, service: str
    ) -> tuple[list[str], BackupProbe | None]:
        """The backup/restore checks, and the download probe's own facts.

        The preflight wants the problems; the console's read-only options call
        wants the same answer plus whether a UI login is the blocker. Both use
        one code path so the recommendation cannot disagree with the plan.
        """
        problems: list[str] = []
        # The backup/restore mint authenticates its calls with the
        # stored key and needs somewhere to park the chosen value
        # before it mutates the service.
        if self._ctx.pending is None:
            problems.append(
                f"{service}: no pending-secret store is available, so "
                "the backup/restore mint cannot survive a crash after "
                "the config restore"
            )
        declared_ui = self._ui_password_name()
        if declared_ui and self._ctx.mint_values.get(declared_ui) is None:
            problems.append(
                f"{service}: write.ui_password names {declared_ui!r}, "
                "which has no stored value; the UI login cannot open "
                "the backup download"
            )
        if self._ctx.vault_value is None:
            problems.append(
                f"{service}: the store holds no value for this "
                "credential, so the backup cannot be authenticated and "
                "the old key cannot be proven live"
            )
            return problems, None
        backup = self._checked_call(
            service, "GET", "/system/backup",
            key=self._ctx.vault_value,
        )
        if backup is None:
            return problems, None
        backup_status, _ = backup
        if backup_status in (401, 403):
            # A crash after the restore's restart leaves the service on the
            # parked key with the store still on the old one. That is the
            # resumable state, not a blocker.
            pending = (
                self._ctx.pending.get(self._ctx.credential.name)
                if self._ctx.pending is not None
                else None
            )
            if pending is not None:
                verdict, _ = self._authenticate_settled(
                    service, pending.reveal()
                )
                if verdict == "live":
                    return problems, None
            problems.append(
                f"{service}: the stored key does not authorize "
                "the backup API; the backup/restore mint cannot "
                "read or replace config.xml"
            )
            return problems, None
        if backup_status != 200:
            problems.append(
                f"{service}: /system/backup returned HTTP "
                f"{backup_status}; the backup/restore mint needs "
                "that API before it can change the key"
            )
            return problems, None
        # The API answering is not enough: the mint reads config.xml from a
        # *web* route, and that route is behind the service's UI login when
        # authentication is on. A name that cannot exist makes this read-only.
        probe = self._checked_call(
            service, "GET",
            "/backup/manual/__credarr_probe__.zip",
            key=self._ctx.vault_value,
            versioned=False,
            follow_redirects=False,
        )
        check = self._backup_probe(service, probe, self._ctx.vault_value)
        if check.problem is not None:
            problems.append(check.problem)
        return problems, check

    def _backup_probe(
        self, service: str, probe: tuple[int, object] | None, key: str
    ) -> BackupProbe:
        """The backup-download verdict, retrying through a declared UI login.

        The first probe uses the API key. A Servarr download is a web route, so
        with UI authentication on it answers a redirect even while the API key
        is live. When `write.ui_password` is declared, the run logs in once and
        asks again with the session cookie; a 404 for a name that cannot exist
        is the healthy answer.
        """
        declared = bool(self._ui_password_name())
        if probe is None:
            return BackupProbe(None, ui_password_configured=declared)
        status, _ = probe
        if not 300 <= status < 400:
            return BackupProbe(
                _backup_route_problem(service, probe),
                ui_password_configured=declared,
            )
        try:
            method, username = self._ui_auth_method(service, key)
        except (RotationError, TransportError) as exc:
            return BackupProbe(
                str(exc), True, "", declared, False
            )
        can_help = method in ("forms", "basic") and bool(username)
        if not declared:
            return BackupProbe(
                _backup_route_problem(service, probe),
                True,
                method,
                False,
                can_help,
            )
        try:
            headers = self._ui_auth_headers(service, key)
        except (RotationError, TransportError) as exc:
            return BackupProbe(str(exc), True, method, True, can_help)
        if headers is None:
            return BackupProbe(
                f"{service}: the backup download redirected (HTTP "
                f"{status}) although the service reports its UI "
                "authentication off; a proxy may be answering instead of "
                "the service",
                True,
                method,
                True,
                False,
            )
        if not headers:
            return BackupProbe(
                f"{service}: the UI credential did not produce a login "
                "header; the backup/restore mint cannot read config.xml",
                True,
                method,
                True,
                can_help,
            )
        retry = self._checked_call(
            service, "GET",
            "/backup/manual/__credarr_probe__.zip",
            key=key,
            versioned=False,
            follow_redirects=False,
            extra_headers=headers,
        )
        if retry is None:
            return BackupProbe(None, True, method, True, False)
        if retry[0] == 404:
            return BackupProbe(None, True, method, True, False)
        if 300 <= retry[0] < 400:
            return BackupProbe(
                f"{service}: the stored UI credential did not open the "
                f"backup download (HTTP {retry[0]} after login); check "
                "the password named by write.ui_password. The "
                "backup/restore mint cannot read config.xml.",
                True,
                method,
                True,
                can_help,
            )
        return BackupProbe(
            f"{service}: after the UI login the backup download answered "
            f"HTTP {retry[0]} for a name that cannot exist; the "
            "backup/restore mint cannot read config.xml",
            True,
            method,
            True,
            False,
        )

    def rotation_options(self) -> dict[str, object]:
        """What this Servarr credential can do, read-only.

        The console asks this before showing a method: backup/restore when the
        download is open (or a UI login opens it), a rebuilt config only when
        the API proves SQLite plus the critical fields, and the operator's
        manual mint as the honest last resort. The planner still reads the
        manifest; this answer only decides what the console offers.
        """
        credential = self._ctx.credential
        service = service_for(credential)
        source = MINT_SOURCES.get(service)
        if (
            source is None
            or source.mechanism != "reset"
            or str(credential.write.get("mechanism") or "") != "servarr_command"
            or credential.credential_class not in ("A", "A-unv")
            or credential.never_rotate
        ):
            return {
                "applicable": False,
                "service": service,
                "reason": "this credential has no Servarr-style rotation",
            }

        def problems_for(check: Callable[[], list[str]]) -> list[str]:
            start = len(self._ctx.preflight_notes)
            try:
                value = check()
            except CredctlError as exc:
                return [str(exc)]
            notes = self._ctx.preflight_notes[start:]
            if value:
                return list(value)
            return notes

        backup_start = len(self._ctx.preflight_notes)
        try:
            backup_problems, probe = self._backup_preflight(service)
        except CredctlError as exc:
            backup_problems, probe = [str(exc)], None
        backup_notes = self._ctx.preflight_notes[backup_start:]
        backup_reasons = list(backup_problems) or backup_notes
        reconstruct_reasons = problems_for(
            lambda: self._reconstruct_preflight(service)
        )
        manual_reasons = problems_for(
            lambda: self._manual_preflight(service)
        )

        backup_available = not backup_reasons
        reconstruct_available = not reconstruct_reasons
        manual_available = not manual_reasons

        write = credential.write
        if write.get("manual_mint") is True:
            selected = "manual"
        elif write.get("reconstruct_config") is True:
            selected = "reconstruct"
        else:
            selected = "backup_restore"

        configured = bool(self._ui_password_name()) and (
            self._ctx.mint_values.get(self._ui_password_name()) is not None
        )
        login_required = bool(probe and probe.login_required)
        if backup_available:
            recommended = "backup_restore"
        elif reconstruct_available:
            recommended = "reconstruct"
        elif manual_available:
            recommended = "manual"
        else:
            recommended = None

        return {
            "applicable": True,
            "service": service,
            "selected": selected,
            "recommended": recommended,
            "methods": {
                "backup_restore": {
                    "available": backup_available,
                    "automatic": True,
                    "reason": backup_reasons[0] if backup_reasons else "",
                    "ui_password": {
                        "required": login_required,
                        "configured": configured,
                        "can_help": bool(probe and probe.ui_password_can_help),
                        "method": probe.auth_method if probe else "",
                    },
                },
                "reconstruct": {
                    "available": reconstruct_available,
                    "automatic": True,
                    "reason": (
                        reconstruct_reasons[0] if reconstruct_reasons else ""
                    ),
                },
                "manual": {
                    "available": manual_available,
                    "automatic": False,
                    "reason": (
                        manual_reasons[0]
                        if manual_reasons
                        else "You rotate the key in the service's own UI and "
                        "paste it."
                    ),
                },
            },
        }

    def _reconstruct_config_xml(
        self, service: str, expected: str, new_key: str
    ) -> str:
        """Read the host config at mint time and build the config XML.

        The preflight already checked the same fields; this repeats the read
        because a config change between preflight and the restore must not be
        silently baked into the new file. A failure here happens before the
        restore, so the old key is still live.
        """
        status, payload = self._call(
            self._ctx.host, service, "GET", readiness_path(service),
            key=expected, transport=self._ctx.transport,
        )
        if status != 200 or not isinstance(payload, dict):
            raise RotationError(
                f"{service}: could not read system status for the reconstructed "
                f"config (HTTP {status})",
                hint="the pending value is parked and the service is still on "
                "the stored key; nothing has been restored.",
            )
        database = str(payload.get("databaseType") or "").strip().lower()
        if not database:
            raise RotationError(
                f"{service}: /system/status did not report databaseType",
                hint="the rebuilt config cannot be proven safe for a "
                "non-SQLite deployment; nothing has been restored. Use "
                "write.ui_password or write.manual_mint.",
            )
        if "postgres" in database:
            raise RotationError(
                f"{service}: the service reports {database!r}; a rebuilt "
                "config.xml would omit its Postgres settings",
                hint="nothing has been restored; use write.ui_password or "
                "write.manual_mint.",
            )
        status, host_config = self._call(
            self._ctx.host, service, "GET", "/config/host",
            key=expected, transport=self._ctx.transport,
        )
        if status != 200 or not isinstance(host_config, dict):
            raise RotationError(
                f"{service}: could not read /config/host for the reconstructed "
                f"config (HTTP {status})",
                hint="the pending value is parked and the service is still on "
                "the stored key; nothing has been restored.",
            )
        try:
            return _config_xml_from_host(host_config, api_key=new_key)
        except RotationError as exc:
            raise RotationError(
                f"{service}: {exc}",
                hint="the pending value is parked and the service is still on "
                "the stored key; nothing has been restored.",
            ) from None

    def _ui_password_name(self) -> str:
        """The credential holding the service's UI password, when declared."""
        return str(self._ctx.credential.write.get("ui_password") or "").strip()

    def _manual_mint_problems(
        self, service: str, expected: str, provided: str
    ) -> list[str]:
        """Why a supplied replacement key cannot be used, read-only.

        The old key must be the one the service stopped accepting, and the new
        one must be the one it now accepts. A still-live stored key means the
        operator has not rotated in the service's UI yet; an accepted supplied
        key alone is not enough, because the service would then have two
        working keys and the holder reads would be ambiguous.
        """
        if provided == expected:
            return [
                f"{service}: the supplied key is the stored key; rotate the key "
                "in the service's own UI first, then supply the new one"
            ]
        old_verdict, old_detail = self._authenticate_settled(service, expected)
        if old_verdict == "live":
            return [
                f"{service}: the stored key still authenticates; rotate the key "
                "in the service's own UI first, then supply the new one. Nothing "
                "has been changed."
            ]
        if old_verdict != "dead" or old_detail != "HTTP 401":
            return [
                f"{service}: could not prove the stored key is dead "
                f"({old_verdict}: {old_detail}). A Servarr refuses a revoked key "
                "with HTTP 401; anything else is ambiguous, so the manual mint "
                "will not write a holder. Nothing has been changed."
            ]
        new_verdict, new_detail = self._authenticate_settled(service, provided)
        if new_verdict != "live":
            return [
                f"{service}: the supplied key does not authenticate "
                f"({new_verdict}: {new_detail}); copy the key the service shows "
                "after its regenerate, and supply that. Nothing has been changed."
            ]
        return []

    def _mint_provided(self, step: Step) -> str:
        """Accept a key the operator rotated in the service's own UI.

        This is the `write.manual_mint` path: no backup is read and no config is
        restored. The operator has already caused the only mutation (the
        service revoked the old key), so this method proves that state, parks
        the supplied value before any holder write, and lets the normal
        propagation run. A crash after the first holder is recoverable because
        the value is in the pending store.
        """
        service = step.target
        if self._ctx.minted is not None:
            return f"{service}: key already accepted by this run; nothing to redo"

        expected = self._ctx.vault_value
        if expected is None:
            raise RotationError(
                f"{service}: refusing a manual mint with no stored value",
                hint="the stored key is what proves the service rotated away "
                "from it. Store the credential and re-run; nothing has been "
                "changed.",
            )
        pending = self._ctx.pending
        if pending is None:
            raise RotationError(
                f"{service}: refusing a manual mint with no pending-secret store",
                hint="a crash after a holder write would leave the service on a "
                "key credarr did not record. This deployment has no place to "
                "park it, so nothing has been changed.",
            )

        name = self._ctx.credential.name
        parked = pending.get(name)
        if parked is not None and parked.reveal() == expected:
            # A stale copy of the old key is not a candidate; keeping it would
            # make the next check see the stored key twice.
            pending.clear(name)
            parked = None

        provided = self._ctx.provided
        if provided is not None:
            provided = provided.strip()
            if not provided:
                provided = None
        if provided is None:
            if parked is None:
                raise RotationError(
                    f"{service}: the manual mint needs the service's new key",
                    hint="rotate the key in the service's Settings > General "
                    "page, then supply the new key to this run. There is no "
                    "backup or config restore in this mode.",
                )
            provided = parked.reveal()
            resumed = True
        else:
            if parked is not None and parked.reveal() != provided:
                # A previous run may have parked the key the service now
                # accepts. That key is the only safe resume; a different
                # supplied value must not overwrite it. A dead parked key is
                # not a resume - the operator rotated again - so it may be
                # replaced after the normal old/new verification below.
                verdict, detail = self._authenticate_settled(
                    service, parked.reveal()
                )
                if verdict != "dead":
                    raise RotationError(
                        f"{service}: a previous run parked a different key "
                        f"({verdict}: {detail}); the supplied key was not used",
                        hint="resume that run with the parked key, or clear the "
                        "pending value after confirming the service's current "
                        "key. Nothing has been changed.",
                    )
            resumed = parked is not None and parked.reveal() == provided

        problems = self._manual_mint_problems(service, expected, provided)
        if problems:
            raise RotationError(
                problems[0],
                hint="the manual mint writes nothing until the service accepts "
                "the supplied key and refuses the stored one.",
            )

        pending.set(name, Secret(provided))
        self._ctx.minted = Secret(provided)
        self._ctx.minted_service = service
        self._ctx.resumed = resumed
        self._confirm_old_key_dead(service, expected)
        return (
            "accepted the key rotated in the service's UI; no backup or config "
            "restore was used"
        )

    def _ui_auth_method(self, service: str, key: str) -> tuple[str, str]:
        """The service's UI authentication method and username, read-only."""
        status, host_config = self._call(
            self._ctx.host, service, "GET", "/config/host",
            key=key, transport=self._ctx.transport,
        )
        if status != 200 or not isinstance(host_config, dict):
            raise RotationError(
                f"{service}: could not read the UI authentication method "
                f"(HTTP {status})",
                hint="the UI credential can only be used while the stored API "
                "key still authenticates; nothing has been changed.",
            )
        return (
            str(host_config.get("authenticationMethod") or "").lower(),
            str(host_config.get("username") or ""),
        )

    def _ui_auth_headers(self, service: str, key: str) -> dict[str, str] | None:
        """Headers that open the service's web UI, from `write.ui_password`.

        Forms auth is the measured default: log in with the username the
        service reports and the stored password, then send the session cookie
        to the web route. Basic auth sends the password on every request.
        External/OIDC auth has no username/password route, so it is refused
        with the manual-mint option rather than guessed at.
        """
        declared = self._ui_password_name()
        if not declared:
            return None
        secret = self._ctx.mint_values.get(declared)
        if secret is None:
            raise RotationError(
                f"{service}: write.ui_password names {declared!r}, which has no "
                "stored value",
                hint="store the service's UI password as that credential, or "
                "use write.manual_mint and supply the key on rotate.",
            )
        method, username = self._ui_auth_method(service, key)
        if method in ("", "none"):
            return None
        if method == "basic":
            if not username:
                raise RotationError(
                    f"{service}: the service reports Basic authentication but no "
                    "username"
                )
            token = base64.b64encode(
                f"{username}:{secret.reveal()}".encode()
            ).decode()
            return {"Authorization": f"Basic {token}"}
        if method == "forms":
            if not username:
                raise RotationError(
                    f"{service}: the service reports Forms authentication but no "
                    "username"
                )
            return self._login(
                self._ctx.host, service, username=username,
                password=secret.reveal(), transport=self._ctx.transport,
            )
        if method == "external":
            raise RotationError(
                f"{service}: the service authenticates through an external "
                "provider; credarr has no username/password route to it",
                hint="use write.manual_mint and supply the key rotated in the "
                "service's UI, or set Authentication to 'Disabled for Local "
                "Addresses' for credarr's address. Nothing has been changed.",
            )
        raise RotationError(
            f"{service}: unsupported UI authentication method {method!r}",
            hint="credarr measured Forms and Basic; use write.manual_mint or "
            "'Disabled for Local Addresses'. Nothing has been changed.",
        )

    def _backup_ui_headers(
        self, service: str, key: str
    ) -> dict[str, str] | None:
        """UI headers only when the download route actually asks for a login.

        `write.ui_password` is an authentication aid, not a mandate to log in.
        A service with auth off (or `DisabledForLocalAddresses` for credarr's
        address) answers the probe 404; the API key opens the download and a
        stale UI password must not fail the run. The mint re-probes read-only
        rather than trusting a preflight verdict that may be minutes old.
        """
        if not self._ui_password_name():
            return None
        probe = self._checked_call(
            service, "GET", "/backup/manual/__credarr_probe__.zip",
            key=key, versioned=False, follow_redirects=False,
        )
        if probe is None or probe[0] == 404:
            return None
        if 300 <= probe[0] < 400:
            return self._ui_auth_headers(service, key)
        return None

    def _mint_api(self, step: Step) -> str:
        """Mint through the service's own backup API.

        The service cannot return a reset key, so the value is chosen here. It
        is persisted in the pending store *before* the config restore, then
        written into a backup's config.xml and restored over the API. The
        restart is the point that revokes the old key, and the pending value is
        the only thing that lets a run resume after a crash at that point.

        Failure ordering: everything before the restore is read-only for the
        credential (a backup is created, but no key changes). Once the restore
        is accepted, a failure leaves the service either on the old key (before
        the restart) or on the pending key (after it); either is recoverable by
        a rerun because the pending value is parked.

        `write.reconstruct_config` uses the same ordering with a different
        source: `/config/host` supplies the config fields and a chosen key is
        written into a rebuilt `config.xml`, so no backup download, UI session
        or password is involved. The restore upload is still the only write.
        """
        service = step.target
        if self._ctx.minted is not None:
            return f"{service}: key already minted by this run; nothing to redo"

        expected = self._ctx.vault_value
        if expected is None:
            raise RotationError(
                f"{service}: refusing a backup/restore mint with no stored value",
                hint="the backup/restore call authenticates with the current "
                "key, and the old key is what proves the restore took effect. "
                "Store the credential and re-run; nothing has been changed.",
            )
        pending = self._ctx.pending
        if pending is None:
            raise RotationError(
                f"{service}: refusing a backup/restore mint with no pending-secret "
                "store",
                hint="a crash after the restore's restart would leave the "
                "service on a key credarr did not record. This deployment has "
                "no place to park it, so nothing has been changed.",
            )

        name = self._ctx.credential.name
        candidate = pending.get(name)
        if candidate is not None and candidate.reveal() == expected:
            # A crash after RECORD can leave the just-recorded value in a
            # pending store that has not been pruned (the CLI's file store has
            # no startup prune). It is not a second key; keeping it would make
            # the next run see both "stored" and "pending" authenticating.
            pending.clear(name)
            candidate = None

        old_verdict, old_detail = self._authenticate_settled(service, expected)
        if old_verdict == "unknown":
            raise RotationError(
                f"{service}: cannot ask whether the stored key is live "
                f"({old_detail})",
                hint="the backup/restore mint will not create a backup or restore "
                "a config until the current key is known to authenticate.",
            )

        if candidate is not None:
            candidate_verdict, candidate_detail = self._authenticate_settled(
                service, candidate.reveal()
            )
        else:
            candidate_verdict, candidate_detail = "absent", "no pending value"

        if old_verdict == "live" and candidate_verdict == "live":
            raise RotationError(
                f"{service}: both the stored key and the pending key "
                "authenticate",
                hint="the service could be mid-restart or an access layer may "
                "be accepting both. A restore now would make the state more "
                "ambiguous; wait for the service to settle and re-run.",
            )

        if candidate_verdict == "live":
            # The restore already happened and the service accepted the parked
            # value. Do not make another backup or write another config.
            self._ctx.minted = candidate
            self._ctx.minted_service = service
            self._ctx.resumed = True
            self._confirm_old_key_dead(service, expected)
            return "already-restored: continuing with the pending key"

        if old_verdict != "live":
            raise RotationError(
                f"{service}: neither the stored key nor the pending key is "
                f"confirmed live (stored: {old_detail}; pending: "
                f"{candidate_detail})",
                hint="a backup/restore mint needs one of them to authenticate. "
                "Nothing has been changed; restore access and re-run. If this "
                "run was started on the other surface (CLI or server), resume "
                "it there: the pending value lives beside that surface's "
                "canonical store.",
            )

        if candidate is None:
            # 32 hex characters is the shape Servarr writes into config.xml.
            candidate = Secret(token_hex(16))
            # Persist before the backup read so a crash at any point after the
            # restore has a value to resume with. The backup itself is not a
            # credential change, but doing this first keeps the write ordering
            # one rule: pending before mutation.
            pending.set(name, candidate)
        elif candidate_verdict != "dead":
            raise RotationError(
                f"{service}: the pending key could not be checked safely "
                f"({candidate_detail})",
                hint="the stored key is live, but the parked value was neither "
                "accepted nor refused cleanly. Refusing to restore over a "
                "config whose outcome cannot be read; nothing has been changed.",
            )

        if self._reconstruct_config():
            rebuilt = self._reconstruct_config_xml(
                service, expected, candidate.reveal()
            )
            status, _ = self._restore_config(
                self._ctx.host,
                service,
                key=expected,
                xml=rebuilt.encode("utf-8"),
                transport=self._ctx.transport,
            )
            if status not in (200, 201, 202):
                hint = (
                    "the rebuilt config was not accepted. The pending value is "
                    "parked and the service is still on the stored key; nothing "
                    "has been written to any holder."
                )
                if 300 <= status < 400:
                    hint = (
                        "the upload was redirected (HTTP "
                        f"{status}), which is a proxy answering, not a restore. "
                        "The pending value is parked and the service is still on "
                        "the stored key; nothing has been written to any holder."
                    )
                raise RotationError(
                    f"{service}: refused the reconstructed config restore "
                    f"(HTTP {status})",
                    hint=hint,
                )
            self._restart_service(service, key=expected)
            self._await_restart_key(
                service, old_key=expected, new_key=candidate.reveal()
            )
            self._ctx.minted = candidate
            self._ctx.minted_service = service
            self._ctx.resumed = False
            return (
                "rebuilt config.xml from the API, restored the chosen key and "
                "restarted the service"
            )

        ui_headers = self._backup_ui_headers(service, expected)
        if ui_headers:
            xml, _backup = self._backup_config(
                self._ctx.host,
                service,
                key=expected,
                transport=self._ctx.transport,
                auth_headers=ui_headers,
            )
        else:
            xml, _backup = self._backup_config(
                self._ctx.host,
                service,
                key=expected,
                transport=self._ctx.transport,
            )
        current = _config_xml_api_key(xml)
        if current is None:
            raise RotationError(
                f"{service}: the temporary backup has no ApiKey in config.xml",
                hint="refusing to restore a config whose current key cannot be "
                "read. The pending value is parked; the backup was deleted.",
            )
        if current not in (expected, candidate.reveal()):
            raise RotationError(
                f"{service}: config.xml holds a key that is neither the stored "
                "key nor the pending value",
                hint="something else changed the config, or the pending store "
                "was lost. Refusing to overwrite it; the temporary backup was "
                "deleted and no key was changed.",
            )

        if current == expected:
            restored = _replace_config_xml_key(xml, candidate.reveal())
            status, _ = self._restore_config(
                self._ctx.host,
                service,
                key=expected,
                xml=restored.encode("utf-8"),
                transport=self._ctx.transport,
            )
            if status not in (200, 201, 202):
                hint = (
                    "the pending value is parked and the service is still on the "
                    "stored key; nothing has been written to any holder."
                )
                if 300 <= status < 400:
                    hint = (
                        "the upload was redirected (HTTP "
                        f"{status}), which is a login or a proxy answering, not a "
                        "restore. The pending value is parked and the service is "
                        "still on the stored key; nothing has been written to any "
                        "holder."
                    )
                raise RotationError(
                    f"{service}: refused the config-only restore (HTTP {status})",
                    hint=hint,
                )
        # If config.xml already holds the candidate, a previous run uploaded
        # the restore but died before the restart. Restarting is the safe
        # completion; uploading it again would be an unnecessary write.

        self._restart_service(service, key=expected)
        self._await_restart_key(
            service, old_key=expected, new_key=candidate.reveal()
        )
        self._ctx.minted = candidate
        self._ctx.minted_service = service
        # A parked candidate is not a resume by itself. If config.xml already
        # held it, this run only completed the restart; if it held the stored
        # key, this run performed the restore and did mint.
        self._ctx.resumed = current == candidate.reveal()
        return "restored a chosen key over the backup API and restarted the service"

    def _mint_qbittorrent(self, step: Step) -> str:
        """Replace qBittorrent's single API key and park the new one at once.

        `POST /app/rotateAPIKey` is a reset: the response carries the new value
        and the old one stops working immediately. The response is the only
        copy of the new key, so it is written to the pending store before any
        further call. A crash after the response but before the store write is
        the one window this path cannot close without a local file fallback;
        the run refuses to mint without a pending store rather than pretend
        otherwise.
        """
        service = step.target
        if self._ctx.minted is not None:
            return f"{service}: key already minted by this run; nothing to redo"
        expected = self._ctx.vault_value
        if expected is None:
            raise RotationError(
                f"{service}: refusing to rotate with no stored value",
                hint="the rotate call authenticates with the current key, and "
                "the old key is what proves a resume from a first attempt. "
                "Store the credential and re-run; nothing has been changed.",
            )
        pending = self._ctx.pending
        if pending is None:
            raise RotationError(
                f"{service}: refusing to rotate with no pending-secret store",
                hint="the rotate response is the only copy of the new key; a "
                "crash before the vault write would lose it. Nothing has been "
                "changed.",
            )

        name = self._ctx.credential.name
        candidate = pending.get(name)
        if candidate is not None and candidate.reveal() == expected:
            # A crash after RECORD can leave the just-recorded value parked.
            # It is not a second key; keeping it would make the next run see
            # both the store and the pending copy authenticate.
            pending.clear(name)
            candidate = None

        old_verdict, old_detail = self._authenticate_settled(service, expected)
        if old_verdict == "unknown":
            raise RotationError(
                f"{service}: cannot ask whether the stored key is live "
                f"({old_detail})",
                hint="the rotate call would revoke it without proof that it "
                "is the current key. Nothing has been changed.",
            )
        if candidate is not None:
            candidate_verdict, candidate_detail = self._authenticate_settled(
                service, candidate.reveal()
            )
        else:
            candidate_verdict, candidate_detail = "absent", "no pending value"

        if old_verdict == "live" and candidate_verdict == "live":
            raise RotationError(
                f"{service}: both the stored key and the pending key "
                "authenticate",
                hint="qBittorrent has one API key. This is ambiguous, so "
                "rotating would invalidate whichever one is actually live. "
                "Wait for the service to settle and re-run.",
            )
        if candidate_verdict == "live":
            self._ctx.minted = candidate
            self._ctx.minted_service = service
            self._ctx.resumed = True
            self._confirm_old_key_dead(service, expected)
            return "already-rotated: continuing with the pending key"
        if old_verdict != "live":
            raise RotationError(
                f"{service}: neither the stored key nor the pending key is "
                f"confirmed live (stored: {old_detail}; pending: "
                f"{candidate_detail})",
                hint="a rotate needs one of them to authenticate. Nothing has "
                "been changed; restore access and re-run. If this run was "
                "started on the other surface (CLI or server), resume it "
                "there: the pending value lives beside that surface's store.",
            )
        if candidate is not None:
            if candidate_verdict != "dead":
                raise RotationError(
                    f"{service}: the pending key could not be checked safely "
                    f"({candidate_detail})",
                    hint="the stored key is live, but the parked value was "
                    "neither accepted nor refused cleanly. Nothing has been "
                    "changed.",
                )
            pending.clear(name)

        status, body = self._call(
            self._ctx.host, service, "POST", "/app/rotateAPIKey",
            key=f"Bearer {expected}", auth_header="Authorization",
            transport=self._ctx.transport,
        )
        if status != 200:
            raise RotationError(
                f"{service} refused to rotate its API key (HTTP {status})",
                hint="the call is authenticated with the CURRENT key. A 403 "
                "means it is already dead; check the pending store or "
                "qBittorrent's config before re-running.",
            )
        new_key = body.get("apiKey") if isinstance(body, dict) else None
        if (
            not isinstance(new_key, str)
            or not new_key.startswith("qbt_")
            or len(new_key) != 32
        ):
            raise RotationError(
                f"{service}: the rotate response carried no usable API key",
                hint="the old key is already revoked and the new value could "
                "not be read. Do not rotate again; inspect qBittorrent's "
                "config and the pending store.",
            )
        if new_key == expected:
            raise RotationError(
                f"{service}: the rotate was accepted but the key is unchanged",
                hint="the old key is not proven dead, so propagating it would "
                "not prove a rotation. Nothing has been written to a holder.",
            )
        # Park before asking anything else: this is the only copy.
        pending.set(name, Secret(new_key))

        verdict, detail = self._authenticate_settled(service, new_key)
        if verdict != "live":
            raise RotationError(
                f"{service}: the newly rotated key does not authenticate "
                f"({detail})",
                hint="the old key is already revoked and the new value is in "
                "the pending store. Nothing has been written to a holder; "
                "re-run to resume.",
            )
        self._ctx.minted = Secret(new_key)
        self._ctx.minted_service = service
        self._ctx.resumed = False
        self._confirm_old_key_dead(service, expected)
        if self._ctx.old_key_dead:
            return "rotated the API key; the previous key is already revoked"
        return (
            "rotated the API key; the previous key could not be confirmed dead, "
            "so exercise-only confirmation will not be claimed"
        )

    def _mint_seerr(self, step: Step) -> str:
        """Replace Seerr's own API key and park the new one at once.

        `POST /settings/main/regenerate` is a reset: the response carries the
        new value and the old key stops working immediately. The response is
        the only copy, so it is written to the pending store before any other
        call. Measured on 3.5.0: the route updates the running process in
        place, so no restart is needed and settings.json is saved before the
        response.

        A deployment that sets Seerr's `API_KEY` environment variable pins the
        key: `generateApiKey` returns that value, so regenerate answers 200
        with the stored key unchanged. That is a no-op, not a rotation, and it
        is refused here rather than recorded.
        """
        service = step.target
        if self._ctx.minted is not None:
            return f"{service}: key already minted by this run; nothing to redo"
        expected = self._ctx.vault_value
        if expected is None:
            raise RotationError(
                f"{service}: refusing to rotate with no stored value",
                hint="the regenerate call authenticates with the current key. "
                "Store the credential and re-run; nothing has been changed.",
            )
        pending = self._ctx.pending
        if pending is None:
            raise RotationError(
                f"{service}: refusing to rotate with no pending-secret store",
                hint="the regenerate response is the only copy of the new key; "
                "a crash before the vault write would lose it. Nothing has "
                "been changed.",
            )

        name = self._ctx.credential.name
        candidate = pending.get(name)
        if candidate is not None and candidate.reveal() == expected:
            # A crash after RECORD can leave the just-recorded value parked.
            # It is not a second key; keeping it would make the next run see
            # both the store and the pending copy authenticate.
            pending.clear(name)
            candidate = None

        old_verdict, old_detail = self._authenticate_settled(service, expected)
        if old_verdict == "unknown":
            raise RotationError(
                f"{service}: cannot ask whether the stored key is live "
                f"({old_detail})",
                hint="the regenerate call would revoke it without proof that "
                "it is the current key. Nothing has been changed.",
            )
        if candidate is not None:
            candidate_verdict, candidate_detail = self._authenticate_settled(
                service, candidate.reveal()
            )
        else:
            candidate_verdict, candidate_detail = "absent", "no pending value"

        if old_verdict == "live" and candidate_verdict == "live":
            raise RotationError(
                f"{service}: both the stored key and the pending key "
                "authenticate",
                hint="Seerr has one API key. This is ambiguous, so regenerating "
                "would invalidate whichever one is actually live. Wait for the "
                "service to settle and re-run.",
            )
        if candidate_verdict == "live":
            self._ctx.minted = candidate
            self._ctx.minted_service = service
            self._ctx.resumed = True
            self._confirm_old_key_dead(service, expected)
            return "already-rotated: continuing with the pending key"
        if old_verdict != "live":
            raise RotationError(
                f"{service}: neither the stored key nor the pending key is "
                f"confirmed live (stored: {old_detail}; pending: "
                f"{candidate_detail})",
                hint="a regenerate needs one of them to authenticate. Nothing "
                "has been changed; restore access and re-run. If this run was "
                "started on the other surface (CLI or server), resume it "
                "there: the pending value lives beside that surface's store.",
            )
        if candidate is not None:
            if candidate_verdict != "dead":
                raise RotationError(
                    f"{service}: the pending key could not be checked safely "
                    f"({candidate_detail})",
                    hint="the stored key is live, but the parked value was "
                    "neither accepted nor refused cleanly. Nothing has been "
                    "changed.",
                )
            pending.clear(name)

        status, body = self._call(
            self._ctx.host, service, "POST", "/settings/main/regenerate",
            key=expected, auth_header="X-API-Key",
            transport=self._ctx.transport,
        )
        if status != 200:
            raise RotationError(
                f"{service} refused to regenerate its API key (HTTP {status})",
                hint="the call is authenticated with the CURRENT key. A 403 "
                "means it is already dead; check the pending store or Seerr's "
                "settings before re-running.",
            )
        new_key = body.get("apiKey") if isinstance(body, dict) else None
        if not isinstance(new_key, str) or not new_key:
            raise RotationError(
                f"{service}: the regenerate response carried no usable API key",
                hint="the old key may already be revoked and the new value "
                "could not be read. Do not regenerate again; inspect Seerr's "
                "settings and the pending store.",
            )
        if new_key == expected:
            raise RotationError(
                f"{service}: regenerate returned the stored key unchanged",
                hint="this is what a pinned `API_KEY` environment variable "
                "looks like: the route answers 200 but the key cannot change. "
                "Remove API_KEY from Seerr's environment, restart it once, and "
                "re-run. Nothing has been written to a holder.",
            )
        # Park before asking anything else: this is the only copy.
        pending.set(name, Secret(new_key))

        verdict, detail = self._authenticate_settled(service, new_key)
        if verdict != "live":
            raise RotationError(
                f"{service}: the regenerated key does not authenticate "
                f"({detail})",
                hint="the old key is already revoked and the new value is in "
                "the pending store. Nothing has been written to a holder; "
                "re-run to resume.",
            )
        self._ctx.minted = Secret(new_key)
        self._ctx.minted_service = service
        self._ctx.resumed = False
        self._confirm_old_key_dead(service, expected)
        if self._ctx.old_key_dead:
            return "regenerated the API key; the previous key is already revoked"
        return (
            "regenerated the API key; the previous key could not be confirmed "
            "dead, so exercise-only confirmation will not be claimed"
        )

    def _jellyfin_app_name(self) -> str:
        """The AppName of every key credarr mints for this credential.

        One source, because the mint writes this name and the revoke sweeps
        by it - two spellings would make the sweep match nothing, silently.
        """
        return f"credarr-{self._ctx.credential.name}"

    def _mint_jellyfin(self, step: Step) -> str:
        """Mint a Jellyfin API key by creating one, and read its value back.

        Two calls, because the create does not hand the value over: `POST
        /Auth/Keys?app=` answers 204 and stores a 32-hex GUID that appears
        nowhere in the response. `GET /Auth/Keys` lists every AccessToken in
        full, so the new one is read from there.

        The old key is left alone. Jellyfin supports many API keys at once, so
        minting does not revoke anything and no window exists between minting
        and propagating - the whole reason this path is worth having.

        Both routes are gated on `RequiresElevation`, which in Jellyfin any
        API key satisfies outright - an API key *is* a global administrator.
        So the mint authenticates with the credential being rotated, and its
        first GET is what proves the vault's copy is still live: a 401 there
        refuses before anything is created. A second key would carry exactly
        the same authority, so it would add another standing credential
        rather than least privilege.
        """
        service = step.target
        minting = self._ctx.vault_value
        if minting is None:
            raise RotationError(
                f"{service}: the vault holds no value for this credential",
                hint="the mint authenticates with the credential being "
                "rotated, so there is nothing to authenticate with until the "
                "vault holds one; restore the vault entry and re-run",
            )
        # List keys before minting so the new one is identified by diff, not
        # by name: names are not unique, so a rerun would find two rows with
        # the same name. A resume mints again and takes the newest key; the
        # key a dead run created is not adopted, because its name cannot
        # prove who made it - the revoke's sweep deletes it by that name, and
        # that is the only thing the name is trusted for.
        app = self._jellyfin_app_name()
        status, body = self._call(
            self._ctx.host, service, "GET", "/Auth/Keys",
            key=minting,
            auth_transport=MINT_SOURCES[service].auth_transport,
            transport=self._ctx.transport,
        )
        if status != 200:
            raise RotationError(
                f"{service} would not list its keys (HTTP {status})",
                hint="the key authenticating this request needs "
                "`RequiresElevation`; in Jellyfin an API key grants it "
                "outright, so a refusal here means the key is wrong",
            )
        before = {item.get("AccessToken") for item in
                  (body.get("Items", []) if isinstance(body, dict) else [])
                  if isinstance(item, dict)}

        status, _ = self._call(
            self._ctx.host, service, "POST",
            "/Auth/Keys?" + urllib.parse.urlencode({"app": app}),
            key=minting,
            auth_transport=MINT_SOURCES[service].auth_transport,
            transport=self._ctx.transport,
        )
        if status != 204:
            raise RotationError(
                f"{service} refused to mint an API key (HTTP {status})",
                hint="the key authenticating this request needs "
                "`RequiresElevation`; in Jellyfin an API key grants it "
                "outright, so a refusal here means the key is wrong",
            )
        status, body = self._call(
            self._ctx.host, service, "GET", "/Auth/Keys",
            key=minting,
            auth_transport=MINT_SOURCES[service].auth_transport,
            transport=self._ctx.transport,
        )
        if status != 200:
            raise RotationError(
                f"{service} would not list its keys (HTTP {status})",
                hint="the mint succeeded; reading the value back failed, so a "
                "key now exists that this run cannot report",
            )
        after = {item.get("AccessToken") for item in
                 (body.get("Items", []) if isinstance(body, dict) else [])
                 if isinstance(item, dict)}
        new_keys = after - before
        if len(new_keys) != 1:
            raise RotationError(
                f"{service}: expected exactly one new key after mint, found "
                f"{len(new_keys)}",
                hint="refusing to guess which key to use",
            )
        self._ctx.minted = Secret(new_keys.pop())
        self._ctx.minted_service = service
        return f"minted a new key named {app!r}"

    def _propagate(self, step: Step) -> str:
        """Write the new key to every declared copy, then exercise the holder.

        "Every declared copy" is not every row the API lists. A qualified target
        names one row inside its slot, and Seerr and Prowlarr each hold both the
        Sonarr and the Radarr key - so a write that ignored the qualifier would
        hand Sonarr's new credential to Radarr's copy, replacing a working one
        with a revoked key. See `_select_rows`.
        """
        system, slot = split_target(step.target)
        described = holder_for(system, slot)
        if described is None:
            raise RotationError(
                f"{step.target}: no writer known for that slot",
                hint=f"known: {', '.join(sorted(known_systems()))}",
            )
        if described.write == "seerr_api":
            return self._propagate_seerr(step, described)
        if described.write == "qui_api":
            return self._propagate_qui(step, described)
        api_path = described.api_path
        if self._ctx.minted is None:
            raise RotationError(
                f"nothing to propagate for {step.target}: no key was minted",
                hint="this means the mint step did not run; refusing to write a "
                "stale value over a working one",
            )

        status, rows = self._call(
            self._ctx.host, system, "GET", f"/{api_path}",
            key=self._service_key(system),
            transport=self._ctx.transport,
        )
        if status != 200 or not isinstance(rows, list):
            raise RotationError(
                f"could not list {step.target} (HTTP {status})",
                hint="authenticating with the *new* key; if this fails with 401 "
                "the service did not actually rotate",
            )
        rows = self._select_rows(step.target, rows)

        target_field = self._resolve_field(step)
        written = 0
        interval = self._ctx.write_interval
        # Row label -> (verdict, detail) from the holder's own test. Kept for
        # the promotion pass, which decides whether the write is confirmed.
        exercises: dict[str, tuple[str, str]] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            label = str(row.get("id"))
            # The list endpoint redacts apiKey as "********", exactly as it
            # redacts on a single GET of some other resources. Building the PUT
            # from the list therefore writes the redaction back, which is
            # rejected with 400 - and the id-only list is all that is needed to
            # find the resources to fetch properly.
            status, resource = self._call(
                self._ctx.host, system, "GET", f"/{api_path}/{row.get('id')}",
                key=self._service_key(system),
                transport=self._ctx.transport,
            )
            if status != 200 or not isinstance(resource, dict):
                self._ctx.holders.append(
                    HolderOutcome(step.target, label, "failed",
                                  f"could not read the resource (HTTP {status})")
                )
                raise RotationError(
                    f"{step.target} id={row.get('id')}: could not read the "
                    f"resource (HTTP {status})"
                )

            if not self._ctx.holders and interval > 0:
                log_line(f"      pacing {interval:g}s between holder writes")
            if self._ctx.holders and interval > 0:
                time.sleep(interval)
            attempt = 1
            while attempt <= WRITE_ATTEMPTS:
                # Deep, not shallow: `fields` is a list of dicts, so a shallow
                # copy would mutate the fetched `resource` below and the
                # exercise would send the new key instead of the stored value.
                payload = copy.deepcopy(resource)
                payload["id"] = resource.get("id")
                wrote_target = False
                for field_ in payload.get("fields") or []:
                    if field_.get("name") == target_field:
                        field_["value"] = self._ctx.minted.reveal()
                        wrote_target = True
                if not wrote_target:
                    # A 202 for a PUT that changes nothing is the same silent
                    # success as writing the mask back: the row keeps the old
                    # (revoked) key and the promotion pass can only report it
                    # after the fact. Refuse before the request, naming the drift.
                    raise RotationError(
                        f"{step.target} id={row.get('id')}: the resource has no "
                        f"{target_field!r} field",
                        hint="the service's row shape changed, or the field name "
                        "is wrong; refusing a PUT that would change nothing",
                    )
                # The fence, per row rather than per step. A propagation step writes
                # sixteen rows; checking only at the step boundary would let a
                # process that lost the lease keep writing for the rest of it.
                if self._ctx.lease_check is not None:
                    self._ctx.lease_check()

                status, refusal = self._call(
                    self._ctx.host, system, "PUT", f"/{api_path}/{row.get('id')}",
                    body=payload, key=self._service_key(system),
                    transport=self._ctx.transport,
                )
                if status not in (200, 201, 202):
                    verdict, reason = classify_refusal(status, refusal)
                    # Scrubbed before it is logged, journaled or reported. The
                    # refusal text comes from the service, and a validation error
                    # that echoes the submitted resource is carrying the very
                    # credential being rotated.
                    reason = scrub(reason, self._ctx.minted, self._ctx.vault_value)
                    if verdict in ("transient", "unknown"):
                        # Upstream is rate-limiting or timing out. Widen the
                        # gap for every row after this one rather than retry
                        # this row four times against a limiter that has
                        # already said no.
                        interval = min(interval * 2 or MAX_WRITE_INTERVAL,
                                       MAX_WRITE_INTERVAL)
                        log_line(
                            f"      upstream refused: widening the gap between "
                            f"writes to {interval:g}s"
                        )
                        if attempt < WRITE_ATTEMPTS:
                            delay = self._ctx.write_backoff * (2 ** (attempt - 1))
                            log_line(
                                f"      {step.target}[{label}] {verdict}: "
                                f"{reason[:80]} - retry {attempt + 1} in {delay}s"
                            )
                            time.sleep(delay)
                            attempt += 1
                            continue
                        raise RotationError(
                            f"{step.target} id={row.get('id')} still failing after "
                            f"{WRITE_ATTEMPTS} attempts: {reason}",
                            hint="the upstream indexer service is the bottleneck, "
                            "not this tool. Nothing was written to the remaining "
                            "holders; re-run to converge from here.",
                        )
                if status not in (200, 201, 202):
                    # The RESPONSE is what explains a refusal. Explaining the
                    # request payload tells you nothing - it has no title or errors
                    # to read - which is why the first version of this fix changed
                    # the capture and left the output exactly as before.
                    # Same scrubbing as the retry path above: this detail is
                    # recorded per holder in the journal, so it outlives the run.
                    detail = scrub(
                        _explain(refusal) or f"API returned {status}",
                        self._ctx.minted, self._ctx.vault_value,
                    )
                    self._ctx.holders.append(
                        HolderOutcome(step.target, label, "failed", detail)
                    )
                    raise RotationError(
                        f"{step.target} id={row.get('id')} refused the write: {detail}",
                        hint="the service's own validation message is above; a 400 "
                        "here is usually a malformed request rather than a "
                        "refused credential",
                    )
                break
            # Ask the app that owns the row to use its stored value. The payload
            # is the pre-write GET, mask intact, so the test reads the value the
            # process stored - not the one this run just supplied. One call per
            # written row; a failed test leaves the row unproven.
            exercises[label] = self._exercise(described, system, resource)
            written += 1
            # "written" deliberately means only that the API accepted. It is not
            # evidence the value was stored, and reporting it as "updated" would
            # claim a certainty nobody has.
            self._ctx.holders.append(HolderOutcome(step.target, label, "written"))

        # Promote each written row only when the holder's own test accepted the
        # stored value and the old issuer key is confirmed dead. There is no
        # local read-equal; anything weaker stays "written" and says so.
        promoted: list[HolderOutcome] = []
        for holder in self._ctx.holders:
            if holder.target != step.target or holder.outcome != "written":
                promoted.append(holder)
                continue
            verdict, exercise_detail = exercises.get(
                holder.label, ("unsupported", "")
            )
            # Only the protocol's three facts can make the test's acceptance
            # mean equality: the new key authenticates (done at mint), the old
            # key is dead, and the holder accepts the stored value.
            if verdict == "accepted" and self._ctx.old_key_dead is True:
                promoted.append(HolderOutcome(
                    step.target, holder.label, "confirmed", exercise_detail,
                    "exercised",
                ))
            elif verdict == "accepted":
                promoted.append(HolderOutcome(
                    step.target, holder.label, "written",
                    "the holder's own test accepts the stored value, but the "
                    "issuer's old key is still live or its revocation could "
                    "not be confirmed; equality is not proven",
                ))
            elif verdict == "rejected":
                promoted.append(HolderOutcome(
                    step.target, holder.label, "written",
                    "the API accepted the write, but the holder's own test "
                    "rejects the stored value; a stale process or a 401 access "
                    f"layer looks the same ({exercise_detail})",
                ))
            else:
                reason = (
                    "no exercise endpoint is measured for this holder"
                    if verdict == "unsupported"
                    else f"the holder's own test was inconclusive ({exercise_detail})"
                )
                promoted.append(HolderOutcome(
                    step.target, holder.label, "written",
                    f"the API accepted the write; the holder's API exposes no "
                    f"readable copy and {reason}; the value is not proven",
                ))
        self._ctx.holders = promoted
        self._journal_holders()

        if not written:
            return "0 row(s) written; there was nothing to verify"
        confirmed = sum(
            1 for h in self._ctx.holders
            if h.target == step.target and h.outcome == "confirmed"
        )
        if confirmed == written:
            return f"{written} row(s) written, verified by exercise"
        return (
            f"{written} row(s) written, not proven: the holder's API exposes "
            f"no equality readback and {written - confirmed} row(s) lack an "
            "exercise confirmation"
        )

    def _propagate_seerr(self, step: Step, holder: Holder) -> str:
        """Write a Seerr-held key over its settings API and read it back.

        Arr rows use PUT /settings/{service}/{id}; Jellyfin is a single object
        and uses POST /settings/jellyfin. Both update the running process
        directly, so no restart or file write is involved. Seerr's own API key
        authenticates the call and is read from the runtime store, never from a
        settings file.
        """
        if self._ctx.minted is None:
            raise RotationError(
                f"nothing to propagate for {step.target}: no key was minted",
                hint="this means the mint step did not run; refusing to write a "
                "stale value over a working one",
            )
        row = self._row_name(step.target)
        if row is None:
            raise RotationError(
                f"{step.target}: does not name which holder to write. Seerr "
                "holds several services' credentials, so the target needs a row "
                "qualifier"
            )
        minted = self._ctx.minted.reveal()
        # The target already names the row; repeating it in the label prints
        # `[qBittorrent][qBittorrent]` in the report.
        label = ""
        try:
            try:
                api_key = self._service_key(holder.system)
            except (ConfigError, TransportError) as exc:
                raise RotationError(
                    f"cannot read {holder.system}'s own API key ({exc})",
                    hint="store Seerr's own key before rotating a credential "
                    "it holds",
                ) from exc
            if not api_key:
                raise RotationError(
                    f"no API key for {holder.system!r}; nothing could "
                    "authenticate the settings write",
                    hint="store Seerr's own key before rotating a credential "
                    "it holds",
                )

            instance, label = self._seerr_instance(holder, row, api_key)
            # These fields identify the stored object or are derived from the
            # server and are read-only in Seerr's settings schema; sending any
            # back makes the write a validation error.
            update = {
                k: v for k, v in instance.items()
                if k not in (
                    ("id", "serverId", "name", "libraries")
                    if row == "jellyfin" else ("id",)
                )
            }
            update["apiKey"] = minted
            if row == "jellyfin":
                status, _ = self._call(
                    self._ctx.host, holder.system, "POST",
                    "/settings/jellyfin", body=update, key=api_key,
                    auth_header=holder.auth_header_name,
                    auth_transport=holder.auth_transport,
                    transport=self._ctx.transport,
                )
            else:
                instance_id = instance.get("id")
                if instance_id is None:
                    raise RotationError(
                        f"the {row} instance has no id, so the write cannot "
                        "be addressed",
                        hint="the settings section changed shape; nothing was "
                        "written to it",
                    )
                # Seerr's OpenAPI schema marks these required and a stored
                # instance need not carry them: without them the PUT is a
                # measured 400 ("must have required property ..."), not an
                # update.
                update.setdefault("enableSeasonFolders", False)
                update.setdefault("minimumAvailability", "In Cinema")
                status, _ = self._call(
                    self._ctx.host, holder.system, "PUT",
                    f"/settings/{row}/{instance_id}", body=update, key=api_key,
                    auth_header=holder.auth_header_name,
                    auth_transport=holder.auth_transport,
                    transport=self._ctx.transport,
                )
            if status != 200:
                raise RotationError(
                    f"Seerr refused the {row} settings write (HTTP {status})",
                    hint="the mint already ran and the old key is revoked. "
                    "Re-run once the settings API accepts the write.",
                )
            self._await_seerr_key(holder, row, api_key, minted)
        except RotationError as exc:
            # A refusal must reach the report as this holder's failure, not as
            # an unattempted step.
            self._ctx.holders.append(
                HolderOutcome(step.target, label, "failed", str(exc))
            )
            raise
        self._ctx.holders.append(
            HolderOutcome(step.target, label, "confirmed", "", "read-equal")
        )
        return (
            f"written to {holder.system}.{holder.slot}[{row}] over the API "
            f"and confirmed against the running {holder.system}"
        )

    def _seerr_instance(
        self, holder: Holder, row: str, api_key: str
    ) -> tuple[dict, str]:
        """The one settings object this target names, and its display label."""
        status, body = self._call(
            self._ctx.host, holder.system, "GET",
            holder.readback_path.format(service=row), key=api_key,
            auth_header=holder.auth_header_name,
            auth_transport=holder.auth_transport,
            transport=self._ctx.transport,
        )
        if status != 200:
            raise RotationError(
                f"could not read Seerr's {row} settings (HTTP {status})",
                hint="the old key is already revoked; restore access and "
                "re-run to finish",
            )
        if row == "jellyfin":
            if not isinstance(body, dict) or not body:
                raise RotationError(
                    "Seerr has no Jellyfin settings object, so there is "
                    "nothing to update",
                    hint="the old key is already revoked; restore the Jellyfin "
                    "settings, then re-run to finish",
                )
            return body, str(body.get("name") or "Jellyfin")
        if not isinstance(body, list):
            raise RotationError(
                f"Seerr returned an unexpected settings shape for {row!r}",
                hint="the old key is already revoked; nothing was written",
            )
        if not body:
            raise RotationError(
                f"the settings section holds no {row} instances, so there is "
                "nothing to update",
                hint="the old key is already revoked; restore the instance, "
                "then re-run to finish",
            )
        if len(body) > 1:
            raise RotationError(
                f"the settings section holds {len(body)} {row} instances and "
                "this build can update exactly one",
                hint="which instance holds this credential is not in the "
                "manifest, so nothing was written",
            )
        instance = body[0]
        if not isinstance(instance, dict):
            raise RotationError(
                f"the {row} settings row is not an object",
                hint="the old key is already revoked; nothing was written",
            )
        return instance, str(instance.get("name", row))

    def _await_seerr_key(
        self, holder: Holder, row: str, api_key: str, minted: str
    ) -> None:
        """Wait for the running process to report the value just written."""
        deadline = time.time() + SEERR_READBACK_TIMEOUT
        last = "no read-back completed"
        while True:
            try:
                status, body = self._call(
                    self._ctx.host, holder.system, "GET",
                    holder.readback_path.format(service=row), key=api_key,
                    auth_header=holder.auth_header_name,
                    auth_transport=holder.auth_transport,
                    transport=self._ctx.transport,
                )
            except TransportError as exc:
                last = f"{type(exc).__name__}: {exc}"
            else:
                if status == 200 and self._seerr_holds(body, row, minted):
                    return
                last = f"HTTP {status}"
            if time.time() >= deadline:
                break
            time.sleep(SEERR_READBACK_INTERVAL)
        raise RotationError(
            f"the settings API accepted the write, but the running process "
            f"did not report the new {row} key within "
            f"{SEERR_READBACK_TIMEOUT}s ({last})",
            hint="the old key is already revoked. Re-run once Seerr is "
            "responsive; this run has not recorded the new value.",
        )

    @staticmethod
    def _seerr_holds(body: object, row: str, minted: str) -> bool:
        if row == "jellyfin":
            return isinstance(body, dict) and body.get("apiKey") == minted
        return (
            isinstance(body, list)
            and bool(body)
            and all(
                isinstance(item, dict) and item.get("apiKey") == minted
                for item in body
            )
        )

    def _propagate_qui(self, step: Step, holder: Holder) -> str:
        """Write a qBittorrent API key into one qui instance and test it.

        qui stores instance credentials encrypted, so there is no plaintext
        read-back. The proof is qui's own `POST /instances/{id}/test`: qui
        decrypts the stored value and asks qBittorrent to accept it, which is
        stronger than a disk read because it exercises the running process.
        """
        if self._ctx.minted is None:
            raise RotationError(
                f"nothing to propagate for {step.target}: no key was minted",
                hint="this means the mint step did not run; refusing to write "
                "a stale value over a working one",
            )
        row = self._row_name(step.target)
        if row is None:
            raise RotationError(
                f"{step.target}: does not name which qui instance to write",
                hint="qui can hold several instances, so the target needs a "
                "row qualifier",
            )
        minted = self._ctx.minted.reveal()
        # The target already names the row; repeating it in the label prints
        # `[qBittorrent][qBittorrent]` in the report.
        label = ""
        try:
            try:
                api_key = self._service_key(holder.system)
            except (ConfigError, TransportError) as exc:
                raise RotationError(
                    f"cannot read {holder.system}'s own API key ({exc})",
                    hint="store qui's own key before rotating a credential it "
                    "holds",
                ) from exc
            if not api_key:
                raise RotationError(
                    f"no API key for {holder.system!r}; nothing could "
                    "authenticate the instance write",
                    hint="store qui's own key before rotating a credential it "
                    "holds",
                )

            status, rows = self._call(
                self._ctx.host, holder.system, "GET", holder.api_path,
                key=api_key, auth_header=holder.auth_header_name,
                auth_transport=holder.auth_transport,
                transport=self._ctx.transport,
            )
            if status != 200 or not isinstance(rows, list):
                raise RotationError(
                    f"could not list qui instances (HTTP {status})",
                    hint="the old qBittorrent key is already revoked; restore "
                    "qui access and re-run to finish",
                )
            matches = [
                item for item in rows
                if isinstance(item, dict) and item.get("name") == row
            ]
            if not matches:
                raise RotationError(
                    f"qui has no instance named {row!r}, so there is nothing "
                    "to update",
                    hint="the old key is already revoked; restore the instance, "
                    "then re-run to finish",
                )
            if len(matches) > 1:
                raise RotationError(
                    f"qui has {len(matches)} instances named {row!r}",
                    hint="which one holds this credential is ambiguous, so "
                    "nothing was written",
                )
            instance = matches[0]
            instance_id = instance.get("id")
            if instance_id is None:
                raise RotationError(
                    f"the qui instance {row!r} has no id, so the write cannot "
                    "be addressed",
                    hint="the instance shape changed; nothing was written",
                )
            host = instance.get("host")
            if not isinstance(host, str) or not host:
                raise RotationError(
                    f"the qui instance {row!r} has no host, so the write cannot "
                    "be addressed",
                    hint="the instance shape changed; nothing was written",
                )
            update = {
                "name": instance.get("name") or row,
                "host": host,
                "username": instance.get("username") or "",
                "apiKey": minted,
            }
            status, _ = self._call(
                self._ctx.host, holder.system, "PUT",
                f"{holder.api_path}/{instance_id}", body=update, key=api_key,
                auth_header=holder.auth_header_name,
                auth_transport=holder.auth_transport,
                transport=self._ctx.transport,
            )
            if status != 200:
                raise RotationError(
                    f"qui refused the {row} instance write (HTTP {status})",
                    hint="the mint already ran and the old key is revoked. "
                    "Re-run once qui accepts the write.",
                )
            self._await_qui_test(holder, instance_id, api_key)
        except RotationError as exc:
            self._ctx.holders.append(
                HolderOutcome(step.target, label, "failed", str(exc))
            )
            raise
        self._ctx.holders.append(
            HolderOutcome(step.target, label, "confirmed", "", "exercised")
        )
        return (
            f"written to {holder.system}.{holder.slot}[{row}] over the API "
            f"and confirmed by {holder.system}'s own connection test"
        )

    def _await_qui_test(
        self, holder: Holder, instance_id: object, api_key: str
    ) -> None:
        """Wait for qui to connect with the stored value."""
        deadline = time.time() + SEERR_READBACK_TIMEOUT
        last = "no connection test completed"
        while True:
            try:
                status, body = self._call(
                    self._ctx.host, holder.system, "POST",
                    holder.readback_path.format(id=instance_id), key=api_key,
                    auth_header=holder.auth_header_name,
                    auth_transport=holder.auth_transport,
                    transport=self._ctx.transport,
                )
            except TransportError as exc:
                last = f"{type(exc).__name__}: {exc}"
            else:
                if (
                    status == 200
                    and isinstance(body, dict)
                    and body.get("connected") is True
                ):
                    return
                if isinstance(body, dict) and body.get("error"):
                    last = scrub(str(body["error"]),
                                 self._ctx.minted, self._ctx.vault_value)
                else:
                    last = f"HTTP {status}"
            if time.time() >= deadline:
                break
            time.sleep(SEERR_READBACK_INTERVAL)
        raise RotationError(
            f"qui accepted the instance write, but its connection test did not "
            f"confirm the new key within {SEERR_READBACK_TIMEOUT}s ({last})",
            hint="the old key is already revoked. Re-run once qui and "
            "qBittorrent are responsive; this run has not recorded the new "
            "value.",
        )

    def _record(self) -> str:
        """Write the new value to the vault.

        Last, deliberately. Every earlier step can be re-derived from the
        service that minted the value, but a vault that has been written and a
        propagation that failed cannot be distinguished from a rotation that
        never happened. Doing it last means the canonical copy only moves once
        the copies it feeds have already moved.
        """
        if self._ctx.minted is None:
            raise RotationError(
                "cannot record: no value was minted",
                hint="writing the vault before anything is propagated would "
                "leave the canonical copy ahead of every consumer",
            )
        if self._ctx.vault_setter is None:
            raise RotationError(
                "cannot record: this run has no way to write the vault",
                hint="the executor needs a mutable secret source; a read-only "
                "one would leave the vault stale",
            )
        self._ctx.vault_setter(self._ctx.minted)
        if self._ctx.pending is not None:
            try:
                self._ctx.pending.clear(self._ctx.credential.name)
            except Exception as exc:
                # The canonical write is the fact that matters; a failed
                # cleanup must not turn a completed rotation into a failure.
                # The leftover is a copy of the value just recorded, and the
                # store prunes that on its next start.
                log_line(
                    "      warning: the canonical value was recorded, but the "
                    f"pending copy could not be cleared ({type(exc).__name__})"
                )
                return "written; pending copy could not be cleared"
        return "written"

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

    def _revoke_jellyfin(self, step: Step) -> str:
        """Delete the key this rotation replaced.

        Reached only from the plan's final REVOKE step, and arriving here
        means every holder was confirmed - the mint created a key rather than
        replacing one, so the old one is still live and a rotation that never
        deletes it leaves a credential accumulating indefinitely.

        Authenticated by the key this run minted: it is the credential every
        holder now carries, the old key is only the target, and deleting the
        target does not touch its successor - so a rerun of this step is safe.

        It also sweeps what interrupted runs before it left behind. A run that
        died between its mint and its revoke leaves a key whose value the
        vault never recorded, so no value match can identify it; the sweep
        goes by name instead - `credarr-<credential>`, the namespace this
        build mints under. That is the one place this module trusts a name
        over a value, and it is deliberate: the alternative is dead keys
        accumulating forever. A key a human created under exactly that name is
        indistinguishable from a stray and is swept with it.

        It fails loudly, and deliberately. The rotation itself succeeded, but a
        credential this build replaced is still valid - which is the drift this
        tool exists to surface. Reporting success over a live stale key would
        be the exact failure this whole project refuses.
        """
        minted = self._ctx.minted
        if minted is None:
            raise RotationError(
                f"{step.target}: nothing was minted by this run, so the revoke "
                "has no key to authenticate with",
                hint="the revoke follows the mint by construction; re-run "
                "the rotation to resume from where it stopped",
            )
        # `minted` is a Secret; the transport takes the plain value, as every
        # other call site does.
        minting = minted.reveal()
        # The vault value is captured once, when the context was built, and the
        # vault is only written at the RECORD step - so this is still the key
        # that was replaced even though the vault has since moved on.
        target = self._ctx.vault_value
        if target is None:
            raise RotationError(
                f"{step.target}: the vault holds no value for this credential, "
                "so the key that was replaced cannot be identified",
                hint="the rotation is complete and every holder is confirmed; "
                "the previous key is still valid and must be revoked by hand "
                "from Jellyfin's dashboard",
            )
        status, body = self._call(
            self._ctx.host, step.target, "GET", "/Auth/Keys",
            key=minting,
            auth_transport=MINT_SOURCES[step.target].auth_transport,
            transport=self._ctx.transport,
        )
        items = body.get("Items") if isinstance(body, dict) else None
        if status != 200 or not isinstance(items, list):
            # Shape as well as status: a 200 whose body is not a listing is
            # not evidence that there is no old key to revoke.
            raise RotationError(
                f"{step.target}: could not list keys to find the old one "
                f"(HTTP {status})",
                hint="the rotation is complete and every holder is confirmed; "
                "the previous key is still valid and can be revoked from "
                "Jellyfin's dashboard",
            )
        app = self._jellyfin_app_name()
        doomed = [item for item in items if isinstance(item, dict)
                  and item.get("AccessToken") == target]
        # Strays: keys a dead run minted under credarr's own name, whose
        # values the vault never recorded. The minted key carries the same
        # name and is excluded by value - a sweep that took it would break
        # every holder the run just confirmed. A row without a token cannot
        # authenticate, so it is skipped, exactly as the value match skips it.
        strays = [item for item in items if isinstance(item, dict)
                  and item.get("AppName") == app
                  and item.get("AccessToken")
                  and item.get("AccessToken") not in (target, minting)]
        if not doomed and not strays:
            # Not an error: it was revoked already, or the vault held a value
            # this Jellyfin never knew. Nothing to do either way.
            return f"{step.target}: no previous key left to revoke"
        leftovers = []
        for item in (*doomed, *strays):
            # Every match, not the first. Real tokens are unique, so a second
            # match means the key list is corrupted - and stopping at the
            # first would leave a live key behind either way.
            status, _ = self._call(
                self._ctx.host, step.target, "DELETE",
                f"/Auth/Keys/{urllib.parse.quote(item['AccessToken'])}",
                key=minting,
                auth_transport=MINT_SOURCES[step.target].auth_transport,
                transport=self._ctx.transport,
            )
            if status != 204:
                leftovers.append(item.get("AppName", "unnamed"))
        if leftovers:
            raise RotationError(
                f"{step.target}: {len(leftovers)} key(s) could not be "
                f"revoked ({', '.join(leftovers)})",
                hint="the rotation itself succeeded - every holder is "
                "confirmed and the vault holds the new value. What is wrong is "
                "that a key this run was to delete is still live, which is "
                "drift this tool is built to surface rather than swallow. "
                "Revoke it from Jellyfin's dashboard.",
            )
        # The DELETE returns a status code; the listing is the fact. A 204 that
        # did not remove the row would otherwise be reported as a clean revoke
        # over a key that still authenticates - the stale credential this step
        # exists to prove gone.
        status, body = self._call(
            self._ctx.host, step.target, "GET", "/Auth/Keys",
            key=minting,
            auth_transport=MINT_SOURCES[step.target].auth_transport,
            transport=self._ctx.transport,
        )
        remaining = body.get("Items") if isinstance(body, dict) else None
        if status != 200 or not isinstance(remaining, list):
            raise RotationError(
                f"{step.target}: could not list keys to confirm the revoke "
                f"(HTTP {status})",
                hint="the DELETE was accepted, but whether it removed the old "
                "key is now unknown. The rotation itself succeeded - every "
                "holder is confirmed and the vault holds the new value - so "
                "check Jellyfin's key list and delete any stale key by hand.",
            )
        if any(isinstance(item, dict) and item.get("AccessToken") == target
               for item in remaining):
            raise RotationError(
                f"{step.target}: the previous key survived its deletion; it is "
                "still live",
                hint="the rotation itself succeeded - every holder is confirmed "
                "and the vault holds the new value - but the old key still "
                "authenticates. Delete it from Jellyfin's dashboard.",
            )
        if any(isinstance(item, dict) and item.get("AccessToken")
               and item.get("AppName") == app
               and item.get("AccessToken") != minting for item in remaining):
            raise RotationError(
                f"{step.target}: a key left by an interrupted run survived its "
                "deletion; it is still live",
                hint="the rotation itself succeeded - every holder is confirmed "
                "and the vault holds the new value - but a key credarr minted "
                "in an earlier run still authenticates. Delete it from "
                "Jellyfin's dashboard.",
            )
        done = []
        if doomed:
            done.append(f"revoked {len(doomed)} previous key(s)")
        if strays:
            done.append(f"swept {len(strays)} stray key(s) left by "
                        "interrupted runs")
        return f"{step.target}: " + " and ".join(done)

    def _grafana_account(self, service: str, token: str) -> tuple[str, str]:
        """The service account a Grafana token belongs to, by reading it.

        Measured on 12.1.1: `/api/user` for a token answers `login` as
        `sa-<org>-<name>` (its `id` is 0, not the account id), and
        `/api/serviceaccounts/search` answers the account row. Token names are
        unique per organisation, so the account id is what addresses one.

        Always called with a token: the mint authenticates with the credential
        being rotated, the revoke with the one it minted.
        """
        bearer = {"key": f"Bearer {token}", "auth_header": "Authorization"}
        status, me = self._call(
            self._ctx.host, service, "GET", "/api/user",
            transport=self._ctx.transport, **bearer,
        )
        login = str(me.get("login") or "") if isinstance(me, dict) else ""
        if status != 200 or not login:
            raise RotationError(
                f"{service}: the token for this call is not live (HTTP {status})",
                hint="a rotation authenticates with the credential being "
                "rotated. If the predecessor was already deleted, its "
                "replacement is the value this run minted; restore it and "
                "re-run.",
            )
        if not login.startswith("sa-"):
            raise RotationError(
                f"{service}: /api/user answered {login!r}, not a service-account "
                "login",
                hint="a rotation requires a service-account token; a personal "
                "API key or a browser session is a different credential",
            )
        parts = login.split("-", 2)
        if len(parts) != 3 or not parts[2]:
            raise RotationError(
                f"{service}: the token's login {login!r} does not name a "
                "service account"
            )
        name = parts[2]
        query = urllib.parse.urlencode({"query": name, "perpage": 100})
        status, found = self._call(
            self._ctx.host, service, "GET",
            f"/api/serviceaccounts/search?{query}",
            transport=self._ctx.transport, **bearer,
        )
        accounts = found.get("serviceAccounts") if isinstance(found, dict) else None
        match = next(
            (
                row for row in accounts or []
                if isinstance(row, dict) and row.get("name") == name and row.get("id")
            ),
            None,
        )
        if status == 403:
            raise RotationError(
                f"{service}: the service account {name!r} cannot manage tokens "
                "(HTTP 403)",
                hint="creating a token needs `serviceaccounts:write`, which "
                "Grafana grants to the account's Admin role; a Viewer account "
                "cannot rotate its own token",
            )
        if status != 200 or match is None:
            raise RotationError(
                f"{service}: could not find the service account {name!r} "
                f"(HTTP {status})",
                hint="creating a token needs `serviceaccounts:write`, which "
                "Grafana grants to the account's Admin role; a Viewer account "
                "cannot rotate its own token",
            )
        return str(match["id"]), name
    def _mint_authorizer(self, service: str) -> tuple[str | None, str]:
        """The value that authorises this credential's mint and revoke.

        A credential rotates itself unless it declares `write.mint_with`, in
        which case the named credential's stored value is the rotator. That is
        what lets a least-privilege key - one that cannot mint anything itself -
        be rotated by the admin key that holds `apikeys:*`. Returns the value
        and the rotator's name ("" for self-rotation).
        """
        declared = str(self._ctx.credential.write.get("mint_with") or "")
        if not declared:
            return self._ctx.vault_value, ""
        rotator = self._ctx.mint_values.get(declared)
        if rotator is None:
            raise RotationError(
                f"{service}: write.mint_with names {declared!r}, which has no "
                "stored value in this run",
                hint="store that credential, or declare it in the same "
                "manifest, before rotating this one. Nothing has changed.",
            )
        return rotator.reveal(), declared

    @staticmethod
    def _match_unique(
        service: str, rows: list[dict], field: str, value: str
    ) -> dict | None:
        """The single row whose `field` equals `value`; many matches fail closed.

        Reissue mints identify their row from the credential itself (Arcane's
        `keyPrefix`, Gitea's `token_last_eight`). More than one match means a
        malformed listing, and guessing would delete the wrong credential.
        """
        matches = [row for row in rows if str(row.get(field) or "") == value]
        if len(matches) > 1:
            raise RotationError(
                f"{service}: more than one row carries the {field} for this "
                "credential",
                hint="refusing to guess which row is the live one. Nothing has "
                "been changed.",
            )
        return matches[0] if matches else None
    def _gitea_basic(self, service: str) -> tuple[str, str]:
        """The username and password that manage this credential's tokens.

        Gitea's token routes are Basic-only (`reqBasicOrRevProxyAuth` upstream;
        measured on 1.27.2, where a `write:user` token answers 401), so a token
        cannot rotate itself. `write.mint_with` names the credential holding
        the password and `write.username` names the user.
        """
        username = str(self._ctx.credential.write.get("username") or "")
        password, rotator = self._mint_authorizer(service)
        if not username or password is None or not rotator:
            raise RotationError(
                f"{service}: the token routes need Basic auth; declare "
                "write.username and write.mint_with",
                hint="a Gitea token cannot mint or delete tokens. Nothing has "
                "changed.",
            )
        return username, password

    @staticmethod
    def _basic_header(username: str, password: str) -> str:
        raw = f"{username}:{password}".encode()
        return "Basic " + base64.b64encode(raw).decode()
    def _old_credential_dead(self, service: str, old: str) -> bool:
        """Whether the issuer proves the old value revoked: an answered 401.

        Deliberately not `_authenticate`'s verdict alone: that maps 403 to
        "dead", and an access layer refusing the route produces the same 403
        for a live key. The rule is the one `_confirm_old_key_dead` already
        applies - a bare 403 is not a credential verdict.
        """
        verdict, detail = self._authenticate(service, old)
        return verdict == "dead" and detail == "HTTP 401"

    # -- reissue mints: create alongside, revoke last -------------------------
    #
    # Grafana, Arcane and Gitea generate the secret and return it once. The
    # per-service differences live in `REISSUERS`; this code owns the ordering
    # that makes the shape safe: never revoke before the replacement exists,
    # never call a revoke clean without an answered 401, and never guess which
    # row belongs to a credential.

    def _reissue_call_kwargs(
        self, service: str, spec: Reissue, *, prefer_minted: bool = False
    ) -> tuple[dict, str, str]:
        """(call kwargs, raw authoriser value, rotator name) for the API calls.

        `prefer_minted` is the revoke's rule: with no declared rotator, the
        replacement this run minted authorises the list and delete, because it
        is certainly live while the predecessor may already be unreachable.
        """
        if spec.auth == "basic":
            username, password = self._gitea_basic(service)
            return (
                {"key": self._basic_header(username, password),
                 "auth_header": "Authorization"},
                password,
                "",
            )
        if (
            prefer_minted
            and self._ctx.minted is not None
            and not str(self._ctx.credential.write.get("mint_with") or "")
        ):
            return self._auth_kwargs(service, self._ctx.minted.reveal()), \
                self._ctx.minted.reveal(), ""
        value, rotator = self._mint_authorizer(service)
        return self._auth_kwargs(service, value), value or "", rotator

    def _reissue_path(self, spec: Reissue, path: str, *, account: str = "",
                      username: str = "", row_id: str = "") -> str:
        return path.format(
            account=urllib.parse.quote(account),
            username=urllib.parse.quote(username),
            id=urllib.parse.quote(row_id),
        )

    def _reissue_account(self, service: str, spec: Reissue, raw: str) -> str:
        if spec.list_kind != "grafana_account":
            return ""
        account_id, _name = self._grafana_account(service, raw)
        return account_id

    def _reissue_rows(self, service: str, spec: Reissue, kwargs: dict,
                      *, account: str, username: str) -> list[dict]:
        """Every row the service lists, paged to the end.

        Pagination shapes differ (Arcane: start/limit plus totalItems; Gitea:
        page/limit plus a short page); both stop only on a short page or the
        advertised total, so a sweep cannot silently miss a stray on page 2.
        """
        rows: list[dict] = []
        path = self._reissue_path(spec, spec.list_path, account=account,
                                  username=username)
        if spec.list_kind == "grafana_account":
            status, body = self._call(
                self._ctx.host, service, "GET", path,
                transport=self._ctx.transport, **kwargs,
            )
            if status in (401, 403):
                raise RotationError(
                    f"{service}: the authorising credential was refused "
                    f"(HTTP {status})",
                    hint="creating a token needs `serviceaccounts:write`, "
                    "which Grafana grants to the account's Admin role. "
                    "Nothing has changed.",
                )
            if status != 200 or not isinstance(body, list):
                raise RotationError(
                    f"{service}: could not list rows (HTTP {status})",
                    hint="nothing has been written to a holder.",
                )
            return [item for item in body if isinstance(item, dict)]
        if spec.page_style == "page_limit":
            page, limit = 1, 50
            while True:
                query = urllib.parse.urlencode({"page": page, "limit": limit})
                status, body = self._call(
                    self._ctx.host, service, "GET", f"{path}?{query}",
                    transport=self._ctx.transport, **kwargs,
                )
                if status in (401, 403):
                    raise RotationError(
                        f"{service}: Basic auth was refused (HTTP {status})",
                        hint=spec.hints.get(
                            "auth",
                            "check the credential this rotation authenticates "
                            "with. Nothing has changed.",
                        ),
                    )
                if status != 200 or not isinstance(body, list):
                    raise RotationError(
                        f"{service}: could not list rows (HTTP {status})",
                        hint="nothing has been written to a holder.",
                    )
                rows.extend(item for item in body if isinstance(item, dict))
                if len(body) < limit:
                    break
                page += 1
            return rows

        start, limit = 0, 100
        while True:
            query = urllib.parse.urlencode(
                {"start": start, "limit": limit, "search": ""}
            )
            status, body = self._call(
                self._ctx.host, service, "GET", f"{path}?{query}",
                transport=self._ctx.transport, **kwargs,
            )
            if status in (401, 403):
                raise RotationError(
                    f"{service}: the authorising credential cannot list rows "
                    f"(HTTP {status})",
                    hint=spec.hints.get(
                        "auth",
                        "check the credential this rotation authenticates "
                        "with. Nothing has changed.",
                    ),
                )
            if status != 200 or not isinstance(body, dict):
                raise RotationError(
                    f"{service}: could not list rows (HTTP {status})",
                    hint="nothing has been written to a holder.",
                )
            page_rows = body.get(spec.data_field) if spec.data_field else body
            if not isinstance(page_rows, list):
                raise RotationError(f"{service}: the row list was not a list")
            rows.extend(item for item in page_rows if isinstance(item, dict))
            total = (
                (body.get("pagination") or {}).get("totalItems")
                if spec.data_field else None
            )
            if (
                len(page_rows) < limit
                or not isinstance(total, int)
                or len(rows) >= total
            ):
                break
            start += limit
        return rows

    def _reissue_current(self, service: str, spec: Reissue, rows: list[dict],
                         value: str, write: Mapping) -> dict | None:
        """The row a value belongs to, by fingerprint or by declared name."""
        if spec.locate == "declared_name":
            declared = str(write.get(spec.declared_name_field) or "")
            mapped = [
                dict(row, _match=re.sub(r"\.credarr\.\d+$", "",
                                        str(row.get("name") or "")))
                for row in rows
            ]
            return self._match_unique(service, mapped, "_match", declared)
        fingerprint = (
            value[:spec.fingerprint_len]
            if spec.fingerprint_from == "prefix"
            else value[-spec.fingerprint_len:]
        )
        return self._match_unique(
            service, rows, spec.fingerprint_field, fingerprint
        )

    def _reissue_values(self, spec: Reissue, current: dict,
                        write: Mapping) -> list:
        """The grants to re-issue: the manifest's list, else the row's own."""
        if spec.declared_values_field:
            declared = write.get(spec.declared_values_field)
            if isinstance(declared, list) and declared:
                return list(declared)
            copied = current.get(spec.declared_values_field)
            return [item for item in copied or [] if item]
        return []

    def _reissue_body(self, spec: Reissue, name: str, values: list) -> dict:
        body: dict = {"name": name}
        if spec.body == "permissions":
            body["permissions"] = [
                item if isinstance(item, dict) else {"permission": str(item)}
                for item in values
            ]
        elif spec.body == "scopes":
            body["scopes"] = [str(item) for item in values]
        return body

    def _reissue_mint(self, step: Step) -> str:
        """Create the replacement alongside the old value; revoke is later."""
        service = step.target
        spec = REISSUERS[service]
        if self._ctx.minted is not None:
            return f"{service}: secret already minted by this run; nothing to redo"
        expected = self._ctx.vault_value
        if expected is None:
            raise RotationError(
                f"{service}: refusing to mint without a stored value",
                hint="the old value identifies the row to replace. Nothing "
                "has changed.",
            )
        write = self._ctx.credential.write
        kwargs, raw, rotator = self._reissue_call_kwargs(service, spec)
        account = self._reissue_account(service, spec, raw)
        username = str(write.get("username") or "")
        rows = self._reissue_rows(
            service, spec, kwargs, account=account, username=username
        )
        current = self._reissue_current(service, spec, rows, expected, write)
        if current is None:
            raise RotationError(
                f"{service}: the stored value is not in the {spec.list_label}",
                hint="the value may belong to another account, or the listing "
                "may be incomplete. Nothing has changed.",
            )
        if any(current.get(field) for field in spec.protected_fields):
            raise RotationError(
                f"{service}: {current.get('name')!r} is protected from "
                f"deletion ({spec.protected_hint})",
                hint="this row cannot be replaced by create-and-revoke; "
                "nothing has changed.",
            )
        name = str(current.get("name") or "")
        if not name:
            raise RotationError(
                f"{service}: the row carries no name to reuse",
                hint="nothing has changed; the name is how the replacement is "
                "identified for the revoke.",
            )
        base = re.sub(r"\.credarr\.\d+$", "", name)
        declared_name = (
            str(write.get(spec.declared_name_field) or "")
            if spec.declared_name_field else ""
        )
        if declared_name and declared_name != base:
            raise RotationError(
                f"{service}: write.{spec.declared_name_field} is "
                f"{declared_name!r} but the credential in use is named "
                f"{base!r}",
                hint="the declaration and the service disagree; fix one before "
                "rotating. Nothing has changed.",
            )
        new_name = (
            f"{base}.credarr.{int(time.time())}"
            if spec.name_style == "namespace" else name
        )
        values = self._reissue_values(spec, current, write)
        if spec.body in ("permissions", "scopes") and not values:
            raise RotationError(
                f"{service}: the row carries no grants to re-issue",
                hint=f"declare write.{spec.declared_values_field}, or give the "
                "row at least one grant in the service. Nothing has changed.",
            )
        status, created = self._call(
            self._ctx.host, service, "POST",
            self._reissue_path(spec, spec.create_path, account=account,
                               username=username),
            body=self._reissue_body(spec, new_name, values),
            transport=self._ctx.transport, **kwargs,
        )
        if status == 403:
            raise RotationError(
                f"{service} refused to create the replacement (HTTP 403): "
                f"{spec.create_denied}",
                hint="nothing has been written to a holder.",
            )
        if not 200 <= status < 300 or not isinstance(created, dict):
            raise RotationError(
                f"{service} refused to create the replacement (HTTP {status})",
                hint="nothing has been written to a holder; the previous value "
                "is still live.",
            )
        data = created.get(spec.data_field) if spec.data_field else created
        if not isinstance(data, dict):
            raise RotationError(
                f"{service}: the create response carried no object"
            )
        key = data.get(spec.response_key_field)
        handle = data.get("id")
        if (
            not isinstance(key, str)
            or not handle
            or (spec.value_prefix and not key.startswith(spec.value_prefix))
            or (spec.value_len and len(key) != spec.value_len)
        ):
            raise RotationError(
                f"{service}: the create answered without a usable secret",
                hint="the service returns the secret once. Do not mint again; "
                "check the service's list and delete the row this run could "
                "not capture.",
            )
        self._ctx.minted = Secret(key)
        self._ctx.minted_service = service
        self._ctx.minted_handle = str(handle)
        verdict, detail = self._authenticate_settled(service, key)
        if verdict != "live":
            raise RotationError(
                f"{service}: the new value does not authenticate ({detail})",
                hint="the row exists but was not accepted; nothing has been "
                "written to a holder. The previous value is still live.",
            )
        return (
            f"minted a replacement for {base!r}"
            + (f" as {new_name!r}" if new_name != base else "")
            + (f" using rotator {rotator!r}" if rotator else "")
            + "; the previous value is revoked after the holders are confirmed"
        )

    def _reissue_revoke(self, step: Step) -> str:
        """Delete the predecessor and any credarr-named stray, then prove it."""
        service = step.target
        spec = REISSUERS[service]
        minted = self._ctx.minted
        handle = self._ctx.minted_handle
        if minted is None or not handle:
            raise RotationError(
                f"{service}: nothing was minted by this run, so the revoke has "
                "no credential to authenticate with",
                hint="the revoke follows the mint by construction; re-run the "
                "rotation to resume from where it stopped",
            )
        kwargs, raw, _rotator = self._reissue_call_kwargs(
            service, spec, prefer_minted=True
        )
        account = self._reissue_account(service, spec, raw)
        username = str(self._ctx.credential.write.get("username") or "")
        rows = self._reissue_rows(
            service, spec, kwargs, account=account, username=username
        )
        current = next(
            (row for row in rows if str(row.get("id")) == handle), None
        )
        if current is None:
            raise RotationError(
                f"{service}: the replacement is not in the {spec.list_label}",
                hint="every holder is confirmed and the vault holds the new "
                "value, but the replacement cannot be found to identify the "
                "predecessor. Check the service's list before deleting "
                "anything by hand.",
            )
        name = str(current.get("name") or "")
        base = (
            re.sub(r"\.credarr\.\d+$", "", name)
            if spec.sweep == "namespace" else name
        )
        doomed = [
            row for row in rows
            if str(row.get("id")) != handle
            and not any(row.get(field) for field in spec.protected_fields)
            and (
                row.get("name") == base
                or (
                    spec.sweep == "namespace"
                    and str(row.get("name") or "").startswith(
                        base + ".credarr."
                    )
                )
            )
        ]
        failures: list[str] = []
        for row in doomed:
            status, _ = self._call(
                self._ctx.host, service, "DELETE",
                self._reissue_path(spec, spec.delete_path, account=account,
                                   username=username, row_id=str(row.get("id"))),
                transport=self._ctx.transport, **kwargs,
            )
            if status not in (200, 204):
                failures.append(str(row.get("name") or row.get("id")))
        if failures:
            raise RotationError(
                f"{service}: {len(failures)} row(s) could not be revoked "
                f"({', '.join(failures)})",
                hint="the rotation itself succeeded - every holder is "
                "confirmed and the vault holds the new value - but a row this "
                "run was to delete is still live. Delete it in the service.",
            )
        old = self._ctx.vault_value
        if old is not None and not self._old_credential_dead(service, old):
            raise RotationError(
                f"{service}: the previous value is still live after the revoke",
                hint="every holder is confirmed and the vault holds the new "
                "value, but the old value was not refused with a 401. Delete "
                "it in the service and align the declaration with the service.",
            )
        if not doomed:
            return f"{service}: no previous value left to revoke"
        return f"{service}: revoked {len(doomed)} previous value(s)"

    def _gitea_hook(self, service: str) -> tuple[dict, str, str]:
        """(hook row, token, repo) for the credential's declared hook.

        Measured on 1.27.2: the hook list exposes each hook's `config.url` but
        never the secret, so the URL is the identity; a hook update needs a
        token with `write:repository`, named through `write.mint_with`.
        """
        write = self._ctx.credential.write
        repo = str(write.get("repo") or "")
        hook_url = str(write.get("hook_url") or "")
        token, rotator = self._mint_authorizer(service)
        if not rotator:
            raise RotationError(
                f"{service}: write.mint_with is required; the hook API needs a "
                "Gitea token with write:repository",
                hint="nothing has changed.",
            )
        auth = self._auth_kwargs(service, token)
        status, hooks = self._call(
            self._ctx.host, service, "GET", f"/repos/{repo}/hooks",
            transport=self._ctx.transport, **auth,
        )
        if status in (401, 403):
            raise RotationError(
                f"{service}: the token cannot list hooks on {repo!r} "
                f"(HTTP {status})",
                hint="write.mint_with must name a Gitea token with "
                "write:repository. Nothing has changed.",
            )
        if status != 200 or not isinstance(hooks, list):
            raise RotationError(
                f"{service}: could not list hooks on {repo!r} (HTTP {status})",
                hint="nothing has been written.",
            )
        mapped = [
            dict(row, _match=str((row.get("config") or {}).get("url") or ""))
            for row in hooks if isinstance(row, dict)
        ]
        hook = self._match_unique(service, mapped, "_match", hook_url)
        if hook is None:
            raise RotationError(
                f"{service}: no hook on {repo!r} points at {hook_url!r}",
                hint="write.hook_url must match the hook's configured URL; "
                "nothing has been written.",
            )
        return hook, token or "", repo

    def _mint_gitea_hook(self, step: Step) -> str:
        """Write a chosen secret into a Gitea webhook.

        Measured on 1.27.2: `PATCH /repos/{owner}/{repo}/hooks/{id}` accepts a
        partial `config.secret` update and answers 200; no read returns the
        secret; `POST .../hooks/{id}/tests` answers 204. The value is chosen
        here and written over the API, so the previous secret dies at that
        write and the proof is the accepted write plus the attempted delivery,
        not an equality read.
        """
        service = step.target
        if self._ctx.minted is not None:
            return f"{service}: secret already minted by this run; nothing to redo"
        hook, token, repo = self._gitea_hook(service)
        hook_id = hook.get("id")
        if not hook_id:
            raise RotationError(
                f"{service}: the hook row carries no id", hint="nothing has changed."
            )
        value = token_hex(16)
        auth = self._auth_kwargs(service, token)
        status, _ = self._call(
            self._ctx.host, service, "PATCH",
            f"/repos/{repo}/hooks/{hook_id}",
            body={"config": {"secret": value}},
            transport=self._ctx.transport, **auth,
        )
        if status != 200:
            raise RotationError(
                f"{service}: the hook update was refused (HTTP {status})",
                hint="nothing has been written; the previous secret is still "
                "in place.",
            )
        status, _ = self._call(
            self._ctx.host, service, "POST",
            f"/repos/{repo}/hooks/{hook_id}/tests",
            transport=self._ctx.transport, **auth,
        )
        delivered = (
            "a test delivery was accepted"
            if status == 204
            else f"the test delivery answered HTTP {status}"
        )
        self._ctx.minted = Secret(value)
        self._ctx.minted_service = service
        self._ctx.minted_handle = str(hook_id)
        hook_url = str(self._ctx.credential.write.get("hook_url"))
        return (
            f"wrote a new secret to the hook at {hook_url!r} ({delivered}); "
            "the service never returns the secret, so the write is proven and "
            "the receiver's copy is a deploy-time step"
        )

    def _restart_service(self, service: str, *, key: str) -> None:
        """Ask a Servarr app to restart itself over its own API.

        The request is authenticated with the still-live key. A dropped
        connection is treated as accepted because Servarr commonly closes the
        socket while it restarts; the key-transition poll that follows is what
        proves whether the restart actually happened.
        """
        try:
            status, _ = self._call(
                self._ctx.host, service, "POST", "/system/restart",
                key=key, transport=self._ctx.transport,
            )
        except ConfigError as exc:
            raise RotationError(
                f"{service}: no URL is configured for the service-native "
                f"restart ({exc})",
                hint="declare the service URL. The "
                "new key is parked in the pending store; nothing has been "
                "written to any holder.",
            ) from exc
        except TransportError as exc:
            log_line(
                f"      {service}: the restart request dropped the connection "
                f"({type(exc).__name__}); waiting for the service to come back"
            )
            return
        if status not in (200, 201, 202):
            raise RotationError(
                f"{service} refused the service-native restart (HTTP {status})",
                hint="the backup/restore path needs POST /api/.../system/restart "
                "and a supervisor that starts the app again after that call "
                "(for example the LinuxServer s6 image). The new key is parked "
                "in the pending store. The restored config is staged: starting "
                "the service now activates the parked key while every holder "
                "still uses the old, now-revoked one. Re-run as soon as it is "
                "reachable and do not use the service until holders are written.",
            )

    def _await_restart_key(
        self, service: str, *, old_key: str, new_key: str
    ) -> None:
        """Wait until the new key is accepted and the old key is not still live.

        This is the restart's proof. A 200 from the restart route only says the
        request was queued; the service can still be running the old config, or
        never come back. A 403 or unknown old-key answer proceeds without
        exercise-only proof; only HTTP 401 sets `old_key_dead`. The pending
        value is parked before the restore, so a timeout is a recoverable stall
        rather than a lost credential.
        """
        deadline = time.time() + READINESS_TIMEOUT
        old_verdict = new_verdict = "unknown"
        last_old = last_new = "no attempt completed"
        while time.time() < deadline:
            old_verdict, last_old = self._authenticate(service, old_key)
            new_verdict, last_new = self._authenticate(service, new_key)
            if new_verdict == "live" and old_verdict != "live":
                # Only a 401 proves the old key is dead. A 403 or an unknown
                # answer is not evidence that it is still live, so the run
                # proceeds - but it must not use exercise-only confirmation.
                self._ctx.old_key_dead = last_old == "HTTP 401"
                if not self._ctx.old_key_dead:
                    log_line(
                        f"      {service}: the old key was {last_old}, which "
                        "is not proof it is dead; exercise-only confirmation "
                        "will not be claimed"
                    )
                return
            time.sleep(READINESS_INTERVAL)
        if new_verdict != "live":
            raise RotationError(
                f"{service}: the service-native restart did not make the "
                f"restored key usable within {READINESS_TIMEOUT}s "
                f"(old key: {last_old}; new key: {last_new})",
                hint="the new key is parked in the pending store. The service "
                "may have no supervisor to start it again after "
                "POST /api/.../system/restart; start it manually and re-run. "
                "If the service pins its API key in an environment variable "
                "(for example AUTH__APIKEY), a config restore cannot change "
                "it; use write.manual_mint or unset it. Do not mint again.",
            )
        raise RotationError(
            f"{service}: the service accepted the restored key but the old "
            f"key still authenticates after {READINESS_TIMEOUT}s",
            hint="the restart did not take effect, or the service is accepting "
            "both keys. The new key is parked in the pending store; restart "
            "the service and re-run. Nothing has been written to any holder.",
        )

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

    def _auth_kwargs(self, service: str, key: str | None) -> dict:
        """How a service's own key is carried on an API call.

        qBittorrent 5.3 accepts only `Authorization: Bearer`; `X-API-Key` is a
        later addition, so the header used for every other service is a 403
        here. Seerr reads `X-API-Key`. Everything else keeps the Servarr
        default.
        """
        if service == "qbittorrent":
            return {
                "key": f"Bearer {key}" if key is not None else None,
                "auth_header": "Authorization",
            }
        if service == "seerr":
            return {"key": key, "auth_header": "X-API-Key"}
        if service == "grafana":
            # A Grafana Bearer token; Basic admin auth is a different credential
            # and is not used by this build.
            return {
                "key": f"Bearer {key}" if key is not None else None,
                "auth_header": "Authorization",
            }
        if service == "gitea":
            # Gitea tokens travel as `Authorization: token <value>`; the token
            # routes themselves are Basic-only and are called with an explicit
            # header by the mint.
            return {
                "key": f"token {key}" if key is not None else None,
                "auth_header": "Authorization",
            }
        return {"key": key}

    def _authenticate(self, service: str, key: str | None) -> tuple[str, str]:
        """Ask the service whether `key` is a live credential.

        Three verdicts, not two, because the middle one matters:

        live     the service accepted it.
        dead     the service refused it (401/403).
        unknown  the service could not be reached.

        `unknown` is deliberately distinct from `dead`. A service that is down
        says nothing about whether a key works, and collapsing the two is how a
        recovery ends up acting on a credential that was fine.
        """
        path = readiness_path(service)
        try:
            status, _ = self._call(
                self._ctx.host, service, "GET", path,
                transport=self._ctx.transport,
                **self._auth_kwargs(service, key),
            )
        except TransportError as exc:
            # A transport failure is an answer of its own: the service could
            # not be reached. Without this it escaped, which made the
            # "unknown" verdict unreachable and the retry that depends on it
            # dead code - a service restarting moments ago looked like a hard
            # failure rather than a temporary one.
            return "unknown", f"{type(exc).__name__}: {exc}"
        if 200 <= status < 300:
            return "live", f"HTTP {status}"
        if status in (401, 403):
            if service == "gitea" and status == 403:
                # Gitea validates the token first and answers 403 when the
                # token lacks the route's scope (measured on 1.27.2: a
                # write:repository token gets 403 on /user). The token is live;
                # the route is out of scope. A revoked token answers 401, so
                # the revoke check below still sees dead.
                return "live", "HTTP 403"
            return "dead", f"HTTP {status}"
        return "unknown", f"HTTP {status}"

    def _authenticate_settled(self, service: str, key: str) -> tuple[str, str]:
        """Authenticate, tolerating a service that is still coming up.

        Only transport failures are retried. A 401 is an answer, and repeating
        a question that has already been answered only delays the report.
        """
        deadline = time.time() + self._ctx.settle_timeout
        verdict, detail = self._authenticate(service, key)
        while verdict == "unknown" and time.time() < deadline:
            time.sleep(READINESS_INTERVAL)
            verdict, detail = self._authenticate(service, key)
        return verdict, detail

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
            verdict, detail = self._authenticate(service, old_key)
            # A bare 403 is not a credential verdict: an access layer refusing
            # the status route for a live key produces exactly that. The
            # measured *arr answer for a revoked key is 401, qBittorrent's is
            # 403 on its version route, and Seerr's is 403 on /auth/me (the
            # route this check calls), so only those enable the exercise-only
            # reading.
            dead_detail = (
                "HTTP 403" if service in ("qbittorrent", "seerr") else "HTTP 401"
            )
            if verdict == "dead" and detail == dead_detail:
                self._ctx.old_key_dead = True
                return
            if time.time() >= deadline:
                self._ctx.old_key_dead = False
                if verdict == "dead":
                    state = f"was refused with {detail}, which is ambiguous"
                elif verdict == "live":
                    state = "still accepts it"
                else:
                    state = f"was {verdict}"
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

_CONFIG_XML_KEY = re.compile(r"<ApiKey>([^<]*)</ApiKey>")

# The fields a stock Servarr writes into config.xml. The tuple is
# (XML element, /config/host JSON key, kind). ApiKey is set separately: the
# whole point of the reconstructed path is to install a key credarr chose.
_CONFIG_XML_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("BindAddress", "bindAddress", "str"),
    ("Port", "port", "int"),
    ("SslPort", "sslPort", "int"),
    ("EnableSsl", "enableSsl", "bool"),
    ("LaunchBrowser", "launchBrowser", "bool"),
    ("AuthenticationMethod", "authenticationMethod", "enum"),
    ("AuthenticationRequired", "authenticationRequired", "enum"),
    ("AllowedHosts", "allowedHosts", "str"),
    ("AnalyticsEnabled", "analyticsEnabled", "bool"),
    ("LogLevel", "logLevel", "str"),
    ("LogSizeLimit", "logSizeLimit", "int"),
    ("ConsoleLogLevel", "consoleLogLevel", "str"),
    ("Branch", "branch", "str"),
    ("SslCertPath", "sslCertPath", "str"),
    ("SslCertPassword", "sslCertPassword", "str"),
    ("UrlBase", "urlBase", "str"),
    ("TrustedNetworks", "trustedNetworks", "str"),
    ("InstanceName", "instanceName", "str"),
    ("UpdateAutomatically", "updateAutomatically", "bool"),
    ("UpdateMechanism", "updateMechanism", "enum"),
    ("UpdateScriptPath", "updateScriptPath", "str"),
    ("ProxyEnabled", "proxyEnabled", "bool"),
    ("ProxyType", "proxyType", "enum"),
    ("ProxyHostname", "proxyHostname", "str"),
    ("ProxyPort", "proxyPort", "int"),
    ("ProxyUsername", "proxyUsername", "str"),
    ("ProxyPassword", "proxyPassword", "str"),
    ("ProxyBypassFilter", "proxyBypassFilter", "str"),
    ("ProxyBypassLocalAddresses", "proxyBypassLocalAddresses", "bool"),
    ("CertificateValidation", "certificateValidation", "enum"),
    ("BackupFolder", "backupFolder", "str"),
    ("BackupInterval", "backupInterval", "int"),
    ("BackupRetention", "backupRetention", "int"),
    ("TrustCgnatIpAddresses", "trustCgnatIpAddresses", "bool"),
)

# A rebuilt config must carry the settings that decide whether the service is
# reachable and whether the UI still authenticates. The API exposes all of these
# on the pinned builds; a missing one is a refusal, not a default.
_CRITICAL_CONFIG_FIELDS = frozenset({
    "bindAddress",
    "port",
    "sslPort",
    "enableSsl",
    "authenticationMethod",
    "authenticationRequired",
    "urlBase",
    "sslCertPath",
    "sslCertPassword",
    "instanceName",
    "updateMechanism",
    "logLevel",
    "branch",
})


def _config_enum(value: object) -> str:
    """API camelCase enum -> the PascalCase config.xml spelling."""
    text = str(value or "")
    if not text:
        return ""
    if text == "disabledForLocalAddresses":
        return "DisabledForLocalAddresses"
    return text[0].upper() + text[1:]


def _config_value(value: object, kind: str) -> str:
    if kind == "bool":
        if isinstance(value, str):
            return "True" if value.lower() in ("true", "1", "yes") else "False"
        return "True" if value else "False"
    if kind == "int":
        try:
            return str(int(value))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return ""
    if kind == "enum":
        return _config_enum(value)
    return "" if value is None else str(value)


def _config_xml_from_host(host_config: Mapping[str, object], *, api_key: str) -> str:
    """Build the config.xml a stock Servarr would have, with a chosen key.

    Every field comes from `GET /config/host`; the user account and password are
    not part of config.xml and are not touched. The critical fields are
    mandatory, because omitting one would reset it on the service's next start
    and could make the UI or the listener unreachable.
    """
    missing = sorted(
        key for key in _CRITICAL_CONFIG_FIELDS
        if host_config.get(key) is None
    )
    if missing:
        raise RotationError(
            "config/host did not expose the fields a rebuilt config.xml needs: "
            + ", ".join(missing),
            hint="the reconstructed config would reset those settings; nothing "
            "has been restored. Use write.ui_password or write.manual_mint.",
        )

    lines = ["<Config>"]
    for element, key, kind in _CONFIG_XML_FIELDS:
        if key not in host_config:
            continue
        value = host_config.get(key)
        if value is None:
            continue
        lines.append(
            f"  <{element}>{_xml_escape(_config_value(value, kind))}</{element}>"
        )
    lines.append(f"  <ApiKey>{_xml_escape(api_key)}</ApiKey>")
    lines.append("</Config>")
    return "\n".join(lines) + "\n"


def _config_xml_api_key(text: str) -> str | None:
    """The ApiKey element's value, from config.xml text or a backup's copy."""
    match = _CONFIG_XML_KEY.search(text)
    return match.group(1) if match and match.group(1) else None


def _replace_config_xml_key(text: str, new_key: str) -> str:
    """Replace exactly one ApiKey, preserving every other config byte."""
    replaced, count = _CONFIG_XML_KEY.subn(
        lambda _match: f"<ApiKey>{new_key}</ApiKey>",
        text,
        count=1,
    )
    if count != 1:
        raise RotationError(
            "config.xml has no ApiKey element to replace",
            hint="the service's backup did not contain the config shape this "
            "build measured. Nothing has been restored.",
        )
    return replaced


def _backup_route_problem(
    service: str, probe: tuple[int, object] | None
) -> str | None:
    """Why the backup download route cannot be used, or None when it can.

    Servarr's backup download is a web route (`/backup/manual/...`), not an API
    route: with the service's UI authentication on it answers 302 to `/login`
    even while `/api/<version>` accepts the key, and the mint cannot read
    config.xml. Measured on Sonarr 4.0.20.3014, Radarr 6.4.4.10685 and Prowlarr
    2.6.5.5623 (2026-10-22): auth off answers 404 for a name that cannot exist,
    auth on answers 302. `probe` is None when the host could not be reached,
    which the caller already reports.
    """
    if probe is None:
        return None
    status, body = probe
    if status == 404:
        return None
    if status in (301, 302, 303, 307, 308):
        return (
            f"{service}: the backup download is behind the service's web UI "
            f"login (HTTP {status}); its API key cannot open that route, so "
            "the backup/restore mint cannot read config.xml. Declare "
            "write.ui_password with the service's UI credential, use "
            "write.manual_mint and supply the key rotated in the service's UI, "
            "or set Authentication to 'Disabled for Local Addresses' for "
            "credarr's address (or None) and retry"
        )
    if status == 200:
        page = "<html" in str(body).lower() or "<!doctype" in str(body).lower()
        return (
            f"{service}: the backup download answered 200 for a name that "
            "cannot exist"
            + (" (a login page)" if page else "")
            + "; a proxy may be answering instead of the service, so the "
            "backup/restore mint cannot read config.xml"
        )
    return (
        f"{service}: the backup download answered HTTP {status}; the "
        "backup/restore mint needs that route to read config.xml"
    )


def _servarr_backup_config(
    host: HostConfig, service: str, *,
    key: str,
    transport: Transport,
    auth_headers: Mapping[str, str] | None = None,
    timeout: int | None = None,
) -> tuple[str, str]:
    """Create a manual backup, read its config.xml, and delete the backup.

    The archive is downloaded and read inside the host's Python process. Only
    the small config.xml crosses the transport; the database copy never has a
    name on disk (it lives in an unlinked temporary file) and the service-side
    backup is deleted before returning. A failure to delete is a failure: the
    archive contains the still-live key, so restoring over it would leave a
    second copy behind for no reason.
    """
    version = api_version(service)
    root = host.url(service).rstrip("/")
    api = f"{root}/api/{version}"
    script = (
        "import base64,json,sys,tempfile,time,urllib.error,urllib.request,zipfile\n"
        f"MAX_CONTROL_BYTES = {MAX_JSON_RESPONSE_BYTES}\n"
        f"MAX_BACKUP_BYTES = {MAX_BACKUP_BYTES}\n"
        f"MAX_CONFIG_XML_BYTES = {MAX_CONFIG_XML_BYTES}\n"
        f"api = {api!r}\n"
        f"root = {root!r}\n"
        f"key = {key!r}\n"
        f"auth_headers = {dict(auth_headers or {})!r}\n"
        "def fail(stage, name=''):\n"
        "    sys.stdout.write(json.dumps({'error': stage, 'backup': name}))\n"
        "    sys.exit(0)\n"
        "def call(url, method='GET', body=None):\n"
        "    data = json.dumps(body).encode() if body is not None else None\n"
        "    request = urllib.request.Request(url, data=data, method=method)\n"
        "    request.add_header('X-Api-Key', key)\n"
        "    if body is not None:\n"
        "        request.add_header('Content-Type', 'application/json')\n"
        "    try:\n"
        "        with urllib.request.urlopen(request, timeout=60) as response:\n"
        "            raw = response.read(MAX_CONTROL_BYTES + 1)\n"
        "            if len(raw) > MAX_CONTROL_BYTES:\n"
        "                return -2, b''\n"
        "            return response.status, raw\n"
        "    except urllib.error.HTTPError as exc:\n"
        "        return exc.code, b''\n"
        "    except Exception:\n"
        "        return -1, b''\n"
        "status, raw = call(api + '/system/backup')\n"
        "if status != 200:\n"
        "    fail('list HTTP ' + str(status))\n"
        "try:\n"
        "    before = {item.get('id') for item in json.loads(raw) "
        "if isinstance(item, dict)}\n"
        "except Exception:\n"
        "    fail('list was not a backup array')\n"
        "status, raw = call(api + '/command', 'POST', {'name': 'Backup'})\n"
        "if status not in (200, 201, 202):\n"
        "    fail('backup command HTTP ' + str(status))\n"
        "command_id = None\n"
        "try:\n"
        "    command = json.loads(raw)\n"
        "    if isinstance(command, dict) and isinstance(command.get('id'), int):\n"
        "        command_id = command['id']\n"
        "except Exception:\n"
        "    pass\n"
        "if command_id is None:\n"
        "    fail('backup command returned no id; refusing to guess when the "
        "archive is ready')\n"
        "deadline = time.time() + 180\n"
        "while time.time() < deadline:\n"
        "    status, raw = call(api + '/command/' + str(command_id))\n"
        "    if status == 200:\n"
        "        try:\n"
        "            command = json.loads(raw)\n"
        "        except Exception:\n"
        "            command = {}\n"
        "        state = str(command.get('status') or '')\n"
        "        if state == 'completed':\n"
        "            break\n"
        "        if state in ('failed', 'aborted', 'cancelled', 'orphaned'):\n"
        "            detail = str(command.get('message') or "
        "command.get('exception') or 'no detail')\n"
        "            fail('the backup command ' + state + ' (' + detail + ')')\n"
        "    time.sleep(1)\n"
        "else:\n"
        "    fail('the backup command did not finish within 180s')\n"
        "deadline = time.time() + 120\n"
        "new = None\n"
        "while time.time() < deadline:\n"
        "    status, raw = call(api + '/system/backup')\n"
        "    if status == 200:\n"
        "        try:\n"
        "            rows = json.loads(raw)\n"
        "        except Exception:\n"
        "            rows = []\n"
        "        for item in rows:\n"
        "            if not isinstance(item, dict):\n"
        "                continue\n"
        "            path = str(item.get('path') or '')\n"
        "            if item.get('id') not in before and "
        "path.startswith('/backup/manual/'):\n"
        "                new = item\n"
        "                break\n"
        "        if new is not None:\n"
        "            break\n"
        "    time.sleep(1)\n"
        "if new is None:\n"
        "    fail('no manual backup appeared within 120s')\n"
        "path = str(new.get('path') or '')\n"
        "name = str(new.get('name') or '')\n"
        "if not path.startswith('/backup/manual/'):\n"
        "    fail('backup path was not a manual backup', name)\n"
        "xml = None\n"
        "stage = None\n"
        "class _NoRedirect(urllib.request.HTTPRedirectHandler):\n"
        "    def redirect_request(self, *args, **kwargs):\n"
        "        return None\n"
        "def open_backup():\n"
        "    for attempt in range(3):\n"
        "        try:\n"
        "            request = urllib.request.Request(root + path, method='GET')\n"
        "            request.add_header('X-Api-Key', key)\n"
        "            for _header, _value in auth_headers.items():\n"
        "                request.add_header(_header, _value)\n"
        "            opener = urllib.request.build_opener(_NoRedirect)\n"
        "            return opener.open(request, timeout=60)\n"
        "        except urllib.error.HTTPError as exc:\n"
        "            if 500 <= exc.code < 600 and attempt < 2:\n"
        "                time.sleep(1)\n"
        "                continue\n"
        "            raise\n"
        "try:\n"
        "    with open_backup() as response:\n"
        "        with tempfile.TemporaryFile() as temp:\n"
        "            total = 0\n"
        "            while True:\n"
        "                chunk = response.read(1024 * 1024)\n"
        "                if not chunk:\n"
        "                    break\n"
        "                total += len(chunk)\n"
        "                if total > MAX_BACKUP_BYTES:\n"
        "                    stage = ('the backup exceeded ' "
        "+ str(MAX_BACKUP_BYTES) + ' bytes')\n"
        "                    break\n"
        "                temp.write(chunk)\n"
        "            if stage is None:\n"
        "                temp.seek(0)\n"
        "                try:\n"
        "                    with zipfile.ZipFile(temp) as archive:\n"
        "                        names = [n for n in archive.namelist() "
        "if n.rsplit('/', 1)[-1].lower() == 'config.xml']\n"
        "                        if not names:\n"
        "                            stage = 'the backup contains no config.xml'\n"
        "                        elif len(names) > 1:\n"
        "                            stage = ('the backup contains ' "
        "+ str(len(names)) + ' config.xml files')\n"
        "                        else:\n"
        "                            with archive.open(names[0]) as member:\n"
        "                                xml = member.read(MAX_CONFIG_XML_BYTES + 1)\n"
        "                            if len(xml) > MAX_CONFIG_XML_BYTES:\n"
        "                                xml = None\n"
        "                                stage = ('config.xml exceeded ' "
        "+ str(MAX_CONFIG_XML_BYTES) + ' bytes')\n"
        "                except Exception:\n"
        "                    stage = 'the downloaded backup was not a readable ZIP'\n"
        "except urllib.error.HTTPError as exc:\n"
        "    if 300 <= exc.code < 400:\n"
        "        stage = ('the backup download redirected to the service "
        "login (HTTP ' + str(exc.code) + ')')\n"
        "    else:\n"
        "        stage = 'the backup download returned HTTP ' + str(exc.code)\n"
        "except Exception:\n"
        "    stage = 'the backup download could not be read'\n"
        "status, _ = call(api + '/system/backup/' + str(new.get('id')), "
        "'DELETE')\n"
        "if status not in (200, 204):\n"
        "    fail('could not delete the temporary backup', name)\n"
        "if stage is not None or xml is None:\n"
        "    fail(stage or 'could not read config.xml from the backup', name)\n"
        "sys.stdout.write(json.dumps({'xml': base64.b64encode(xml).decode(), "
        "'backup': name}))\n"
    )
    out = transport.run_python(script, timeout=timeout or CONFIG_READ_TIMEOUT)
    try:
        payload = json.loads(out)
    except json.JSONDecodeError:
        raise RotationError(
            f"{service}: the backup probe returned no usable result",
            hint="nothing has been restored. Check that the service's backup "
            "API is reachable and authenticates with its stored key.",
        ) from None
    if not isinstance(payload, dict):
        raise RotationError(f"{service}: the backup probe returned no usable result")
    if payload.get("error"):
        error = str(payload.get("error") or "")
        backup = str(payload.get("backup") or "")
        if "redirected to the service login" in error:
            # Measured on Sonarr 4.0.20, Radarr 6.4.4 and Prowlarr 2.6.5: with
            # the service's UI authentication on, the backup download is a web
            # route behind the login even while /api/<version> accepts the key.
            # With a declared UI credential the login was attempted; a redirect
            # here means it did not open the route.
            hint = (
                "the service's backup download is behind its web UI login, and "
                "the API key cannot open that route. "
                + (
                    "The UI login with write.ui_password did not open it; check "
                    "that stored password. "
                    if auth_headers
                    else "If write.ui_password is declared, check its stored "
                    "value; otherwise declare it, use write.manual_mint and "
                    "supply the key rotated in the service's UI. "
                )
                + "Setting the service's Authentication to 'Disabled for Local "
                "Addresses' for credarr's address (or None) also works. Nothing "
                "has been restored."
            )
        elif "delete" in error:
            hint = (
                "the temporary backup could not be deleted and still contains the "
                "current key. Delete it from the service's Backups page before "
                "retrying; nothing has been restored."
            )
        elif "did not finish within" in error or "returned no id" in error:
            hint = (
                "nothing has been restored. The backup command may still be "
                "running and may leave a completed backup on the service; check "
                "its Backups page before retrying."
            )
        else:
            hint = (
                "nothing has been restored. Check the service's backup API "
                "and its stored key."
            )
        raise RotationError(
            f"{service}: could not read config.xml over the backup API "
            f"({error}"
            + (f"; backup {backup!r}" if backup else "")
            + ")",
            hint=hint,
        )
    encoded = payload.get("xml")
    if not isinstance(encoded, str):
        raise RotationError(f"{service}: the backup probe returned no config.xml")
    try:
        xml = base64.b64decode(encoded).decode("utf-8-sig")
    except (ValueError, UnicodeDecodeError):
        raise RotationError(
            f"{service}: the backup's config.xml was not readable UTF-8"
        ) from None
    if len(xml) > 2_000_000:
        raise RotationError(f"{service}: the backup's config.xml is unexpectedly large")
    return xml, str(payload.get("backup") or "")


def _servarr_restore_config(
    host: HostConfig, service: str, *,
    key: str,
    xml: bytes,
    transport: Transport,
    timeout: int | None = None,
) -> tuple[int, object]:
    """Upload one config.xml inside a config-only ZIP.

    The extension matters. The pinned Sonarr build accepts `.xml` at the
    upload route but its backup service has no XML branch in this release: an
    `.xml` upload is treated as a **database** and moved over `sonarr.db`.
    A ZIP containing only `config.xml` is the shape the backup service
    actually understands, and it restores only that file.

    The archive is built here, so no host file is involved. The upload is the
    only mutation; the caller persists the chosen key before calling this.
    """
    version = api_version(service)
    url = f"{host.url(service).rstrip('/')}/api/{version}/system/backup/restore/upload"
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("config.xml", xml)
    boundary = f"----credarr{token_hex(12)}"
    head = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; '
        'filename="credarr-config.zip"\r\n'
        "Content-Type: application/zip\r\n\r\n"
    ).encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    body = head + archive.getvalue() + tail
    script = (
        "import sys,urllib.error,urllib.request\n"
        f"url = {url!r}\n"
        f"key = {key!r}\n"
        f"body = {body!r}\n"
        f"boundary = {boundary!r}\n"
        "class _NoRedirect(urllib.request.HTTPRedirectHandler):\n"
        "    def redirect_request(self, *args, **kwargs):\n"
        "        return None\n"
        "request = urllib.request.Request(url, data=body, method='POST')\n"
        "request.add_header('X-Api-Key', key)\n"
        "request.add_header('Content-Type', "
        "'multipart/form-data; boundary=' + boundary)\n"
        "try:\n"
        "    opener = urllib.request.build_opener(_NoRedirect)\n"
        "    with opener.open(request, timeout=120) as response:\n"
        "        sys.stdout.write('\\x00' + str(response.status))\n"
        "except urllib.error.HTTPError as exc:\n"
        "    sys.stdout.write('\\x00' + str(exc.code))\n"
        "except Exception:\n"
        "    sys.stdout.write('\\x00-1')\n"
    )
    out = transport.run_python(script, timeout=timeout or CONFIG_RESTORE_TIMEOUT)
    parts = out.split("\x00")
    if len(parts) < 2:
        raise RotationError(f"{service}: the restore probe returned no status")
    try:
        status = int(parts[1])
    except ValueError:
        raise RotationError(
            f"{service}: the restore probe returned no usable status"
        ) from None
    if status == -1:
        raise TransportError(
            f"{service}: the config restore could not be reached",
            hint="the restore may or may not have been applied; the pending "
            "value is parked, so re-running re-reads the service state and "
            "resumes from whatever the service actually holds.",
        )
    return status, None


def _servarr_login(
    host: HostConfig, service: str, *,
    username: str,
    password: str,
    transport: Transport,
    timeout: int | None = None,
) -> dict[str, str]:
    """Log in to a Servarr web UI and return the session header.

    Forms auth is a web route, not an API one: `POST /login` with a form body
    answers 302 with the auth cookie on success, and 302 to
    `loginFailed=true` without one on failure. The cookie is sent only to the
    backup download, which is the route the API key cannot open.
    """
    url = f"{host.url(service).rstrip('/')}/login"
    body = urllib.parse.urlencode({"username": username, "password": password})
    script = (
        "import json,sys,urllib.error,urllib.request\n"
        f"url = {url!r}\n"
        f"body = {body!r}\n"
        "class _NoRedirect(urllib.request.HTTPRedirectHandler):\n"
        "    def redirect_request(self, *args, **kwargs):\n"
        "        return None\n"
        "request = urllib.request.Request(url, data=body.encode(), "
        "method='POST')\n"
        "request.add_header('Content-Type', "
        "'application/x-www-form-urlencoded')\n"
        "try:\n"
        "    opener = urllib.request.build_opener(_NoRedirect)\n"
        "    with opener.open(request, timeout=60) as response:\n"
        "        sys.stdout.write(json.dumps({'error': 'the login answered "
        "HTTP ' + str(response.status) + ' instead of a redirect'}))\n"
        "except urllib.error.HTTPError as exc:\n"
        "    location = exc.headers.get('Location') or ''\n"
        "    cookies = exc.headers.get_all('Set-Cookie') or []\n"
        "    pairs = [raw.split(';', 1)[0] for raw in cookies]\n"
        "    pairs = [pair for pair in pairs if '=' in pair]\n"
        "    if 'loginFailed' in location or not pairs:\n"
        "        sys.stdout.write(json.dumps({'error': 'the service refused "
        "the UI login'}))\n"
        "    else:\n"
        "        sys.stdout.write(json.dumps({'cookie': '; '.join(pairs)}))\n"
        "except Exception:\n"
        "    sys.stdout.write(json.dumps({'error': 'the login request could "
        "not be read'}))\n"
    )
    out = transport.run_python(script, timeout=timeout or API_TIMEOUT)
    try:
        payload = json.loads(out)
    except json.JSONDecodeError:
        raise RotationError(
            f"{service}: the UI login returned no usable result",
            hint="check that the service's web UI is reachable; nothing has "
            "been changed.",
        ) from None
    if not isinstance(payload, dict) or payload.get("error"):
        error = (
            str(payload.get("error")) if isinstance(payload, dict)
            else "no usable result"
        )
        raise RotationError(
            f"{service}: the UI login failed ({error})",
            hint="check the stored password named by write.ui_password and "
            "that the service uses Forms or Basic authentication. Nothing has "
            "been changed.",
        )
    cookie = payload.get("cookie")
    if not isinstance(cookie, str) or not cookie:
        raise RotationError(
            f"{service}: the UI login returned no session cookie",
            hint="nothing has been changed.",
        )
    return {"Cookie": cookie}


def _servarr_call(
    host: HostConfig, service: str, method: str, path: str,
    *, body: dict | None = None, key: str | None = None,
    transport: Transport | None = None, auth_header: str = "X-Api-Key",
    auth_transport: str = "header", timeout: int | None = None,
    versioned: bool = True, follow_redirects: bool = True,
    extra_headers: Mapping[str, str] | None = None,
) -> tuple[int, object]:
    """Call a Servarr API, from the host that owns it.

    Routed through the transport rather than made locally, because the config's
    URLs are loopback addresses - they mean "from the machine running the
    service". Making them from the controller would either fail outright or,
    worse, silently reach a different service on the same port.

    `versioned=False` addresses a web route (`/backup/manual/...`), which has no
    `/api/<version>` prefix. `follow_redirects=False` lets a caller see a 302 for
    what it is: Servarr's web routes answer the login redirect when the service's
    UI authentication is on, and following it would turn a capability failure
    into a 200 login page.

    A connection failure is a reportable condition, not a traceback: it is
    exactly what the preflight exists to find. `timeout` bounds the transport
    call itself, so a caller answering a human (the Services view) can cap a
    blackholed host instead of inheriting the deployment's command timeout.
    """
    version = api_version(service)
    # Jellyfin has no `/api/{version}` prefix - its routes are `/Auth/Keys` -
    # so a versioned prefix would turn a real 404 into the wrong kind of one.
    prefix = "" if version is None or not versioned else f"/api/{version}"
    url = f"{host.url(service).rstrip('/')}{prefix}{path}"
    if not url.startswith(("http://", "https://")):
        raise RotationError(
            f"refusing to call {url!r}: not an http(s) URL",
            hint="the base URL comes from the host config; a non-http scheme "
            "here means the config is wrong",
        )
    # What an error message may quote. Captured before the credential is
    # embedded below, so no failure message has to rely on scrub() to be safe.
    # The probe still carries the key: that is what query auth needs.
    display_url = url
    if key is not None and auth_transport == "query":
        # Done here rather than in the generated script: it is string building the
        # caller can read, and it keeps `__import__` out of the probe.
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}ApiKey={urllib.parse.quote(str(key))}"

    if follow_redirects:
        # The default path is the plain urlopen the wire-body tests patch;
        # only a caller that must see a redirect builds an opener.
        opener_line = ""
        open_line = (
            f"    with urllib.request.urlopen(request, timeout={API_TIMEOUT}) "
            "as response:\n"
        )
    else:
        opener_line = (
            "class _NoRedirect(urllib.request.HTTPRedirectHandler):\n"
            "    def redirect_request(self, *args, **kwargs):\n"
            "        return None\n"
            "opener = urllib.request.build_opener(_NoRedirect)\n"
        )
        open_line = f"    with opener.open(request, timeout={API_TIMEOUT}) as response:\n"

    if transport is None:
        raise RotationError(
            f"cannot reach {service}: no transport configured",
            hint="the executor must route API calls through the host transport",
        )

    # The key goes in the script's source, not its argv: argv is world-readable
    # through /proc on the host running the probe.
    #
    # `auth_header` is a literal from this module and never manifest input.
    # Servarr reads `X-Api-Key`; Seerr reads `X-API-Key`. HTTP treats header
    # names case-insensitively, but each application compares its own spelling,
    # so the wrong one is a 403 that reads as a refusal rather than a typo.
    script = (
        "import json, sys, urllib.error, urllib.request\n"
        f"method = {method!r}\n"
        f"url = {url!r}\n"
        f"MAX_RESPONSE_BYTES = {MAX_JSON_RESPONSE_BYTES}\n"
        # The body crosses as JSON text and is decoded on the far side: one encode
        # here, one decode there. Embedding the Python object instead would
        # make repr() emit `nan` and `inf` for non-finite floats, which are
        # bare names and would abort the call with a NameError instead of
        # sending what the service actually said.
        f"body = json.loads({json.dumps(body)!r})\n"
        f"key = {key!r}\n"
        f"auth_header = {auth_header!r}\n"
        f"user_agent = {USER_AGENT!r}\n"
        f"extra_headers = {dict(extra_headers or {})!r}\n"
        "data = json.dumps(body).encode() if body is not None else None\n"
        "request = urllib.request.Request(url, data=data, method=method)\n"
        "request.add_header('Content-Type', 'application/json')\n"
        "request.add_header('User-Agent', user_agent)\n"
        "if key is not None:\n"
        "    request.add_header(auth_header, key)\n"
        "for _header, _value in extra_headers.items():\n"
        "    request.add_header(_header, _value)\n"
        + opener_line
        + "try:\n"
        + open_line
        + "        raw = response.read(MAX_RESPONSE_BYTES + 1)\n"
        "        if len(raw) > MAX_RESPONSE_BYTES:\n"
        "            sys.stdout.write('\\x00-2\\x00')\n"
        "        else:\n"
        "            sys.stdout.write('\\x00' + str(response.status) + '\\x00' + raw.decode())\n"
        "except urllib.error.HTTPError as exc:\n"
        # The body is the only thing distinguishing 'this service refused' from
        # 'this request was malformed', and a 400 on a rotation write is
        # otherwise indistinguishable from a refusal. Only the diagnostic fields
        # are lifted out: an error response can echo the submitted resource,
        # and that resource carries the credential being propagated.
        "    import json as _json\n"
        "    try:\n"
        "        _b = json.loads(exc.read().decode()[:8192])\n"
        "        if isinstance(_b, dict):\n"
        "            _d = {k: _b[k] for k in "
        "('title', 'errors', 'detail', 'message', 'errorMessage') if k in _b}\n"
        "        elif isinstance(_b, list):\n"
        # The holder test routes answer with a list of problem objects; lifting
        # only `errorMessage` keeps the submitted resource out of the note.
        "            _d = [{'errorMessage': _x['errorMessage']} for _x in _b "
        "if isinstance(_x, dict) and isinstance(_x.get('errorMessage'), str)]\n"
        "        else:\n"
        "            _d = None\n"
        "        _note = _json.dumps(_d)[:600] if _d else ''\n"
        "    except Exception:\n"
        "        _note = ''\n"
        "    sys.stdout.write('\\x00' + str(exc.code) + '\\x00' + _note)\n"
        "except Exception as exc:\n"
        "    sys.stdout.write('\\x00-1\\x00' + type(exc).__name__)\n"
    )
    out = transport.run_python(script, timeout=timeout)
    parts = out.split("\x00")
    if len(parts) < 3:
        raise RotationError(
            f"{service}: the probe returned no usable response",
            hint="a probe that cannot reach the service must say so rather "
            "than look like a refusal",
        )
    status_text, payload = parts[1], parts[2]
    try:
        status = int(status_text)
    except ValueError:
        raise RotationError(f"{service}: unusable status {status_text!r}") from None

    if status == -2:
        raise RotationError(
            f"{service}: the response from {display_url} exceeded "
            f"{MAX_JSON_RESPONSE_BYTES} bytes; refusing to buffer it",
            hint="the route is meant to answer with a small JSON document. "
            "Nothing has been written; check for a proxy or service fault "
            "that is streaming a non-JSON body.",
        )
    if status == -1:
        raise TransportError(
            f"{service} at {display_url} could not be reached: {payload}",
            hint="this is what the preflight is for; nothing has been changed",
        )
    if not payload.strip():
        return status, None
    try:
        return status, json.loads(payload)
    except json.JSONDecodeError:
        return status, payload


def exercise_holder(
    host: HostConfig,
    transport: Transport,
    holder: Holder,
    resource: dict,
    service_key: str,
    *,
    call: Callable[..., tuple[int, object]] = _servarr_call,
    timeout: float = EXERCISE_TIMEOUT,
    secrets: tuple[str | None, ...] = (),
) -> tuple[str, str]:
    """Ask a holder's own test route to use the stored value.

    The resource is the row exactly as the pre-write GET returned it, mask
    intact. Servarr treats the mask as "unchanged" and substitutes the stored
    value, so the test exercises what the running process holds. Shared by the
    rotation executor and the standing audit; both must ask the same question.

    An indexer test can fail after authentication - a disabled Prowlarr indexer
    (410) or an empty category result. That is content state, not a credential
    rejection, so it counts as accepted while retaining the service's words.
    """
    if not holder.test_path:
        return "unsupported", ""
    try:
        status, payload = call(
            host, holder.system, "POST",
            "/" + holder.test_path.lstrip("/"),
            body=resource, key=service_key, transport=transport,
            auth_header=holder.auth_header_name,
            auth_transport=holder.auth_transport,
            timeout=timeout,
        )
    except (TransportError, RotationError) as exc:
        return "inconclusive", scrub_url_credentials(
            scrub(str(exc), service_key, *secrets)
        )
    detail = scrub_url_credentials(
        scrub(_explain(payload), service_key, *secrets)
    )
    if 200 <= status < 300:
        return "accepted", detail
    if _names_credential(detail):
        return "rejected", detail
    if holder.slot == "indexers" and (
        status == 410 or _indexer_functional_failure(detail)
    ):
        # The key reached the upstream and authenticated; the indexer itself is
        # disabled or returned no category results. That is not a credential
        # rejection, so it must not make the copy unverifiable.
        return "accepted", detail
    return "inconclusive", detail or f"HTTP {status}"
