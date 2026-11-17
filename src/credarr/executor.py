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
import contextlib
import copy
import re
import time
import urllib.parse
from collections.abc import Callable, Mapping
from secrets import token_hex

from .errors import ConfigError, CredctlError, RotationError, TransportError
from .executor_steps.record import RecordSteps
from .executor_steps.revoke import RevokeSteps
from .executor_steps.support import (
    _CRITICAL_CONFIG_FIELDS,
    MAX_WRITE_INTERVAL,
    MINT_VALUE_ATTEMPTS,
    READINESS_INTERVAL,
    READINESS_TIMEOUT,
    SEERR_READBACK_INTERVAL,
    SEERR_READBACK_TIMEOUT,
    WRITE_ATTEMPTS,
    _backup_route_problem,
    _config_xml_api_key,
    _config_xml_from_host,
    _explain,
    _replace_config_xml_key,
    _servarr_backup_config,
    _servarr_call,
    _servarr_login,
    _servarr_restore_config,
    classify_refusal,
    log_line,
)
from .executor_steps.types import (
    BackupProbe,
    ExecutionResult,
    HolderOutcome,
    RotationContext,
    Verdict,
)
from .executor_steps.verify import VerifySteps
from .model import split_target
from .pending import PendingSecrets
from .redact import Secret, scrub
from .rotate import RotationPlan, Step, StepKind, service_for
from .writers import (
    MINT_SOURCES,
    REISSUERS,
    Holder,
    MintSource,
    Reissue,
    auth_kwargs,
    auth_shape,
    holder_for,
    known_systems,
    readiness_path,
)


class Executor(VerifySteps, RecordSteps, RevokeSteps):
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
        self._preflight_mints(services, problems)
        self._preflight_holders(plan, problems)
        self._preflight_notes(problems)
        self._preflight_unfinished(problems)
        return problems

    def _preflight_mints(self, services: set[str], problems: list[str]) -> None:
        # 1. The mint target must answer, and must have a key to authenticate
        #    the command with. A service that is down or has no key cannot be
        #    rotated at all.
        for service in sorted(services):
            self._preflight_mint(service, problems)

    def _preflight_mint(self, service: str, problems: list[str]) -> None:
        answered = self._checked_call(
            service, "GET", readiness_path(service),
            **auth_kwargs(service, self._ctx.vault_value))
        if answered is None:
            return
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
            return
        if source is not None and source.mechanism == "reset":
            if self._reconstruct_config():
                problems.extend(self._reconstruct_preflight(service))
                return
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
                return
            problems.extend(self._backup_preflight(service)[0])
            return
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
            self._preflight_reissue(service, source, problems)
            return
        if write_mechanism == "gitea_hook_secret":
            try:
                self._gitea_hook(service)
            except (RotationError, TransportError) as exc:
                problems.append(str(exc))
            return
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

    def _preflight_reissue(
        self, service: str, source: MintSource, problems: list[str]
    ) -> None:
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
        return

    def _preflight_holders(self, plan: RotationPlan, problems: list[str]) -> None:
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
                self._preflight_qui(step, system, described, problems)
                continue
            if described.write == "bazarr_api":
                self._preflight_bazarr(step, system, described, problems)
                continue
            if described.write == "seerr_api":
                self._preflight_seerr(step, system, described, problems)
                continue
            self._preflight_holder(step, system, described, problems)

    def _preflight_qui(
        self, step: Step, system: str, described: Holder, problems: list[str]
    ) -> None:
        row = self._row_name(step.target)
        if row is None:
            problems.append(
                f"{step.target}: does not name which qui instance to "
                "write"
            )
            return
        try:
            api_key = self._service_key(system)
        except (ConfigError, TransportError) as exc:
            problems.append(
                f"{step.target}: cannot read {system}'s own API key "
                f"({exc}), so no write to it could be authenticated"
            )
            return
        if not api_key:
            problems.append(
                f"{step.target}: no API key for {system!r}; store "
                f"{system}'s own key before rotating a credential it holds"
            )
            return
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
            return
        status, body = answered
        if status != 200 or not isinstance(body, list):
            problems.append(
                f"{step.target}: cannot list {system} instances "
                f"(HTTP {status}); the write would fail after the key "
                "was already revoked"
            )
            return
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
        return

    def _preflight_bazarr(
        self, step: Step, system: str, described: Holder, problems: list[str]
    ) -> None:
        row = self._row_name(step.target)
        if row is None:
            problems.append(
                f"{step.target}: does not name which Bazarr settings "
                "section to write"
            )
            return
        try:
            api_key = self._service_key(system)
        except (ConfigError, TransportError) as exc:
            problems.append(
                f"{step.target}: cannot read {system}'s own API key "
                f"({exc}), so no write to it could be authenticated"
            )
            return
        if not api_key:
            problems.append(
                f"{step.target}: no API key for {system!r}; store "
                f"{system}'s own key before rotating a credential it holds"
            )
            return
        answered = self._checked_call(
            system, "GET", described.readback_path, key=api_key,
            auth_header=described.auth_header_name,
            auth_transport=described.auth_transport,
        )
        if answered is None:
            problems.append(
                f"{step.target}: {system} was unreachable during "
                "preflight; the write could not be confirmed"
            )
            return
        status, body = answered
        if status != 200 or not isinstance(body, dict):
            problems.append(
                f"{step.target}: cannot read {system}'s settings "
                f"(HTTP {status}); the write would fail after the key "
                "was already revoked"
            )
        elif not isinstance(body.get(row), dict) or not body[row].get(
            described.readback_field
        ):
            problems.append(
                f"{step.target}: {system} has no {row} settings entry "
                "holding a key, so a rotation would revoke the old key "
                "and update nothing"
            )
        return

    def _preflight_seerr(
        self, step: Step, system: str, described: Holder, problems: list[str]
    ) -> None:
        row = self._row_name(step.target)
        if row is None:
            problems.append(
                f"{step.target}: does not name which holder to write"
            )
            return
        try:
            url = self._ctx.host.url(system)
        except ConfigError:
            problems.append(f"{step.target}: no URL for {system}")
            return
        if url is None:
            problems.append(f"{step.target}: no URL for {system}")
            return
        try:
            api_key = self._service_key(system)
        except (ConfigError, TransportError) as exc:
            problems.append(
                f"{step.target}: cannot read {system}'s own API key "
                f"({exc}), so no write to it could be authenticated"
            )
            return
        if not api_key:
            problems.append(
                f"{step.target}: no API key for {system!r}; store "
                f"{system}'s own key before rotating a credential it holds"
            )
            return
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
        return

    def _preflight_holder(
        self, step: Step, system: str, described: Holder, problems: list[str]
    ) -> None:
        try:
            self._resolve_field(step)
        except RotationError as exc:
            problems.append(str(exc))
            return
        try:
            holder_key = self._service_key(system)
        except TransportError as exc:
            problems.append(
                f"{step.target}: cannot read the holder's own API key "
                f"({exc}), so no write to it could be authenticated"
            )
            return
        if not holder_key:
            problems.append(
                f"{step.target}: no API key for the holder service "
                f"{system!r}; nothing could authenticate a write to it"
            )
            return
        answered = self._checked_call(system, "GET", f"/{described.api_path}",
                                      key=holder_key)
        if answered is None:
            return
        status, rows = answered
        if status != 200 or not isinstance(rows, list):
            problems.append(
                f"{step.target}: cannot list rows (HTTP {status}); the "
                f"write would fail after the key was already revoked"
            )
            return
        try:
            selected = self._select_rows(step.target, rows)
        except RotationError as exc:
            problems.append(str(exc))
            return
        if not selected:
            problems.append(
                f"{step.target}: no rows to update, so a rotation would "
                f"change nothing while still invalidating the old key"
            )

    def _preflight_notes(self, problems: list[str]) -> None:
        # Notes are appended, not pre-pended: they explain a check that could
        # not run, and they must not crowd out a reason that says why to stop.
        for note in self._ctx.preflight_notes:
            if note.split(":")[0] not in {p.split(":")[0] for p in problems}:
                problems.append(note)

    def _preflight_unfinished(self, problems: list[str]) -> None:
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
        name = plan.credential.name
        previous = self._ctx.journal.open_attempts().get(name)
        if previous is None:
            previous = self._ctx.journal.last_attempt(name)
        previous_outcome = (
            self._ctx.journal.attempt_outcome(previous)
            if previous is not None else None
        )
        reclaimed = self._ctx.journal.reclaim_stale(name)
        if self._ctx.take_over:
            # Under the lock, so the run that left these behind is not holding
            # it any more; the row still says who decided, because "presumed
            # dead" is a claim about a process, and this one is about a person.
            reclaimed += self._ctx.journal.take_over(name, self._ctx.actor)
        resume_recorded = self._resume_after_record(
            plan, previous, previous_outcome, reclaimed
        )
        if not resume_recorded:
            self._ctx.prior_mint_handle = self._adoptable_mint_handle(
                plan, previous, previous_outcome
            )
        if resume_recorded and previous is not None:
            # The dead attempt's holder rows are the evidence that the
            # propagation completed before RECORD; keep them for the report
            # instead of re-writing every holder just to lose their proof.
            self._ctx.holders = [
                HolderOutcome(row["target"], row["label"], row["outcome"],
                              row["detail"])
                for row in self._ctx.journal.holders(previous)
            ]
        record_ordinal = next(
            (index for index, step in enumerate(plan.steps)
             if step.kind is StepKind.RECORD),
            len(plan.steps),
        )
        result = ExecutionResult(credential=name, attempt=0)
        result.reclaimed = [(p.target, p.detail) for p in reclaimed]
        result.attempt = self._ctx.journal.begin(name)
        if self._ctx.on_started is not None:
            self._ctx.on_started(result.attempt)
        result.revokes_before_holders = plan.revokes_before_holders
        self._ctx.attempt = result.attempt

        for ordinal, step in enumerate(plan.steps):
            try:
                self._ctx.journal.step_started(
                    result.attempt, ordinal, step.kind.value, step.target,
                    step.detail,
                )
                if resume_recorded and ordinal < record_ordinal:
                    # Every step before RECORD completed in the dead attempt.
                    # The key is already on the service and the holders; doing
                    # them again would only add a second write.
                    detail = (
                        f"not re-run: attempt {previous} already completed "
                        "this step"
                    )
                else:
                    # The fence, inside the try so losing the lease is reported as a
                    # failed run rather than escaping as a traceback. If the lock was
                    # reclaimed while this run was slow, the work below belongs to
                    # whoever took over. Checking once per step is not atomic with
                    # the writes, but it stops a reclaimed process before its next
                    # write instead of letting it run to the end and report success
                    # for work that was overtaken.
                    if self._ctx.lease_check is not None:
                        self._ctx.lease_check()
                    self._ctx.current_ordinal = ordinal
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
                self._ctx.journal.step_finished(
                    result.attempt, ordinal, detail,
                    self._ctx.minted_handle if step.kind is StepKind.MINT else None,
                )
                result.failed = step.target
                result.detail = detail
                self._mark_unreached(plan, ordinal)
                # Holders live on the context; the result is what
                # the report reads. Copied on every exit path, because a
                # report rendering no holders is indistinguishable from a
                # rotation that touched none - the exact confusion this
                # per-holder reporting exists to remove. Written before the
                # attempt closes: a closed attempt accepts no new rows.
                result.holders = list(self._ctx.holders)
                self._journal_holders()
                self._ctx.journal.finish(result.attempt, "failed")
                return result

            self._ctx.journal.step_finished(
                result.attempt, ordinal, detail,
                self._ctx.minted_handle if step.kind is StepKind.MINT else None,
            )
            if step.kind is StepKind.MANUAL:
                result.manual.append(step.target)
            else:
                result.completed.append(step.target)
                if step.kind is StepKind.RECORD:
                    result.vault_written = True

        # The final fence. Without it a run that lost the lease after its last
        # step still called `finish('completed')` and reported success for work
        # another run may already own. The attempt is deliberately left open:
        # the owner that reclaimed it is the only run allowed to close it.
        try:
            if self._ctx.lease_check is not None:
                self._ctx.lease_check()
        except Exception as exc:
            detail = scrub(
                f"failed: {exc}", self._ctx.minted, self._ctx.vault_value
            )
            hint = getattr(exc, "hint", None)
            if hint:
                detail += "\n  " + scrub(
                    hint, self._ctx.minted, self._ctx.vault_value
                )
            result.failed = "the credential lease"
            result.detail = detail
            result.holders = list(self._ctx.holders)
            self._journal_holders()
            return result

        result.resumed = self._ctx.resumed
        # As the failure path does, so the record shows what the run achieved
        # and not only what it ran; INSERT OR REPLACE just rewrites what the
        # API path already journalled. Written before the attempt closes: a
        # closed attempt accepts no new rows.
        self._journal_holders()
        self._ctx.journal.finish(result.attempt, "completed")
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
        if mechanism == "sabnzbd_rotate":
            return self._mint_sabnzbd(step)
        if mechanism == "bazarr_rotate":
            return self._mint_bazarr(step)
        if mechanism == "regenerate":
            return self._mint_seerr(step)
        raise RotationError(
            f"{step.target}: no mint implementation for mechanism {mechanism!r}",
            hint="the mint source is registered, but nothing here can run it",
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
                verdict = self._authenticate_settled(
                    service, pending.reveal()
                )
                if verdict.state == "live":
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
                verdict = self._authenticate_settled(
                    service, pending.reveal()
                )
                if verdict.state == "live":
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
        old_verdict = self._authenticate_settled(service, expected)
        if old_verdict.state == "live":
            return [
                f"{service}: the stored key still authenticates; rotate the key "
                "in the service's own UI first, then supply the new one. Nothing "
                "has been changed."
            ]
        if old_verdict.state != "dead" or old_verdict.status != 401:
            return [
                f"{service}: could not prove the stored key is dead "
                f"({old_verdict.state}: {old_verdict.detail}). A Servarr refuses "
                "a revoked key with HTTP 401; anything else is ambiguous, so the "
                "manual mint will not write a holder. Nothing has been changed."
            ]
        new_verdict = self._authenticate_settled(service, provided)
        if new_verdict.state != "live":
            return [
                f"{service}: the supplied key does not authenticate "
                f"({new_verdict.state}: {new_verdict.detail}); copy the key the "
                "service shows after its regenerate, and supply that. Nothing "
                "has been changed."
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
                verdict = self._authenticate_settled(
                    service, parked.reveal()
                )
                if verdict.state != "dead":
                    raise RotationError(
                        f"{service}: a previous run parked a different key "
                        f"({verdict.state}: {verdict.detail}); the supplied key was not used",
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

        old_verdict = self._authenticate_settled(service, expected)
        if old_verdict.state == "unknown":
            raise RotationError(
                f"{service}: cannot ask whether the stored key is live "
                f"({old_verdict.detail})",
                hint="the backup/restore mint will not create a backup or restore "
                "a config until the current key is known to authenticate.",
            )

        if candidate is not None:
            candidate_verdict = self._authenticate_settled(
                service, candidate.reveal()
            )
        else:
            candidate_verdict = Verdict("absent", None, "no pending value")

        if old_verdict.state == "live" and candidate_verdict.state == "live":
            raise RotationError(
                f"{service}: both the stored key and the pending key "
                "authenticate",
                hint="the service could be mid-restart or an access layer may "
                "be accepting both. A restore now would make the state more "
                "ambiguous; wait for the service to settle and re-run.",
            )

        if candidate_verdict.state == "live":
            # The restore already happened and the service accepted the parked
            # value. Do not make another backup or write another config.
            self._ctx.minted = candidate
            self._ctx.minted_service = service
            self._ctx.resumed = True
            self._confirm_old_key_dead(service, expected)
            return "already-restored: continuing with the pending key"

        if old_verdict.state != "live":
            raise RotationError(
                f"{service}: neither the stored key nor the pending key is "
                f"confirmed live (stored: {old_verdict.detail}; pending: "
                f"{candidate_verdict.detail})",
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
        elif candidate_verdict.state != "dead":
            raise RotationError(
                f"{service}: the pending key could not be checked safely "
                f"({candidate_verdict.detail})",
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

        old_verdict = self._authenticate_settled(service, expected)
        if old_verdict.state == "unknown":
            raise RotationError(
                f"{service}: cannot ask whether the stored key is live "
                f"({old_verdict.detail})",
                hint="the rotate call would revoke it without proof that it "
                "is the current key. Nothing has been changed.",
            )
        if candidate is not None:
            candidate_verdict = self._authenticate_settled(
                service, candidate.reveal()
            )
        else:
            candidate_verdict = Verdict("absent", None, "no pending value")

        if old_verdict.state == "live" and candidate_verdict.state == "live":
            raise RotationError(
                f"{service}: both the stored key and the pending key "
                "authenticate",
                hint="qBittorrent has one API key. This is ambiguous, so "
                "rotating would invalidate whichever one is actually live. "
                "Wait for the service to settle and re-run.",
            )
        if candidate_verdict.state == "live":
            self._ctx.minted = candidate
            self._ctx.minted_service = service
            self._ctx.resumed = True
            self._confirm_old_key_dead(service, expected)
            return "already-rotated: continuing with the pending key"
        if old_verdict.state != "live":
            raise RotationError(
                f"{service}: neither the stored key nor the pending key is "
                f"confirmed live (stored: {old_verdict.detail}; pending: "
                f"{candidate_verdict.detail})",
                hint="a rotate needs one of them to authenticate. Nothing has "
                "been changed; restore access and re-run. If this run was "
                "started on the other surface (CLI or server), resume it "
                "there: the pending value lives beside that surface's store.",
            )
        if candidate is not None:
            if candidate_verdict.state != "dead":
                raise RotationError(
                    f"{service}: the pending key could not be checked safely "
                    f"({candidate_verdict.detail})",
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

        verdict = self._authenticate_settled(service, new_key)
        if verdict.state != "live":
            raise RotationError(
                f"{service}: the newly rotated key does not authenticate "
                f"({verdict.detail})",
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

    def _sabnzbd_reset(self, service: str, old_key: str) -> str:
        """Reset SABnzbd's key and return the new value; the response is it."""
        status, body = self._call(
            self._ctx.host, service, "GET",
            "/api?mode=config&name=set_apikey&output=json",
            key=old_key, auth_transport="query", query_key_name="apikey",
            transport=self._ctx.transport,
        )
        if status != 200 or not isinstance(body, dict):
            raise RotationError(
                f"{service} refused the key reset (HTTP {status})",
                hint="the reset is authenticated with the current key. If it "
                "answered 403 the stored key is no longer live; check the "
                "pending store before re-running.",
            )
        new_key = body.get("apikey")
        if (
            not isinstance(new_key, str)
            or len(new_key) != 32
            or any(char not in "0123456789abcdef" for char in new_key.lower())
        ):
            raise RotationError(
                f"{service}: the reset response carried no usable API key",
                hint="the current key is still live; nothing has been changed "
                "except SABnzbd's own config write. Re-run after checking the "
                "service.",
            )
        if new_key == old_key:
            raise RotationError(
                f"{service}: the reset was accepted but the key is unchanged",
                hint="the old key would not be proven dead, so nothing has "
                "been written to a holder.",
            )
        return new_key

    def _sabnzbd_restart(self, service: str, old_key: str, new_key: str) -> None:
        """Ask SABnzbd to restart with the new key, then settle on it."""
        status, _ = self._call(
            self._ctx.host, service, "GET", "/api?mode=restart&output=json",
            key=new_key, auth_transport="query", query_key_name="apikey",
            transport=self._ctx.transport,
        )
        if status == 200:
            return
        # The running process may still be serving the reset's old key on some
        # builds; one retry with the stored key is safer than a blind failure.
        retry_status, _ = self._call(
            self._ctx.host, service, "GET", "/api?mode=restart&output=json",
            key=old_key, auth_transport="query", query_key_name="apikey",
            transport=self._ctx.transport,
        )
        if retry_status != 200:
            raise RotationError(
                f"{service} would not restart (HTTP {status}, then "
                f"{retry_status})",
                hint="the new key is parked in the pending store. Restart "
                "SABnzbd manually and re-run; do not mint again.",
            )

    def _mint_sabnzbd(self, step: Step) -> str:
        """Reset SABnzbd's key, restart, and settle on the new value.

        Measured 2026-10-31 on 5.1.3: set_apikey returns the new key, but the
        old key may keep answering until the process restarts; after
        mode=restart the new key answers 200 and the old key 403 on mode=queue.
        The response is the only copy, so it is parked before the restart.
        """
        service = step.target
        if self._ctx.minted is not None:
            return f"{service}: key already minted by this run; nothing to redo"
        expected = self._ctx.vault_value
        if expected is None:
            raise RotationError(
                f"{service}: refusing to rotate with no stored value",
                hint="the reset authenticates with the current key. Store the "
                "credential and re-run; nothing has been changed.",
            )
        pending = self._ctx.pending
        if pending is None:
            raise RotationError(
                f"{service}: refusing to rotate with no pending-secret store",
                hint="the reset response is the only copy of the new key; a "
                "crash before the vault write would lose it. Nothing has been "
                "changed.",
            )
        name = self._ctx.credential.name
        candidate = pending.get(name)
        if candidate is not None and candidate.reveal() == expected:
            pending.clear(name)
            candidate = None

        old_verdict = self._authenticate_settled(service, expected)
        if old_verdict.state == "unknown":
            raise RotationError(
                f"{service}: cannot ask whether the stored key is live "
                f"({old_verdict.detail})",
                hint="nothing has been changed.",
            )
        if candidate is not None:
            candidate_verdict = self._authenticate_settled(
                service, candidate.reveal()
            )
        else:
            candidate_verdict = Verdict("absent", None, "no pending value")

        if old_verdict.state == "dead" and candidate_verdict.state == "live":
            self._ctx.minted = candidate
            self._ctx.minted_service = service
            self._ctx.resumed = True
            self._confirm_old_key_dead(service, expected)
            return "already-rotated: continuing with the pending key"
        if old_verdict.state == "dead":
            raise RotationError(
                f"{service}: neither the stored key nor the pending key is "
                f"confirmed live (stored: {old_verdict.detail}; pending: "
                f"{candidate_verdict.detail})",
                hint="the reset may have completed without a parked value. "
                "Restore access and reset the key again; nothing has been "
                "written to a holder.",
            )

        if candidate is None or candidate_verdict.state == "dead":
            new_key = self._sabnzbd_reset(service, expected)
            pending.set(name, Secret(new_key))
            candidate = Secret(new_key)
        elif candidate_verdict.state == "live":
            # The reset happened and the old key has not been restarted away
            # yet. The restart below settles it; this is the measured
            # pre-restart state, not an ambiguity.
            pass
        else:
            raise RotationError(
                f"{service}: the pending key could not be checked safely "
                f"({candidate_verdict.detail})",
                hint="nothing has been written to a holder.",
            )

        self._sabnzbd_restart(service, expected, candidate.reveal())
        self._await_restart_key(
            service, old_key=expected, new_key=candidate.reveal())
        self._confirm_old_key_dead(service, expected)
        self._ctx.minted = candidate
        self._ctx.minted_service = service
        self._ctx.resumed = False
        if self._ctx.old_key_dead:
            return "reset the key, restarted, and proved the old key dead"
        return (
            "reset the key and restarted; the old key was not proven dead, "
            "so exercise-only confirmation will not be claimed"
        )

    def _bazarr_choice(self) -> str:
        """A 32-hex key with at least one letter.

        Bazarr's dynaconf coerces an all-numeric form value to int and answers
        406. A 32-hex value is all digits about 3e-7 of the time; regenerate it
        rather than hand the form a value the validator will coerce.
        """
        while True:
            key = token_hex(16)
            if not key.isdigit():
                return key

    def _bazarr_write(self, service: str, expected: str, candidate: Secret,
                      pending: PendingSecrets, name: str) -> Secret:
        """Write the chosen value, re-choosing it if the service rejects it.

        A 406/422 is the form validator refusing the value, not the credential:
        the old key is still live and nothing was written. Re-choosing is safe
        only after re-proving that, so a write that did land despite its answer
        is never overwritten with a second value. Any other status is raised as
        before; an auth failure is never retried.
        """
        for attempt in range(1, MINT_VALUE_ATTEMPTS + 1):
            status, _ = self._call(
                self._ctx.host, service, "POST", "/api/system/settings",
                body={"settings-auth-apikey": candidate.reveal()},
                key=expected, auth_header="X-API-KEY",
                auth_transport="header",
                content_type="application/x-www-form-urlencoded",
                transport=self._ctx.transport,
            )
            if status in (200, 204):
                return candidate
            if status not in (406, 422):
                raise RotationError(
                    f"{service} refused the settings write (HTTP {status})",
                    hint="the old key is still live; nothing has been written "
                    "to a holder. Re-run once the settings API accepts the "
                    "write.",
                )
            still_live = self._authenticate_settled(service, expected)
            if still_live.state == "unknown":
                raise RotationError(
                    f"{service}: the settings write answered HTTP {status} but "
                    f"whether the stored key still authenticates could not be "
                    f"checked ({still_live.detail})",
                    hint="the chosen value is parked. Re-run once the service "
                    "answers; do not mint again until it does.",
                )
            if still_live.state != "live":
                raise RotationError(
                    f"{service}: the settings write answered HTTP {status} but "
                    f"the stored key no longer authenticates ({still_live.detail})",
                    hint="the value may have been applied despite the answer. "
                    "The chosen value is parked; re-run to resume it, or "
                    "restore access before minting again.",
                )
            if attempt == MINT_VALUE_ATTEMPTS:
                # A rejected value was never applied, so leaving it parked
                # would make the next run resume a value the service refuses.
                pending.clear(name)
                raise RotationError(
                    f"{service} refused the settings write (HTTP {status}) "
                    f"after {MINT_VALUE_ATTEMPTS} chosen values",
                    hint="the old key is still live; nothing has been written "
                    "to a holder. The service's value rule is narrower than a "
                    "32-hex key; check it before re-running.",
                )
            pending.clear(name)
            candidate = Secret(self._bazarr_choice())
            pending.set(name, candidate)
            log_line(
                f"      {service} rejected the chosen value (HTTP {status}); "
                f"choosing another ({attempt + 1}/{MINT_VALUE_ATTEMPTS})"
            )
        raise AssertionError("unreachable: the loop either returns or raises")

    def _mint_bazarr(self, step: Step) -> str:
        """Replace Bazarr's own API key with a chosen form value.

        Measured 2026-10-31 on 1.6.2: `settings-auth-apikey` replaces the key
        in the running process with no restart; the new key answers 200 and the
        old key 401 immediately. The chosen value is parked before the write.
        """
        service = step.target
        if self._ctx.minted is not None:
            return f"{service}: key already minted by this run; nothing to redo"
        expected = self._ctx.vault_value
        if expected is None:
            raise RotationError(
                f"{service}: refusing to rotate with no stored value",
                hint="the settings write authenticates with the current key. "
                "Store the credential and re-run; nothing has been changed.",
            )
        pending = self._ctx.pending
        if pending is None:
            raise RotationError(
                f"{service}: refusing to rotate with no pending-secret store",
                hint="the chosen key must survive a crash between the form "
                "write and the vault write. Nothing has been changed.",
            )
        name = self._ctx.credential.name
        candidate = pending.get(name)
        if candidate is not None and candidate.reveal() == expected:
            pending.clear(name)
            candidate = None

        old_verdict = self._authenticate_settled(service, expected)
        if old_verdict.state == "unknown":
            raise RotationError(
                f"{service}: cannot ask whether the stored key is live "
                f"({old_verdict.detail})",
                hint="nothing has been changed.",
            )
        if candidate is not None:
            candidate_verdict = self._authenticate_settled(
                service, candidate.reveal()
            )
        else:
            candidate_verdict = Verdict("absent", None, "no pending value")

        if old_verdict.state == "dead" and candidate_verdict.state == "live":
            self._ctx.minted = candidate
            self._ctx.minted_service = service
            self._ctx.resumed = True
            self._confirm_old_key_dead(service, expected)
            return "already-rotated: continuing with the pending key"
        if old_verdict.state == "dead":
            raise RotationError(
                f"{service}: neither the stored key nor the pending key is "
                f"confirmed live (stored: {old_verdict.detail}; pending: "
                f"{candidate_verdict.detail})",
                hint="restore access and re-run; nothing has been written to "
                "a holder.",
            )
        if candidate_verdict.state == "unknown":
            raise RotationError(
                f"{service}: the pending key could not be checked safely "
                f"({candidate_verdict.detail})",
                hint="nothing has been written to a holder.",
            )
        if candidate_verdict.state == "live":
            raise RotationError(
                f"{service}: both the stored key and the pending key "
                "authenticate",
                hint="Bazarr has one API key. This is ambiguous, so rotating "
                "would invalidate whichever one is actually live. Wait for the "
                "service to settle and re-run.",
            )
        if candidate is None:
            candidate = Secret(self._bazarr_choice())
            pending.set(name, candidate)

        candidate = self._bazarr_write(
            service, expected, candidate, pending, name)
        verdict = self._authenticate_settled(
            service, candidate.reveal())
        if verdict.state != "live":
            raise RotationError(
                f"{service}: the new key does not authenticate ({verdict.detail})",
                hint="the chosen value is parked. Re-run to resume; do not "
                "mint again.",
            )
        self._confirm_old_key_dead(service, expected)
        if not self._ctx.old_key_dead:
            raise RotationError(
                f"{service}: the old key still authenticates after the write",
                hint="the running process did not adopt settings-auth-apikey; "
                "the chosen value is parked. Re-run once it settles.",
            )
        self._ctx.minted = candidate
        self._ctx.minted_service = service
        self._ctx.resumed = False
        return "chose a new key, wrote it to the running process, and proved the old key dead"

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

        old_verdict = self._authenticate_settled(service, expected)
        if old_verdict.state == "unknown":
            raise RotationError(
                f"{service}: cannot ask whether the stored key is live "
                f"({old_verdict.detail})",
                hint="the regenerate call would revoke it without proof that "
                "it is the current key. Nothing has been changed.",
            )
        if candidate is not None:
            candidate_verdict = self._authenticate_settled(
                service, candidate.reveal()
            )
        else:
            candidate_verdict = Verdict("absent", None, "no pending value")

        if old_verdict.state == "live" and candidate_verdict.state == "live":
            raise RotationError(
                f"{service}: both the stored key and the pending key "
                "authenticate",
                hint="Seerr has one API key. This is ambiguous, so regenerating "
                "would invalidate whichever one is actually live. Wait for the "
                "service to settle and re-run.",
            )
        if candidate_verdict.state == "live":
            self._ctx.minted = candidate
            self._ctx.minted_service = service
            self._ctx.resumed = True
            self._confirm_old_key_dead(service, expected)
            return "already-rotated: continuing with the pending key"
        if old_verdict.state != "live":
            raise RotationError(
                f"{service}: neither the stored key nor the pending key is "
                f"confirmed live (stored: {old_verdict.detail}; pending: "
                f"{candidate_verdict.detail})",
                hint="a regenerate needs one of them to authenticate. Nothing "
                "has been changed; restore access and re-run. If this run was "
                "started on the other surface (CLI or server), resume it "
                "there: the pending value lives beside that surface's store.",
            )
        if candidate is not None:
            if candidate_verdict.state != "dead":
                raise RotationError(
                    f"{service}: the pending key could not be checked safely "
                    f"({candidate_verdict.detail})",
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

        verdict = self._authenticate_settled(service, new_key)
        if verdict.state != "live":
            raise RotationError(
                f"{service}: the regenerated key does not authenticate "
                f"({verdict.detail})",
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
        if described.write == "bazarr_api":
            return self._propagate_bazarr(step, described)
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
        try:
            rows = self._select_rows(step.target, rows)
        except RotationError as exc:
            # The step failed before naming any row; "all" is the honest label
            # for a slot that could not be addressed at all.
            self._ctx.holders.append(
                HolderOutcome(step.target, "all", "failed", str(exc))
            )
            raise

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
                    detail = (
                        f"the resource has no {target_field!r} field"
                    )
                    self._ctx.holders.append(
                        HolderOutcome(step.target, label, "failed", detail)
                    )
                    raise RotationError(
                        f"{step.target} id={row.get('id')}: {detail}",
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
                        self._ctx.holders.append(
                            HolderOutcome(step.target, label, "failed", reason)
                        )
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

    def _propagate_bazarr(self, step: Step, holder: Holder) -> str:
        """Write a Sonarr/Radarr key into Bazarr's settings and read it back.

        Bazarr's settings endpoint is a form POST, and its GET returns the
        value the running process holds under `sonarr.apikey` / `radarr.apikey`,
        so the confirmation is a process read-equal rather than a file read or
        a guessed test route. Measured on 1.6.2.
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
                f"{step.target}: does not name which Bazarr settings section "
                "to write. Bazarr holds both Sonarr and Radarr keys, so the "
                "target needs a row qualifier"
            )
        minted = self._ctx.minted.reveal()
        try:
            try:
                api_key = self._service_key(holder.system)
            except (ConfigError, TransportError) as exc:
                raise RotationError(
                    f"cannot read {holder.system}'s own API key ({exc})",
                    hint="store Bazarr's own key before rotating a credential "
                    "it holds",
                ) from exc
            if not api_key:
                raise RotationError(
                    f"no API key for {holder.system!r}; nothing could "
                    "authenticate the settings write",
                    hint="store Bazarr's own key before rotating a credential "
                    "it holds",
                )

            status, before = self._call(
                self._ctx.host, holder.system, "GET", holder.readback_path,
                key=api_key, auth_header=holder.auth_header_name,
                auth_transport=holder.auth_transport,
                transport=self._ctx.transport,
            )
            if status != 200 or not isinstance(before, dict):
                raise RotationError(
                    f"could not read Bazarr's {row} settings (HTTP {status})",
                    hint="the old key is already revoked; restore access and "
                    "re-run to finish",
                )
            section = before.get(row)
            if not isinstance(section, dict):
                raise RotationError(
                    f"Bazarr has no {row} settings entry, so there is nothing "
                    "to update",
                    hint="the old key is already revoked; restore the settings, "
                    "then re-run to finish",
                )

            field = holder.field.format(service=row)
            # Bazarr's dynaconf coerces an all-numeric form value to int and
            # answers 406. A real 32-hex key is all digits about 3e-7 of the
            # time; that write fails loudly rather than reporting confirmed.
            status, _ = self._call(
                self._ctx.host, holder.system, "POST", holder.api_path,
                body={field: minted}, key=api_key,
                auth_header=holder.auth_header_name,
                auth_transport=holder.auth_transport,
                transport=self._ctx.transport,
                content_type="application/x-www-form-urlencoded",
            )
            if status not in (200, 204):
                raise RotationError(
                    f"Bazarr refused the {row} settings write (HTTP {status})",
                    hint="the mint already ran and the old key is revoked. "
                    "Re-run once the settings API accepts the write.",
                )
            status, after = self._call(
                self._ctx.host, holder.system, "GET", holder.readback_path,
                key=api_key, auth_header=holder.auth_header_name,
                auth_transport=holder.auth_transport,
                transport=self._ctx.transport,
            )
            if status != 200 or not isinstance(after, dict):
                raise RotationError(
                    f"Bazarr would not read its {row} settings back "
                    f"(HTTP {status})",
                    hint="the old key is already revoked; restore access and "
                    "re-run to finish",
                )
            observed = (after.get(row) or {}).get(holder.readback_field)
            if observed != minted:
                raise RotationError(
                    f"Bazarr's running process does not report the new {row} "
                    "key",
                    hint="the write was accepted but the process value differs; "
                    "re-run once the settings API settles",
                )
        except RotationError as exc:
            self._ctx.holders.append(
                HolderOutcome(step.target, row, "failed", str(exc))
            )
            raise
        self._ctx.holders.append(
            HolderOutcome(step.target, row, "confirmed", "", "read-equal")
        )
        return (
            f"written to bazarr.settings[{row}] over the API and confirmed "
            "against the running Bazarr"
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
        verdict = self._authenticate(service, old)
        return verdict.state == "dead" and verdict.status == 401

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
            return auth_kwargs(service, self._ctx.minted.reveal()), \
                self._ctx.minted.reveal(), ""
        value, rotator = self._mint_authorizer(service)
        return auth_kwargs(service, value), value or "", rotator

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
        if self._ctx.prior_mint_handle and self._ctx.pending is not None:
            parked = self._ctx.pending.get(self._ctx.credential.name)
            if parked is not None and parked.reveal() != self._ctx.vault_value:
                verdict = self._authenticate_settled(
                    service, parked.reveal()
                )
                if verdict.state == "live":
                    self._ctx.minted = parked
                    self._ctx.minted_service = service
                    self._ctx.minted_handle = self._ctx.prior_mint_handle
                    self._ctx.resumed = True
                    return (
                        "resumed the replacement a dead run created "
                        f"(row {self._ctx.prior_mint_handle})"
                    )
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
        # Record the row this create will replace, before it creates anything.
        # A resume that reaches the revoke can then delete it by id even if an
        # operator renamed it in between. Best effort: a missing id falls back
        # to the name/namespace sweep the revoke already does.
        if self._ctx.attempt is not None and self._ctx.current_ordinal >= 0:
            with contextlib.suppress(Exception):
                row_id = str(current.get("id") or "")
                if row_id:
                    self._ctx.journal.step_predecessor(
                        self._ctx.attempt, self._ctx.current_ordinal, row_id
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
        # Park and journal the row before anything else can fail: the service
        # returned this value once, and a crash before RECORD must leave both
        # the value and its handle for the next run to adopt. Best effort - the
        # value is still in memory for this run.
        if self._ctx.pending is not None:
            with contextlib.suppress(Exception):
                self._ctx.pending.set(self._ctx.credential.name, Secret(key))
        if self._ctx.attempt is not None and self._ctx.current_ordinal >= 0:
            with contextlib.suppress(Exception):
                self._ctx.journal.step_handle(
                    self._ctx.attempt, self._ctx.current_ordinal, str(handle)
                )
        verdict = self._authenticate_settled(service, key)
        if verdict.state != "live":
            raise RotationError(
                f"{service}: the new value does not authenticate ({verdict.detail})",
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
        """Delete the predecessor and any credarr-named stray, then prove it.

        A resumed run (crash after RECORD) has no predecessor value to prove
        dead: RECORD already moved the canonical copy to the successor. It
        relies on deleting every row that matches the predecessor's name or
        namespace; the by-value 401 proof runs only on a fresh rotation.
        """
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
        # A resume after RECORD has the predecessor's row id on the dead mint
        # step. Use it, so a rename between the crash and the resume cannot
        # leave the predecessor unproven.
        recorded = None
        if self._ctx.prior_record and self._ctx.prior_attempt is not None:
            recorded = next(
                (
                    str(step["predecessor"])
                    for step in self._ctx.journal.steps(self._ctx.prior_attempt)
                    if step["kind"] == StepKind.MINT.value
                    and step["predecessor"]
                ),
                None,
            )
            present = {str(row.get("id")) for row in doomed}
            if recorded and recorded not in present:
                for row in rows:
                    if (
                        str(row.get("id")) == recorded
                        and str(row.get("id")) != handle
                        and not any(
                            row.get(field) for field in spec.protected_fields
                        )
                    ):
                        doomed.append(row)
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
        # Prove by the list, not only by the delete responses: a service that
        # answers 204 and keeps the row would otherwise read as revoked. This
        # is also the only proof a resumed run has, because RECORD already
        # moved the canonical copy and the predecessor's value is no longer in
        # hand.
        remaining = self._reissue_rows(
            service, spec, kwargs, account=account, username=username
        )
        survivors = [
            row for row in remaining
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
                or str(row.get("id")) == recorded
            )
        ]
        if survivors:
            raise RotationError(
                f"{service}: {len(survivors)} previous row(s) are still listed "
                f"after the revoke",
                hint="the delete was answered but the row is still in the "
                f"{spec.list_label}. Delete it in the service before treating "
                "this rotation as complete.",
            )
        old = None if self._ctx.prior_record else self._ctx.vault_value
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
        auth = auth_kwargs(service, token)
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
        auth = auth_kwargs(service, token)
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
        self, service: str, *, old_key: str, new_key: str,
    ) -> None:
        """Wait until the new key is accepted and the old key is not still live.

        This is the restart's proof. A 200 from the restart route only says the
        request was queued; the service can still be running the old config, or
        never come back. A 403 or unknown old-key answer proceeds without
        exercise-only proof; only the status the registry records for the
        service's revoked key sets `old_key_dead`. The pending value is parked
        before the restore, so a timeout is a recoverable stall rather than a
        lost credential.
        """
        dead_status = auth_shape(service).dead_status
        deadline = time.time() + READINESS_TIMEOUT
        old_verdict = new_verdict = Verdict("unknown", None, "no attempt completed")
        while time.time() < deadline:
            old_verdict = self._authenticate(service, old_key)
            new_verdict = self._authenticate(service, new_key)
            if new_verdict.state == "live" and old_verdict.state != "live":
                # Only the service's measured rejection proves the old key is
                # dead. A bare 403 is not a credential verdict in general; the
                # callers that measured it pass the service's own answer.
                self._ctx.old_key_dead = (
                    old_verdict.state == "dead"
                    and old_verdict.status == dead_status
                )
                if not self._ctx.old_key_dead:
                    log_line(
                        f"      {service}: the old key was {old_verdict.detail}, "
                        "which is not proof it is dead; exercise-only "
                        "confirmation will not be claimed"
                    )
                return
            time.sleep(READINESS_INTERVAL)
        if new_verdict.state != "live":
            raise RotationError(
                f"{service}: the service-native restart did not make the "
                f"restored key usable within {READINESS_TIMEOUT}s "
                f"(old key: {old_verdict.detail}; "
                f"new key: {new_verdict.detail})",
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









