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

import re
from collections.abc import Callable

from .errors import ConfigError, RotationError, TransportError
from .executor_steps.mint import MintSteps
from .executor_steps.propagate import PropagateSteps
from .executor_steps.record import RecordSteps
from .executor_steps.revoke import RevokeSteps
from .executor_steps.support import (
    _servarr_backup_config,
    _servarr_call,
    _servarr_login,
    _servarr_restore_config,
)
from .executor_steps.types import (
    ExecutionResult,
    HolderOutcome,
    RotationContext,
)
from .executor_steps.verify import VerifySteps
from .model import split_target
from .redact import scrub
from .rotate import RotationPlan, Step, StepKind
from .writers import (
    MINT_SOURCES,
    REISSUERS,
    Holder,
    MintSource,
    auth_kwargs,
    holder_for,
    readiness_path,
    seerr_row,
)


class Executor(MintSteps, PropagateSteps, VerifySteps, RecordSteps, RevokeSteps):
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
            elif seerr_row(row).readback_shape == "object":
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











































    # -- reissue mints: create alongside, revoke last -------------------------
    #
    # Grafana, Arcane and Gitea generate the secret and return it once. The
    # per-service differences live in `REISSUERS`; this code owns the ordering
    # that makes the shape safe: never revoke before the replacement exists,
    # never call a revoke clean without an answered 401, and never guess which
    # row belongs to a credential.
