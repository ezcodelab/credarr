"""The record step drivers, behind `Executor`.

The methods are move-only from the executor; `self` is the same object, so
the journal, the bound transport and the rotation context are the ones the
orchestrator created.
"""

from __future__ import annotations

from credarr.errors import RotationError
from credarr.journal import Outcome, PendingStep, outcome_state
from credarr.redact import Secret
from credarr.rotate import RotationPlan, StepKind
from credarr.writers import MINT_SOURCES, REISSUERS

from .support import PENDING_MINTS, log_line
from .types import HolderOutcome


class RecordSteps:
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

    def _adoptable_mint_handle(
        self,
        plan: RotationPlan,
        previous: int | None,
        previous_outcome: str | None,
    ) -> str:
        """The handle of a create-alongside mint that died before finishing.

        The service returned the successor once and the mint parked it. A crash
        between the create and the mint step's finish leaves the row live, its
        parked value durable, and the handle on the open step. Adopting that
        pair finishes the rotation without creating a third secret; without the
        handle the slot is ignored and the normal mint path runs.

        A reached RECORD is `_resume_after_record`'s shape, and Jellyfin records
        no handle by design (its revoke sweeps by name).
        """
        if previous is None or self._ctx.pending is None:
            return ""
        if previous_outcome is not None:
            abandoned = outcome_state(previous_outcome) is Outcome.ABANDONED
            if not abandoned or not self._ctx.take_over:
                return ""
        mint = next(
            (step for step in plan.steps if step.kind is StepKind.MINT), None
        )
        if mint is None:
            return ""
        if (
            mint.target not in REISSUERS
            and str(self._ctx.credential.write.get("mechanism") or "")
            != "gitea_hook_secret"
        ):
            return ""
        steps = self._ctx.journal.steps(previous)
        if any(
            step["kind"] == StepKind.RECORD.value
            and step["finished_at"] is not None
            and outcome_state(step["outcome"]) is Outcome.COMPLETED
            for step in steps
        ):
            return ""
        return next(
            (
                str(step["handle"]) for step in steps
                if step["kind"] == StepKind.MINT.value and step["handle"]
            ),
            "",
        )

    def _resume_after_record(
        self,
        plan: RotationPlan,
        previous: int | None,
        previous_outcome: str | None,
        reclaimed: list[PendingStep],
    ) -> bool:
        """Whether this run can finish from the previous attempt's RECORD.

        A kill after the canonical write but before the attempt was closed
        leaves an open attempt whose RECORD step is finished (or whose
        unfinished step this run just reclaimed). Minting again would revoke
        the key the service and every holder already received. Two mint shapes
        can finish from here: the pending-backed mints, and a create-alongside
        mint that recorded the row handle it created before RECORD. Jellyfin
        records no handle and deliberately re-mints and sweeps by name.
        """
        if previous is None:
            return False
        # A completed or failed attempt is history. Only an open attempt or one
        # a previous takeover/reclaim already closed can hide a half-done RECORD.
        previous_state = outcome_state(previous_outcome)
        if previous_state not in (Outcome.INTERRUPTED, Outcome.ABANDONED):
            return False
        # An already-abandoned attempt is history unless this run explicitly
        # takes it over. A plain new rotation (a due policy, or an operator
        # pressing Rotate again later) is asking for a new key, not a resume.
        if previous_outcome is not None and not self._ctx.take_over:
            return False
        mint = next((step for step in plan.steps if step.kind is StepKind.MINT), None)
        if mint is None or self._ctx.vault_value is None:
            return False
        source = MINT_SOURCES.get(mint.target)
        pending_mint = source is not None and source.mechanism in PENDING_MINTS
        if pending_mint and self._ctx.pending is None:
            return False
        if not any(step.kind is StepKind.RECORD for step in plan.steps):
            return False
        previous_steps = self._ctx.journal.steps(previous)
        handle = next(
            (str(step["handle"]) for step in previous_steps
             if step["kind"] == StepKind.MINT.value and step["handle"]),
            None,
        )
        if not pending_mint and handle is None:
            return False
        record_steps = [
            step for step in previous_steps
            if step["kind"] == StepKind.RECORD.value
        ]
        if not record_steps:
            return False
        abandoned = previous_state is Outcome.ABANDONED
        if not abandoned:
            took_over_record = any(
                step.attempt_id == previous and step.kind == StepKind.RECORD.value
                for step in reclaimed
            )
            finished_record = any(
                step["finished_at"] is not None
                and outcome_state(step["outcome"]) is Outcome.COMPLETED
                for step in record_steps
            )
            if not took_over_record and not finished_record:
                return False
        name = plan.credential.name
        candidate = (
            self._ctx.pending.get(name) if self._ctx.pending is not None else None
        )
        if (
            pending_mint
            and candidate is not None
            and candidate.reveal() != self._ctx.vault_value
        ):
            # RECORD had not written the canonical value yet. The parked value
            # is still the successor; the normal mint path resumes it.
            return False
        # The canonical value must be the one the service is actually using
        # before it can stand in for the mint. If it does not authenticate, the
        # pending store was lost or the operator changed the wrong copy; the
        # normal mint path will fail closed rather than propagate the old key.
        verdict = self._authenticate_settled(
            mint.target, self._ctx.vault_value
        )
        if verdict.state != "live":
            return False
        if candidate is not None:
            self._ctx.pending.clear(name)
        self._ctx.prior_record = True
        self._ctx.prior_attempt = previous
        self._ctx.minted = Secret(self._ctx.vault_value)
        self._ctx.minted_service = mint.target
        if handle is not None:
            self._ctx.minted_handle = handle
        self._ctx.resumed = True
        return True

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
