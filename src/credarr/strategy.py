"""The uniform strategy vocabulary: create, set, test, finish.

The engine's concrete plan is still the authority for what a rotation does and
in what order. This module maps that plan onto the roadmap's four phases and
publishes the declared properties beside it, so a caller can see whether every
`set` path is proven instead of inferring "rotatable" from a step count.

It never changes a plan, an exit code, or a class. `claimable` is a display
fact: a measured version behind the service and no planner blocker. A manual
strategy is typed as such rather than being dressed up as a measured one.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Credential
from .provenance import measured_version
from .rotate import RotationPlan, StepKind, service_for

CREATE = "create"
SET = "set"
TEST = "test"
FINISH = "finish"
PHASES = (CREATE, SET, TEST, FINISH)

MANUAL = "manual"
MEASURED = "measured"
ASSUMED = "assumed"
UNVERIFIED = "unverified"


@dataclass(frozen=True, slots=True)
class Strategy:
    credential: str
    phases: tuple[str, ...]
    revocation: str
    availability: str
    verification: str
    provenance: str
    claimable: bool
    blockers: tuple[str, ...]
    measured_version: str | None

    def as_json(self) -> dict[str, object]:
        return {
            "credential": self.credential,
            "phases": list(self.phases),
            "revocation": self.revocation,
            "availability": self.availability,
            "verification": self.verification,
            "provenance": self.provenance,
            "claimable": self.claimable,
            "blockers": list(self.blockers),
            "measured_version": self.measured_version,
        }


def strategy_for(credential: Credential, plan: RotationPlan) -> Strategy:
    """Map one concrete plan onto the four-phase contract, without inflating it."""
    mint = next((step for step in plan.steps if step.kind is StepKind.MINT), None)
    record = next((step for step in plan.steps if step.kind is StepKind.RECORD), None)
    propagated = [step for step in plan.steps if step.kind is StepKind.PROPAGATE]
    manual = [step for step in plan.steps if step.kind is StepKind.MANUAL]
    phases: list[str] = []
    if mint is not None or manual:
        phases.append(CREATE)
    if propagated or manual:
        phases.append(SET)
    if propagated:
        phases.append(TEST if any("test" in step.detail.lower() for step in propagated) else SET)
    if record is not None:
        phases.append(FINISH)
    # A phase list contains each name once; TEST is evidence, not a duplicate
    # of SET, so it is reported separately below.
    ordered = tuple(dict.fromkeys(phase for phase in phases if phase in PHASES))
    if plan.revokes_before_holders:
        revocation = "on_create"
        availability = "no_overlap"
    elif plan.revokes_last:
        revocation = "after_holders"
        availability = "overlap"
    else:
        revocation = "never"
        availability = "overlap"
    if any("process" in step.detail.lower() for step in propagated):
        verification = "process_readback"
    elif propagated:
        verification = "holder_test"
    elif manual:
        verification = "none"
    else:
        verification = "none"
    service = service_for(credential)
    version = measured_version(service)
    if credential.credential_class in ("B", "never_rotate"):
        provenance = MANUAL
    elif version:
        provenance = MEASURED
    else:
        provenance = ASSUMED
    blockers = tuple(plan.blocked_by)
    claimable = (
        bool(plan.executable)
        and provenance == MEASURED
        and all(step.reversible for step in plan.steps if step.kind is StepKind.PROPAGATE)
    )
    return Strategy(
        credential=credential.name,
        phases=ordered,
        revocation=revocation,
        availability=availability,
        verification=verification,
        provenance=provenance,
        claimable=claimable,
        blockers=blockers,
        measured_version=version,
    )
