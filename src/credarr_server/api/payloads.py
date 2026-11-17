"""JSON projections shared by more than one domain.

A payload names statuses and counts; it never carries a value, a fingerprint,
or a secret. The console's status-retention rule is documented in
`docs/STATE_MACHINES.md` section 8 and implemented by
`_console_credential_json`."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from credarr import provenance
from credarr.audit import CredentialResult, Status
from credarr.model import Consumer, Credential
from credarr.writers import holder_for
from credarr_server import auto_rotation
from credarr_server.audit_log import AuditRun, ConsumerState, CredentialState
from credarr_server.store import AutoRotation


def _check_json(check: CredentialResult) -> dict[str, Any]:
    """One scoped result for the app page. No values and no fingerprints."""
    return {
        "name": check.credential.name,
        "status": check.status.value,
        "detail": check.detail,
        "reason": check.reason,
        "consumers": [
            {
                "target": str(consumer.consumer.target),
                "status": consumer.status.value,
                "detail": consumer.detail,
                "reason": consumer.reason,
                "observed_count": consumer.observed_count,
            }
            for consumer in check.consumers
        ],
    }


def _run_json(run: AuditRun) -> dict[str, Any]:
    return {
        "id": run.id,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "exit_code": run.exit_code,
        "exit_status": run.exit_status.value if run.exit_status is not None else None,
        "detail": run.detail,
    }


def _rotation_detail(result: Any) -> str:
    """Why a finished rotation is not clean, in the engine's own words.

    The shapes `execution_exit_code` gives 1 for: a step that failed (the
    engine's scrubbed sentence, hint included), a failed/unreached holder,
    holders that were written but never confirmed, or manual steps the build
    could not perform. A real failure outranks a remaining manual step so the
    row never hides the reason the stack is inconsistent. The summary is the
    fallback for a shape this build cannot name.

    Holder targets are mapped to plain service names and deduped: the operator
    reads which services were touched, and the target stubs stay in the run's
    own holder list.
    """
    if result.failed:
        return result.detail
    broken = _holder_names(
        holder.target
        for holder in result.holders
        if holder.outcome in ("failed", "not-reached")
    )
    if broken:
        return "failed: " + ", ".join(broken)
    unconfirmed = _holder_names(
        holder.target for holder in result.holders if holder.outcome == "written"
    )
    if unconfirmed:
        return "not confirmed: " + ", ".join(unconfirmed)
    if result.manual:
        return "manual steps outstanding: " + ", ".join(
            _holder_names(result.manual)
        )
    return "not confirmed: " + (result.summary() or "a holder was never confirmed")


# Target systems whose plain name is not title case. Everything else is
# title-cased, so a new service does not need a line here to read correctly.
_SERVICE_LABELS = {"qbittorrent": "qBittorrent", "qui": "qui"}

def _holder_names(targets: Iterable[str]) -> list[str]:
    """Plain service names for holder targets, in order, without repeats."""
    names: list[str] = []
    for target in targets:
        system = str(target).split(".", 1)[0]
        name = _SERVICE_LABELS.get(system, system.title())
        if name not in names:
            names.append(name)
    return names


def _auto_json(state: AutoRotation | None, last_rotation: float | None) -> dict[str, Any]:
    """The policy as the console reads it. No secret exists in this row."""
    if state is None:
        return {
            "enabled": False,
            "every_days": None,
            "next_due_at": None,
            "last_check_at": None,
            "last_outcome": None,
            "last_detail": "",
            "paused": False,
        }
    return {
        "enabled": state.enabled,
        "every_days": state.every_days,
        "next_due_at": auto_rotation.next_due_at(state, last_rotation),
        "last_check_at": state.last_check_at,
        "last_outcome": state.last_outcome,
        "last_detail": state.last_detail,
        "paused": state.paused,
    }


def _console_credential_json(
    credential: Credential,
    stored_at: float | None,
    observed: CredentialState | None,
    observed_at: float | None,
    auto_rotation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """One credential as the console reads it: declared, stored, observed.

    A recorded status is only shown while it is about the state declared now;
    `docs/STATE_MACHINES.md` section 8 names the three ways it stops applying.
    """
    audited = list(observed.consumers) if observed is not None else []
    declared = [str(consumer.target) for consumer in credential.consumers]
    matches: list[ConsumerState | None] = []
    for index, target in enumerate(declared):
        found = audited[index] if index < len(audited) else None
        matches.append(found if found is not None and found.target == target else None)
    provisioning_matches = observed is not None and (
        (observed.status is Status.ABSENT) == (not credential.provisioned)
    )
    current = (
        observed is not None
        and observed_at is not None
        and provisioning_matches
        and (stored_at is None or stored_at <= observed_at)
    )
    whole_shape = (
        current and bool(audited) and len(audited) == len(declared) and all(matches)
    )
    # A run can finish before it reaches a holder: no value is stored, the
    # credential is not provisioned, or its canonical could not be read. With
    # holders declared, that finding is about this credential and the status
    # column should show it. INDIRECT is not in this set: it means the run had
    # no holders at all, so it lends nothing to a holder set declared now.
    ran_out = (
        current
        and bool(declared)
        and not audited
        and observed is not None
        and observed.status in (Status.UNVERIFIABLE, Status.ABSENT, Status.ERROR)
    )
    reported = whole_shape or ran_out
    detail = observed.detail if reported and observed is not None else None
    reason = observed.reason if reported and observed is not None else None
    if (
        reported
        and not audited
        and observed is not None
        and observed.status is Status.UNVERIFIABLE
        and stored_at is None
    ):
        detail = "no value stored yet"
        reason = "value_missing"
    vault = credential.vault
    return {
        "name": credential.name,
        "description": credential.description,
        "class": credential.credential_class,
        "max_age_days": credential.max_age_days,
        "never_rotate": credential.never_rotate,
        "provisioned": credential.provisioned,
        "canonical": dict(credential.canonical),
        "write": dict(credential.write),
        "stored": stored_at is not None,
        "vault": (
            {"backend": vault.backend, "file": vault.file, "path": list(vault.path)}
            if vault is not None
            else None
        ),
        "status": observed.status.value if reported else None,
        "detail": detail,
        "reason": reason,
        "auto_rotation": auto_rotation or _auto_json(None, None),
        "consumers": [
            _consumer_json(consumer, matches[index] if current else None)
            for index, consumer in enumerate(credential.consumers)
        ],
    }


def _consumer_json(consumer: Consumer, observed: ConsumerState | None) -> dict[str, Any]:
    """One holder: declared shape, whether this build can write it, the finding.

    `managed` is `provenance.managed`'s answer - the display gate, never a
    rotation decision - and `holder` plus `provenance` are its ingredients, so
    the console can say why a holder is monitor-only instead of just wearing
    the badge.
    """
    target = consumer.target
    holder = holder_for(target.system, target.slot)
    return {
        "target": str(target),
        "count": consumer.count,
        # What the holder's API listed in the audited run, when it could be
        # counted. Next to the declaration so a console can offer to set
        # `count` to the live number instead of asking for a hand count; None
        # means the run could not count it, not "no rows".
        "observed_count": observed.observed_count if observed else None,
        "mechanism": consumer.mechanism,
        "host": consumer.host,
        "note": consumer.note,
        "holder": holder is not None,
        "manual": consumer.indirect or holder is None,
        "exercised": (
            not consumer.indirect
            and holder is not None
            and bool(holder.test_path or holder.readback)
        ),
        "managed": provenance.managed(target.system, target.slot),
        "version": provenance.measured_version(target.system),
        "provenance": provenance.provenance_text(target.system),
        "status": observed.status.value if observed else None,
        "detail": observed.detail if observed else None,
        "reason": observed.reason if observed else None,
    }

