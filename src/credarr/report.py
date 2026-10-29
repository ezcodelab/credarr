"""Rendering results.

Two formats, one data model. The human format is what an operator reads; the
JSON format is what CI reads, and its schema is part of the public interface
because someone will build a dashboard on it.

Neither ever renders a credential. The only value that reaches output is a
fingerprint, and fingerprints are salted per run by default, so even that is
not an oracle for guessing the value behind it.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any, TextIO

from .audit import AuditResult, ConsumerResult, CredentialResult, Status
from .errors import ExitCode

# Terminal styling, suppressed when the stream is not a tty.
_STYLE = {
    Status.MATCH: ("ok  ", "\033[32m"),
    Status.DRIFT: ("DRIFT", "\033[31m"),
    Status.MISSING: ("MISS ", "\033[33m"),
    Status.ERROR: ("ERROR", "\033[31m"),
    Status.UNVERIFIABLE: ("skip", "\033[90m"),
    Status.LIVE: ("live", "\033[36m"),
    # Credential-level INDIRECT is the no-holder aggregate; consumer rows use
    # the manual marker below. The JSON value stays `indirect`.
    Status.INDIRECT: ("n/a ", "\033[90m"),
    Status.ABSENT: ("----", "\033[90m"),
}
_CONSUMER_STYLE = {
    **_STYLE,
    Status.INDIRECT: ("manual", "\033[90m"),
}
_RESET = "\033[0m"


def _wrap(text: str, width: int) -> list[str]:
    """Fold a description onto lines, without breaking the indentation of the
    block scalars the manifest uses."""
    import textwrap

    return textwrap.wrap(" ".join(text.split()), width=width) or [""]


def _paint(
    status: Status,
    colour: bool,
    style: Mapping[Status, tuple[str, str]] | None = None,
) -> str:
    label, code = (style or _STYLE).get(status, ("    ", ""))
    if colour:
        return f"{code}{label}{_RESET}"
    return label


def render_human(result: AuditResult, stream: TextIO, *, colour: bool | None = None) -> None:
    colour = stream.isatty() if colour is None else colour
    write = lambda line="": print(line, file=stream)  # noqa: E731

    write("Credential audit - fingerprints only, no values")
    if result.fingerprint_salt_pinned:
        write()
        write(
            "  ! fingerprint salt is pinned, so fingerprints are stable across "
            "runs and an attacker holding a leaked"
        )
        write("    output plus the salt can test candidate values against them.")
    write()

    for credential in result.results:
        _render_credential(credential, write, colour)

    counts = result.counts()
    write()
    ordered = sorted(counts.items(), key=lambda kv: kv[0].value)
    summary = "  ".join(f"{status.value} {n}" for status, n in ordered)
    write(f"{len(result.results)} credential(s): {summary or 'none'}")

    if result.problems:
        write()
        for credential in result.problems:
            write(f"  {credential.credential.name}: {credential.status.value}")
            for consumer in credential.consumers:
                if consumer.status.is_problem:
                    write(f"      {consumer.consumer.target}: {consumer.detail}")


def _render_credential(credential: CredentialResult, write: Any, colour: bool) -> None:
    declared = credential.credential
    age = f"max age {declared.max_age_days}d" if declared.max_age_days else "no rotation schedule"
    write(
        f"  {declared.name}  [{declared.credential_class}, {age}]"
        + (f"  {credential.canonical_fingerprint}" if credential.canonical_fingerprint else "")
    )

    if not credential.consumers:
        # A credential with no consumers is either the canonical holder or a
        # documented blocker. Its description is the only place the reason is
        # written down, so showing it beats a generic marker.
        detail = credential.detail or (
            "canonical holder, nothing else keeps a copy"
            if credential.canonical_fingerprint
            else "nothing to verify"
        )
        write(f"      {_paint(credential.status, colour)}  {detail}")
        if not credential.canonical_fingerprint and declared.description:
            for line in _wrap(declared.description, 88):
                write(f"              {line}")
        write()
        return

    for consumer in credential.consumers:
        write(_render_consumer(credential, consumer, colour))
    _render_mismatches(write, credential)
    write()


_TARGET_WIDTH = 42


def _render_consumer(credential: CredentialResult, consumer: ConsumerResult, colour: bool) -> str:
    marker = _paint(consumer.status, colour, _CONSUMER_STYLE)
    target = str(consumer.consumer.target)
    line = f"      {marker}  {target:<{_TARGET_WIDTH}} "

    if consumer.status is Status.MATCH:
        if len(consumer.observed) == 1:
            return line.rstrip() + f"  ({consumer.observed[0].qualified})"
        return line.rstrip() + f"  ({len(consumer.observed)} copies)"

    if consumer.status is Status.UNVERIFIABLE and consumer.observed:
        labels = ", ".join(o.qualified for o in consumer.observed)
        return f"{line}{labels} - {consumer.detail}"

    return line.rstrip() + f"  {consumer.detail}"


def _render_mismatches(write: Any, credential: CredentialResult) -> None:
    """Name every stale copy: which row, which field, which fingerprint.

    A drift report that only says "1 of 2 differ" sends the operator back to
    the database to find out which. This names them, and prints fingerprints
    rather than values, because the report is meant to be pasted into a ticket
    and a credential in a ticket is a credential that has to be rotated.
    """
    for consumer in credential.consumers:
        if not consumer.mismatched:
            continue
        for mismatch in consumer.mismatched:
            where = f"{mismatch.label}:{mismatch.field}" if mismatch.field else mismatch.label
            write(f"                {where:<34} {mismatch.fingerprint}")


def render_json(result: AuditResult, stream: TextIO) -> None:
    """Machine-readable output.

    Fingerprints distinguish values within this observation; cross-run comparison
    is unsupported even when opt-in salt pinning technically makes it possible.
    Dashboard history must store events, never these value-derived identifiers.
    """
    payload = {
        "version": 1,
        "fingerprint_salt_pinned": result.fingerprint_salt_pinned,
        "summary": {
            "credentials": len(result.results),
            "status": result.exit_status.value,
            "counts": {status.value: n for status, n in result.counts().items()},
        },
        "credentials": [_credential_json(r) for r in result.results],
    }
    json.dump(payload, stream, indent=2, sort_keys=True)
    stream.write("\n")


def _credential_json(credential: CredentialResult) -> dict[str, Any]:
    declared = credential.credential
    return {
        "name": declared.name,
        "class": declared.credential_class,
        "status": credential.status.value,
        "max_age_days": declared.max_age_days,
        "provisioned": declared.provisioned,
        "canonical_fingerprint": credential.canonical_fingerprint,
        "declared_copies": declared.declared_copies,
        "observed_copies": credential.observed_copies,
        "detail": credential.detail,
        "consumers": [
            {
                "target": str(c.consumer.target),
                "host": c.consumer.host,
                "count": c.consumer.count,
                "mechanism": c.consumer.mechanism,
                "status": c.status.value,
                "observed": len(c.observed),
                # The live row count the holder's API listed, when it could be
                # counted; next to `count` for the same reason the API payload
                # carries it (DECISIONS 26).
                "observed_count": c.observed_count,
                "fingerprints": list(c.fingerprints),
                # Which row and field are stale. Machine-readable for the same
                # reason the human output names them: a CI failure has to be
                # actionable without a human reading a table.
                "mismatched": [
                    {"label": m.label, "field": m.field, "fingerprint": m.fingerprint}
                    for m in c.mismatched
                ],
                "detail": c.detail,
            }
            for c in credential.consumers
        ],
    }


def exit_code_for(result: AuditResult) -> int:
    return {
        Status.MATCH: ExitCode.OK,
        Status.DRIFT: ExitCode.DRIFT,
        Status.MISSING: ExitCode.DRIFT,
        Status.ERROR: ExitCode.UNREACHABLE,
    }.get(result.exit_status, ExitCode.OK)


def rotation_json(
    credential: Any, host: Any, plan: Any, problems: Iterable[str] = ()
) -> dict[str, Any]:
    """A rotation plan, or the reason there isn't one, as data.

    One shape for `--json` and for the API's plan endpoint, so the same plan
    cannot be described two ways to two callers. `problems` is the preflight's
    answer, and is empty for a refused plan: a refused plan is not checked
    against the live stack, because it cannot run either way.

    `--json` is registered on every subcommand, and the rotate path used to
    ignore it: a job doing `rotate --json | jq` got prose and a silent parse
    failure. The refusal is the case that matters, because its exit code says
    "not rotatable" without saying which holder stopped it - so the reason
    travels here rather than having to be scraped from a message.
    """
    return {
        "version": 3,
        "credential": credential.name,
        "class": credential.credential_class,
        "host": host.name,
        "refused": bool(plan.blocked_by),
        "blocked_by": list(plan.blocked_by),
        # Whether the mint would revoke the old credential before any holder is
        # updated. Published because a count of confirmed holders says nothing
        # about *when* they were confirmed: a plan that revokes first has a
        # window where every holder holds a dead key, and a consumer that reads
        # only the step list would not know that.
        #
        # This is a property of the plan's shape, not of a run's outcome, so it is
        # False whenever the plan is refused: a refused plan mints nothing, and
        # claiming a window over a run that cannot happen is a false statement
        # about system state. A consumer should read it as "if this ran, the mint
        # would come first", alongside `refused`.
        "revokes_before_holders": bool(
            plan.revokes_before_holders and not plan.blocked_by
        ),
        # How the new value is obtained. `backup_restore` is the automated
        # Servarr mint; `provided` is the explicit no-backup/restore opt-out
        # where the operator rotates the key in the service's own UI and the
        # console must ask for it. A refused plan names the shape it would have
        # had, so the console can explain the choice before it is enabled.
        "mint_via": str(getattr(plan, "mint_via", "") or ""),
        "manual_mint": str(getattr(plan, "mint_via", "") or "") == "provided",
        "steps": [
            {
                "kind": step.kind.value,
                "target": step.target,
                "detail": step.detail,
                # The two facts the typed-confirmation prompt is built from:
                # whether the step can be undone, and why it exists at all.
                "reversible": bool(step.reversible),
                "reason": step.reason,
            }
            for step in plan.steps
        ],
        "problems": list(problems),
    }


def render_rotation_json(
    credential: Any,
    host: Any,
    plan: Any,
    stream: TextIO,
    problems: Iterable[str] = (),
) -> None:
    """Write `rotation_json` as the documented document."""
    _emit(rotation_json(credential, host, plan, problems), stream)


def execution_json(result: Any) -> dict[str, Any]:
    """A completed rotation as data, for `--json` and the API's run endpoint.

    `clean`, not `ok`: a run can raise nothing and still leave a written holder
    unconfirmed, so a machine reading only "no exception" would record an
    undelivered rotation as done.
    """
    return {
        "credential": result.credential,
        "attempt": result.attempt,
        "completed": list(result.completed),
        "failed": result.failed,
        "detail": result.detail,
        "manual": list(result.manual),
        "holders": [
            {
                "target": holder.target,
                "label": holder.label,
                "outcome": holder.outcome,
                "detail": holder.detail,
                "method": holder.method,
            }
            for holder in result.holders
        ],
        "resumed": bool(result.resumed),
        "reclaimed": [[target, detail] for target, detail in result.reclaimed],
        "vault_written": bool(result.vault_written),
        "revokes_before_holders": bool(result.revokes_before_holders),
        "clean": bool(result.clean),
        "summary": result.summary(),
    }


def render_execution_json(result: Any, stream: TextIO) -> None:
    """Write `execution_json` as the documented document."""
    _emit(execution_json(result), stream)


def _emit(payload: dict[str, Any], stream: TextIO) -> None:
    stream.write(json.dumps(payload, indent=2, sort_keys=True))
    stream.write("\n")
