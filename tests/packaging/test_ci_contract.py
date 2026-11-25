"""The CI shape a pull request waits on.

`check`, `container` and `smoke` are the branch-protection contexts. They may
wait on the cheap gate, never on each other: a required job serialised behind
another required job adds its whole runtime to every pull request. And when the
gate fails they must fail, not skip, because a skipped required check counts as
passing and would let a red branch merge.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
AUTO_MERGE = ROOT / ".github" / "workflows" / "auto-merge.yml"
REQUIRED = ("check", "container", "smoke")
GATE = "gate"


def jobs() -> dict[str, Any]:
    workflow = yaml.safe_load(WORKFLOW.read_text())
    assert isinstance(workflow, dict)
    return workflow["jobs"]


def needs(job: dict[str, Any]) -> list[str]:
    declared = job.get("needs", [])
    return [declared] if isinstance(declared, str) else list(declared)


def reaches(job: str, target: str, seen: set[str] | None = None) -> bool:
    seen = seen or set()
    if job in seen:
        return False
    seen.add(job)
    for dependency in needs(jobs()[job]):
        if dependency == target or reaches(dependency, target, seen):
            return True
    return False


def test_the_required_checks_are_jobs() -> None:
    assert set(REQUIRED) <= set(jobs())


def test_required_jobs_never_wait_on_each_other() -> None:
    for name in REQUIRED:
        for other in REQUIRED:
            if other != name:
                assert not reaches(name, other), (
                    f"{name} waits on {other}; the required checks run in parallel"
                )


def test_a_failed_gate_fails_the_required_jobs_instead_of_skipping_them() -> None:
    for name in REQUIRED:
        job = jobs()[name]
        assert GATE in needs(job), f"{name} does not wait on the {GATE}"
        assert "always()" in str(job.get("if", "")), (
            f"{name} would be skipped when the {GATE} fails, and a skipped "
            "required check counts as passing"
        )


def test_the_merge_waits_for_the_run_not_a_check_listing() -> None:
    """A required job behind `needs` has no check run until its dependency
    finishes, so a listing of required checks can be all-green while the
    suite, the image and the browser have not started. Waiting on the run
    itself is what closes that window; the merge is still gated by branch
    protection."""
    merge = yaml.safe_load(AUTO_MERGE.read_text())["jobs"]["merge"]
    commands = "\n".join(str(step.get("run", "")) for step in merge["steps"])
    assert "gh run watch" in commands
    assert "gh pr checks" not in commands
