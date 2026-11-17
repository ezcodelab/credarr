"""A docstring is a budget, and a rule belongs in the document that owns it.

The audit found the console's status-retention rule living as a 25-line
docstring in `app.py` while `docs/STATE_MACHINES.md` section 8, the machine
that owns the audit ledger, did not state it. A rule that long is a document,
and code that carries the document drifts from it with nothing to notice.

No `src` docstring may exceed 20 lines. The baseline below is the measured
set at the ratchet's introduction; each entry may shrink, none may grow, and
an entry must be deleted once its docstring fits on its own. Adding an entry
is a deliberate loosening and shows up in this file's diff.
"""

from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
STATE_MACHINES = ROOT / "docs/STATE_MACHINES.md"
PAYLOADS = SRC / "credarr_server/api/payloads.py"

MAX_LINES = 20

# path:name -> the length measured when the budget landed. `<module>` is the
# file's own docstring. Only shrink; delete an entry when it is at the cap.
BASELINE = {
    "src/credarr/executor.py:<module>": 33,
    "src/credarr/executor_steps/revoke.py:_revoke_jellyfin": 24,
    "src/credarr/journal.py:<module>": 25,
    "src/credarr/model.py:<module>": 23,
    "src/credarr/provenance.py:<module>": 21,
    "src/credarr/rotate.py:<module>": 25,
    "src/credarr/services.py:<module>": 33,
    "src/credarr/writers.py:<module>": 60,
    "src/credarr/writers.py:Holder": 21,
    "src/credarr/writers.py:MintSource": 23,
    "src/credarr_server/notifier.py:<module>": 28,
    "src/credarr_server/store.py:<module>": 22,
}


def docstring_lines() -> dict[str, int]:
    """Every `src` docstring as `path:name` and its rendered line count."""
    found: dict[str, int] = {}
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(
                node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                continue
            doc = ast.get_docstring(node, clean=False)
            if doc is None:
                continue
            key = f"{path.relative_to(ROOT).as_posix()}:{getattr(node, 'name', '<module>')}"
            found[key] = len(inspect.cleandoc(doc).splitlines())
    return found


def function_docstring(path: Path, name: str) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            doc = ast.get_docstring(node, clean=False)
            assert doc is not None, f"{path.name}:{name} has no docstring"
            return inspect.cleandoc(doc)
    raise AssertionError(f"{path} has no function {name}")


def section(text: str, number: int) -> str:
    match = re.search(
        rf"^## {number}\..*?(?=^## \d+\.)", text, re.MULTILINE | re.DOTALL
    )
    assert match is not None, f"docs/STATE_MACHINES.md has no section {number}"
    return " ".join(match.group(0).split())


def test_no_unlisted_docstring_exceeds_the_budget() -> None:
    over = sorted(
        f"{key} ({lines} lines)"
        for key, lines in docstring_lines().items()
        if lines > MAX_LINES and key not in BASELINE
    )
    assert not over, (
        f"src docstrings over {MAX_LINES} lines with no baseline entry: {over}; "
        "shorten it or move the rule into docs/, do not add an entry"
    )


def test_the_baseline_only_shrinks() -> None:
    found = docstring_lines()
    problems: list[str] = []
    for key, pinned in BASELINE.items():
        actual = found.get(key)
        if actual is None:
            problems.append(f"{key}: no such docstring, remove the baseline entry")
        elif actual <= MAX_LINES:
            problems.append(
                f"{key}: {actual} lines, within the budget, remove the baseline entry"
            )
        elif actual > pinned:
            problems.append(f"{key}: grew from {pinned} to {actual} lines")
    assert not problems, "docstring baseline is stale: " + repr(problems)


def test_the_retention_rule_lives_in_the_state_machine_doc() -> None:
    rules = section(STATE_MACHINES.read_text(encoding="utf-8"), 8)
    for phrase in (
        "recorded status is only shown while it is about the state declared now",
        "the value moved",
        "`provisioned` moved",
        "the holders changed",
        "shortcut:",
    ):
        assert phrase in rules, (
            f"docs/STATE_MACHINES.md section 8 no longer states {phrase!r}; "
            "the ledger rule needs one home"
        )


def test_the_console_docstring_points_at_the_rule() -> None:
    doc = function_docstring(PAYLOADS, "_console_credential_json")
    assert "docs/STATE_MACHINES.md" in doc and "section 8" in doc, (
        "the console docstring must link to the retention rule instead of holding it"
    )
