"""AGENTS.md is the entry point every agent reads: pin it to the tree.

Three drifts the audit found, each invisible until an agent follows the prose:
a path that only exists under `docs/`, a layout that omits the modules added
since it was written, and a gate the document names that no check runs. A test
is the only place these stay true, because nothing imports a document.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AGENTS = ROOT / "AGENTS.md"

# Backticked names that are not repository paths.
NOT_A_REPO_PATH = {
    # Seerr's own settings file, named to say credarr never writes it.
    "settings.json",
}
# A bare `.py` token in the prose means a module under `src/`. The package
# markers are described by package, not by row.
BARE_MODULE_ROOTS = ("src",)
LAYOUT_ALLOWED = {"__init__.py", "__main__.py"}
PATH_SUFFIXES = (".md", ".py", ".mjs", ".yaml", ".toml", ".json", ".css")


def prose() -> str:
    return AGENTS.read_text(encoding="utf-8")


def backticked(text: str) -> list[str]:
    return re.findall(r"`([^`\n]+)`", text)


def named_paths(text: str) -> list[str]:
    """The tokens that read as repository paths, not routes or URLs."""
    found = set()
    for token in backticked(text):
        if token in NOT_A_REPO_PATH:
            continue
        if " " in token or token.startswith(("/", "-")):
            continue
        if not token.endswith(PATH_SUFFIXES):
            continue
        found.add(token)
    return sorted(found)


def resolve(token: str) -> Path | None:
    """What the token means in the document's own grammar.

    A slash means repo-relative. A bare module name is looked up under `src/`
    only, because the prose says "registered in `writers.py`" and means the
    one module. A bare document name means next to AGENTS.md; a document that
    lives under `docs/` has to say so.
    """
    if "/" in token:
        candidate = ROOT / token
        return candidate if candidate.exists() else None
    if token.endswith(".py"):
        matches = [
            path
            for root in BARE_MODULE_ROOTS
            for path in (ROOT / root).rglob(token)
        ]
        return matches[0] if len(matches) == 1 else None
    candidate = ROOT / token
    return candidate if candidate.exists() else None


def make_targets() -> set[str]:
    return set(
        re.findall(r"^([a-zA-Z][a-zA-Z0-9_-]*):", (ROOT / "Makefile").read_text(), re.M)
    )


def test_every_path_named_in_agents_md_exists() -> None:
    text = prose()
    missing = {}
    for token in named_paths(text):
        if resolve(token) is None:
            missing[token] = text.count(f"`{token}`")
    assert not missing, (
        "AGENTS.md names paths that do not resolve in this grammar "
        "(token: occurrences): " + repr(missing)
    )


def layout_block(text: str) -> str:
    match = re.search(r"## Layout\n\n```\n(.*?)```", text, re.S)
    assert match is not None, "AGENTS.md has no Layout code block"
    return match.group(1)


def named_in_layout(name: str, block: str) -> bool:
    if name in block:
        return True
    stem = name.removesuffix(".py")
    return any(
        stem in [part.strip() for part in group.split(",")]
        for group in re.findall(r"\{([^}]*)\}\.py", block)
    )


def test_every_source_module_is_named_in_the_layout() -> None:
    block = layout_block(prose())
    missing = sorted(
        path.name
        for path in (ROOT / "src").rglob("*.py")
        if path.name not in LAYOUT_ALLOWED and not named_in_layout(path.name, block)
    )
    assert not missing, (
        "src modules no agent can find from AGENTS.md's layout: " + repr(missing)
    )


def test_every_make_target_named_in_agents_md_is_defined() -> None:
    named = {
        match.group(1)
        for token in backticked(prose())
        if (match := re.fullmatch(r"make ([a-zA-Z][a-zA-Z0-9_-]*)", token))
    }
    missing = sorted(named - make_targets())
    assert not missing, "AGENTS.md names Makefile targets that do not exist: " + repr(missing)


def test_the_ui_audit_is_a_real_check_gate() -> None:
    """A gate that is not tracked cannot run on a fresh clone."""
    assert "ui-audit" in make_targets(), "make ui-audit is not defined"
    check = re.search(r"^check:([^\n]*)", (ROOT / "Makefile").read_text(), re.M)
    assert check is not None and "ui-audit" in check.group(1), (
        "make check does not run the UI audit: " + repr(check.group(1) if check else None)
    )
    tracked = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--", "ui-system/bin/ui_system.py"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    assert tracked, "ui-system/bin/ui_system.py is not tracked, so CI cannot run it"


def test_clean_removes_python_caches() -> None:
    assert "clean" in make_targets(), "make clean is not defined"
    body = re.search(r"^clean:[^\n]*(?:\n\t[^\n]*)*", (ROOT / "Makefile").read_text(), re.M)
    assert body is not None and "__pycache__" in body.group(0), (
        "make clean does not remove __pycache__"
    )
