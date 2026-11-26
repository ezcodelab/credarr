"""The docs an agent follows are pinned to the tree, not to memory.

`AGENTS.md` is the local entry point and is deliberately not published; the
public GitHub tree carries `README.md` and `docs/`. A gate named in either has
to exist, a path has to resolve, and a module a reader is told about has to be
listed where they look. The audit found all three drifted: a root
`DECISIONS.md` that lives under `docs/`, a Modules block missing the modules
added since, and a UI audit no check ran.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LOCAL_AGENTS = ROOT / "AGENTS.md"
PUBLIC_DOCS = (
    ROOT / "README.md",
    ROOT / "docs/README.md",
    ROOT / "docs/ARCHITECTURE.md",
    ROOT / "docs/CONTRIBUTING.md",
)

# Backticked names that are not repository paths.
NOT_A_REPO_PATH = {
    # The operator's own config; the tree ships credarr.example.yaml.
    "credarr.yaml",
    # The engine/CLI declaration an operator writes; no file ships in the tree.
    "credentials.yaml",
    # Seerr's own settings file, named to say credarr never writes it.
    "settings.json",
}
LAYOUT_ALLOWED = {"__init__.py", "__main__.py"}
PATH_SUFFIXES = (".md", ".py", ".mjs", ".yaml", ".toml", ".json", ".css")
BARE_ROOTS = {
    ".py": ("src", "tests"),
    ".md": (".", "docs"),
    ".json": (".", "ui"),
    ".yaml": (".",),
    ".toml": (".",),
    ".css": ("ui/src",),
    ".mjs": ("ui/tests",),
}


def backticked(text: str) -> list[str]:
    return re.findall(r"`([^`\n]+)`", text)


def named_paths(text: str) -> list[str]:
    found = set()
    for token in backticked(text):
        if token in NOT_A_REPO_PATH or " " in token or token.startswith(("/", "-")):
            continue
        if token.endswith(PATH_SUFFIXES):
            found.add(token)
    return sorted(found)


def resolve(token: str, document: Path) -> Path | None:
    if token.startswith("../"):
        candidate = (document.parent / token).resolve()
        return candidate if candidate.exists() else None
    if "/" in token:
        candidate = ROOT / token
        return candidate if candidate.exists() else None
    suffix = Path(token).suffix
    matches = {
        path.resolve()
        for root in BARE_ROOTS.get(suffix, (".",))
        for path in (ROOT / root).rglob(token)
        if not {".venv", "node_modules", "__pycache__"} & set(path.parts)
    }
    return next(iter(matches)) if len(matches) == 1 else None


def missing_paths(documents: tuple[Path, ...]) -> dict[str, list[str]]:
    missing: dict[str, list[str]] = {}
    for document in documents:
        for token in named_paths(document.read_text(encoding="utf-8")):
            if resolve(token, document) is None:
                missing.setdefault(token, []).append(
                    str(document.relative_to(ROOT))
                )
    return missing


def modules_block(document: Path, heading: str) -> str:
    text = document.read_text(encoding="utf-8")
    match = re.search(rf"{re.escape(heading)}\n\n```\n(.*?)```", text, re.S)
    assert match is not None, f"{document} has no {heading} block"
    return match.group(1)


def named_in_block(name: str, block: str) -> bool:
    if name in block:
        return True
    stem = name.removesuffix(".py")
    return any(
        stem in [part.strip() for part in group.split(",")]
        for group in re.findall(r"\{([^}]*)\}\.py", block)
    )


def undocumented_modules(block: str) -> list[str]:
    return sorted(
        path.name
        for path in (ROOT / "src").rglob("*.py")
        if path.name not in LAYOUT_ALLOWED and not named_in_block(path.name, block)
    )


def make_targets() -> set[str]:
    return set(
        re.findall(r"^([a-zA-Z][a-zA-Z0-9_-]*):", (ROOT / "Makefile").read_text(), re.M)
    )


def named_targets(documents: tuple[Path, ...]) -> set[str]:
    named = set()
    for document in documents:
        named |= {
            match.group(1)
            for token in backticked(document.read_text(encoding="utf-8"))
            if (match := re.fullmatch(r"make ([a-zA-Z][a-zA-Z0-9_-]*)", token))
        }
    return named


def test_every_path_in_the_public_docs_exists() -> None:
    missing = missing_paths(PUBLIC_DOCS)
    assert not missing, (
        "public docs name paths that do not resolve (token: documents): " + repr(missing)
    )


def test_every_source_module_is_named_in_the_architecture_modules_block() -> None:
    missing = undocumented_modules(modules_block(ROOT / "docs/ARCHITECTURE.md", "## Modules"))
    assert not missing, (
        "src modules missing from docs/ARCHITECTURE.md's Modules block: " + repr(missing)
    )


def test_every_make_target_named_in_the_public_docs_is_defined() -> None:
    missing = sorted(named_targets(PUBLIC_DOCS) - make_targets())
    assert not missing, "public docs name Makefile targets that do not exist: " + repr(missing)


@pytest.mark.skipif(
    not LOCAL_AGENTS.exists(),
    reason="AGENTS.md is a local file, deliberately not published",
)
def test_agents_md_is_in_sync_when_present() -> None:
    """The local entry point gets the same three checks, where it exists."""
    missing = missing_paths((LOCAL_AGENTS,))
    assert not missing, "AGENTS.md names paths that do not resolve: " + repr(missing)
    missing_modules = undocumented_modules(modules_block(LOCAL_AGENTS, "## Layout"))
    assert not missing_modules, (
        "src modules missing from AGENTS.md's Layout block: " + repr(missing_modules)
    )
    missing_targets = sorted(named_targets((LOCAL_AGENTS,)) - make_targets())
    assert not missing_targets, (
        "AGENTS.md names Makefile targets that do not exist: " + repr(missing_targets)
    )


def test_the_default_compose_has_no_docker_socket() -> None:
    """Docker is the agent's surface; the BFF compose must never gain it."""
    text = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    assert "docker.sock" not in text
    assert "CREDARR_AGENT_PORT" in text
    assert "docker.sock" not in (ROOT / "Dockerfile").read_text(encoding="utf-8")


def test_the_agent_has_its_own_image_and_the_docs_say_so() -> None:
    """One version, two images: a command override is not a security boundary."""
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM runtime AS agent" in dockerfile
    assert "FROM runtime AS server" in dockerfile
    assert 'ENTRYPOINT ["credarr-agent"]' in dockerfile
    assert 'CMD ["run"]' in dockerfile
    assert (ROOT / "Makefile").read_text(encoding="utf-8").count(
        "docker build --target"
    ) == 2

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    sync = (ROOT / "docs/SYNC.md").read_text(encoding="utf-8")
    for text in (readme, sync):
        assert "credarr-agent" in text
        assert "CREDARR_AGENT_PORT" in text
    assert "ghcr.io/ezcodelab/credarr-agent" in readme
    assert "Audit and rotation work without an agent" in readme
    assert "no agent" in sync.lower()
    assert "CREDARR_AGENT_ACK_ROOTFUL" not in readme
    assert "CREDARR_AGENT_ROOTFUL" not in readme
    assert "CREDARR_VAULT_TREE_KEY" in readme
    assert "CREDARR_AGENT_CA_CERT" in readme
    assert "agent-ca.crt" in readme


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
