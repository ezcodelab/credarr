#!/usr/bin/env python3
"""Create or audit a project's portable UI system."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

STARTER = Path(__file__).resolve().parent.parent / "references/ui/starter"
CONFIG = "ui-system/config.json"
SCRIPT_TARGET = "ui-system/bin/ui_system.py"
SCRIPT_SOURCE = STARTER / SCRIPT_TARGET
UNFILLED_MARKER = "<!-- ui-contract:unfilled -->"
GALLERY_MARKER = "data-ui-gallery"

CONTRACT_PLACEHOLDERS = (
    "Fill each heading with the project's own answer.",
    "Remove the `ui-contract:unfilled` comment",
    "Name the product and the one problem",
    "Describe who uses it",
    "State the single job",
    "Name the character, the world",
    "Point to `ui-system/tokens.css`",
    "Name two to four approved references",
    "Design and list: empty, loading, error",
    "Record contrast targets",
    "Set a budget for initial script",
    "List the runnable checks and viewport widths",
)

FILES = (
    ("ui-contract.md", "docs/ui-contract.md"),
    ("UI_SYSTEM.md", "docs/UI_SYSTEM.md"),
    ("tokens.css", "ui-system/tokens.css"),
    ("gallery.html", "ui-system/gallery.html"),
    ("README.md", "ui-system/README.md"),
)

DEFAULT_PATHS = {
    "contract": "docs/ui-contract.md",
    "system": "docs/UI_SYSTEM.md",
    "tokens": "ui-system/tokens.css",
    "gallery": "ui-system/gallery.html",
    "readme": "ui-system/README.md",
    "script": SCRIPT_TARGET,
}

CONTRACT_HEADINGS = (
    "Product",
    "Audience",
    "One job",
    "Direction",
    "Tokens",
    "References",
    "States",
    "Accessibility",
    "Performance",
    "Acceptance",
)

SYSTEM_HEADINGS = (
    "Direction",
    "Tokens",
    "Components",
    "States",
    "Accessibility",
    "Responsive",
    "Performance",
)

TOKEN_NAMES = (
    "--bg",
    "--surface",
    "--surface-raised",
    "--text",
    "--text-muted",
    "--border",
    "--accent",
    "--ok",
    "--warn",
    "--bad",
    "--radius-sm",
    "--radius-md",
    "--radius-lg",
    "--font-sans",
    "--font-mono",
    "--space-1",
    "--space-2",
    "--space-3",
    "--space-4",
    "--space-5",
    "--space-6",
    "--space-7",
    "--space-8",
    "--text-xs",
    "--text-sm",
    "--text-md",
    "--text-lg",
    "--text-xl",
    "--text-2xl",
)

TOKEN_DECLARATION = re.compile(r"(--[A-Za-z0-9_-]+)\s*:")


def init_project(project: Path) -> int:
    if not STARTER.is_dir():
        print(
            "This is the project-local audit copy. Run `init` once from the "
            "harness's brain/bin/ui_system.py; use this copy for `audit`."
        )
        return 2
    targets = [(STARTER / source, project / destination) for source, destination in FILES]
    targets.append((SCRIPT_SOURCE, project / SCRIPT_TARGET))
    existing = [target for _, target in targets if target.exists()]
    if existing:
        for target in existing:
            print(f"exists: {target}")
        print("refusing to overwrite; no files written")
        return 2

    missing_sources = [source for source, _ in targets if not source.is_file()]
    if missing_sources:
        for source in missing_sources:
            print(f"missing starter file: {source}")
        return 2
    if project.exists() and not project.is_dir():
        print(f"not a directory: {project}")
        return 2

    for source, target in targets:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        print(f"wrote {target.relative_to(project)}")
    return 0


def contract_headings(text: str) -> set[str]:
    headings: set[str] = set()
    in_fence = False
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        marker = line.lstrip("#")
        if not in_fence and marker != line and marker.startswith(" "):
            headings.add(marker.strip())
    return headings


def project_paths(project: Path) -> tuple[dict[str, str] | None, str]:
    """Read an optional ui-system/config.json; default to the starter layout."""
    paths = dict(DEFAULT_PATHS)
    config = project / CONFIG
    if not config.is_file():
        return paths, ""
    try:
        data = json.loads(config.read_text(errors="replace"))
    except (OSError, ValueError) as exc:
        return None, f"invalid {config}: {exc}"
    if not isinstance(data, dict):
        return None, f"invalid {config}: expected a JSON object"
    for key in DEFAULT_PATHS:
        if key not in data:
            continue
        value = data[key]
        if not isinstance(value, str) or not value.strip():
            return None, f"invalid {config}: {key} must be a non-empty path"
        candidate = Path(value.strip())
        if candidate.is_absolute() or ".." in candidate.parts:
            return None, f"invalid {config}: {key} must stay inside the project"
        paths[key] = value.strip()
    return paths, ""


def audit_project(project: Path) -> int:
    problems: list[str] = []

    paths, config_error = project_paths(project)
    if config_error:
        print(config_error)
        return 2

    contract = project / paths["contract"]
    system = project / paths["system"]
    tokens = project / paths["tokens"]
    gallery = project / paths["gallery"]
    for relative in paths.values():
        path = project / relative
        if not path.is_file():
            problems.append(f"missing file: {path}")

    if contract.is_file():
        text = contract.read_text(errors="replace")
        if UNFILLED_MARKER in text:
            problems.append(f"unfilled contract: remove {UNFILLED_MARKER} from {contract}")
        for placeholder in CONTRACT_PLACEHOLDERS:
            if placeholder in text:
                problems.append(f"placeholder contract text: {placeholder!r} in {contract}")
        found = contract_headings(text)
        for heading in CONTRACT_HEADINGS:
            if heading not in found:
                problems.append(f"missing heading: {heading} in {contract}")

    if system.is_file():
        text = system.read_text(errors="replace")
        if len(text.strip()) < 200:
            problems.append(f"empty system document: {system}")
        found = contract_headings(text)
        for heading in SYSTEM_HEADINGS:
            if heading not in found:
                problems.append(f"missing heading: {heading} in {system}")

    if gallery.is_file():
        text = gallery.read_text(errors="replace")
        if GALLERY_MARKER not in text:
            problems.append(f"missing {GALLERY_MARKER} marker in {gallery}")
        if len(text.strip()) < 200:
            problems.append(f"empty gallery: {gallery}")

    if tokens.is_file():
        css = re.sub(r"/\*.*?\*/", "", tokens.read_text(errors="replace"), flags=re.DOTALL)
        found = set(TOKEN_DECLARATION.findall(css))
        for name in TOKEN_NAMES:
            if name not in found:
                problems.append(f"missing token: {name} in {tokens}")

    if problems:
        for problem in problems:
            print(problem)
        return 2

    print("ui system: schema OK (visual and taste review are separate)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="copy the starter into a project")
    init.add_argument("project", help="project directory to initialise")

    audit = commands.add_parser(
        "audit",
        help="check a project's UI system (uses ui-system/config.json when present)",
    )
    audit.add_argument("project", help="project directory to audit")

    args = parser.parse_args(argv)
    project = Path(args.project).expanduser()
    if args.command == "init":
        return init_project(project)
    return audit_project(project)


if __name__ == "__main__":
    sys.exit(main())
