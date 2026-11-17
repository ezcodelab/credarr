#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Scan the public tree for private paths, hostnames, and token shapes."""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterator
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "state", "__pycache__", ".venv", "bench/results", "jobs"}
DEFAULT_PATTERNS = [
    r"/home/[^/\s]+/Documents/homelab",
    r"Documents/homelab",
    r"/Users/[^/\s]+/Documents/homelab",
    r"ssh://git@[^/\s]+:[0-9]+",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\bgh[pousr]_[A-Za-z0-9]{30,}\b",
    r"\bsk-[A-Za-z0-9]{20,}\b",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"\b(?:10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})\b",
]


def load_patterns(path: Path | None) -> list[re.Pattern[str]]:
    patterns = [re.compile(item) for item in DEFAULT_PATTERNS]
    if path and path.is_file():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(re.compile(line))
    return patterns


def files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if path.suffix in {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip"}:
            continue
        if path.name == "scan_private.py" or path.name == "denylist.txt":
            continue
        yield path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path())
    parser.add_argument("--denylist", type=Path, default=Path("scripts/denylist.txt"))
    args = parser.parse_args()
    root = args.root.resolve()
    denylist = args.denylist if args.denylist.is_absolute() else root / args.denylist
    patterns = load_patterns(denylist)
    problems = []
    for path in files(root):
        try:
            text = path.read_text(errors="replace")
        except OSError as error:
            problems.append((path.relative_to(root), 0, str(error)))
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            for pattern in patterns:
                if pattern.search(line):
                    problems.append((path.relative_to(root), line_no, pattern.pattern))
    if problems:
        print("Private-path scan failed:")
        for path, line_no, pattern in problems:
            print(f"- {path}:{line_no}: {pattern}")
        return 1
    print("Private-path scan: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
