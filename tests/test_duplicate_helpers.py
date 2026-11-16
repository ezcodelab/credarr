"""Two module-level functions with the same body are one decision, twice.

The audit found `_fsync_directory` copied verbatim into the engine and the
server: a fix to one copy would leave the other. This test is the ratchet, and
it also catches the next copy that arrives under a different name.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

# A body this short is a coincidence, not a shared decision.
MIN_STATEMENTS = 2


def module_functions() -> list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]:
    found: list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = []
    for path in sorted(SRC.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if len(node.body) < MIN_STATEMENTS:
                continue
            found.append((str(path.relative_to(ROOT)), node))
    return found


def normalised_body(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    return ast.dump(ast.Module(body=node.body, type_ignores=[]))


def test_no_two_module_level_functions_share_a_body() -> None:
    groups: dict[str, list[str]] = {}
    for path, node in module_functions():
        groups.setdefault(normalised_body(node), []).append(
            f"{path}:{node.lineno} {node.name}"
        )
    duplicates = [bodies for bodies in groups.values() if len(bodies) > 1]
    assert not duplicates, (
        "module-level functions with identical bodies (extract one): " + repr(duplicates)
    )
