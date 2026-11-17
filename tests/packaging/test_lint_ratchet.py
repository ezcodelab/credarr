"""The lint size ratchet is pinned to the tree.

`[tool.ruff.lint]` selects C901/PLR0912/PLR0915 behind thresholds that now
leave no function over them: `app._mount` was split into `credarr_server.api`
routers and `Executor.preflight` into named checks. Both halves are
load-bearing: a looser threshold or a broader ignore is the ratchet slipping,
and any new per-file entry is a loosening. Removing an entry is safe because
`ruff check .` re-proves the function was actually fixed; adding a path, or a
code outside the three, fails here so the change shows in this file's diff.

The exemption list is empty on purpose. Ruff has no function-scoped ignore, so
a future oversized function is caught by `ruff check .`, not by an entry; a
global `ignore` would disable the rule everywhere, so it is checked by name as
well.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / "pyproject.toml"

SIZE_RULES = ("C901", "PLR0912", "PLR0915")
EXEMPT: dict[str, set[str]] = {}


@pytest.fixture(scope="module")
def lint_config() -> dict:
    with PYPROJECT.open("rb") as handle:
        return tomllib.load(handle)["tool"]["ruff"]["lint"]


def test_the_size_rules_are_selected(lint_config: dict) -> None:
    missing = sorted(set(SIZE_RULES) - set(lint_config.get("select", [])))
    assert not missing, f"pyproject.toml no longer selects {missing}"


@pytest.mark.parametrize(
    ("section", "key", "value"),
    [
        ("mccabe", "max-complexity", 35),
        ("pylint", "max-branches", 35),
        ("pylint", "max-statements", 100),
    ],
)
def test_size_thresholds_are_the_measured_values(
    lint_config: dict, section: str, key: str, value: int
) -> None:
    found = lint_config.get(section, {}).get(key)
    assert found == value, f"[tool.ruff.lint.{section}] {key} must stay {value}, got {found!r}"


def broad(code: str) -> bool:
    """Whether a selector covers one of the size rules.

    Ruff matches selectors by prefix, and `ALL` is its everything selector with
    no prefix relation to the codes, so it is checked by name.
    """
    return code == "ALL" or any(rule.startswith(code) for rule in SIZE_RULES)


def size_ignores(ignores: dict[str, list[str]]) -> dict[str, set[str]]:
    """The per-file entries that suppress a size rule, including broad ones."""
    return {
        path: {code for code in codes if broad(code)}
        for path, codes in ignores.items()
        if any(broad(code) for code in codes)
    }


def test_size_exemptions_may_only_shrink(lint_config: dict) -> None:
    found = size_ignores(lint_config.get("per-file-ignores", {}))
    added = sorted(set(found) - set(EXEMPT))
    assert not added, f"size-rule exemptions the ratchet never measured: {added}"
    for path, allowed in EXEMPT.items():
        extra = sorted(found.get(path, set()) - allowed)
        assert not extra, f"{path} ignores {extra}, beyond the measured {sorted(allowed)}"


def test_no_global_ignore_disables_a_size_rule(lint_config: dict) -> None:
    """A global ignore switches the rule off everywhere, invisibly.

    The per-file list is pinned above; without this, adding "C901" - or "PL",
    or "ALL" - to the global list would pass every other test here while
    `ruff check .` stopped enforcing the ratchet.
    """
    offenders = sorted(code for code in lint_config.get("ignore", []) if broad(code))
    assert not offenders, f"global ignore disables the size ratchet: {offenders}"
