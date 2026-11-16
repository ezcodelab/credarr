"""The lint size ratchet is pinned to the tree.

`[tool.ruff.lint]` selects C901/PLR0912/PLR0915 behind thresholds measured to
leave only `executor.preflight` and `app._mount` over them. Both halves are
load-bearing: a looser threshold or a broader ignore is the ratchet slipping,
and the exemption may only shrink. Removing an entry is safe because
`ruff check .` re-proves the function was actually fixed; adding a path, or a
code outside the three, fails here so the loosening is a visible diff.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / "pyproject.toml"

SIZE_RULES = ("C901", "PLR0912", "PLR0915")
EXEMPT = {
    "src/credarr/executor.py": {"C901", "PLR0912", "PLR0915"},
    "src/credarr_server/app.py": {"C901", "PLR0912", "PLR0915"},
}


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


def size_ignores(ignores: dict[str, list[str]]) -> dict[str, set[str]]:
    """The entries that suppress a size rule, including broad prefixes.

    `ALL` is ruff's everything selector and has no prefix relation to the
    codes, so it is checked by name.
    """
    def broad(code: str) -> bool:
        return code == "ALL" or any(rule.startswith(code) for rule in SIZE_RULES)

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
