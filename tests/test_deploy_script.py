"""The apps pin travels as an AGit PR, never as a push to protected main.

`make ship` once built and pushed an image and then failed at
`git push origin main` into homelab-applications, leaving the stack on the old
image while the driver reported a failure at the last step. These scans are
cheap and catch the obvious regression.
"""

from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "deploy-gitea"


def test_pin_uses_agit_and_not_a_push_to_main():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "refs/for/main" in text
    assert "push origin main" not in text
    assert "reset --hard" not in text


def test_pin_is_checked_against_origin_main():
    # The local file alone is how a stale, unmerged pin commit read as success.
    text = SCRIPT.read_text(encoding="utf-8")
    assert "show origin/main:compose/credarr/compose.yaml" in text


def test_merge_token_is_operator_supplied():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "${GITEA_TOKEN:-}" in text
    # No file, vault or default value may stand in for the operator's token.
    assert "gitea.token" not in text
    assert "GITEA_TOKEN=" not in text.replace("GITEA_TOKEN=$GITEA_TOKEN", "")
