"""Gitea token rotation, against a fake service.

Gitea's token routes are Basic-auth only, so a token cannot rotate itself: the
manifest names a password credential through `write.mint_with` and the user
through `write.username`. The token list exposes `token_last_eight`, which is
what lets the credential's own value identify its row.
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from credarr.config import HostConfig
from credarr.errors import RotationError
from credarr.executor import Executor, RotationContext
from credarr.journal import Journal
from credarr.model import Manifest
from credarr.redact import Secret
from credarr.rotate import Step, StepKind, plan_rotation

GITEA_OLD = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4"
GITEA_NEW = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c"
PASSWORD = "fixture-admin-pass"

MANIFEST = """
version: 1
credentials:
  gitea_api_token:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [v, gitea]}
    write:
      mechanism: gitea_token
      username: admin
      mint_with: gitea_admin_password
  gitea_admin_password:
    class: B
    never_rotate: true
    vault: {backend: ansible-vault, file: v.yml, path: [v, gitea_password]}
"""

NO_ROTATOR = """
version: 1
credentials:
  gitea_api_token:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [v, gitea]}
    write:
      mechanism: gitea_token
      username: admin
"""

HOOK_MANIFEST = """
version: 1
credentials:
  gitea_webhook_secret:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [v, hook]}
    write:
      mechanism: gitea_hook_secret
      mint_with: gitea_api_token
      repo: admin/fx-repo
      hook_url: http://deploy/hook
  gitea_api_token:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [v, gitea]}
    write:
      mechanism: gitea_token
      username: admin
      mint_with: gitea_admin_password
  gitea_admin_password:
    class: B
    never_rotate: true
    vault: {backend: ansible-vault, file: v.yml, path: [v, gitea_password]}
"""

HOOK_NO_FIELDS = """
version: 1
credentials:
  gitea_webhook_secret:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [v, hook]}
    write:
      mechanism: gitea_hook_secret
"""


def _credential(text: str):
    manifest = Manifest.parse(
        text, known_targets=(), known_backends=("ansible-vault",)
    )
    return next(iter(manifest.credentials.values()))


HOST = HostConfig(
    name="media", urls={"gitea": "http://127.0.0.1:3010"}, containers={}
)


class FakeAPI:
    def __init__(self) -> None:
        self.tokens = {
            1: {"id": 1, "name": "fx-deploy", "token_last_eight": GITEA_OLD[-8:],
                "scopes": ["write:repository", "read:repository"]},
        }
        self.secrets = {GITEA_OLD: 1}
        self.next_id = 2
        self.basic_denied = False
        self.create_denied = False
        self.hook_denied = False
        self.hooks = {
            1: {"id": 1, "config": {"url": "http://deploy/hook",
                                    "content_type": "json"}},
        }
        self.hook_secrets = {1: "old-webhook-secret"}
        self.hook_tests = 0
        self.calls: list[tuple[str, str, str]] = []

    def __call__(self, _host, service, method, path, *, body=None, key=None,
                 auth_header="X-Api-Key", **_kwargs):
        self.calls.append((service, method, path))
        if service != "gitea":
            return 404, None
        if path == "/user":
            value = key.removeprefix("token ") if key else None
            if value not in self.secrets:
                return 401, None
            scopes = self.tokens[self.secrets[value]].get("scopes") or []
            # Gitea answers 403 when the token is live but lacks read:user.
            return (200, {"login": "admin"}) if "read:user" in scopes else (403, None)
        if path.startswith("/users/admin/tokens"):
            expected = "Basic " + base64.b64encode(
                f"admin:{PASSWORD}".encode()
            ).decode()
            if self.basic_denied or key != expected:
                return 401, None
            if method == "GET":
                return 200, [dict(row) for row in self.tokens.values()]
            if method == "POST" and path == "/users/admin/tokens":
                if self.create_denied:
                    return 403, None
                if any(row.get("name") == body["name"]
                       for row in self.tokens.values()):
                    # Gitea rejects a duplicate token name for one user; the
                    # mint namespaces the replacement instead.
                    return 400, None
                token_id = self.next_id
                self.next_id += 1
                self.tokens[token_id] = {
                    "id": token_id, "name": body["name"],
                    "token_last_eight": GITEA_NEW[-8:], "scopes": body["scopes"],
                }
                self.secrets[GITEA_NEW] = token_id
                return 201, {"id": token_id, "name": body["name"],
                             "sha1": GITEA_NEW, "scopes": body["scopes"]}
            if method == "DELETE":
                wanted = int(path.rsplit("/", 1)[1])
                self.tokens.pop(wanted, None)
                for value, token_id in list(self.secrets.items()):
                    if token_id == wanted:
                        del self.secrets[value]
                return 204, None
        if path == "/repos/admin/fx-repo/hooks" and method == "GET":
            value = key.removeprefix("token ") if key else None
            if value not in self.secrets:
                return 401, None
            return 200, [
                {"id": row["id"], "config": dict(row["config"])}
                for row in self.hooks.values()
            ]
        if path == "/repos/admin/fx-repo/hooks/1" and method == "PATCH":
            value = key.removeprefix("token ") if key else None
            if value not in self.secrets:
                return 401, None
            if self.hook_denied:
                return 403, None
            secret = (body.get("config") or {}).get("secret")
            if not secret:
                return 422, None
            self.hook_secrets[1] = secret
            # Gitea never returns the secret; the response echoes the rest.
            return 200, {"id": 1, "config": dict(self.hooks[1]["config"])}
        if path == "/repos/admin/fx-repo/hooks/1/tests" and method == "POST":
            self.hook_tests += 1
            return 204, None
        return 404, None


def _executor(tmp_path: Path, api: FakeAPI, text: str = MANIFEST,
              mint_values: dict | None = None):
    ctx = RotationContext(
        credential=_credential(text),
        host=HOST,
        transport=None,
        journal=Journal(tmp_path / "j.db"),
        vault_value=GITEA_OLD,
        mint_values=mint_values if mint_values is not None else {
            "gitea_admin_password": Secret(PASSWORD),
        },
        settle_timeout=0.0,
    )
    return Executor(ctx, servarr_call=api), ctx


def test_a_gitea_plan_requires_the_password_rotator():
    plan = plan_rotation(_credential(NO_ROTATOR), HOST)

    assert plan.executable is False
    assert any("write.mint_with is required" in reason for reason in plan.blocked_by)


def test_a_gitea_plan_is_a_create_whose_revoke_runs_last():
    plan = plan_rotation(_credential(MANIFEST), HOST)

    assert plan.blocked_by == [], plan.blocked_by
    assert plan.revokes_before_holders is False
    assert plan.revokes_last is True
    assert [step.kind for step in plan.steps] == [
        StepKind.MINT, StepKind.RECORD, StepKind.REVOKE,
    ]


def test_gitea_mint_copies_the_scopes_and_namespaces_the_name(tmp_path):
    api = FakeAPI()
    executor, ctx = _executor(tmp_path, api)

    detail = executor._reissue_mint(
        Step(StepKind.MINT, "gitea", "mint", reversible=False)
    )

    assert "fx-deploy" in detail
    assert ctx.minted == Secret(GITEA_NEW)
    assert ctx.minted_handle == "2"
    assert api.tokens[2]["name"].startswith("fx-deploy.credarr.")
    assert api.tokens[2]["scopes"] == ["write:repository", "read:repository"]
    # The predecessor is untouched until the revoke step.
    assert GITEA_OLD in api.secrets


def test_gitea_mint_refuses_when_the_stored_token_is_not_listed(tmp_path):
    api = FakeAPI()
    api.tokens = {}
    executor, ctx = _executor(tmp_path, api)

    with pytest.raises(RotationError, match="not in the user's token list"):
        executor._reissue_mint(
            Step(StepKind.MINT, "gitea", "mint", reversible=False)
        )

    assert ctx.minted is None


def test_gitea_mint_refuses_a_declared_name_that_does_not_match(tmp_path):
    text = MANIFEST.replace("      username: admin\n",
                            "      username: admin\n      token_name: something-else\n")
    api = FakeAPI()
    executor, ctx = _executor(tmp_path, api, text)

    with pytest.raises(RotationError, match=r"write\.token_name"):
        executor._reissue_mint(
            Step(StepKind.MINT, "gitea", "mint", reversible=False)
        )

    assert ctx.minted is None


def test_gitea_revoke_deletes_the_predecessor_and_its_strays(tmp_path):
    api = FakeAPI()
    executor, _ctx = _executor(tmp_path, api)
    executor._reissue_mint(
        Step(StepKind.MINT, "gitea", "mint", reversible=False)
    )
    api.tokens[7] = {"id": 7, "name": "fx-deploy",
                     "token_last_eight": "deadbeef", "scopes": ["read:user"]}
    api.secrets["deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"] = 7

    detail = executor._reissue_revoke(
        Step(StepKind.REVOKE, "gitea", "revoke", reversible=False)
    )

    assert "revoked 2" in detail
    assert set(api.tokens) == {2}
    assert set(api.secrets) == {GITEA_NEW}

def test_gitea_revoke_fails_closed_when_the_old_token_survives(tmp_path):
    api = FakeAPI()
    executor, _ctx = _executor(tmp_path, api)
    executor._reissue_mint(
        Step(StepKind.MINT, "gitea", "mint", reversible=False)
    )
    api.tokens[1]["name"] = "renamed-by-hand"

    with pytest.raises(RotationError, match="still live"):
        executor._reissue_revoke(
            Step(StepKind.REVOKE, "gitea", "revoke", reversible=False)
        )


def test_gitea_preflight_reports_bad_basic_auth(tmp_path):
    api = FakeAPI()
    api.basic_denied = True
    executor, _ctx = _executor(tmp_path, api)

    problems = executor.preflight(plan_rotation(_credential(MANIFEST), HOST))

    assert any("Basic auth was refused" in problem for problem in problems), problems


def test_gitea_preflight_reports_a_missing_rotator(tmp_path):
    api = FakeAPI()
    executor, ctx = _executor(tmp_path, api)
    ctx.mint_values = {}

    problems = executor.preflight(plan_rotation(_credential(MANIFEST), HOST))

    assert any("no stored value" in problem for problem in problems), problems


# -- webhook secret ---------------------------------------------------------


def test_a_hook_plan_requires_the_token_and_the_hook_identity():
    plan = plan_rotation(_credential(HOOK_NO_FIELDS), HOST)

    assert plan.executable is False
    reasons = " ".join(plan.blocked_by)
    assert "write.mint_with" in reasons
    assert "write.repo" in reasons
    assert "write.hook_url" in reasons


def test_a_hook_plan_revokes_before_holders():
    plan = plan_rotation(_credential(HOOK_MANIFEST), HOST)

    assert plan.blocked_by == [], plan.blocked_by
    assert plan.revokes_before_holders is True
    assert [step.kind for step in plan.steps] == [
        StepKind.MINT, StepKind.RECORD,
    ]


def test_the_hook_secret_is_chosen_and_written_over_the_api(tmp_path):
    api = FakeAPI()
    executor, ctx = _executor(
        tmp_path, api, HOOK_MANIFEST,
        mint_values={"gitea_api_token": Secret(GITEA_OLD)},
    )

    detail = executor._dispatch(
        Step(StepKind.MINT, "gitea", "mint", reversible=False)
    )

    assert ctx.minted is not None
    assert ctx.minted.reveal() != "old-webhook-secret"
    assert api.hook_secrets[1] == ctx.minted.reveal()
    assert api.hook_tests == 1
    assert "test delivery" in detail


def test_the_hook_mint_refuses_when_no_hook_matches(tmp_path):
    api = FakeAPI()
    api.hooks = {}
    executor, ctx = _executor(
        tmp_path, api, HOOK_MANIFEST,
        mint_values={"gitea_api_token": Secret(GITEA_OLD)},
    )

    with pytest.raises(RotationError, match="no hook"):
        executor._mint_gitea_hook(
            Step(StepKind.MINT, "gitea", "mint", reversible=False)
        )

    assert ctx.minted is None


def test_the_hook_update_refusal_keeps_the_old_secret(tmp_path):
    api = FakeAPI()
    api.hook_denied = True
    executor, ctx = _executor(
        tmp_path, api, HOOK_MANIFEST,
        mint_values={"gitea_api_token": Secret(GITEA_OLD)},
    )

    with pytest.raises(RotationError, match="HTTP 403"):
        executor._mint_gitea_hook(
            Step(StepKind.MINT, "gitea", "mint", reversible=False)
        )

    assert api.hook_secrets[1] == "old-webhook-secret"
    assert ctx.minted is None


def test_hook_preflight_reports_a_missing_hook(tmp_path):
    api = FakeAPI()
    api.hooks = {}
    executor, _ctx = _executor(
        tmp_path, api, HOOK_MANIFEST,
        mint_values={"gitea_api_token": Secret(GITEA_OLD)},
    )

    problems = executor.preflight(plan_rotation(_credential(HOOK_MANIFEST), HOST))

    assert any("no hook" in problem for problem in problems), problems
