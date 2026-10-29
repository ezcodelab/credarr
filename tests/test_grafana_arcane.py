"""Grafana service-account tokens and Arcane scoped keys, against fake services.

Both are create-shaped mints: the service generates the secret and returns it
once, so the replacement is made alongside the old credential and the old one
is deleted last. Each measured fact the implementation depends on is pinned
here: the liveness route, the name/prefix the predecessor is found by, the
account/key listing, and the fail-closed checks.
"""

from __future__ import annotations

import urllib.parse
from pathlib import Path

import pytest

from credarr.config import HostConfig
from credarr.errors import ManifestError, RotationError, TransportError
from credarr.executor import Executor, RotationContext
from credarr.journal import Journal
from credarr.model import Manifest
from credarr.redact import Secret
from credarr.rotate import Step, StepKind, plan_rotation

GRAFANA_OLD = "glsa_oldtokenvalue0123456789"
GRAFANA_NEW = "glsa_newtokenvalue0123456789"
ARCANE_OLD = "arc_oldkeyvalue_0123456789"
ARCANE_NEW = "arc_newkeyvalue_0123456789"
ARCANE_ROTATOR = "arc_rotatorkeyvalue_0123456789"
GRAFANA_LOGIN = "sa-1-credarr-homepage"
GRAFANA_NAME = "homelab-homepage"

GRAFANA_MANIFEST = """
version: 1
credentials:
  grafana_api_token:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [v, grafana]}
    write:
      mechanism: grafana_service_token
      token_name: homelab-homepage
"""

GRAFANA_NO_NAME = GRAFANA_MANIFEST.replace(
    "      token_name: homelab-homepage\n", ""
)

ARCANE_MANIFEST = """
version: 1
credentials:
  arcane_api_key:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [v, arcane]}
    write:
      mechanism: arcane_api_key
      key_name: homelab-deploy-trigger
      permissions: [gitops:list, gitops:sync]
"""

ARCANE_NO_META = """
version: 1
credentials:
  arcane_api_key:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [v, arcane]}
    write:
      mechanism: arcane_api_key
"""

ARCANE_WITH_ROTATOR = """
version: 1
credentials:
  arcane_api_key:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [v, arcane]}
    write:
      mechanism: arcane_api_key
      mint_with: arcane_rotator
"""


def _credential(text: str):
    manifest = Manifest.parse(
        text, known_targets=(), known_backends=("ansible-vault",)
    )
    return next(iter(manifest.credentials.values()))


HOST = HostConfig(
    name="media",
    urls={"grafana": "http://127.0.0.1:3000",
          "arcane": "http://127.0.0.1:3552"},
    containers={},
)


class FakeAPI:
    """Both services' routes, with just enough state to prove the order."""

    def __init__(self) -> None:
        # Grafana tokens by id: a token's value is only ever returned at
        # creation, exactly as the service behaves.
        self.grafana_tokens = {
            "11": {"name": GRAFANA_NAME, "value": GRAFANA_OLD}
        }
        self.grafana_next_id = 12
        self.grafana_denied = False
        # Simulates an access layer that answers 403 for a live old token.
        self.grafana_old_forbidden = False
        self.arcane_keys = {1: {"id": 1, "name": "homelab-deploy-trigger",
                                "isStatic": False,
                                "keyPrefix": ARCANE_OLD[:12],
                                "permissions": [
                                    {"permission": "apikeys:list"},
                                    {"permission": "apikeys:create"},
                                    {"permission": "apikeys:delete"},
                                    {"permission": "gitops:list"},
                                    {"permission": "gitops:sync"},
                                ]}}
        self.arcane_secrets = {ARCANE_OLD: 1}
        self.arcane_next_id = 2
        self.arcane_list_denied = False
        self.arcane_create_denied = False
        self.arcane_old_forbidden = False
        self.arcane_auth: list[str] = []
        self.calls: list[tuple[str, str, str]] = []

    def __call__(self, _host, service, method, path, *, body=None,
                 key=None, auth_header="X-Api-Key", **_kwargs):
        self.calls.append((service, method, path))
        if service == "grafana":
            token = key.removeprefix("Bearer ") if key else None
            if path == "/api/user":
                if any(record["value"] == token
                       for record in self.grafana_tokens.values()):
                    if self.grafana_old_forbidden and token == GRAFANA_OLD:
                        return 403, None
                    return 200, {"id": 0, "login": GRAFANA_LOGIN}
                return 401, None
            if path.startswith("/api/serviceaccounts/search"):
                if self.grafana_denied:
                    return 403, None
                return 200, {"serviceAccounts": [
                    {"id": 1, "name": "credarr-homepage", "login": GRAFANA_LOGIN}
                ]}
            if path == "/api/serviceaccounts/1/tokens" and method == "GET":
                return 200, [
                    {"id": token_id, "name": record["name"]}
                    for token_id, record in self.grafana_tokens.items()
                ]
            if path == "/api/serviceaccounts/1/tokens" and method == "POST":
                if self.grafana_denied:
                    return 403, None
                token_id = str(self.grafana_next_id)
                self.grafana_next_id += 1
                self.grafana_tokens[token_id] = {
                    "name": body["name"], "value": GRAFANA_NEW,
                }
                return 200, {"id": token_id, "key": GRAFANA_NEW,
                             "name": body["name"]}
            if path.startswith("/api/serviceaccounts/1/tokens/") and method == "DELETE":
                self.grafana_tokens.pop(path.rsplit("/", 1)[1], None)
                return 200, None
            return 404, None
        if service == "arcane":
            self.arcane_auth.append(str(key))
            if path == "/api/auth/me":
                if key in self.arcane_secrets:
                    if self.arcane_old_forbidden and key == ARCANE_OLD:
                        return 403, None
                    return 200, {"id": 1, "username": "admin"}
                return 401, None
            if path.startswith("/api/api-keys") and method == "GET":
                if self.arcane_list_denied:
                    return 403, None
                params = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
                search = (params.get("search") or [""])[0]
                start = int((params.get("start") or ["0"])[0])
                limit = int((params.get("limit") or ["100"])[0])
                rows = [
                    dict(row) for row in self.arcane_keys.values()
                    if not search or search in row["name"]
                ]
                return 200, {"data": rows[start:start + limit],
                             "pagination": {"totalItems": len(rows)}}
            if path == "/api/api-keys" and method == "POST":
                if self.arcane_create_denied:
                    return 403, None
                key_id = self.arcane_next_id
                self.arcane_next_id += 1
                self.arcane_keys[key_id] = {
                    "id": key_id, "name": body["name"], "isStatic": False,
                    "isBootstrap": False, "keyPrefix": ARCANE_NEW[:12],
                    "permissions": list(body.get("permissions") or []),
                }
                self.arcane_secrets[ARCANE_NEW] = key_id
                return 200, {"data": {"id": key_id, "key": ARCANE_NEW,
                                      "name": body["name"]}}
            if path.startswith("/api/api-keys/") and method == "DELETE":
                wanted = int(path.rsplit("/", 1)[1])
                self.arcane_keys.pop(wanted, None)
                for value, key_id in list(self.arcane_secrets.items()):
                    if key_id == wanted:
                        del self.arcane_secrets[value]
                return 200, None
            return 404, None
        return 404, None


def _executor(tmp_path: Path, api: FakeAPI, text: str, vault_value: str):
    ctx = RotationContext(
        credential=_credential(text),
        host=HOST,
        transport=None,  # not reached: every call is the fake
        journal=Journal(tmp_path / "j.db"),
        vault_value=vault_value,
        settle_timeout=0.0,
    )
    return Executor(ctx, servarr_call=api), ctx


# -- planning ---------------------------------------------------------------


def test_a_grafana_plan_is_a_create_whose_revoke_runs_last():
    plan = plan_rotation(_credential(GRAFANA_MANIFEST), HOST)

    assert plan.blocked_by == [], plan.blocked_by
    assert plan.executable is True
    assert plan.revokes_before_holders is False
    assert plan.revokes_last is True
    assert [step.kind for step in plan.steps] == [
        StepKind.MINT, StepKind.RECORD, StepKind.REVOKE,
    ]


def test_a_grafana_plan_without_a_token_name_is_refused():
    plan = plan_rotation(_credential(GRAFANA_NO_NAME), HOST)

    assert plan.executable is False
    assert any("write.token_name" in reason for reason in plan.blocked_by)


def test_an_arcane_plan_is_a_create_whose_revoke_runs_last():
    plan = plan_rotation(_credential(ARCANE_MANIFEST), HOST)

    assert plan.blocked_by == [], plan.blocked_by
    assert plan.revokes_before_holders is False
    assert plan.revokes_last is True
    assert [step.kind for step in plan.steps] == [
        StepKind.MINT, StepKind.RECORD, StepKind.REVOKE,
    ]


def test_an_arcane_plan_needs_no_metadata_and_discovers_the_key(tmp_path):
    """The credential's own prefix identifies its row, so name and grants are
    copied from the service instead of being declared."""
    plan = plan_rotation(_credential(ARCANE_NO_META), HOST)

    assert plan.blocked_by == [], plan.blocked_by
    assert plan.revokes_before_holders is False
    assert plan.revokes_last is True
    assert [step.kind for step in plan.steps] == [
        StepKind.MINT, StepKind.RECORD, StepKind.REVOKE,
    ]

    api = FakeAPI()
    executor, ctx = _executor(tmp_path, api, ARCANE_NO_META, ARCANE_OLD)
    detail = executor._reissue_mint(
        Step(StepKind.MINT, "arcane", "mint", reversible=False)
    )

    assert "homelab-deploy-trigger" in detail
    assert ctx.minted == Secret(ARCANE_NEW)
    assert api.arcane_keys[2]["name"] == "homelab-deploy-trigger"
    assert api.arcane_keys[2]["permissions"] == [
        {"permission": "apikeys:list"},
        {"permission": "apikeys:create"},
        {"permission": "apikeys:delete"},
        {"permission": "gitops:list"},
        {"permission": "gitops:sync"},
    ]


def test_an_arcane_plan_refuses_declared_metadata_of_the_wrong_shape():
    plan = plan_rotation(
        _credential(ARCANE_MANIFEST.replace(
            "      permissions: [gitops:list, gitops:sync]\n",
            "      permissions: []\n",
        )),
        HOST,
    )

    assert plan.executable is False
    assert any("write.permissions" in reason for reason in plan.blocked_by)


def test_a_mint_with_self_reference_is_refused():
    plan = plan_rotation(
        _credential(ARCANE_MANIFEST.replace(
            "      key_name:",
            "      mint_with: arcane_api_key\n      key_name:",
        )),
        HOST,
    )

    assert plan.executable is False
    assert any("self-rotate" in reason for reason in plan.blocked_by)


# -- Grafana ----------------------------------------------------------------


def test_grafana_mint_creates_a_replacement_and_leaves_the_old_live(tmp_path):
    api = FakeAPI()
    executor, ctx = _executor(tmp_path, api, GRAFANA_MANIFEST, GRAFANA_OLD)

    detail = executor._reissue_mint(
        Step(StepKind.MINT, "grafana", "mint", reversible=False)
    )

    assert "replacement" in detail
    assert ctx.minted == Secret(GRAFANA_NEW)
    assert ctx.minted_service == "grafana"
    assert ctx.minted_handle == "12"
    # The predecessor survives the mint; the revoke step runs after holders.
    assert any(record["value"] == GRAFANA_OLD
               for record in api.grafana_tokens.values())


def test_grafana_mint_refuses_a_viewer_account_with_the_reason(tmp_path):
    api = FakeAPI()
    api.grafana_denied = True
    executor, ctx = _executor(tmp_path, api, GRAFANA_MANIFEST, GRAFANA_OLD)

    with pytest.raises(RotationError, match="cannot manage tokens"):
        executor._reissue_mint(
            Step(StepKind.MINT, "grafana", "mint", reversible=False)
        )

    assert ctx.minted is None


def test_grafana_revoke_deletes_the_predecessor_and_its_strays(tmp_path):
    api = FakeAPI()
    executor, _ctx = _executor(tmp_path, api, GRAFANA_MANIFEST, GRAFANA_OLD)
    executor._reissue_mint(
        Step(StepKind.MINT, "grafana", "mint", reversible=False)
    )
    # A token an interrupted run left behind, same namespace.
    api.grafana_tokens["13"] = {
        "name": GRAFANA_NAME + ".credarr.1700000000",
        "value": "glsa_strayvalue_0123456789",
    }

    detail = executor._reissue_revoke(
        Step(StepKind.REVOKE, "grafana", "revoke", reversible=False)
    )

    assert "revoked 2" in detail
    assert [record["value"] for record in api.grafana_tokens.values()] == [GRAFANA_NEW]


def test_grafana_revoke_fails_closed_when_the_old_token_survives(tmp_path):
    api = FakeAPI()
    executor, _ctx = _executor(tmp_path, api, GRAFANA_MANIFEST, GRAFANA_OLD)
    executor._reissue_mint(
        Step(StepKind.MINT, "grafana", "mint", reversible=False)
    )
    # A human renames the predecessor between mint and revoke, so the declared
    # name matches nothing and the old value is still live after the revoke.
    api.grafana_tokens["11"]["name"] = "renamed-by-hand"

    with pytest.raises(RotationError, match="still live"):
        executor._reissue_revoke(
            Step(StepKind.REVOKE, "grafana", "revoke", reversible=False)
        )


def test_grafana_revoke_does_not_read_a_403_as_revoked(tmp_path):
    """A 403 is not a credential verdict: an access layer answers it for a
    live token too."""
    api = FakeAPI()
    executor, _ctx = _executor(tmp_path, api, GRAFANA_MANIFEST, GRAFANA_OLD)
    executor._reissue_mint(
        Step(StepKind.MINT, "grafana", "mint", reversible=False)
    )
    api.grafana_tokens["11"]["name"] = "renamed-by-hand"
    api.grafana_old_forbidden = True

    with pytest.raises(RotationError, match="still live"):
        executor._reissue_revoke(
            Step(StepKind.REVOKE, "grafana", "revoke", reversible=False)
        )


# -- Arcane -----------------------------------------------------------------


def test_arcane_mint_creates_a_same_named_key_and_keeps_the_old_live(tmp_path):
    api = FakeAPI()
    executor, ctx = _executor(tmp_path, api, ARCANE_MANIFEST, ARCANE_OLD)

    detail = executor._reissue_mint(
        Step(StepKind.MINT, "arcane", "mint", reversible=False)
    )

    assert "replacement" in detail
    assert ctx.minted == Secret(ARCANE_NEW)
    assert ctx.minted_handle == "2"
    assert ARCANE_OLD in api.arcane_secrets


def test_arcane_refuses_a_static_bootstrap_key_before_minting(tmp_path):
    api = FakeAPI()
    api.arcane_keys[1]["isStatic"] = True
    executor, ctx = _executor(tmp_path, api, ARCANE_MANIFEST, ARCANE_OLD)

    with pytest.raises(RotationError, match="static"):
        executor._reissue_mint(
            Step(StepKind.MINT, "arcane", "mint", reversible=False)
        )

    assert ctx.minted is None


def test_arcane_refuses_an_environment_pairing_key_before_minting(tmp_path):
    """`isBootstrap` is the second protected shape: a live environment
    authenticates with that key, and Arcane refuses to delete it."""
    api = FakeAPI()
    api.arcane_keys[1]["isBootstrap"] = True
    executor, ctx = _executor(tmp_path, api, ARCANE_MANIFEST, ARCANE_OLD)

    with pytest.raises(RotationError, match="pairing key"):
        executor._reissue_mint(
            Step(StepKind.MINT, "arcane", "mint", reversible=False)
        )

    assert ctx.minted is None


def _add_rotator(
    api: FakeAPI,
    permissions: tuple[str, ...] = (
        "apikeys:list", "apikeys:create", "apikeys:delete", "gitops:list",
    ),
) -> None:
    api.arcane_keys[3] = {
        "id": 3, "name": "arcane-rotator", "isStatic": False,
        "keyPrefix": ARCANE_ROTATOR[:12],
        "permissions": [{"permission": item} for item in permissions],
    }
    api.arcane_secrets[ARCANE_ROTATOR] = 3


def test_arcane_rotates_a_least_privilege_key_with_the_rotator(tmp_path):
    """The target cannot mint anything itself; the rotator's value authorises
    both the create and the delete, and the copied grants stay the target's."""
    api = FakeAPI()
    api.arcane_keys[1]["permissions"] = [{"permission": "gitops:list"}]
    _add_rotator(api)
    executor, ctx = _executor(tmp_path, api, ARCANE_WITH_ROTATOR, ARCANE_OLD)
    ctx.mint_values = {"arcane_rotator": Secret(ARCANE_ROTATOR)}

    detail = executor._reissue_mint(
        Step(StepKind.MINT, "arcane", "mint", reversible=False)
    )

    assert "arcane_rotator" in detail
    assert ARCANE_ROTATOR in api.arcane_auth
    assert api.arcane_keys[2]["permissions"] == [{"permission": "gitops:list"}]

    executor._reissue_revoke(
        Step(StepKind.REVOKE, "arcane", "revoke", reversible=False)
    )

    assert ARCANE_ROTATOR in api.arcane_auth
    assert set(api.arcane_keys) == {2, 3}


def test_arcane_mint_refuses_when_the_declared_rotator_is_missing(tmp_path):
    api = FakeAPI()
    executor, ctx = _executor(tmp_path, api, ARCANE_WITH_ROTATOR, ARCANE_OLD)

    with pytest.raises(RotationError, match="no stored value"):
        executor._reissue_mint(
            Step(StepKind.MINT, "arcane", "mint", reversible=False)
        )

    assert ctx.minted is None


def test_arcane_preflight_reports_a_rotator_without_mint_permissions(tmp_path):
    api = FakeAPI()
    _add_rotator(api, permissions=("gitops:list",))
    executor, ctx = _executor(tmp_path, api, ARCANE_WITH_ROTATOR, ARCANE_OLD)
    ctx.mint_values = {"arcane_rotator": Secret(ARCANE_ROTATOR)}

    problems = executor.preflight(plan_rotation(_credential(ARCANE_WITH_ROTATOR), HOST))

    assert any(
        "rotator" in problem and "apikeys" in problem for problem in problems
    ), problems


def test_arcane_mint_403_names_the_permissions_it_needs(tmp_path):
    api = FakeAPI()
    api.arcane_create_denied = True
    executor, ctx = _executor(tmp_path, api, ARCANE_MANIFEST, ARCANE_OLD)

    with pytest.raises(RotationError, match="apikeys:create"):
        executor._reissue_mint(
            Step(StepKind.MINT, "arcane", "mint", reversible=False)
        )

    assert ctx.minted is None


def test_arcane_revoke_deletes_the_predecessor_and_its_strays(tmp_path):
    api = FakeAPI()
    executor, _ctx = _executor(tmp_path, api, ARCANE_MANIFEST, ARCANE_OLD)
    executor._reissue_mint(
        Step(StepKind.MINT, "arcane", "mint", reversible=False)
    )
    # A key a dead run left behind under the same name.
    api.arcane_keys[7] = {"id": 7, "name": "homelab-deploy-trigger",
                          "isStatic": False}
    api.arcane_secrets["arc_stray_0123456789"] = 7

    detail = executor._reissue_revoke(
        Step(StepKind.REVOKE, "arcane", "revoke", reversible=False)
    )

    assert "revoked 2" in detail
    assert set(api.arcane_keys) == {2}
    assert set(api.arcane_secrets) == {ARCANE_NEW}


def test_arcane_revoke_fails_closed_when_the_old_key_survives(tmp_path):
    api = FakeAPI()
    executor, _ctx = _executor(tmp_path, api, ARCANE_MANIFEST, ARCANE_OLD)
    executor._reissue_mint(
        Step(StepKind.MINT, "arcane", "mint", reversible=False)
    )
    # The old key is now named something else, so nothing matches for deletion.
    api.arcane_keys[1]["name"] = "renamed-by-hand"

    with pytest.raises(RotationError, match="still live"):
        executor._reissue_revoke(
            Step(StepKind.REVOKE, "arcane", "revoke", reversible=False)
        )


def test_arcane_revoke_does_not_read_a_403_as_revoked(tmp_path):
    api = FakeAPI()
    executor, _ctx = _executor(tmp_path, api, ARCANE_MANIFEST, ARCANE_OLD)
    executor._reissue_mint(
        Step(StepKind.MINT, "arcane", "mint", reversible=False)
    )
    api.arcane_keys[1]["name"] = "renamed-by-hand"
    api.arcane_old_forbidden = True

    with pytest.raises(RotationError, match="still live"):
        executor._reissue_revoke(
            Step(StepKind.REVOKE, "arcane", "revoke", reversible=False)
        )


def test_arcane_revoke_sweeps_every_page_of_keys(tmp_path):
    """A sweep that stopped at page one would leave a stray key live while
    reporting a clean revoke."""
    api = FakeAPI()
    executor, _ctx = _executor(tmp_path, api, ARCANE_MANIFEST, ARCANE_OLD)
    executor._reissue_mint(
        Step(StepKind.MINT, "arcane", "mint", reversible=False)
    )
    for key_id in range(100, 201):
        api.arcane_keys[key_id] = {"id": key_id,
                                   "name": "homelab-deploy-trigger",
                                   "isStatic": False}
        api.arcane_secrets[f"arc_stray_{key_id}"] = key_id

    detail = executor._reissue_revoke(
        Step(StepKind.REVOKE, "arcane", "revoke", reversible=False)
    )

    assert "revoked 102" in detail
    assert set(api.arcane_keys) == {2}


def test_two_arcane_credentials_cannot_name_one_key():
    text = ARCANE_MANIFEST + """
  arcane_api_key_two:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [v, arcane2]}
    write:
      mechanism: arcane_api_key
      key_name: homelab-deploy-trigger
      permissions: [gitops:list]
"""

    with pytest.raises(ManifestError, match="both name the Arcane key"):
        Manifest.parse(text, known_targets=(), known_backends=("ansible-vault",))


def test_arcane_mint_refuses_when_the_stored_key_is_not_listed(tmp_path):
    api = FakeAPI()
    api.arcane_keys = {2: {"id": 2, "name": "someone-else",
                           "keyPrefix": "arc_ffffffff"}}
    executor, ctx = _executor(tmp_path, api, ARCANE_NO_META, ARCANE_OLD)

    with pytest.raises(RotationError, match="not in the service's key list"):
        executor._reissue_mint(
            Step(StepKind.MINT, "arcane", "mint", reversible=False)
        )

    assert ctx.minted is None


def test_arcane_mint_refuses_a_declared_name_that_does_not_match(tmp_path):
    text = ARCANE_MANIFEST.replace(
        "key_name: homelab-deploy-trigger", "key_name: something-else"
    )
    api = FakeAPI()
    executor, ctx = _executor(tmp_path, api, text, ARCANE_OLD)

    with pytest.raises(RotationError, match=r"write\.key_name"):
        executor._reissue_mint(
            Step(StepKind.MINT, "arcane", "mint", reversible=False)
        )

    assert ctx.minted is None
    assert 2 not in api.arcane_keys


# -- preflight --------------------------------------------------------------


def test_both_new_plans_pass_a_preflight_with_a_live_value(tmp_path):
    api = FakeAPI()
    executor, _ = _executor(tmp_path, api, GRAFANA_MANIFEST, GRAFANA_OLD)
    assert executor.preflight(plan_rotation(_credential(GRAFANA_MANIFEST), HOST)) == []

    executor, _ = _executor(tmp_path, api, ARCANE_MANIFEST, ARCANE_OLD)
    assert executor.preflight(plan_rotation(_credential(ARCANE_MANIFEST), HOST)) == []


def test_grafana_preflight_refuses_a_viewer_account_before_apply(tmp_path):
    api = FakeAPI()
    api.grafana_denied = True
    executor, _ = _executor(tmp_path, api, GRAFANA_MANIFEST, GRAFANA_OLD)

    problems = executor.preflight(plan_rotation(_credential(GRAFANA_MANIFEST), HOST))

    assert any("cannot manage tokens" in problem for problem in problems), problems


def test_arcane_preflight_refuses_a_static_key_before_apply(tmp_path):
    api = FakeAPI()
    api.arcane_keys[1]["isStatic"] = True
    executor, _ = _executor(tmp_path, api, ARCANE_MANIFEST, ARCANE_OLD)

    problems = executor.preflight(plan_rotation(_credential(ARCANE_MANIFEST), HOST))

    assert any("static" in problem for problem in problems), problems


def test_arcane_preflight_refuses_a_pairing_key_before_apply(tmp_path):
    api = FakeAPI()
    api.arcane_keys[1]["isBootstrap"] = True
    executor, _ = _executor(tmp_path, api, ARCANE_MANIFEST, ARCANE_OLD)

    problems = executor.preflight(plan_rotation(_credential(ARCANE_MANIFEST), HOST))

    assert any("pairing key" in problem for problem in problems), problems


def test_grafana_preflight_reports_a_stalled_host_as_a_problem(tmp_path):
    """A transport failure mid-check is one problem among the others, not an
    exception that drops every problem already found."""
    api = FakeAPI()
    executor, _ = _executor(tmp_path, api, GRAFANA_MANIFEST, GRAFANA_OLD)

    def stalled(host, service, method, path, **kwargs):
        if path.startswith("/api/serviceaccounts/search"):
            raise TransportError("grafana stalled")
        return api(host, service, method, path, **kwargs)

    executor._call = stalled
    problems = executor.preflight(plan_rotation(_credential(GRAFANA_MANIFEST), HOST))

    assert any("stalled" in problem for problem in problems), problems
