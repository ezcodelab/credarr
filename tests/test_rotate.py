"""The rotation planner.

The planner's job is not to rotate. It is to refuse to plan a rotation that
cannot finish. A rotation that stops halfway leaves the new value in the vault
and nowhere else, so the service it belongs to breaks in a way nobody will
connect back to the change that caused it.

These tests therefore care most about the refusals.
"""

from __future__ import annotations

import pytest

from credarr.config import HostConfig
from credarr.errors import ManifestError
from credarr.model import Manifest
from credarr.rotate import StepKind, plan_rotation, service_for
from credarr.targets import build_registry

REGISTRY = build_registry()

HOST = HostConfig(
    name="media",
    urls={"sonarr": "http://127.0.0.1:8989", "radarr": "http://127.0.0.1:7878",
          "prowlarr": "http://127.0.0.1:9696"},
)



JELLYFIN_MANIFEST = """
version: 1
credentials:
  jellyfin_api_token:
    class: A
    max_age_days: 90
    canonical: {service: jellyfin}
    vault: {backend: ansible-vault, file: v.yml, path: [a, b]}
    write: {mechanism: jellyfin_auth_keys}
    consumers:
      - target: seerr.settings_json[jellyfin]
        count: 1
        mechanism: process_api
"""

def _credential(text: str):
    manifest = Manifest.parse(
        text, known_targets=REGISTRY.known_targets(), known_backends=("ansible-vault",)
    )
    return next(iter(manifest.credentials.values()))


MINIMAL = """
version: 1
credentials:
  prowlarr_api_key:
    class: A-unv
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [a, b]}
    write: {mechanism: servarr_command}
    consumers:
      - target: sonarr.indexers
        count: 10
      - target: radarr.indexers
        count: 6
      - target: homepage.label
        mechanism: redeploy
"""

NO_HOLDERS = """
version: 1
credentials:
  prowlarr_api_key:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [a, b]}
    write: {mechanism: servarr_command}
"""

SEERR_SELF = """
version: 1
credentials:
  seerr_api_key:
    class: A
    max_age_days: 90
    canonical: {service: seerr}
    vault: {backend: ansible-vault, file: v.yml, path: [a, b]}
    write: {mechanism: seerr_regenerate}
"""


def test_a_complete_rotation_is_executable():
    plan = plan_rotation(_credential(MINIMAL), HOST)

    assert plan.executable
    assert plan.blocked_by == []
    targets = [s.target for s in plan.steps]
    assert targets == [
        "prowlarr",          # mint
        "sonarr.indexers",   # propagate
        "radarr.indexers",   # propagate
        "homepage.label",    # manual redeploy
        "a.b",               # vault
    ]


def test_a_credential_with_no_holders_still_plans_its_mint_and_record():
    """No holders means nothing to propagate, not nothing to rotate.

    An unused service key still needs a fresh value; the absence of copies is
    not a refusal, and inventing one would make the UI's Plan action lie.
    """
    plan = plan_rotation(_credential(NO_HOLDERS), HOST)

    assert plan.blocked_by == [], plan.blocked_by
    assert plan.executable
    kinds = [step.kind for step in plan.steps]
    assert StepKind.MINT in kinds
    assert StepKind.RECORD in kinds
    assert StepKind.PROPAGATE not in kinds
    assert StepKind.MANUAL not in kinds


def test_a_seerr_key_with_no_holders_rotates_itself():
    """Seerr's own key is a mint, not a holder.

    The service can regenerate its single key over its settings API, so an
    undeclared copy is not a reason to refuse: with no holders the plan is the
    mint plus the record, and the new key is still proven live by the executor.
    """
    plan = plan_rotation(_credential(SEERR_SELF), HOST)

    assert plan.blocked_by == [], plan.blocked_by
    assert plan.executable
    assert plan.mint_via == "regenerate"
    assert plan.revokes_before_holders
    assert [step.kind for step in plan.steps] == [StepKind.MINT, StepKind.RECORD]
    assert [step.target for step in plan.steps] == ["seerr", "a.b"]


def test_a_servarr_plan_uses_the_backup_api_not_a_config_path():
    """The access promise: a URL and an API key are enough. The plan must say
    what it replaces and that it restarts, before anyone approves it."""
    host = HostConfig(
        name="media",
        urls={"prowlarr": "http://127.0.0.1:9696"},
        containers={"prowlarr": "prowlarr"},
    )
    plan = plan_rotation(_credential(MINIMAL), host)

    assert plan.executable
    assert plan.mint_via == "backup_restore"
    mints = [step for step in plan.steps if step.kind is StepKind.MINT]
    assert len(mints) == 1
    assert mints[0].reversible is False
    assert "back up config over the API" in mints[0].detail
    assert "config file" in mints[0].reason
    assert "pending" in mints[0].reason
    assert "restart" in mints[0].reason


def test_the_mint_step_is_marked_irreversible():
    """Mint invalidates the old key before any consumer has the new one. There
    is no way back, and the plan must not imply otherwise."""
    plan = plan_rotation(_credential(MINIMAL), HOST)
    mint = next(s for s in plan.steps if s.kind is StepKind.MINT)

    assert mint.reversible is False


def test_an_unknown_target_is_refused_before_planning():
    """An unknown holder cannot reach the planner and become a skip.

    The static registry is deliberately unforgiving: a target with no writer is
    rejected while parsing, so a typo cannot silently leave a live service
    holding a revoked key.
    """
    with pytest.raises(ManifestError, match=r"acme\.arr_config"):
        _credential(MINIMAL.replace("sonarr.indexers", "acme.arr_config[Sonarr]"))


def test_profilarr_is_a_known_manual_target() -> None:
    """The copy validates, but the plan names it for the operator instead of
    pretending this build can write Profilarr's Arr row."""
    text = MINIMAL.replace(
        "sonarr.indexers", "profilarr.arr_config[Sonarr]"
    )
    plan = plan_rotation(_credential(text), HOST)
    manual = [step for step in plan.steps if step.kind is StepKind.MANUAL]

    assert any(step.target == "profilarr.arr_config[Sonarr]" for step in manual)
    assert plan.executable


def test_an_unknown_mint_mechanism_blocks_rather_than_guessing():
    text = MINIMAL.replace("mechanism: servarr_command", "mechanism: something_new")
    plan = plan_rotation(_credential(text), HOST)

    assert not plan.executable
    assert any("something_new" in reason for reason in plan.blocked_by)


def test_a_credential_with_no_vault_reference_blocks():
    text = MINIMAL.replace(
        "    vault: {backend: ansible-vault, file: v.yml, path: [a, b]}\n", ""
    )
    plan = plan_rotation(_credential(text), HOST)

    assert not plan.executable
    assert any("vault" in reason for reason in plan.blocked_by)


def test_indirect_consumers_are_listed_not_silently_dropped():
    """They need a redeploy. A rotation that forgets them leaves a live service
    holding a revoked key, and the plan is the last place to notice."""
    plan = plan_rotation(_credential(MINIMAL), HOST)
    manual = [s for s in plan.steps if s.kind is StepKind.MANUAL]

    assert len(manual) == 1
    assert manual[0].target == "homepage.label"
    assert plan.executable


def test_a_holder_with_no_writer_becomes_a_named_manual_step():
    """The plan runs and says which copy to update by hand.

    A manual step keeps the run INCOMPLETE (exit 1) and blocks auto-rotation,
    so "we could not write it" is never reported as delivered.
    """
    text = """
version: 1
credentials:
  prowlarr_api_key:
    class: A-unv
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [a, b]}
    write: {mechanism: servarr_command}
    consumers:
      - target: acme.secret
"""
    manifest = Manifest.parse(
        text, known_targets=("acme.secret",), known_backends=("ansible-vault",)
    )
    credential = next(iter(manifest.credentials.values()))
    plan = plan_rotation(credential, HOST)

    manual = [s for s in plan.steps if s.kind is StepKind.MANUAL]
    assert plan.executable
    assert [step.target for step in manual] == ["acme.secret"]
    assert "update this copy by hand" in manual[0].detail


def test_every_step_explains_itself():
    """A plan nobody can justify is a plan nobody should approve."""
    plan = plan_rotation(_credential(MINIMAL), HOST)
    assert all(s.reason for s in plan.steps)


# -- the class is enforced, not merely documented ------------------------------
#
# Every refusal so far came from a holder's missing writer or an unsupported
# mechanism. Those are different questions: a writer is a fact about one holder
# and can be added tomorrow, while the class is the operator's judgement about
# the whole credential. With nothing reading it, adding a writer would have
# silently lifted the refusal the class exists to impose.

WRITABLE_A_UNV = """
version: 1
credentials:
  prowlarr_api_key:
    class: A-unv
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [a, b]}
    write: {mechanism: servarr_command}
    consumers:
      - target: sonarr.indexers
        count: 2
"""


def test_class_a_unv_rotates_when_every_holder_has_a_writer():
    """A-unv no longer blocks: it runs and leaves manual steps where it must.

    Both holders here have writers and the mint mechanism is supported, so the
    plan is executable. The class is still read - B and never_rotate refuse -
    but A-unv is "rotate now, finish by hand", not a refusal.
    """
    plan = plan_rotation(_credential(WRITABLE_A_UNV), HOST)

    assert plan.executable
    assert not any("A-unv" in reason for reason in plan.blocked_by)


def test_class_b_is_refused_even_with_a_supported_mechanism():
    """A manifest can declare B while naming a mintable mechanism.

    Nothing stops an operator writing that. The class is the authoritative
    statement that the value cannot be minted here, so it has to win over a
    mechanism string that happens to parse.
    """
    # An age keeps `never_rotate` out of it, so this tests the class alone.
    text = WRITABLE_A_UNV.replace("class: A-unv", "class: B").replace(
        "max_age_days: 90", "max_age_days: 180"
    )
    plan = plan_rotation(_credential(text), HOST)

    assert not plan.executable
    assert any("class B" in reason for reason in plan.blocked_by)
    assert not any("never_rotate" in reason for reason in plan.blocked_by)


def test_never_rotate_is_refused_whatever_the_class_says():
    text = MINIMAL.replace(
        "class: A-unv", "class: A-unv\n    never_rotate: true"
    )
    plan = plan_rotation(_credential(text), HOST)

    assert not plan.executable
    assert any("never_rotate" in reason for reason in plan.blocked_by)


def test_class_a_with_writers_is_still_executable():
    """The control: class A is not a blanket refusal."""
    text = WRITABLE_A_UNV.replace("class: A-unv", "class: A")
    plan = plan_rotation(_credential(text), HOST)

    assert plan.executable
    assert plan.blocked_by == []


def test_class_a_runs_an_indirect_copy_as_manual():
    """The copy is manual; the key still rotates and the operator is told."""
    text = MINIMAL.replace("class: A-unv", "class: A")
    plan = plan_rotation(_credential(text), HOST)

    assert plan.executable
    assert plan.blocked_by == []
    assert any(
        step.kind is StepKind.MANUAL and step.target == "homepage.label"
        for step in plan.steps
    )


def test_class_a_runs_a_copy_this_build_cannot_write():
    """A missing writer names the copy; it does not freeze the mint."""
    text = """
version: 1
credentials:
  prowlarr_api_key:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [a, b]}
    write: {mechanism: servarr_command}
    consumers:
      - target: acme.secret
"""
    manifest = Manifest.parse(
        text, known_targets=("acme.secret",), known_backends=("ansible-vault",)
    )
    credential = next(iter(manifest.credentials.values()))
    plan = plan_rotation(credential, HOST)

    assert plan.executable
    assert any(
        step.kind is StepKind.MANUAL and step.target == "acme.secret"
        for step in plan.steps
    )


def test_class_a_runs_a_writer_with_no_confirmation_route():
    """The row is written; the run reports it unproven rather than refusing."""
    text = """
version: 1
credentials:
  lidarr_api_key:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [a, b]}
    write: {mechanism: servarr_command}
    consumers:
      - target: lidarr.indexers
        count: 1
"""
    plan = plan_rotation(_credential(text), HOST)

    assert plan.executable
    assert plan.blocked_by == []
    assert any(
        step.kind is StepKind.PROPAGATE and step.target == "lidarr.indexers"
        for step in plan.steps
    )


def test_a_refused_plan_still_lists_its_steps_and_every_reason():
    """An operator needs the whole picture, not only the refusal."""
    plan = plan_rotation(
        _credential(WRITABLE_A_UNV.replace(
            "    vault: {backend: ansible-vault, file: v.yml, path: [a, b]}\n", ""
        )),
        HOST,
    )

    assert not plan.executable
    assert [s.target for s in plan.steps], "the step list vanished behind the refusal"
    assert any("no vault reference" in r for r in plan.blocked_by), plan.blocked_by


# -- revocation ordering is published, not implied ----------------------------


def test_a_servarr_plan_states_that_it_revokes_before_propagating():
    plan = plan_rotation(_credential(MINIMAL), HOST)
    assert plan.revokes_before_holders is True


def test_the_ordering_flag_is_published_in_the_json_payload():
    """A consumer reading only the payload must be able to see the window.

    The decision record for Sonarr and Radarr requires holders updated before
    revocation, which a Servarr key cannot satisfy. The refusal is the resolution;
    this is what stops the payload from implying otherwise.
    """
    import io
    import json as _json

    from credarr.report import render_rotation_json

    credential = _credential(MINIMAL)
    stream = io.StringIO()
    render_rotation_json(credential, HOST, plan_rotation(credential, HOST), stream)
    payload = _json.loads(stream.getvalue())

    assert payload["revokes_before_holders"] is True
    assert payload["refused"] is False


def test_a_jellyfin_key_plan_mints_before_revoking(tmp_path):
    """The mint must not revoke. Jellyfin holds many API keys at once.

    Every Servarr mint revokes immediately, which forces a window where every
    holder holds a dead key. Jellyfin does not: the mint creates a second key
    and the old one is deleted at the end. So the plan must say the mint does
    not revoke, and must carry a REVOKE step that comes after every holder.
    """
    credential = _credential(JELLYFIN_MANIFEST)

    plan = plan_rotation(credential, HOST)

    assert plan.blocked_by == [], plan.blocked_by
    assert plan.revokes_before_holders is False
    kinds = [s.kind for s in plan.steps]
    assert StepKind.MINT in kinds and StepKind.REVOKE in kinds
    assert kinds.index(StepKind.MINT) < kinds.index(StepKind.REVOKE)
    # Revoke comes after the holders: a Jellyfin key left live until every
    # holder is confirmed is the whole point of the mechanism.
    assert kinds.index(StepKind.PROPAGATE) < kinds.index(StepKind.REVOKE)


def test_a_jellyfin_credential_is_minted_from_its_name(tmp_path):
    """The production manifest names the credential and says nothing else.

    `canonical.service` is the override; the name is the default path, and it
    has to know the services this build can mint for. A jellyfin credential
    that reaches planning as its own name is refused with `unknown service`,
    which reads like an operator error and is not one.
    """
    manifest = """
version: 1
credentials:
  jellyfin_api_token:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [a, b]}
    write: {mechanism: jellyfin_auth_keys}
    consumers:
      - target: seerr.settings_json[jellyfin]
        count: 1
        mechanism: process_api
"""
    credential = _credential(manifest)

    plan = plan_rotation(credential, HOST)

    assert plan.blocked_by == [], plan.blocked_by
    assert [s.target for s in plan.steps if s.kind is StepKind.MINT] == ["jellyfin"]


def test_the_service_a_credential_belongs_to_has_one_derivation():
    """The planner and the capability report must not disagree about which
    service a credential is attached to - a second copy of this rule would let
    one say "prowlarr can rotate this" while the plan refuses as an unknown
    name.

    The name is the default path, and a name that resolves to nothing comes
    back as itself rather than as a guess; the override is a separate test.
    """
    assert service_for(_credential(MINIMAL)) == "prowlarr"
    assert service_for(_credential(JELLYFIN_MANIFEST)) == "jellyfin"
    assert service_for(
        _credential(MINIMAL.replace("prowlarr_api_key", "mystery_password"))
    ) == "mystery_password"
    assert service_for(
        _credential(MINIMAL.replace("prowlarr_api_key", "qbittorrent_password"))
    ) == "qbittorrent"


def test_canonical_service_overrides_the_name():
    """The name is a convenience, so the declared service has to win.

    `readarr_api_key` derives `readarr`, which this build has no mint source
    for: without the override the plan refuses with `unknown service`, and with
    it the mint asks Sonarr - the service the credential actually belongs to.
    """
    manifest = """
version: 1
credentials:
  readarr_api_key:
    class: A
    max_age_days: 90
    canonical: {service: sonarr}
    vault: {backend: ansible-vault, file: v.yml, path: [a, b]}
    write: {mechanism: servarr_command}
    consumers:
      - target: sonarr.indexers
        count: 1
"""
    credential = _credential(manifest)

    assert service_for(credential) == "sonarr"
    plan = plan_rotation(credential, HOST)
    assert plan.blocked_by == [], plan.blocked_by
    # Both mint steps - the backup and the restore - ask Sonarr, and nothing in
    # the plan is named after the credential.
    assert {s.target for s in plan.steps if s.kind is StepKind.MINT} == {"sonarr"}


def test_a_jellyfin_name_with_a_servarr_mechanism_is_refused(tmp_path):
    """The name must not route a create-only service to a reset.

    `servarr_command` plans a backup/restore mint; Jellyfin has no such
    mechanism, and its create mechanism needs a REVOKE step this plan would
    never add. A name that resolves must not make that plan look legitimate.
    """
    manifest = """
version: 1
credentials:
  jellyfin_api_token:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [a, b]}
    write: {mechanism: servarr_command}
    consumers:
      - target: seerr.settings_json[jellyfin]
        count: 1
        mechanism: process_api
"""
    credential = _credential(manifest)

    plan = plan_rotation(credential, HOST)

    assert any("Servarr-style reset" in b for b in plan.blocked_by), plan.blocked_by
    assert StepKind.MINT not in [s.kind for s in plan.steps], [
        (s.kind, s.target) for s in plan.steps
    ]


MANUAL_MINT = MINIMAL.replace(
    "write: {mechanism: servarr_command}",
    "write: {mechanism: servarr_command, manual_mint: true}",
)


def test_a_manual_mint_plan_uses_a_supplied_key_and_no_backup():
    """The opt-out is a plan shape, not a preflight surprise.

    The operator rotates the key in the service's own UI; the plan must say
    there is no backup or restore before it is approved. The old key is already
    revoked at that point, so the revoke-before-holders warning still applies.
    """
    plan = plan_rotation(_credential(MANUAL_MINT), HOST)

    assert plan.blocked_by == [], plan.blocked_by
    assert plan.mint_via == "provided"
    assert plan.revokes_before_holders
    mint = next(step for step in plan.steps if step.kind is StepKind.MINT)
    assert "no backup" in mint.detail
    assert "manual_mint" in mint.reason
    assert "backup/restore" not in mint.detail


def test_manual_mint_and_a_ui_password_cannot_be_combined():
    text = MINIMAL.replace(
        "write: {mechanism: servarr_command}",
        "write: {mechanism: servarr_command, manual_mint: true, "
        "ui_password: sonarr_ui_password}",
    )
    plan = plan_rotation(_credential(text), HOST)

    assert any("cannot both be declared" in reason for reason in plan.blocked_by)


def test_a_ui_password_must_name_a_different_credential():
    text = MINIMAL.replace(
        "write: {mechanism: servarr_command}",
        "write: {mechanism: servarr_command, ui_password: prowlarr_api_key}",
    )
    plan = plan_rotation(_credential(text), HOST)

    assert any("must not name this credential" in reason for reason in plan.blocked_by)


def test_a_manual_mint_outside_servarr_is_refused():
    text = JELLYFIN_MANIFEST.replace(
        "write: {mechanism: jellyfin_auth_keys}",
        "write: {mechanism: jellyfin_auth_keys, manual_mint: true}",
    )
    plan = plan_rotation(_credential(text), HOST)

    assert any(
        "only for write.mechanism 'servarr_command'" in reason
        for reason in plan.blocked_by
    )


def test_a_ui_password_stays_on_the_backup_restore_path():
    """The UI credential is an authentication aid, not a second mint shape.

    It only changes who opens the download; the plan still uses the measured
    backup/restore mint and names the credential so the operator can see what
    will be used.
    """
    text = MINIMAL.replace(
        "write: {mechanism: servarr_command}",
        "write: {mechanism: servarr_command, ui_password: prowlarr_ui_password}",
    )
    plan = plan_rotation(_credential(text), HOST)

    assert plan.blocked_by == [], plan.blocked_by
    assert plan.mint_via == "backup_restore"
    mint = next(step for step in plan.steps if step.kind is StepKind.MINT)
    assert "prowlarr_ui_password" in mint.reason


def test_a_ui_password_must_name_a_credential_for_the_same_service():
    """A cross-service reference is a typo, not a UI password.

    It would also make the service-key resolver skip another service's real API
    key, so the planner refuses it by the name convention before that matters.
    """
    text = MINIMAL.replace(
        "write: {mechanism: servarr_command}",
        "write: {mechanism: servarr_command, ui_password: sonarr_ui_password}",
    )
    plan = plan_rotation(_credential(text), HOST)

    assert any(
        "must name a credential for 'prowlarr'" in reason
        for reason in plan.blocked_by
    )


RECONSTRUCT = MINIMAL.replace(
    "write: {mechanism: servarr_command}",
    "write: {mechanism: servarr_command, reconstruct_config: true}",
)


def test_a_reconstructed_plan_is_automatic_and_skips_the_backup_download():
    plan = plan_rotation(_credential(RECONSTRUCT), HOST)

    assert plan.blocked_by == [], plan.blocked_by
    assert plan.executable
    assert plan.mint_via == "reconstructed"
    assert plan.revokes_before_holders
    mint = next(step for step in plan.steps if step.kind is StepKind.MINT)
    assert "config.xml" in mint.detail
    assert "restore" in mint.detail
    assert "no backup" in mint.reason.lower()
    assert "PostgreSQL" in mint.reason
    assert "AllowedHosts" in mint.reason


def test_reconstruct_config_cannot_be_combined_with_the_other_opt_ins():
    for other in ("manual_mint: true", "ui_password: prowlarr_ui_password"):
        text = MINIMAL.replace(
            "write: {mechanism: servarr_command}",
            f"write: {{mechanism: servarr_command, reconstruct_config: true, "
            f"{other}}}",
        )
        plan = plan_rotation(_credential(text), HOST)
        assert any("cannot be combined" in reason for reason in plan.blocked_by)


def test_reconstruct_config_is_refused_outside_servarr():
    text = JELLYFIN_MANIFEST.replace(
        "write: {mechanism: jellyfin_auth_keys}",
        "write: {mechanism: jellyfin_auth_keys, reconstruct_config: true}",
    )
    plan = plan_rotation(_credential(text), HOST)

    assert any(
        "only for write.mechanism 'servarr_command'" in reason
        for reason in plan.blocked_by
    )
