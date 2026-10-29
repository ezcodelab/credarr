"""The runtime seam: the store's working copy is what the audit compares.

DECISIONS decision 2 claims the app does not read a vault at runtime. These
tests pin that where it can actually break: an audit through
`runtime_manifest` + `StoreSource` must find the working copy the store
holds - and must not find the declared vault reference, which is provenance.
"""

from __future__ import annotations

import pytest

from conftest import SONARR_KEY
from credarr import facade
from credarr.audit import AuditResult, Status
from credarr.errors import ExitCode, SecretSourceError
from credarr.model import Credential, Manifest, VaultRef
from credarr.redact import Secret
from credarr.report import exit_code_for
from credarr.targets import build_registry
from credarr_server.source import (
    APP_BACKEND,
    StoreSource,
    app_ref,
    rotation_manifest,
    runtime_manifest,
    stored_service_keys,
)
from credarr_server.store import TopologyStore

REGISTRY = build_registry()


def audit(app) -> AuditResult:
    return facade.audit(
        app.config, runtime_manifest(app.store), StoreSource(app.store)
    )


def test_the_working_copy_is_what_the_audit_compares(app) -> None:
    result = audit(app)
    assert [(r.credential.name, r.status) for r in result.results] == [
        ("sonarr_api_key", Status.MATCH),
        ("seerr_api_key", Status.INDIRECT),
    ]
    assert result.exit_status is Status.MATCH


def test_a_changed_working_copy_reads_as_drift(app) -> None:
    app.store.set_value("sonarr_api_key", Secret("0" * 32))
    result = audit(app)
    assert [r.status for r in result.results] == [Status.DRIFT, Status.INDIRECT]
    # The same exit code the CLI would give for the same audit (report.py),
    # which is what the ledger records.
    assert exit_code_for(result) == ExitCode.DRIFT


def test_a_credential_without_a_working_copy_is_not_drift(
    tmp_path, app
) -> None:
    """Unverifiable, not a problem: the app has nothing to compare yet, and a
    fresh install must not report every credential as failed."""
    bare = TopologyStore(tmp_path / "bare.db")
    bare.import_manifest(app.manifest, REGISTRY)
    result = facade.audit(app.config, runtime_manifest(bare), StoreSource(bare))
    assert [r.status for r in result.results] == [
        Status.UNVERIFIABLE, Status.UNVERIFIABLE
    ]
    assert result.problems == []
    assert result.exit_status is Status.UNVERIFIABLE


def test_the_declared_vault_becomes_the_app_reference_at_runtime(app) -> None:
    credential = runtime_manifest(app.store).credentials["sonarr_api_key"]
    assert credential.vault == app_ref(app.store.path, "sonarr_api_key")
    assert credential.vault.backend == APP_BACKEND
    # Provenance stays where export needs it: the stored topology still names
    # the vault the value was imported from.
    declared = app.store.load_manifest().credentials["sonarr_api_key"].vault
    assert declared is not None and declared.backend == "ansible-vault"


def test_the_source_returns_the_stored_value(app) -> None:
    value = StoreSource(app.store).get(app_ref(app.store.path, "sonarr_api_key"))
    assert value is not None and value.reveal() == SONARR_KEY


def test_the_source_refuses_a_declared_vault_reference(app) -> None:
    source = StoreSource(app.store)
    with pytest.raises(SecretSourceError, match="only its own references"):
        source.get(VaultRef(backend="ansible-vault", file="vault.yml", path=("keys", "k")))
    with pytest.raises(SecretSourceError, match="only its own references"):
        source.get(VaultRef(backend=APP_BACKEND, file="app.db", path=()))


def test_a_declared_vault_that_exists_is_still_not_read(app) -> None:
    """The regression this guards is someone rebuilding the vault-backed
    source at runtime: that source would try to read this file and fail on a
    plaintext one, turning the audit into an error. The runtime audit ignores
    the file because `runtime_manifest` replaced the reference."""
    (app.manifest.parent / "vault.yml").write_text(
        "keys:\n  sonarr_api_key: plaintext-not-a-vault\n"
    )
    result = audit(app)
    assert [r.status for r in result.results] == [Status.MATCH, Status.INDIRECT]


def test_the_source_records_a_rotated_value_in_the_working_copy(app) -> None:
    """The engine's setter writes the app's copy, which is what makes the store
    a rotation target rather than only an audit source."""
    rotated = "a" * 32
    StoreSource(app.store).set(
        app_ref(app.store.path, "sonarr_api_key"), Secret(rotated)
    )
    stored = app.store.get_value("sonarr_api_key")
    assert stored is not None and stored.reveal() == rotated
    assert [r.status for r in audit(app).results] == [Status.DRIFT, Status.INDIRECT]


def test_the_source_refuses_to_write_through_a_declared_vault(app) -> None:
    source = StoreSource(app.store)
    with pytest.raises(SecretSourceError, match="only its own references"):
        source.set(
            VaultRef(backend="ansible-vault", file="vault.yml", path=("keys", "k")),
            Secret("x"),
        )


def test_the_rotation_manifest_anchors_only_the_target(app) -> None:
    """A rotation records into the app's store whether or not a value has been
    stored yet; every other credential keeps its declared reference."""
    manifest = rotation_manifest(app.store, "sonarr_api_key")
    assert manifest.credentials["sonarr_api_key"].vault == app_ref(
        app.store.path, "sonarr_api_key"
    )
    declared = app.store.load_manifest().credentials["sonarr_api_key"].vault
    assert declared is not None and declared.backend == "ansible-vault"


def test_the_rotation_manifest_cannot_anchor_an_undeclared_name(app) -> None:
    from credarr_server.store import UnknownCredential

    with pytest.raises(UnknownCredential):
        rotation_manifest(app.store, "nope")


def test_a_services_own_key_is_a_normal_stored_credential(app) -> None:
    """`<service>_api_key` is the whole convention; no parallel map type."""
    keys = stored_service_keys(app.store, app.store.load_manifest())
    assert keys["sonarr"].reveal() == SONARR_KEY


def test_an_unstored_service_key_is_not_answered(app) -> None:
    """Declared is not stored: the resolver must fall back, not invent a key."""
    bare = TopologyStore(app.store.path.with_name("bare-keys.db"))
    bare.import_manifest(app.manifest, REGISTRY)
    assert stored_service_keys(bare, bare.load_manifest()) == {}


def test_a_service_key_uses_the_same_service_derivation_as_the_planner() -> None:
    """`canonical.service` must win over a name the convention cannot read.

    The production Jellyfin credential is `jellyfin_api_token`, not
    `jellyfin_api_key`; deriving only from a suffix would lose its key.
    """
    manifest = Manifest(
        version=1,
        credentials={
            "jellyfin_api_token": Credential(
                name="jellyfin_api_token", canonical={"service": "jellyfin"}
            ),
            "sonarr_api_key": Credential(name="sonarr_api_key"),
        },
    )

    class StubStore:
        def get_value(self, name: str) -> Secret | None:
            return {
                "jellyfin_api_token": Secret("jellyfin-key"),
                "sonarr_api_key": Secret("sonarr-key"),
            }.get(name)

    keys = stored_service_keys(StubStore(), manifest)  # type: ignore[arg-type]
    assert keys["jellyfin"].reveal() == "jellyfin-key"
    assert keys["sonarr"].reveal() == "sonarr-key"


def test_a_ui_password_is_not_mistaken_for_the_services_api_key() -> None:
    """The new credential's name naturally starts with the service name.

    `sonarr_ui_password` derives to `sonarr`, so a first-match resolver would
    hand a web password to holder API calls. The declared UI password must be
    skipped; the service's own key remains the API key.
    """
    manifest = Manifest(
        version=1,
        credentials={
            "sonarr_ui_password": Credential(name="sonarr_ui_password"),
            "sonarr_api_key": Credential(
                name="sonarr_api_key",
                write={"ui_password": "sonarr_ui_password"},
            ),
        },
    )

    class StubStore:
        def get_value(self, name: str) -> Secret | None:
            return {
                "sonarr_ui_password": Secret("ui-password"),
                "sonarr_api_key": Secret("sonarr-key"),
            }.get(name)

    keys = stored_service_keys(StubStore(), manifest)  # type: ignore[arg-type]

    assert keys["sonarr"].reveal() == "sonarr-key"


def test_a_cross_service_ui_password_does_not_remove_the_real_key() -> None:
    """The resolver scopes the exclusion to the referencing service.

    A bad `prowlarr_api_key` line naming `sonarr_api_key` as its UI password is
    refused by the planner, but the resolver must not let that line hide
    Sonarr's real API key if it is ever read from an unplanned manifest.
    """
    manifest = Manifest(
        version=1,
        credentials={
            "sonarr_api_key": Credential(name="sonarr_api_key"),
            "prowlarr_api_key": Credential(
                name="prowlarr_api_key",
                write={"ui_password": "sonarr_api_key"},
            ),
        },
    )

    class StubStore:
        def get_value(self, name: str) -> Secret | None:
            return {
                "sonarr_api_key": Secret("sonarr-key"),
                "prowlarr_api_key": Secret("prowlarr-key"),
            }.get(name)

    keys = stored_service_keys(StubStore(), manifest)  # type: ignore[arg-type]

    assert keys["sonarr"].reveal() == "sonarr-key"
    assert keys["prowlarr"].reveal() == "prowlarr-key"
