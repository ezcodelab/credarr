"""The app's own working copies, presented to the engine as a secret source.

DECISIONS decision 2: SQLite is the runtime source of record and a vault is
an import/export format. So the runtime audit does not read ansible-vault or
sops - it compares the values the app holds against what the stack holds.
This module is that seam. `runtime_manifest` gives every credential whose
value the app holds the app's own reference, and `StoreSource` answers those
references from the topology store.

The declared vault references stay in the store (`load_manifest`), where
export needs them; at runtime they are provenance - where a value came from -
and nothing reads them.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from credarr.config import Config
from credarr.errors import SecretSourceError
from credarr.model import Credential, Manifest, VaultRef
from credarr.redact import Secret
from credarr.rotate import service_for, ui_password_names

from .store import TopologyStore, UnknownCredential

APP_BACKEND = "credarr"


def app_ref(database: Path, name: str) -> VaultRef:
    """The reference the app answers for one credential's working copy."""
    return VaultRef(backend=APP_BACKEND, file=str(database), path=(name,))


def runtime_config(config: Config, store: TopologyStore) -> Config:
    """The config the engine should use, with store service facts overlaid.

    `credarr.yaml` remains the deployment bootstrap and keeps secrets out of the
    database. Once a service row exists, the store is authoritative for its
    URL: a blank field clears the YAML value, because otherwise an operator
    could not remove a stale URL from the console. Container names stay
    read-only discovery metadata in the file.
    """
    services = store.services()
    if not services:
        return config
    host = config.host(config.default_host)
    urls = dict(host.urls)
    for service in services:
        if service.url is None:
            urls.pop(service.name, None)
        else:
            urls[service.name] = service.url
    hosts = dict(config.hosts)
    hosts[config.default_host] = replace(host, urls=urls)
    return replace(config, hosts=hosts)


def runtime_manifest(store: TopologyStore) -> Manifest:
    """The stored topology as the engine should see it at runtime.

    A credential whose value the app holds gets the app's own reference; one
    without keeps `vault: None`, which the audit reports as unverifiable
    rather than as drift - nothing is wrong, the value has simply not been
    stored yet. The engine's wording for that state is its own ("no canonical
    reference in the manifest"); the app's copy for it is "no value stored
    yet" and belongs to the UI.
    """
    manifest = store.load_manifest()
    # Presence, not values: one query answers the whole topology. A per-name
    # `get_value` loop opened a connection per credential just to discard the
    # secret.
    #
    # shortcut: a value cleared between this read and the audit reads as
    # ERROR (exit 4) for one run, and a value stored after it reads as
    # unverifiable; the next run corrects either. Revisit if the UI offers
    # "run now" while an import is in flight.
    stored = set(store.working_copy_times())
    credentials = {}
    for name, credential in manifest.credentials.items():
        credentials[name] = replace(
            credential, vault=app_ref(store.path, name) if name in stored else None
        )
    return Manifest(version=manifest.version, credentials=credentials)


def rotation_manifest(store: TopologyStore, name: str) -> Manifest:
    """The stored topology with `name` re-anchored to the app's own store.

    `runtime_manifest` leaves a credential with no working copy without a
    vault, because an audit must report it as unverifiable rather than as
    drift. A rotation needs the opposite: it mints, records the new value and
    compares the service against the app's copy, so the app's reference is the
    canonical one whether or not a value is stored yet. Every other credential
    keeps the reference it declared - this is the one being rotated.
    """
    manifest = store.load_manifest()
    if name not in manifest.credentials:
        raise UnknownCredential(name)
    credentials = dict(manifest.credentials)
    credentials[name] = replace(
        manifest.credentials[name], vault=app_ref(store.path, name)
    )
    return Manifest(version=manifest.version, credentials=credentials)


def stored_service_keys(
    store: TopologyStore, manifest: Manifest
) -> dict[str, Secret]:
    """The app's working copies of each service's own API key.

    This is the store-first half of the holder-key resolver. A service's own key
    is a normal credential, so the service is derived exactly as the planner
    derives it: an explicit `canonical.service`, else the credential's name
    (`sonarr_api_key` -> `sonarr`, `jellyfin_api_token` -> `jellyfin`). There is
    no parallel service-key map to keep in sync. A credential the derivation
    cannot place, or one with no stored value, simply supplies no key; there is
    no local config fallback.

    Only stored values are returned. A declared-but-unstored credential is not
    a key, and reading its vault would make this path a vault reader - which
    the runtime deliberately is not.
    """
    keys: dict[str, Secret] = {}
    for name, credential in manifest.credentials.items():
        if name in ui_password_names(manifest, service_for(credential)):
            continue
        value = store.get_value(name)
        if value is not None:
            keys.setdefault(service_for(credential), value)
    return keys


def stored_mint_values(
    store: TopologyStore, manifest: Manifest, credential: Credential
) -> dict[str, Secret]:
    """The stored values of credentials this one names for a mint.

    `write.mint_with` lets a least-privilege credential be rotated by the admin
    credential that holds the minting grants. `write.ui_password` names the
    credential holding the service's own UI password, which opens the backup
    download when the service's authentication is on. Only the named working
    copies are read, and only when this credential asks for them; a missing
    name or value comes back empty so preflight and the mint report it in their
    own words.
    """
    declared: set[str] = set()
    for field_name in ("mint_with", "ui_password"):
        name = str(credential.write.get(field_name) or "").strip()
        if name:
            declared.add(name)
    values: dict[str, Secret] = {}
    for name in declared:
        other = manifest.credentials.get(name)
        if other is None or not other.provisioned:
            continue
        value = store.get_value(name)
        if value is not None:
            values[name] = value
    return values


class StorePending:
    """The app database's pending-mint slot."""

    def __init__(self, store: TopologyStore) -> None:
        self.store = store

    def get(self, credential: str) -> Secret | None:
        return self.store.get_pending(credential)

    def set(self, credential: str, value: Secret) -> None:
        self.store.set_pending(credential, value)

    def clear(self, credential: str) -> None:
        self.store.clear_pending(credential)


class StoreSource:
    """A `SecretSource` that reads and records the app's working copies."""

    name = "the app store"

    def __init__(self, store: TopologyStore) -> None:
        self.store = store

    def _name(self, ref: VaultRef) -> str:
        if ref.backend != APP_BACKEND or len(ref.path) != 1:
            raise SecretSourceError(
                f"the app store answers only its own references, not "
                f"{ref.backend} {ref.file}",
                hint="a manifest loaded at runtime carries app references; "
                "a declared vault belongs to import and export",
            )
        return ref.path[0]

    def get(self, ref: VaultRef) -> Secret | None:
        return self.store.get_value(self._name(ref))

    def set(self, ref: VaultRef, value: Secret) -> None:
        """Record the new value after a rotation, so the next audit compares
        the stack against what this app minted.

        The engine calls this with the reference the plan was built against
        (`rotation_manifest`), so the name in the ref is the credential being
        rotated. The same reference check as `get`: a declared vault is never a
        runtime write target.
        """
        self.store.set_value(self._name(ref), value)
