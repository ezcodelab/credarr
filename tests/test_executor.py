"""The executor.

This is the only module that writes anywhere, so the tests concentrate on the
three ways it could hurt somebody:

- **It writes and cannot prove it did.** The *arr indexer endpoint redacts
  apiKey on read, so the API cannot confirm its own write. Verification must come
  from the database, and a write that the API accepted but the database does not
  hold has to be a failure.
- **It re-runs and mints again.** Re-minting after a partial failure produces a
  third key and invalidates whatever the second one already reached. The
  executor has to notice that the service already moved on.
- **It fails halfway and leaves the stack inconsistent.** That is the real
  hazard, and the answer is not to prevent it - it is to make it visible and
  stop.

Everything here runs against fakes. Nothing in this file touches a live service.
"""

from __future__ import annotations

import base64
import io
import json
import time
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from credarr.config import HostConfig
from credarr.errors import RotationError, TransportError
from credarr.executor import (
    CONFIG_READ_TIMEOUT,
    MAX_JSON_RESPONSE_BYTES,
    ExecutionResult,
    Executor,
    RotationContext,
    _config_xml_api_key,
    _config_xml_from_host,
    _servarr_backup_config,
    _servarr_restore_config,
)
from credarr.executor import _servarr_call as real_servarr_call
from credarr.journal import Journal
from credarr.model import Manifest
from credarr.pending import FilePending
from credarr.redact import Secret
from credarr.rotate import RotationPlan, Step, StepKind
from credarr.transport import LocalTransport

REGISTRY_TARGETS = (
    "sonarr.indexers", "radarr.indexers", "prowlarr.indexers",
    "sonarr.download_clients", "radarr.download_clients",
    "prowlarr.applications", "sonarr.applications", "radarr.applications",
    "homepage.label",
)

MANIFEST = """
version: 1
credentials:
  prowlarr_api_key:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [a, b]}
    write: {mechanism: servarr_command}
    consumers:
      - target: sonarr.indexers
        count: 2
      - target: radarr.indexers
        count: 1
"""

SELF_MANIFEST = """
version: 1
credentials:
  sonarr_api_key:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [a, b]}
    write: {mechanism: servarr_command}
    consumers:
      - target: sonarr.indexers
        count: 2
"""

OLD_KEY = "old-key-value-0000000"
NEW_KEY = "new-key-value-1111111"


def _credential():
    manifest = Manifest.parse(MANIFEST, known_targets=REGISTRY_TARGETS,
                              known_backends=("ansible-vault",))
    return next(iter(manifest.credentials.values()))


HOST = HostConfig(
    name="media",
    urls={"sonarr": "http://127.0.0.1:8989", "radarr": "http://127.0.0.1:7878",
          "prowlarr": "http://127.0.0.1:9696"},
    containers={s: s for s in ("sonarr", "radarr", "prowlarr", "seerr")},
)


class FakeState:
    """The world: a service key, the rows in each database, what the API does."""

    def __init__(self) -> None:
        # Each service authenticates with its own key. The credential being
        # rotated - Prowlarr's - is a different value entirely.
        self.service_key = {"prowlarr": OLD_KEY, "sonarr": "sonarr-own-key",
                            "radarr": "radarr-own-key"}
        self.rows = {"sonarr": [OLD_KEY, OLD_KEY], "radarr": [OLD_KEY]}
        # The field name the single-row API answers with. A service that renames
        # it turns the writer's PUT into a no-op answered with a success code.
        self.api_row_field = "apiKey"
        # Keys the service refuses, which is not the same as the key it holds:
        # a service whose in-memory credential diverges from its own config is
        # exactly the state the liveness check exists to notice.
        self.rejects: set[str] = set()
        self.api_accepts_write = True
        self.api_writes = 0
        self.backup_calls = 0
        # Whether seerr answers its readiness endpoint. False models the case
        # a successful restart cannot distinguish from success: the container
        # came up and the application inside it did not.
        self.seerr_up = True
        # What the running seerr process reports it is holding, per service.
        # Absent means "the value that was just written", i.e. it adopted.
        self.seerr_reported: dict[str, str] = {}
        # Models Seerr's PUT delay: the update is acknowledged but not yet
        # reflected on the next GET. Set by PUT, consumed by the next GET.
        self.pending_seerr_update: tuple[str, str] | None = None
        # When True, PUT /settings/{service}/{id} returns 400 (rejected).
        self.seerr_put_fails = False
        # When True, GET /settings/{service} returns 503 during read-back.
        self.seerr_readback_fails = False
        # When True, the process never picks up the new value (always reports old).
        self.seerr_readback_stale = False
        # How many instances the sonarr/radarr settings sections answer with.
        self.seerr_row_count = 1
        # Whether Seerr has a Jellyfin settings object at all.
        self.seerr_missing_jellyfin = False
        # (service, path, auth_header) for every API call, so a test can assert
        # a call was actually made - and with which header - rather than
        # inferring it from the absence of a failure.
        self.api_calls: list[tuple[str, str, str]] = []
        # Jellyfin-specific: every call the fake serves, and the tokens the
        # revoke actually deleted - so a test can assert *which* key went.
        self.jellyfin_calls = 0
        self.deleted: list[str] = []
        self.put_status = 202
        # The refusal body, so a test can assert the service's own words reach
        # the report. Without it no test can supply one.
        self.put_body = None
        # Row names, so a database read scoped to one row can be exercised.
        self.row_names: dict[str, list[str]] = {}
        # Every source the executor asked the transport to run. A regression
        # that reintroduced a host file read would show up here.
        self.sources: list[str] = []
        # Optional proof path: the answer the holder's own test endpoint gives.
        # `None` means accepted. The counterpart judge is opt-in so existing
        # tests that only care about wiring are not forced to model it.
        self.exercise_response: tuple[int, object] | None = None
        self.exercise_calls = 0
        self.exercise_bodies: list[dict] = []
        self.counterpart_key: str | None = None
        # The key each list call presented, and whether list calls authenticate
        # at all. The real endpoint does; the default is permissive so tests
        # about wiring do not need to model authentication.
        self.list_keys: list[tuple[str, str | None]] = []
        self.list_requires_key = False
        # A PUT that is acknowledged but does not change the row. The silent
        # no-op the exercise must not be able to paper over.
        self.write_does_not_persist = False
        # The backup download web route's answer to preflight's read-only probe.
        # A healthy *arr answers 404 for a name that cannot exist; the auth-on
        # shape is 302 to the login (measured on Sonarr/Radarr/Prowlarr).
        self.backup_probe_status = 404
        self.backup_probe_body: object = {"title": "Not Found"}
        self.backup_probe_calls = 0
        # Headers the preflight sent on each backup-download probe. The UI
        # credential path must retry with the session cookie, not just log in.
        self.probe_headers: list[dict[str, str] | None] = []
        # What GET /api/v3/config/host reports to the UI-login helper.
        self.ui_auth_method = "forms"
        self.ui_username = "admin"
        # /system/status reports this; the reconstructed config refuses
        # Postgres because the API does not expose its connection settings.
        self.database_type = "sqlite"
        # Host-config fields a test wants the API to omit.
        self.omit_host_fields: set[str] = set()


class FakeTransport:
    """Serves the backup artifact the API-only mint reads, and records every
    source it was asked to run, so a test can assert which API operation
    happened without opening a socket."""

    def __init__(self, state: FakeState) -> None:
        self.state = state

    def run_python(self, code: str, *, timeout: int | None = None) -> str:
        self.state.sources.append(code)
        if "config.xml" in code:
            # Which service is being asked decides whose key comes back; the
            # backup source carries the service name.
            service = "radarr" if "/radarr/" in code else (
                "sonarr" if "/sonarr/" in code else "prowlarr")
            # The backup's config.xml holds whatever that service currently has.
            return self.state.service_key[service]
        return ""


def _servarr_call(state: FakeState):
    def call(host, service, method, path, *, body=None, key=None, transport=None,
             auth_header="X-Api-Key", auth_transport="header", timeout=None,
             versioned=True, follow_redirects=True, extra_headers=None):
        state.api_calls.append((service, path, auth_header))
        if not versioned and path.startswith("/backup/manual/"):
            state.backup_probe_calls += 1
            state.probe_headers.append(extra_headers)
            if extra_headers and "Cookie" in extra_headers:
                # Logged in: a name that cannot exist is the healthy answer.
                return 404, {"title": "Not Found"}
            return state.backup_probe_status, state.backup_probe_body
        if path == "/config/host" and method == "GET":
            host_config = {
                "bindAddress": "*",
                "port": 8989,
                "sslPort": 9898,
                "enableSsl": False,
                "launchBrowser": True,
                "authenticationMethod": state.ui_auth_method,
                "authenticationRequired": "enabled",
                "allowedHosts": "",
                "analyticsEnabled": True,
                "logLevel": "debug",
                "logSizeLimit": 1,
                "consoleLogLevel": "",
                "branch": "main",
                "sslCertPath": "",
                "sslCertPassword": "",
                "urlBase": "",
                "trustedNetworks": "",
                "instanceName": "Sonarr",
                "updateAutomatically": False,
                "updateMechanism": "docker",
                "updateScriptPath": "",
                "proxyEnabled": False,
                "proxyType": "http",
                "proxyHostname": "",
                "proxyPort": 0,
                "proxyUsername": "",
                "proxyPassword": "",
                "proxyBypassFilter": "",
                "proxyBypassLocalAddresses": False,
                "certificateValidation": "enabled",
                "backupFolder": "",
                "backupInterval": 7,
                "backupRetention": 28,
                "trustCgnatIpAddresses": False,
                "username": state.ui_username,
                "password": "a-hashed-value-must-not-leave-this-response",
                "apiKey": state.service_key["prowlarr"],
            }
            for field in state.omit_host_fields:
                host_config.pop(field, None)
            return 200, host_config
        if service == "seerr" and path.startswith("/settings/"):
            # PUT /settings/{service}/{id} — update an arr instance.
            # The PUT is acknowledged but the process does not pick up the
            # change immediately (measured on a disposable container). The fake
            # models this by applying the update on the next GET, not at PUT
            # time.
            if method == "PUT" and path.count("/") == 3:
                name = path.split("/")[2]
                if state.seerr_put_fails:
                    return 400, {"error": "rejected"}
                # Measured on the pinned image: the schema requires both of
                # these, and a stored instance need not carry them.
                for required in ("enableSeasonFolders", "minimumAvailability"):
                    if required not in (body or {}):
                        return 400, {
                            "message": f"must have required property '{required}'"
                        }
                new_key = body.get("apiKey", NEW_KEY)
                # The PUT is acknowledged but the process picks it up on the next
                # GET. The fake returns the OLD value at PUT time and only the
                # pending update is visible on the subsequent poll.
                state.pending_seerr_update = (name, new_key)
                label = "Sonarr" if name == "sonarr" else "Radarr"
                return 200, [{"id": 0, "name": label, "apiKey": OLD_KEY}]
            if method == "POST" and path == "/settings/jellyfin":
                if state.seerr_put_fails:
                    return 400, {"error": "rejected"}
                if "serverId" in (body or {}):
                    return 400, {"message": "serverId is read-only"}
                if "name" in (body or {}):
                    return 400, {"message": "name is read-only"}
                if "libraries" in (body or {}):
                    return 400, {"message": "libraries is read-only"}
                state.pending_seerr_update = (
                    "jellyfin", (body or {}).get("apiKey", NEW_KEY)
                )
                return 200, {"name": "Jellyfin", "apiKey": OLD_KEY}
            # Seerr's own settings read-back: the running process reporting what
            # it loaded at boot. `seerr_reported` lets a test model a service
            # that is up but holding something else.
            name = path.rsplit("/", 1)[-1]
            if state.seerr_readback_fails:
                return 503, {"error": "unavailable"}
            # Apply any pending PUT update on the first GET after it
            if state.pending_seerr_update and state.pending_seerr_update[0] == name:
                state.seerr_reported[name] = state.pending_seerr_update[1]
                state.pending_seerr_update = None
            if state.seerr_readback_stale:
                value = OLD_KEY
            else:
                value = state.seerr_reported.get(name, NEW_KEY)
            if name == "jellyfin":
                if state.seerr_missing_jellyfin:
                    return 200, {}
                return 200, {
                    "id": 1, "name": "Jellyfin", "libraries": [],
                    "serverId": "synthetic-server", "apiKey": value,
                }
            label = "Sonarr" if name == "sonarr" else "Radarr"
            return 200, [{"id": i, "name": label, "apiKey": value}
                         for i in range(state.seerr_row_count)]
        if path == "/status" and service == "seerr":
            # Seerr's own readiness endpoint - the same one
            # compose/seerr/compose.yaml healthchecks with. It answers without a
            # credential, which is why `key` is ignored here rather than checked.
            return (200 if state.seerr_up else 503), {"version": "3.5.0"}
        if path in ("/indexer/test", "/applications/test"):
            state.exercise_calls += 1
            state.exercise_bodies.append(body)
            if state.exercise_response is not None:
                return state.exercise_response
            if state.counterpart_key is None:
                return 200, {}
            # The measured contract: a mask in the fetched row resolves to the
            # value the process stored; a concrete value is used as supplied.
            # The judge is the counterpart's current key.
            rows = state.rows.get(service, [])
            index = (body or {}).get("id", 0)
            stored = (
                rows[index]
                if isinstance(index, int) and index < len(rows)
                else None
            )
            supplied = next(
                (f.get("value") for f in (body or {}).get("fields") or []
                 if f.get("name") == "apiKey"),
                None,
            )
            value = stored if supplied == "********" else supplied
            if value == state.counterpart_key:
                return 200, {}
            return 400, {"message": "invalid credentials"}
        if path == "/system/backup" and method == "GET":
            # The backup/restore preflight asks whether the stored key can read
            # backups before promising a restore. A key the service holds is
            # enough for this fake; the real backup read is exercised live.
            return (200 if key == state.service_key[service] else 401), []
        if path == "/system/restart" and method == "POST":
            return 200, None
        # The single-row path must be matched first: "/indexers/0" also
        # starts with "/indexers", and testing that the wrong way round makes
        # every write look like a successful read that changed nothing.
        if path.startswith("/indexer/"):
            if method == "GET":
                index = int(path.rsplit("/", 1)[1])
                # The real single-row GET redacts the secret; the write replaces
                # it with the new value, and the exercise must send it back as
                # the mask so the holder resolves its own stored value.
                return 200, {"id": index,
                             "fields": [{"name": state.api_row_field,
                                         "value": "********"}]}
            state.api_writes += 1
            if not state.api_accepts_write:
                return state.put_status, state.put_body
            index = int(path.rsplit("/", 1)[1])
            if not state.write_does_not_persist:
                value = next(
                    (
                        field.get("value")
                        for field in (body or {}).get("fields") or []
                        if field.get("name") == state.api_row_field
                    ),
                    NEW_KEY,
                )
                state.rows[service][index] = value
            return 202, None
        if path == "/indexer":
            state.list_keys.append((service, key))
            if state.list_requires_key and key != state.service_key[service]:
                return 401, None
            # The list redacts apiKey, exactly as the live service does. A
            # writer that trusted this would PUT the redaction back.
            return 200, [
                {"id": i, "fields": [{"name": "apiKey", "value": "********"}]}
                for i in range(len(state.rows[service]))
            ]
        if path == "/system/status":
            # Validates the key against the one the service actually holds, not
            # merely its presence. A fake that accepted any key would make the
            # executor's liveness verification vacuous - it would always pass,
            # and the test would prove nothing.
            expected = state.service_key[service]
            live = key == expected and key not in state.rejects
            return (200 if live else 401), {
                "version": "4.0.0",
                "databaseType": state.database_type,
            }
        return 404, None

    return call


def _plan():
    credential = _credential()
    plan = RotationPlan(credential=credential, host=HOST)
    plan.add(StepKind.MINT, "prowlarr", "backup/restore + restart", reversible=False)
    plan.add(StepKind.PROPAGATE, "sonarr.indexers", "PUT 2 rows")
    plan.add(StepKind.PROPAGATE, "radarr.indexers", "PUT 1 row")
    plan.add(StepKind.MANUAL, "homepage.label", "redeploy")
    return plan


def _executor(tmp_path, state):
    transport = FakeTransport(state)
    ctx = RotationContext(
        credential=_credential(),
        host=HOST,
        transport=transport,
        journal=Journal(tmp_path / "j.db"),
        vault_value=OLD_KEY,
        pending=FilePending(tmp_path / "pending.db"),
        settle_timeout=0.0, write_backoff=0.0,
    )

    def backup(host, service, *, key, transport):
        state.backup_calls += 1
        return _api_xml(state.service_key[service]), "backup.zip"

    def restore(host, service, *, key, xml, transport):
        state.service_key[service] = _config_xml_api_key(xml.decode())
        return 200, None

    return Executor(
        ctx,
        servarr_call=_servarr_call(state),
        servarr_backup=backup,
        servarr_restore=restore,
    ), ctx


JELLYFIN_MANIFEST = """
version: 1
credentials:
  jellyfin_api_token:
    class: A
    max_age_days: 90
    canonical:
      service: jellyfin
    vault: {backend: ansible-vault, file: v.yml, path: [a, b]}
    write: {mechanism: jellyfin_auth_keys}
    consumers:
      - target: seerr.settings_json[jellyfin]
        count: 1
        mechanism: process_api
"""


def _jellyfin_credential():
    return next(iter(Manifest.parse(
        JELLYFIN_MANIFEST,
        known_targets=(*REGISTRY_TARGETS, "seerr.settings_json"),
        known_backends=("ansible-vault",),
    ).credentials.values()))


JELLYFIN_HOST = HostConfig(
    name="media",
    urls={"jellyfin": "http://127.0.0.1:8096"},
    containers={"jellyfin": "jellyfin"},
)


def _query(path: str, name: str) -> str | None:
    """A value out of a query string, by name."""
    for part in path.split("?", 1)[-1].split("&"):
        key, _, value = part.partition("=")
        if key == name:
            return value
    return None


def _jellyfin_executor(tmp_path, *, keys=None, keys_after=None):
    """A Jellyfin host with the keys it currently holds.

    `keys` is what `GET /Auth/Keys` returns *before* minting, so a test decides
    what the running server holds rather than what credarr thinks it does - which
    is the state a real rotation has to reason about. `keys_after` is what the
    second GET returns; if None, `keys` is used for both.

    Every call must carry the one key that could authorise it: while minting
    that is the credential being rotated (`previous-key`, the vault value), and
    at revoke time the key this run minted. A call with any other key is a bug,
    and this fake refuses to let one pass.
    """
    state = FakeState()
    keys_before = keys if keys is not None else []
    keys_after_list = keys_after if keys_after is not None else keys_before
    # Mutable copies: a DELETE has to be visible to the listing that follows
    # it, or the revoke's own confirmation would be answered from a stale
    # snapshot.
    before_rows = [dict(row) for row in keys_before]
    after_rows = [dict(row) for row in keys_after_list]
    ctx_box: list[RotationContext] = []

    def call(host, service, method, path, *, body=None, key=None,
             transport=None, auth_header="X-Api-Key",
             auth_transport="header", timeout=None):
        state.jellyfin_calls += 1
        if path == "/System/Info/Public":
            return 200, {"ProductName": "Jellyfin"}
        if path.startswith("/Auth/Keys"):
            # The key rides in the query string, not a header: Jellyfin's
            # X-Emby-Token is disabled by default from v12, so anything sent
            # there is ignored and the request is anonymous.
            #
            # The executor appends `?ApiKey=` to the *url* after the path, so
            # the path argument here never contains it. The key arrives as the
            # `key` kwarg instead - which is what the fake should assert on.
            minted = ctx_box[0].minted
            expected = minted.reveal() if minted is not None else "previous-key"
            assert key == expected, (
                f"{method} {path} authenticated with an unexpected key: the "
                "mint uses the credential being rotated and the revoke uses "
                "the key it minted"
            )
            if method == "POST":
                # The mint names keys with the same spelling the revoke sweeps
                # by; a change to either that the other did not follow would
                # silently match nothing.
                assert _query(path, "app") == "credarr-jellyfin_api_token", path
                return 204, None
            if method == "DELETE":
                # The row actually goes: the revoke re-lists after deleting,
                # and a fake that kept the row would make that check fail.
                state.api_writes += 1
                state.deleted.append(path.rsplit("/", 1)[-1])
                for rows in (before_rows, after_rows):
                    rows[:] = [row for row in rows
                               if row.get("AccessToken") != state.deleted[-1]]
                return 204, None
            # First GET returns keys before mint; second GET returns keys after
            if not hasattr(state, '_get_count'):
                state._get_count = 0
            state._get_count += 1
            held = before_rows if state._get_count == 1 else after_rows
            return 200, {"Items": list(held)}
        return 404, None

    transport = FakeTransport(state)
    ctx = RotationContext(
        credential=_jellyfin_credential(), host=JELLYFIN_HOST,
        transport=transport,
        journal=Journal(tmp_path / "j.db"), vault_value="previous-key",
        settle_timeout=0.0, write_backoff=0.0,
    )
    ctx_box.append(ctx)
    executor = Executor(ctx, servarr_call=call)
    return executor, ctx, state


def test_a_jellyfin_mint_creates_a_key_and_reads_its_value_back(tmp_path):
    """`POST /Auth/Keys` answers 204, so the value is not in the response.

    The mint has to read it from `GET /Auth/Keys`, and it has to identify which
    one it created by diffing before/after lists.
    """
    before = [{"AppName": "existing", "AccessToken": "old-key"}]
    after = [*before, {"AppName": "credarr-jellyfin", "AccessToken": "created-key"}]
    executor, ctx, _state = _jellyfin_executor(tmp_path, keys=before, keys_after=after)

    executor._dispatch(Step(StepKind.MINT, "jellyfin", "mint",
                            reversible=False))

    assert ctx.minted is not None
    assert ctx.minted.reveal() == "created-key"


def test_a_jellyfin_mint_refuses_when_it_cannot_identify_its_key(tmp_path):
    """The value is what makes the rotation; guessing it is not a rotation.

    If the created key cannot be found among the others, propagating anything
    would put a value Seerr cannot use. Failing closed also leaves a key behind,
    so the failure says so rather than letting it accumulate silently.
    """
    keys = [{"AppName": "someone else", "AccessToken": "unrelated-key"}]
    executor, _ctx, _state = _jellyfin_executor(tmp_path, keys=keys)

    with pytest.raises(RotationError, match="expected exactly one new key"):
        executor._dispatch(Step(StepKind.MINT, "jellyfin", "mint",
                                reversible=False))


def test_a_jellyfin_mint_refuses_without_a_vault_value(tmp_path):
    """The mint authenticates with the credential being rotated.

    With no vault value there is nothing to authenticate with, so the refusal
    has to come before any call: a POST would leave behind a key this run
    cannot identify, and no later run could adopt it either.
    """
    executor, ctx, state = _jellyfin_executor(tmp_path, keys=[])
    ctx.vault_value = None

    with pytest.raises(RotationError, match="holds no value"):
        executor._dispatch(Step(StepKind.MINT, "jellyfin", "mint",
                                reversible=False))

    assert state.jellyfin_calls == 0, "the service was touched anyway"


def test_a_jellyfin_mint_refuses_when_the_vault_key_is_dead(tmp_path):
    """The first GET is the liveness check, and it runs before any POST.

    The key authenticating the mint is the credential being rotated, so a
    vault holding a stale value has to refuse here: minting anyway would
    create a key while the vault's copy is already dead, and this run could
    not even name what it made.
    """
    executor, _ctx, _state = _jellyfin_executor(tmp_path, keys=[])

    def refuse(host, service, method, path, **kwargs):
        assert method == "GET", "a dead vault key must refuse before any POST"
        return 401, {"error": "unauthorized"}

    executor._call = refuse

    with pytest.raises(RotationError, match="would not list its keys"):
        executor._dispatch(Step(StepKind.MINT, "jellyfin", "mint",
                                reversible=False))


def test_a_jellyfin_revoke_deletes_only_the_replaced_key(tmp_path):
    """The vault value is the old key, even after the vault has been written.

    `vault_value` is captured once, when the context is built, and the RECORD
    step happens before this one - so it still names the key that was replaced.
    Revoking the minted one here would delete the credential everything now
    uses, which is the most expensive mistake available.
    """
    keys = [{"AppName": "credarr-jellyfin_api_token",
             "AccessToken": "previous-key"},
            {"AppName": "someone else", "AccessToken": "unrelated-key"}]
    executor, ctx, state = _jellyfin_executor(tmp_path, keys=keys)
    ctx.minted = Secret("created-key")

    detail = executor._dispatch(Step(StepKind.REVOKE, "jellyfin", "revoke",
                                     reversible=False))

    assert state.deleted == ["previous-key"], (
        "the revoke deleted something other than the replaced key")
    assert "revoked" in detail


def test_a_jellyfin_revoke_revokes_every_row_holding_the_replaced_value(tmp_path):
    """Every matching row, not just the first.

    Real tokens are unique, so this is the defensive shape: a key list that
    somehow holds the replaced value twice must come out empty, and stopping
    at the first match would leave a live key behind.
    """
    # Two rows for the *same* token value - a corrupted key list rather than a
    # shape Jellyfin produces. Both must go, not just the first.
    keys = [{"AppName": "credarr-jellyfin_api_token",
             "AccessToken": "previous-key",
             "DateCreated": "2026-01-02T00:00:00Z"},
            {"AppName": "credarr-jellyfin_api_token",
             "AccessToken": "previous-key",
             "DateCreated": "2026-01-01T00:00:00Z"}]
    executor, ctx, state = _jellyfin_executor(tmp_path, keys=keys)
    ctx.minted = Secret("created-key")

    executor._dispatch(Step(StepKind.REVOKE, "jellyfin", "revoke",
                            reversible=False))

    assert state.deleted == ["previous-key", "previous-key"], (
        "only one of the two was revoked")


def test_a_jellyfin_revoke_failure_is_reported_as_drift(tmp_path):
    """A stale key that is still live is drift, not a warning.

    The rotation succeeded, so the temptation is to report success and mention
    the leftover in passing. This tool refuses that: a live stale credential is
    exactly the state it exists to surface.
    """
    keys = [{"AppName": "credarr-jellyfin_api_token",
             "AccessToken": "previous-key"}]
    executor, ctx, _state = _jellyfin_executor(tmp_path, keys=keys)
    ctx.minted = Secret("created-key")

    def refuse(host, service, method, path, **kwargs):
        if method == "DELETE":
            return 403, {"error": "nope"}
        return 204 if method == "POST" else (200, {"Items": keys})

    executor._call = refuse

    with pytest.raises(RotationError, match="could not be revoked"):
        executor._dispatch(Step(StepKind.REVOKE, "jellyfin", "revoke",
                                reversible=False))


def test_a_jellyfin_revoke_refuses_when_nothing_was_minted(tmp_path):
    """The revoke is authenticated by the key this run minted.

    That key is the credential every holder now carries; the key being deleted
    never authorises its own deletion, so a run that somehow reaches the
    revoke without a mint fails loudly instead of guessing.
    """
    keys = [{"AppName": "credarr-jellyfin_api_token",
             "AccessToken": "previous-key"}]
    executor, _ctx, state = _jellyfin_executor(tmp_path, keys=keys)

    with pytest.raises(RotationError, match="nothing was minted"):
        executor._dispatch(Step(StepKind.REVOKE, "jellyfin", "revoke",
                                reversible=False))

    assert state.jellyfin_calls == 0, "the service was touched anyway"


def test_a_jellyfin_revoke_reports_a_deletion_that_did_not_take(tmp_path):
    """A 204 that left the key behind is drift, not success.

    The deletion's status code is not the fact; the listing is. A service
    that accepts the deletion and keeps the key would otherwise be reported
    as a clean revoke over a credential that still authenticates.
    """
    keys = [{"AppName": "credarr-jellyfin_api_token",
             "AccessToken": "previous-key"}]
    executor, ctx, _state = _jellyfin_executor(tmp_path, keys=keys)
    ctx.minted = Secret("created-key")

    def no_op_delete(host, service, method, path, **kwargs):
        if method == "DELETE":
            return 204, None
        return 200, {"Items": keys}

    executor._call = no_op_delete

    with pytest.raises(RotationError, match="survived its deletion"):
        executor._dispatch(Step(StepKind.REVOKE, "jellyfin", "revoke",
                                reversible=False))


@pytest.mark.parametrize("second", [(500, None), (200, {"unexpected": "shape"})])
def test_a_jellyfin_revoke_reports_an_unconfirmable_revoke(tmp_path, second):
    """Whether the old key is gone must be proven, not assumed.

    The confirming listing is a second call and can fail on its own - by
    status or by an unreadable body - and the run must not report a revoke it
    could not read the answer to.
    """
    keys = [{"AppName": "credarr-jellyfin_api_token",
             "AccessToken": "previous-key"}]
    executor, ctx, _state = _jellyfin_executor(tmp_path, keys=keys)
    ctx.minted = Secret("created-key")
    listings = {"count": 0}

    def half_dead(host, service, method, path, **kwargs):
        if method == "DELETE":
            return 204, None
        listings["count"] += 1
        if listings["count"] == 1:
            return 200, {"Items": keys}
        return second

    executor._call = half_dead

    with pytest.raises(RotationError, match="could not list keys to confirm"):
        executor._dispatch(Step(StepKind.REVOKE, "jellyfin", "revoke",
                                reversible=False))


def test_a_jellyfin_revoke_sweeps_a_key_an_interrupted_run_left_behind(tmp_path):
    """A stray's value is not in the vault, so only its name can find it.

    A run killed between its mint and its revoke leaves a key whose value the
    vault never recorded. The sweep deletes it by the name credarr mints
    under - and the key this run minted carries the same name, so deleting by
    value is not optional: a sweep that took the row the holders now carry
    would break every one of them.
    """
    keys = [{"AppName": "credarr-jellyfin_api_token",
             "AccessToken": "previous-key"},
            {"AppName": "credarr-jellyfin_api_token",
             "AccessToken": "stray-from-dead-run"},
            {"AppName": "credarr-jellyfin_api_token",
             "AccessToken": "created-key"}]
    executor, ctx, state = _jellyfin_executor(tmp_path, keys=keys)
    ctx.minted = Secret("created-key")

    detail = executor._dispatch(Step(StepKind.REVOKE, "jellyfin", "revoke",
                                     reversible=False))

    assert state.deleted == ["previous-key", "stray-from-dead-run"], (
        "the revoke deleted the wrong set of keys")
    assert "swept 1" in detail, detail


def test_a_jellyfin_revoke_leaves_keys_credarr_never_minted_alone(tmp_path):
    """The sweep claims one name, not every key that looks old.

    An adopted predecessor - a key a human created before this build ever ran
    - carries a name credarr never mints. It is deleted only while the vault
    still names it as the value being replaced; once that link is gone, no
    run can tell it from a key that is in use, and guessing would delete
    somebody's credential.
    """
    keys = [{"AppName": "Jellyfin Web", "AccessToken": "previous-key"},
            {"AppName": "API Key", "AccessToken": "adopted-predecessor"}]
    executor, ctx, state = _jellyfin_executor(tmp_path, keys=keys)
    ctx.minted = Secret("created-key")

    detail = executor._dispatch(Step(StepKind.REVOKE, "jellyfin", "revoke",
                                     reversible=False))

    assert state.deleted == ["previous-key"]
    assert "swept" not in detail, detail


def test_a_jellyfin_revoke_sweeps_a_stray_when_no_previous_key_remains(tmp_path):
    """A stray must not ride on the previous key being present.

    A stray left by an older crash is worth deleting on its own, so the
    no-op return has to mean "neither kind is present", not "the previous
    key is".
    """
    keys = [{"AppName": "credarr-jellyfin_api_token",
             "AccessToken": "stray-from-dead-run"}]
    executor, ctx, state = _jellyfin_executor(tmp_path, keys=keys)
    ctx.minted = Secret("created-key")

    detail = executor._dispatch(Step(StepKind.REVOKE, "jellyfin", "revoke",
                                     reversible=False))

    assert state.deleted == ["stray-from-dead-run"]
    assert "swept 1" in detail, detail


def test_a_jellyfin_revoke_ignores_a_row_with_no_token(tmp_path):
    """A row without an AccessToken cannot authenticate, so it is not a key.

    The sweep deletes by name, and the token is the value the DELETE is
    addressed to - a row that has no token is evidence of neither a live key
    nor a deletable one. Skipping it matches the value match, which skips the
    same row, and keeps a malformed listing from failing a finished rotation.
    """
    keys = [{"AppName": "credarr-jellyfin_api_token",
             "AccessToken": "previous-key"},
            {"AppName": "credarr-jellyfin_api_token"}]
    executor, ctx, state = _jellyfin_executor(tmp_path, keys=keys)
    ctx.minted = Secret("created-key")

    detail = executor._dispatch(Step(StepKind.REVOKE, "jellyfin", "revoke",
                                     reversible=False))

    assert state.deleted == ["previous-key"]
    assert "revoked 1" in detail and "swept" not in detail, detail


def _jellyfin_plan() -> RotationPlan:
    plan = RotationPlan(credential=_jellyfin_credential(), host=JELLYFIN_HOST)
    plan.add(StepKind.MINT, "jellyfin", "mint", reversible=False)
    return plan


def test_the_jellyfin_preflight_needs_the_vault_value_not_a_second_key(tmp_path):
    """A config naming no second key is complete: the vault value does it.

    The mint authenticates with the credential being rotated and the readiness
    probe needs no credential at all, so this plan has every key it needs. The
    transport serves no config.xml, so a regression that made the mint look
    for one would fail this test instead of silently passing.
    """
    executor, _ctx, state = _jellyfin_executor(
        tmp_path, keys=[{"AppName": "seeded", "AccessToken": "previous-key"}])

    class _NoConfigXml(FakeTransport):
        def run_python(self, code, *, timeout=None):
            if "config.xml" in code:
                return ""
            return super().run_python(code, timeout=timeout)

    executor._ctx.transport = _NoConfigXml(state)

    assert executor.preflight(_jellyfin_plan()) == []


def test_the_jellyfin_preflight_reports_a_missing_vault_value(tmp_path):
    """The key the mint needs is the vault's own copy of the credential.

    Missing it is reported before anything runs, because every call the mint
    makes would fail on it.
    """
    executor, ctx, _state = _jellyfin_executor(tmp_path, keys=[])
    ctx.vault_value = None

    problems = executor.preflight(_jellyfin_plan())

    assert any("vault holds no value" in p for p in problems), problems


def test_a_full_rotation_mints_propagates_and_records(tmp_path):
    state = FakeState()
    state.rows["sonarr"] = [OLD_KEY, OLD_KEY]
    executor, ctx = _executor(tmp_path, state)

    result = executor.execute(_plan())

    assert result.ok, result.detail
    assert ctx.minted is not None
    assert state.service_key["prowlarr"] == ctx.minted.reveal()
    # The API mint chooses the key, restores it over a backup, and restarts.
    assert any(
        path == "/system/restart" for _service, path, _header in state.api_calls
    )
    assert set(state.rows["sonarr"]) == {ctx.minted.reveal()}
    assert set(state.rows["radarr"]) == {ctx.minted.reveal()}
    assert "homepage.label" in result.manual
    assert ctx.minted is not None and ctx.minted.reveal() != OLD_KEY


def test_a_started_callback_sees_the_attempt_after_the_journal_row_exists(tmp_path):
    """A scheduler may only announce a start once there is an attempt to name."""
    state = FakeState()
    state.rows["sonarr"] = [OLD_KEY, OLD_KEY]
    executor, ctx = _executor(tmp_path, state)
    seen: list[int] = []
    ctx.on_started = seen.append

    result = executor.execute(_plan())

    assert seen == [result.attempt]
    assert result.attempt > 0


def _exercise_step(tmp_path, state, *, old_key_dead=None):
    """Propagate to Sonarr with a minted value, for the proof-matrix cases."""
    executor, ctx = _executor(tmp_path, state)
    ctx.minted = Secret(NEW_KEY)
    ctx.old_key_dead = old_key_dead
    return executor, ctx, executor._propagate(
        Step(StepKind.PROPAGATE, "sonarr.indexers", "PUT 2 rows")
    )


def test_a_403_on_the_issuer_status_route_does_not_count_as_old_key_dead(tmp_path):
    """A bare 403 is an access layer's answer, not the issuer's credential verdict.

    The measured *arr answer for a revoked key is 401. Counting 403 as dead
    would let a proxy in front of a live old key satisfy the second fact of an
    exercise-only confirmation.
    """
    state = FakeState()
    executor, ctx = _executor(tmp_path, state)

    def status_403(host, service, method, path, *, body=None, key=None,
                   transport=None, **kwargs):
        if path == "/system/status":
            return 403, {}
        return _servarr_call(state)(
            host, service, method, path, body=body, key=key,
            transport=transport, timeout=kwargs.get("timeout"),
        )

    executor._call = status_403
    executor._confirm_old_key_dead("prowlarr", OLD_KEY)

    assert ctx.old_key_dead is False


def test_a_holder_service_key_comes_from_the_app_store(tmp_path):
    """The store is the runtime source of record for a holder's own key."""
    state = FakeState()
    executor, ctx = _executor(tmp_path, state)
    ctx.service_keys = {"sonarr": Secret("sonarr-from-store")}

    assert executor._service_key("sonarr") == "sonarr-from-store"


def test_the_minted_services_own_key_wins_over_the_stores_old_copy(tmp_path):
    """A self-holder needs the value this run minted, not the RECORD-time copy.

    The store is only updated at the end of the run, so preferring it blindly
    would authenticate a holder write with the key the mint just revoked.
    """
    state = FakeState()
    executor, ctx = _executor(tmp_path, state)
    ctx.service_keys = {"sonarr": Secret("sonarr-old-copy")}
    ctx.minted = Secret(NEW_KEY)
    ctx.minted_service = "sonarr"

    assert executor._service_key("sonarr") == NEW_KEY


def test_exercise_uses_the_store_key(tmp_path):
    """A measured test route authenticates with the holder's stored key."""
    state = FakeState()
    executor, ctx = _executor(tmp_path, state)
    ctx.minted = Secret(NEW_KEY)
    ctx.old_key_dead = True
    ctx.service_keys = {"sonarr": Secret(state.service_key["sonarr"])}

    executor._propagate(
        Step(StepKind.PROPAGATE, "sonarr.indexers", "PUT 2 rows")
    )

    holder = next(h for h in ctx.holders if h.target == "sonarr.indexers")
    assert holder.outcome == "confirmed"
    assert holder.method == "exercised"


@pytest.mark.parametrize(
    "message",
    [
        "Unable to connect to indexer: HTTP request failed: [410:Gone] "
        "[GET] at [http://prowlarr:9696/28/api?t=caps&apikey=secret]",
        "Query successful, but no results in the configured categories "
        "were returned from your indexer.",
    ],
)
def test_an_indexer_functional_failure_is_not_a_credential_failure(
    tmp_path, message,
):
    """A disabled upstream indexer or an empty category is not a bad key.

    Prowlarr's 410 is emitted after API-key authentication; Radarr's
    "Query successful" wording says the key worked. Both must confirm the
    copy, while keeping the service's own reason in the holder detail.
    """
    state = FakeState()
    state.exercise_response = (400, [{"errorMessage": message}])
    executor, ctx = _executor(tmp_path, state)
    ctx.minted = Secret(NEW_KEY)
    ctx.old_key_dead = True
    ctx.service_keys = {"sonarr": Secret(state.service_key["sonarr"])}

    executor._propagate(
        Step(StepKind.PROPAGATE, "sonarr.indexers", "PUT 2 rows")
    )

    holders = [h for h in ctx.holders if h.target == "sonarr.indexers"]
    assert [h.outcome for h in holders] == ["confirmed", "confirmed"]
    assert all("secret" not in h.detail for h in holders)
    assert "410:Gone" in holders[0].detail or "no results" in holders[0].detail


# --- Seerr API holders -----------------------------------------------------
#
# Seerr holds arr rows and the Jellyfin object in its settings API. The tests
# below share one job: no combination of circumstances may turn an API write
# into `confirmed` without asking the running process what it holds.


SEERR_HOST = HostConfig(
    name="media",
    urls={"prowlarr": "http://127.0.0.1:9696", "seerr": "http://127.0.0.1:5055"},
    containers={"prowlarr": "prowlarr", "seerr": "seerr"},
)


def _seerr_host(tmp_path: Path) -> HostConfig:
    """Seerr is API-only: no settings.json mount and no config.xml."""
    return SEERR_HOST


def _seerr_executor(tmp_path, *, own_key: str | None = "synthetic-seerr-own-key"):
    state = FakeState()
    service_keys = {} if own_key is None else {"seerr": Secret(own_key)}
    ctx = RotationContext(
        credential=_credential(),
        host=_seerr_host(tmp_path),
        transport=FakeTransport(state),
        journal=Journal(tmp_path / "j.db"),
        vault_value=OLD_KEY,
        pending=FilePending(tmp_path / "pending.db"),
        settle_timeout=0.0, write_backoff=0.0,
        service_keys=service_keys,
    )

    def backup(host, service, *, key, transport):
        state.backup_calls += 1
        return _api_xml(state.service_key[service]), "backup.zip"

    def restore(host, service, *, key, xml, transport):
        state.service_key[service] = _config_xml_api_key(xml.decode())
        return 200, None

    return Executor(
        ctx,
        servarr_call=_servarr_call(state),
        servarr_backup=backup,
        servarr_restore=restore,
    ), ctx, state


def _seerr_plan(tmp_path=None):
    credential = _credential()
    host = _seerr_host(tmp_path) if tmp_path else SEERR_HOST
    plan = RotationPlan(credential=credential, host=host)
    plan.add(StepKind.MINT, "prowlarr", "backup/restore", reversible=False)
    plan.add(StepKind.PROPAGATE, "seerr.settings_json[sonarr]",
             "PUT the new value to the settings API")
    return plan


def test_a_seerr_holder_is_written_and_confirmed(tmp_path):
    """The whole API path: the settings endpoint is updated and the running
    process is asked what it holds. No file and no container action."""
    executor, ctx, state = _seerr_executor(tmp_path)

    result = executor.execute(_seerr_plan(tmp_path))

    assert result.ok, result.detail
    assert state.seerr_reported["sonarr"] == ctx.minted.reveal()
    assert ctx.minted is not None and ctx.minted.reveal() != OLD_KEY
    holder, = result.holders
    assert holder.target == "seerr.settings_json[sonarr]"
    assert holder.outcome == "confirmed"
    assert holder.detail == ""


def test_two_seerr_holders_in_one_plan_each_confirm_their_own(tmp_path):
    """Two PROPAGATE steps against Seerr, each scoped to its own row."""
    executor, ctx, state = _seerr_executor(tmp_path)
    plan = _seerr_plan(tmp_path)
    plan.steps.append(Step(StepKind.PROPAGATE, "seerr.settings_json[radarr]",
                           "PUT the new value to the settings API"))

    result = executor.execute(plan)

    assert result.ok, result.detail
    assert {h.label: h.outcome for h in result.holders} == {
        "Sonarr": "confirmed", "Radarr": "confirmed"}
    assert state.seerr_reported["sonarr"] == ctx.minted.reveal()
    assert state.seerr_reported["radarr"] == ctx.minted.reveal()


def test_an_object_shaped_section_is_confirmed_like_a_list(tmp_path):
    """Seerr's jellyfin section is one object; the arrs are lists.

    The Jellyfin write uses POST /settings/jellyfin rather than the arr PUT,
    and the read-back must accept the object shape.
    """
    executor, ctx, state = _seerr_executor(tmp_path)
    plan = _seerr_plan(tmp_path)
    plan.steps = [
        Step(StepKind.MINT, "prowlarr", "backup/restore", reversible=False),
        Step(StepKind.PROPAGATE, "seerr.settings_json[jellyfin]",
             "POST the new value to the settings API"),
    ]

    result = executor.execute(plan)

    assert result.ok, result.detail
    holder, = result.holders
    assert holder.outcome == "confirmed"
    assert holder.label == "Jellyfin"
    assert state.seerr_reported["jellyfin"] == ctx.minted.reveal()
    assert ("seerr", "/settings/jellyfin", "X-API-Key") in state.api_calls


def test_a_seerr_holder_is_confirmed_from_the_process_not_the_file(tmp_path):
    """`confirmed` means the running process was asked, with its own header."""
    executor, _, state = _seerr_executor(tmp_path)

    executor.execute(_seerr_plan(tmp_path))

    assert ("seerr", "/settings/sonarr", "X-API-Key") in state.api_calls


def test_a_process_holding_the_old_value_is_a_failure(tmp_path):
    """The PUT is acknowledged but the process keeps reporting the old key."""
    executor, _, state = _seerr_executor(tmp_path)
    state.seerr_readback_stale = True

    result = executor.execute(_seerr_plan(tmp_path))

    assert not result.ok
    assert "did not report the new sonarr key" in result.detail
    holder, = result.holders
    assert holder.outcome == "failed"


def test_an_unconfirmable_read_back_is_refused_before_the_mint(tmp_path):
    """A holder that cannot be read back must not be rotated into at all."""
    executor, _, state = _seerr_executor(tmp_path)
    original = _servarr_call(state)

    def refuse(host, service, method, path, **kwargs):
        if service == "seerr" and path.startswith("/settings/"):
            return 403, {"error": "no"}
        return original(host, service, method, path, **kwargs)

    executor._call = refuse

    problems = executor.preflight(_seerr_plan(tmp_path))

    assert any("the read-back that would confirm this write" in problem
               for problem in problems)
    assert state.backup_calls == 0, "preflight refused but the mint still ran"


def test_an_unconfirmable_read_back_at_write_time_is_a_failure(tmp_path):
    """The write-time path, when preflight passed and something changed since."""
    executor, _, state = _seerr_executor(tmp_path)
    assert executor.preflight(_seerr_plan(tmp_path)) == []

    state.seerr_readback_fails = True

    result = executor.execute(_seerr_plan(tmp_path))

    assert not result.ok
    assert "could not read Seerr's sonarr settings" in result.detail
    holder, = result.holders
    assert holder.outcome == "failed"


def test_a_seerr_holder_leaves_the_run_clean_when_confirmed(tmp_path):
    """The negative control: a confirmed holder does not make a run dirty."""
    executor, _, _ = _seerr_executor(tmp_path)

    result = executor.execute(_seerr_plan(tmp_path))

    assert result.ok
    assert result.clean


def test_a_manual_step_is_not_clean():
    """A holder the tool could not update still holds the revoked key."""
    result = ExecutionResult(
        credential="homepage_api_key", attempt=7, manual=["homepage.label"]
    )

    assert not result.clean


def test_the_put_path_makes_no_restart_request(tmp_path):
    """Arr instances use PUT, which updates the running process directly; the
    only restart in the plan is the issuer's own config restore."""
    executor, _, state = _seerr_executor(tmp_path)

    executor.execute(_seerr_plan(tmp_path))

    assert not any(
        service == "seerr" and path == "/system/restart"
        for service, path, _header in state.api_calls
    )


def test_the_readback_reads_the_settings_endpoint(tmp_path):
    """The read-back polls `/api/v1/settings/{service}` for the new key."""
    executor, _, state = _seerr_executor(tmp_path)

    executor.execute(_seerr_plan(tmp_path))

    assert ("seerr", "/settings/sonarr", "X-API-Key") in state.api_calls


def test_a_put_failure_is_reported(tmp_path):
    """A failed PUT is reported as a failed holder, not a confirmed one."""
    executor, _, state = _seerr_executor(tmp_path)
    state.seerr_put_fails = True

    result = executor.execute(_seerr_plan(tmp_path))

    assert not result.ok
    assert "Seerr refused the sonarr settings write (HTTP 400)" in result.detail
    holder, = result.holders
    assert holder.outcome == "failed"


def test_a_multi_instance_section_blocks_preflight(tmp_path):
    """Several instances cannot be rotated: the manifest does not say which."""
    executor, _, state = _seerr_executor(tmp_path)
    state.seerr_row_count = 2

    problems = executor.preflight(_seerr_plan(tmp_path))

    assert any("holds 2 sonarr instances" in problem for problem in problems), problems


def test_an_empty_section_blocks_preflight(tmp_path):
    """No instance means there is nothing the write could reach."""
    executor, _, state = _seerr_executor(tmp_path)
    state.seerr_row_count = 0

    problems = executor.preflight(_seerr_plan(tmp_path))

    assert any("holds no sonarr instances" in problem for problem in problems), problems


def test_a_missing_jellyfin_section_blocks_preflight(tmp_path):
    """Jellyfin must exist as an object before the mint runs."""
    executor, _, state = _seerr_executor(tmp_path)
    state.seerr_missing_jellyfin = True
    plan = _seerr_plan(tmp_path)
    plan.steps = [
        Step(StepKind.MINT, "prowlarr", "backup/restore", reversible=False),
        Step(StepKind.PROPAGATE, "seerr.settings_json[jellyfin]",
             "POST the new value to the settings API"),
    ]

    problems = executor.preflight(plan)

    assert any("has no Jellyfin settings object" in problem for problem in problems), problems


def test_a_multi_instance_section_is_refused_before_the_put(tmp_path):
    """The section can grow after preflight passed; the write refuses."""
    executor, _, state = _seerr_executor(tmp_path)
    assert executor.preflight(_seerr_plan(tmp_path)) == []

    state.seerr_row_count = 2

    result = executor.execute(_seerr_plan(tmp_path))

    assert not result.ok
    assert "holds 2 sonarr instances" in result.detail, result.detail
    holder, = result.holders
    assert holder.outcome == "failed"
    assert state.pending_seerr_update is None, "the refusal still wrote"


def test_an_emptied_section_is_refused_before_the_put(tmp_path):
    """The section can empty after preflight passed; the write says so."""
    executor, _, state = _seerr_executor(tmp_path)
    assert executor.preflight(_seerr_plan(tmp_path)) == []

    state.seerr_row_count = 0

    result = executor.execute(_seerr_plan(tmp_path))

    assert not result.ok
    assert "holds no sonarr instances" in result.detail, result.detail
    holder, = result.holders
    assert holder.outcome == "failed"
    assert state.pending_seerr_update is None, "the refusal still wrote"


def test_an_unqualified_seerr_holder_is_refused_before_anything_is_written(tmp_path):
    """`seerr.settings_json` names one section holding three services' keys."""
    executor, _, state = _seerr_executor(tmp_path)
    plan = _seerr_plan(tmp_path)
    plan.steps = [
        Step(StepKind.MINT, "prowlarr", "backup/restore", reversible=False),
        Step(StepKind.PROPAGATE, "seerr.settings_json", "write the settings"),
    ]

    problems = executor.preflight(plan)

    assert any("does not name which holder" in problem for problem in problems)

    result = executor.execute(plan)

    assert not result.ok
    assert "does not name which holder" in result.detail
    assert state.pending_seerr_update is None


def test_a_missing_url_is_refused_before_anything_is_written(tmp_path):
    """The API write needs a base URL, and finding that out late is costly."""
    executor, _, state = _seerr_executor(tmp_path)
    host = replace(_seerr_host(tmp_path), urls={"prowlarr": "http://127.0.0.1:9696"})
    ctx = RotationContext(
        credential=_credential(), host=host, transport=executor._ctx.transport,
        journal=executor._ctx.journal, vault_value=OLD_KEY,
        settle_timeout=0.0, write_backoff=0.0,
        service_keys=executor._ctx.service_keys,
    )
    executor = Executor(ctx, servarr_call=_servarr_call(state))

    problems = executor.preflight(_seerr_plan(tmp_path))

    assert any("no URL for seerr" in problem for problem in problems)


def test_a_missing_seerr_own_key_is_refused_before_the_mint(tmp_path):
    """No stored Seerr key means the settings write cannot authenticate."""
    executor, _, state = _seerr_executor(tmp_path, own_key=None)

    problems = executor.preflight(_seerr_plan(tmp_path))

    assert any("no API key for 'seerr'" in problem for problem in problems), problems
    assert state.backup_calls == 0


def test_a_completed_run_records_its_holders(tmp_path):
    """The durable record of a run includes what its holders ended up holding."""
    executor, ctx, _ = _seerr_executor(tmp_path)

    result = executor.execute(_seerr_plan(tmp_path))

    assert result.ok, result.detail
    recorded = ctx.journal.holders(result.attempt)
    assert [r["target"] for r in recorded] == ["seerr.settings_json[sonarr]"]
    assert [r["outcome"] for r in recorded] == ["confirmed"]


def test_preflight_accepts_a_healthy_seerr_holder(tmp_path):
    """The negative control for the refusals above."""
    executor, _, _ = _seerr_executor(tmp_path)

    assert executor.preflight(_seerr_plan(tmp_path)) == []


def test_a_seerr_holder_is_not_propagated_as_a_servarr(tmp_path):
    """The dispatch must take the Seerr branch, not the Servarr one."""
    executor, _, state = _seerr_executor(tmp_path)
    plan = _seerr_plan(tmp_path)

    result = executor.execute(plan)

    assert [h.outcome for h in result.holders] == ["confirmed"]
    propagate = [s for s in plan.steps if s.kind is StepKind.PROPAGATE]
    assert "settings API" in propagate[0].detail
    assert "database" not in propagate[0].detail
    assert not [p for p in state.api_calls
                if p[0] == "seerr" and p[1].startswith("/indexer")]


def test_a_failure_carries_its_hint_to_the_operator(tmp_path):
    """`RotationError.hint` says what to do, not just what broke."""
    executor, _, _state = _seerr_executor(tmp_path)

    def refuse(*_args, **_kwargs):
        raise RotationError("the service never came back", hint="start it")

    executor._await_seerr_key = refuse

    result = executor.execute(_seerr_plan(tmp_path))

    assert not result.ok
    assert "the service never came back" in result.detail
    assert "start it" in result.detail
    assert "hint:" not in result.detail


def test_a_second_mint_step_for_one_service_does_not_fake_a_resume(tmp_path):
    """A duplicated MINT is a no-op, and must not read as a recovery.

    The plan carries the backup/restore mint once, and a second step for the
    same service finds `ctx.minted` already set. It must not mint a third key,
    and it must not claim the run resumed an earlier one.
    """
    state = FakeState()
    executor, _ = _executor(tmp_path, state)
    plan = _plan()
    plan.steps.insert(1, Step(StepKind.MINT, "prowlarr",
                              "read the new key back from config.xml",
                              reversible=False))

    result = executor.execute(plan)

    assert result.ok, result.detail
    assert state.backup_calls == 1, "the mint ran more than once"
    assert not result.resumed, "the run reported itself as a recovery"


def test_a_row_without_the_named_field_is_refused_before_the_put(tmp_path):
    """A renamed field would turn the write into a no-op with a 202.

    The value submitted is always the minted one - the mask is never a value
    this writer can send - but a resource whose shape no longer carries the
    field the writer names would get a PUT that changes nothing: the row keeps
    the old (revoked) key while the service answers success. The promotion pass
    would catch it, but only after the request; refuse before it instead.
    """
    state = FakeState()
    state.api_row_field = "api_key"  # the service renamed the field
    executor, _ = _executor(tmp_path, state)

    result = executor.execute(_plan())

    assert not result.ok
    assert "no 'apiKey' field" in result.detail
    assert state.api_writes == 0, "a PUT that could only be a no-op was sent"


def test_execution_stops_at_the_first_failure(tmp_path):
    """Continuing past a failed write spreads the damage across more services
    and makes the rollback harder to reason about than the failure itself."""
    state = FakeState()
    executor, _ = _executor(tmp_path, state)

    original = _servarr_call(state)

    def failing(host, service, method, path, *, body=None, key=None, transport=None):
        if path == "/indexer/0" and service == "sonarr":
            return 500, None
        return original(host, service, method, path, body=body, key=key)

    executor._call = failing
    result = executor.execute(_plan())

    assert not result.ok
    assert result.failed == "sonarr.indexers"
    # radarr was never touched.
    assert state.rows["radarr"] == [OLD_KEY]


def test_nothing_is_written_without_a_minted_value(tmp_path):
    """A propagate step reached without a mint must refuse rather than write a
    stale value over a working one."""
    state = FakeState()
    executor, ctx = _executor(tmp_path, state)
    ctx.minted = None

    plan = _plan()
    plan.steps = [plan.steps[1]]  # propagate only

    result = executor.execute(plan)
    assert not result.ok
    assert "no key was minted" in result.detail
    assert state.api_writes == 0


def test_the_mint_step_is_marked_irreversible_in_the_plan():
    plan = _plan()
    mint = next(s for s in plan.steps if s.kind is StepKind.MINT)
    assert mint.reversible is False


def test_the_vault_is_written_last(tmp_path):
    """The canonical copy must not move before the copies it feeds.

    A vault written first, with propagation then failing, is indistinguishable
    from a rotation that never happened - and every subsequent check reads
    against a value nothing is using.
    """
    state = FakeState()
    order = []
    executor, ctx = _executor(tmp_path, state)

    def record(value):
        order.append(("vault", list(state.rows["sonarr"])))

    ctx.vault_setter = record
    plan = _plan()
    plan.add(StepKind.RECORD, "a.b", "write the new value to the vault")
    result = executor.execute(plan)

    assert result.ok, result.detail
    assert result.vault_written is True, "the RECORD step completed"
    assert order, "the vault was never written"
    # By the time the vault was written, both databases already held the new key.
    assert all(
        row == ctx.minted.reveal() for _, rows in order for row in rows
    ), order


def test_a_run_with_no_vault_setter_refuses_rather_than_skipping(tmp_path):
    """A rotation that cannot record must stop, not report success."""
    state = FakeState()
    executor, ctx = _executor(tmp_path, state)
    ctx.vault_setter = None
    plan = _plan()
    plan.add(StepKind.RECORD, "a.b", "write the new value to the vault")

    result = executor.execute(plan)

    assert not result.ok
    assert "no way to write the vault" in result.detail
    assert result.vault_written is False, (
        "a failed RECORD step must not claim the vault moved"
    )


# --- recovery under interruption -------------------------------------------
#
# "Rotate, then hope propagation works" is only safe if the recovery path is
# tested under interruption rather than after a clean run. These tests kill the
# run at each boundary that matters and require the next run to converge without
# minting again - because a second mint produces a third key and invalidates
# whatever the second one already reached, which is how a recoverable outage
# becomes a long one.

def _interrupted_before_readback(state):
    """A transport that dies on the read-back after the restore was accepted.

    The first config.xml read in a mint is the backup artifact, so dying on it
    tests nothing about the window it is named for - the run never restores.
    This counts reads and dies on the second, which is the read-back.
    """
    class Dying:
        name = "interrupted"
        reads = 0

        def run_python(self, code, *, timeout=None):
            if "config.xml" in code:
                Dying.reads += 1
                if Dying.reads == 2:
                    raise KeyboardInterrupt("crash between reset and read-back")
            return FakeTransport(state).run_python(code, timeout=timeout)

    return Dying()


def Dying_reads_reached_the_readback(transport) -> bool:
    """True once the transport has read config.xml at least twice."""
    return getattr(transport, "reads", 0) >= 2


def test_a_run_is_not_clean_while_a_holder_is_unreached(tmp_path):
    """"Nothing threw" is not "nothing is broken". A holder that was never
    reached is as dead as one that failed, and a scheduled job must be able to
    tell the difference between those and success."""
    state = FakeState()
    executor, _ = _executor(tmp_path, state)

    original = _servarr_call(state)

    def failing(host, service, method, path, *, body=None, key=None, transport=None):
        if path == "/indexer/0" and service == "sonarr":
            return 500, None
        return original(host, service, method, path, body=body, key=key, transport=transport)

    executor._call = failing  # injecting the fault
    result = executor.execute(_plan())

    assert not result.ok
    assert not result.clean
    assert any(h.outcome == "not-reached" for h in result.holders)

    # The durable record says the same thing: an operator reading the journal
    # later can tell untouched from dead, exactly as the report does.
    recorded = Journal(tmp_path / "j.db").holders(result.attempt)
    assert {(r["target"], r["label"], r["outcome"]) for r in recorded} == {
        (h.target, h.label, h.outcome) for h in result.holders
    }


# --- the three mint outcomes, stated precisely ------------------------------
#
# "Starts cleanly" is not a behaviour; these three are, and which one happened
# is the whole of whether a rerun is safe.


# --- a persisted candidate is a candidate, not a credential -----------------
#
# config.xml holding something the vault does not means something wrote it. That
# is a recovery signal, not proof of a working key, and continuing on it would
# push an unverified value into every holder.


def test_an_unknown_vault_value_must_not_mint(tmp_path):
    """No vault entry is not the same as a first attempt.

    A missing vault entry and a credential that was never rotated produce the
    same observation here: the tool cannot see what the previous key was. Minting
    on that observation invalidates whatever every holder already carries, and
    nothing downstream can tell that apart from a legitimate first rotation.
    """
    state = FakeState()
    state.service_key["prowlarr"] = NEW_KEY  # a rotation already happened
    state.rows["sonarr"] = [NEW_KEY]
    state.rows["radarr"] = [NEW_KEY]

    transport = FakeTransport(state)
    ctx = RotationContext(
        credential=_credential(), host=HOST, transport=transport,
        journal=Journal(tmp_path / "j.db"), vault_value=None,
    )
    result = Executor(ctx, servarr_call=_servarr_call(state)).execute(_plan())

    assert not result.ok
    assert state.backup_calls == 0, "minted with no knowledge of the previous key"


def test_the_takeover_is_recorded_in_the_journal(tmp_path):
    """An operator reading the journal later must be able to see it happened."""
    state = FakeState()
    journal = Journal(tmp_path / "j.db", stale_after=900.0)
    dead = journal.begin("prowlarr_api_key")
    journal.step_started(dead, 0, "mint", "prowlarr", "backup/restore")
    with journal._connect() as db:
        db.execute("UPDATE steps SET started_at = ? WHERE finished_at IS NULL",
                   (time.time() - 3600,))

    transport = FakeTransport(state)
    ctx = RotationContext(
        credential=_credential(), host=HOST, transport=transport,
        journal=journal, vault_value=OLD_KEY, settle_timeout=0.0, write_backoff=0.0,
    )
    Executor(ctx, servarr_call=_servarr_call(state)).execute(_plan())

    reopened = Journal(tmp_path / "j.db", stale_after=900.0)
    with reopened._connect() as db:
        outcome = db.execute(
            "SELECT outcome FROM steps WHERE attempt_id = ?", (dead,)
        ).fetchone()["outcome"]
    assert "abandoned" in outcome, outcome


def test_take_over_answers_for_this_credential_and_no_other(tmp_path):
    """The instruction is one operator's assertion about one run.

    Their own credential's fresh step stops being a problem, because they have
    said the run behind it is not coming back. Another credential's does not:
    nobody has said anything about that run, and this run cannot tell whether
    it is alive or not.
    """
    state = FakeState()
    journal = Journal(tmp_path / "j.db", stale_after=900.0)
    mine = journal.begin("prowlarr_api_key")
    journal.step_started(mine, 0, "mint", "prowlarr", "backup/restore")
    theirs = journal.begin("sonarr_api_key")
    journal.step_started(theirs, 0, "mint", "sonarr", "backup/restore")

    executor, ctx = _executor(tmp_path, state)
    ctx.journal = journal

    problems = executor.preflight(_plan())
    assert [p for p in problems if "of this credential is unfinished" in p], problems
    # And the refusal says what to do about it, in the engine's own words.
    assert "take-over" in " ".join(problems), problems
    assert [p for p in problems if "another credential" in p], problems

    ctx.take_over = True
    problems = executor.preflight(_plan())

    assert not [p for p in problems if "of this credential is unfinished" in p], (
        problems
    )
    assert [p for p in problems if "another credential" in p], problems
    # Nothing was closed by looking: the plan is read-only, and the steps end
    # only when a run that reached the lock takes them over.
    assert len(journal.pending()) == 2


def test_the_lock_and_the_step_query_use_the_same_cutoff(tmp_path):
    """They must agree, or a step can be reclaimed while its lock is still held.

    Two different ages would mean either a step blocking forever after its lock
    freed, or a lock freed while its step is still treated as blocking.
    """
    journal = Journal(tmp_path / "j.db", stale_after=123.0)
    assert journal.stale_after == 123.0

    attempt = journal.begin("prowlarr_api_key")
    journal.step_started(attempt, 0, "mint", "prowlarr", "backup/restore")

    with journal._connect() as db:
        db.execute("UPDATE steps SET started_at = ? WHERE finished_at IS NULL",
                   (time.time() - 200,))

    # Past the cutoff, so pending() has stopped reporting it...
    assert not journal.pending()
    # ...and the lock, on the same threshold, is no longer holding it.
    with journal.lock("prowlarr_api_key"):
        pass


def test_a_partially_propagated_database_does_not_block_the_resume(tmp_path):
    """The state a resume exists for must survive preflight.

    A run killed midway leaves consumers holding both keys at once. That is not
    an error - it is the state recovery starts from - so preflight must not
    refuse it. It used to: preflight called the post-write verifier, which
    raises on more than one key, so the very state the tool is built to recover
    from made the tool refuse to start.
    """
    state = FakeState()
    # Exactly what a crash midway leaves behind: some rows new, some old.
    state.service_key["prowlarr"] = NEW_KEY
    state.rows["sonarr"] = [NEW_KEY, NEW_KEY, OLD_KEY, OLD_KEY]
    state.rows["radarr"] = [OLD_KEY]

    executor, _ = _executor(tmp_path, state)
    problems = executor.preflight(_plan())

    assert not [p for p in problems if "different keys" in p], (
        f"preflight refuses a partially-propagated database: {problems}"
    )


ROW_NAMES = ["1337x (Prowlarr)", "Nyaa.si (Prowlarr)", "Knaben (Prowlarr)"]
QUALIFIED = "sonarr.indexers[1337x (Prowlarr)]"
# Deliberately not row 0. The executor labels a holder by the API `id` and matches
# it against the database `Id`, and a fixture whose only qualified row is the
# first one cannot tell whether that correlation holds.
QUALIFIED_LAST = "sonarr.indexers[Knaben (Prowlarr)]"


def _named_call(state, names):
    """The existing fake, plus the `name` field a selector matches on.

    A real *arr list endpoint returns names; the existing fake returned ids only,
    so a qualified target could not have been exercised at all. Naming them here
    keeps the rest of the fake's behaviour - redaction, database digests,
    restart counting - identical.
    """
    base = _servarr_call(state)

    def call(host, service, method, path, *, body=None, key=None, transport=None,
             timeout=None, **kwargs):
        if path == "/indexer" and method == "GET":
            return 200, [
                {"id": i, "name": name,
                 "fields": [{"name": "apiKey", "value": "********"}]}
                for i, name in enumerate(names)
            ]
        if path.startswith("/indexer/") and method == "GET":
            index = int(path.rsplit("/", 1)[1])
            return 200, {
                "id": index, "name": names[index],
                "fields": [{"name": "apiKey", "value": "********"}],
            }
        return base(host, service, method, path, body=body, key=key,
                    transport=transport, timeout=timeout, **kwargs)

    return call


def _named_state(count=2, *, service="sonarr"):
    """A state whose rows carry the names a qualified target selects on.

    Both halves matter and both are needed together: the API list selects the row
    to write, and the database read selects the row to compare. Scoping only one
    of them is exactly the shape of the bug this test exists to pin.
    """
    state = FakeState()
    state.rows[service] = [OLD_KEY] * count
    state.row_names[service] = ROW_NAMES[:count]
    return state


def _propagation_plan(target):
    plan = RotationPlan(credential=_credential(), host=HOST)
    plan.add(StepKind.PROPAGATE, target, "PUT")
    return plan.steps[0]


def _scoped_executor(tmp_path, state):
    """A context with a key already minted, because scoping lives in `_propagate`.

    Minting is covered by its own tests; what matters here is which rows a write
    touches and which rows the read-back compares. The row names come from the
    state so the API list and the database can never disagree about how many
    rows there are.
    """
    names = state.row_names["sonarr"]
    ctx = RotationContext(
        credential=_credential(), host=HOST, transport=FakeTransport(state),
        journal=Journal(tmp_path / "j.db"), vault_value=OLD_KEY,
        settle_timeout=0.0, write_backoff=0.0, write_interval=0.0,
    )
    ctx.minted = Secret(NEW_KEY)
    return Executor(ctx, servarr_call=_named_call(state, names))


def test_a_qualified_target_updates_only_its_own_row(tmp_path):
    """The latent hazard the executor had: one slot, two credentials.

    Sonarr's indexers all carry Prowlarr's key, so this is not the wrong-credential
    case - that is `prowlarr.applications`, below. What this pins is that a
    qualified target writes exactly the row it named.
    """
    state = _named_state(2)

    detail = _scoped_executor(tmp_path, state)._propagate(_propagation_plan(QUALIFIED))

    assert "1 row(s) written" in detail, detail
    assert state.rows["sonarr"][0] == NEW_KEY, "the named row was not written"
    assert state.rows["sonarr"][1] == OLD_KEY, "an unrelated row was written"


def test_a_qualified_row_other_than_the_first_is_still_found(tmp_path):
    """The API `id` must still address the same row after scoping.

    Scoping filters the API list, so a writer that renumbered what it returned
    would write one row while naming another. The value written and the label
    both have to agree with the selected id.
    """
    state = _named_state(3)

    executor = _scoped_executor(tmp_path, state)
    detail = executor._propagate(_propagation_plan(QUALIFIED_LAST))

    assert "1 row(s) written" in detail, detail
    assert state.rows["sonarr"] == [OLD_KEY, OLD_KEY, NEW_KEY], (
        "the wrong row was written - the API id no longer matches the database Id"
    )
    # The API-only writer cannot read the value back, so the honest outcome is
    # `written`, not `confirmed`.
    outcomes = {h.label: h.outcome for h in executor._ctx.holders}
    assert outcomes == {"2": "written"}, outcomes


def test_an_unqualified_target_still_writes_every_row(tmp_path):
    """The control: scoping must not narrow a target that claims the whole slot."""
    state = _named_state(2)

    detail = _scoped_executor(tmp_path, state)._propagate(
        _propagation_plan("sonarr.indexers")
    )

    assert "2 row(s) written" in detail, detail
    assert state.rows["sonarr"] == [NEW_KEY, NEW_KEY]


def test_a_missing_named_row_refuses_rather_than_writing_everything(tmp_path):
    """Silence is the dangerous direction.

    An unmatched selector must not fall back to the whole slot, which is what
    happened unconditionally before: a typo in one consumer would have overwritten
    every row, after the old credential had already been revoked.
    """
    state = _named_state(2)

    with pytest.raises(RotationError, match="no row named 'Not Here'"):
        _scoped_executor(tmp_path, state)._propagate(
            _propagation_plan("sonarr.indexers[Not Here]")
        )

    assert state.api_writes == 0
    assert state.rows["sonarr"] == [OLD_KEY, OLD_KEY]


def test_a_row_and_field_qualifier_writes_that_field(tmp_path):
    """`download_clients[qBittorrent:password]` must not land in `apiKey`.

    The slot registry names one default field per slot, so without the field half
    of the qualifier a password rotation writes the password into the apiKey
    column - leaving the password stale and the apiKey wrong. Latent today, since
    `qbittorrent_password` is refused earlier by its write mechanism.
    """
    state = FakeState()
    state.rows["sonarr"] = [OLD_KEY]
    written: dict[str, str] = {}

    def call(host, service, method, path, *, body=None, key=None, transport=None,
             timeout=None):
        if method == "PUT":
            written.update({f["name"]: f["value"] for f in body["fields"]})
            # The database is the thing the write is verified against, so it has
            # to move too - otherwise the step fails at read-back for a reason
            # unrelated to the field selection under test.
            state.rows["sonarr"] = [body["fields"][0]["value"]]
            return 202, None
        if path == "/downloadclient":
            return 200, [{"id": 0, "name": "qBittorrent"}]
        if path.startswith("/downloadclient/"):
            return 200, {"id": 0, "name": "qBittorrent",
                         "fields": [{"name": "password", "value": OLD_KEY}]}
        return 200, None

    ctx = RotationContext(
        credential=_credential(), host=HOST, transport=FakeTransport(state),
        journal=Journal(tmp_path / "j.db"), vault_value=OLD_KEY,
        settle_timeout=0.0, write_backoff=0.0, write_interval=0.0,
    )
    ctx.minted = Secret(NEW_KEY)
    plan = RotationPlan(credential=_credential(), host=HOST)
    plan.add(StepKind.PROPAGATE, "sonarr.download_clients[qBittorrent:password]", "x")

    Executor(ctx, servarr_call=call)._propagate(plan.steps[0])

    assert written.get("password") == NEW_KEY, written
    assert "apiKey" not in written, "the slot default field was written instead"


class _LocalScriptTransport:
    """Runs the executor's own probe script against a real SQLite file.

    The encoding handling lives in a script string that normally crosses the transport.
    Testing a copy of it here would prove nothing, so the script is executed
    as written, against a database holding the real column values.
    """

    name = "local"

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def run_python(self, code: str, *, timeout: int | None = None) -> str:
        code = code.replace(repr(str(self.db_path)), repr(str(self.db_path)))
        namespace: dict = {"__name__": "__probe__"}
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            exec(compile(code, "<probe>", "exec"), namespace)
        return buffer.getvalue()


def test_the_restart_call_posts_to_the_service_native_route_with_the_live_key(
    tmp_path,
):
    state = FakeState()
    executor, _ = _executor(tmp_path, state)
    calls: list[tuple[str, str, str, str | None]] = []

    def call(host, service, method, path, *, key=None, **kwargs):
        calls.append((service, method, path, key))
        return 200, {}

    executor._call = call

    executor._restart_service("prowlarr", key=OLD_KEY)

    assert calls == [("prowlarr", "POST", "/system/restart", OLD_KEY)]


def test_a_refused_restart_names_the_parked_key_and_the_way_out(tmp_path):
    state = FakeState()
    executor, _ = _executor(tmp_path, state)
    executor._call = lambda *args, **kwargs: (500, {})

    with pytest.raises(RotationError) as caught:
        executor._restart_service("prowlarr", key=OLD_KEY)

    assert "refused the service-native restart" in str(caught.value)
    assert "parked" in caught.value.hint
    assert "now-revoked" in caught.value.hint
    assert "Re-run" in caught.value.hint


def test_restart_key_waits_through_connection_resets(tmp_path, monkeypatch):
    """A probe for the key transition must not die on the thing it is probing.

    A service that was just restarted resets connections for a second or two.
    Letting that escape bypassed the loop, so a service that was merely coming
    back looked like a hard failure - and the rotation aborted moments after it
    had already succeeded.
    """
    monkeypatch.setattr("credarr.executor.READINESS_INTERVAL", 0.01)
    state = FakeState()
    state.service_key["prowlarr"] = NEW_KEY
    executor, _ = _executor(tmp_path, state)
    real = executor._authenticate
    calls = {"n": 0}

    def resetting(service, key):
        if key == NEW_KEY:
            calls["n"] += 1
            if calls["n"] <= 2:
                return "unknown", "ConnectionResetError"
        return real(service, key)

    executor._authenticate = resetting

    executor._await_restart_key(
        "prowlarr", old_key=OLD_KEY, new_key=NEW_KEY
    )

    assert calls["n"] > 2, "returned before the service stopped resetting"


def test_restart_key_fails_when_the_new_key_never_authenticates(tmp_path, monkeypatch):
    monkeypatch.setattr("credarr.executor.READINESS_TIMEOUT", 0.05)
    monkeypatch.setattr("credarr.executor.READINESS_INTERVAL", 0.01)

    state = FakeState()
    executor, _ = _executor(tmp_path, state)

    with pytest.raises(RotationError, match="did not make the restored key usable"):
        executor._await_restart_key(
            "prowlarr", old_key=OLD_KEY, new_key=NEW_KEY
        )


def test_restart_key_proceeds_when_the_old_key_probe_is_inconclusive(tmp_path):
    """A 403 or an unreachable old-key probe is not proof the old key is live.

    The new key is live, so the restart happened. Proceeding is safe; claiming
    exercise-only proof is not.
    """
    state = FakeState()
    executor, ctx = _executor(tmp_path, state)

    def authenticate(service, key):
        if key == NEW_KEY:
            return "live", "HTTP 200"
        return "unknown", "ConnectionResetError"

    executor._authenticate = authenticate

    executor._await_restart_key("prowlarr", old_key=OLD_KEY, new_key=NEW_KEY)

    assert ctx.old_key_dead is False


def test_restart_key_fails_when_the_old_key_stays_live(tmp_path, monkeypatch):
    monkeypatch.setattr("credarr.executor.READINESS_TIMEOUT", 0.05)
    monkeypatch.setattr("credarr.executor.READINESS_INTERVAL", 0.01)

    state = FakeState()
    executor, _ = _executor(tmp_path, state)

    executor._authenticate = lambda service, key: ("live", "HTTP 200")

    with pytest.raises(RotationError, match="old key still authenticates"):
        executor._await_restart_key(
            "prowlarr", old_key=OLD_KEY, new_key=NEW_KEY
        )


def test_a_rate_limited_upstream_is_retried_not_fatal(tmp_path):
    """The 30-minute outage, as a test.

    Sonarr and Radarr each validate an indexer by calling Prowlarr live during
    the save, so Prowlarr rate-limiting reaches us as a 400 from the app holding
    the row. Treating that as fatal halted convergence for every remaining row
    and every later service, and left the credential live in Prowlarr but absent
    from the vault for half an hour.
    """
    state = FakeState()
    executor, _ = _executor(tmp_path, state)

    calls = {"n": 0}
    original = executor._call

    def rate_limited(host, service, method, path, *, body=None, key=None,
                     transport=None, **kwargs):
        if method == "PUT" and service == "sonarr":
            calls["n"] += 1
            if calls["n"] <= 2:
                return 400, {
                    "title": "Invalid request Validation failed",
                    "errors": {"-- ": ["Unable to connect to indexer: "
                                        "[429:TooManyRequests]"]},
                }
        return original(host, service, method, path, body=body, key=key,
                        transport=transport, **kwargs)

    executor._call = rate_limited
    result = executor.execute(_plan())

    assert result.ok, result.detail
    assert result.failed is None, result.detail
    assert calls["n"] > 2, "the rate limit was not retried at all"


def test_a_permanent_refusal_is_not_retried(tmp_path):
    """Retrying forever what will never succeed is its own kind of outage."""
    state = FakeState()
    state.api_accepts_write = False
    state.put_status = 400
    state.put_body = {
        "title": "Invalid request Validation failed",
        "errors": {"-- ": ["Query successful, but no results in the configured "
                            "categories were returned from your indexer."]},
    }
    executor, _ = _executor(tmp_path, state)
    original = executor._call
    puts = {"n": 0}

    def counted(host, service, method, path, *, body=None, key=None, transport=None):
        if method == "PUT":
            puts["n"] += 1
        return original(host, service, method, path, body=body, key=key, transport=transport)

    executor._call = counted
    result = executor.execute(_plan())

    assert not result.ok
    assert puts["n"] == 1, f"a permanent refusal was retried {puts['n']} times"
    assert "no results in the configured categories" in result.detail


def test_a_refusal_that_echoes_the_credential_never_reaches_a_report(tmp_path):
    """The leak this closes.

    Servarr's validation errors echo the resource they refused, and the resource
    carries the credential being rotated. That text is the service's own, so it
    looks safe to print - and it is exactly where the credential ends up: in
    `result.detail`, in each holder's detail, in the journal's step and holder
    rows, and in the operator's terminal from the CLI.
    """
    state = FakeState()
    state.api_accepts_write = False
    state.put_status = 400
    state.put_body = {
        "title": "Validation failed",
        "errors": {"apiKey": [f"Value {NEW_KEY} was rejected by the upstream indexer"]},
    }
    executor, ctx = _executor(tmp_path, state)
    ctx.minted = Secret(NEW_KEY)
    plan = _plan()
    plan.steps = [step for step in plan.steps if step.kind is not StepKind.MINT]

    result = executor.execute(plan)

    assert not result.ok
    for text in (result.detail,
                 *[h.detail for h in result.holders]):
        assert NEW_KEY not in text, f"credential in a report field: {text!r}"

    journal = Journal(tmp_path / "j.db")
    recorded = " ".join(
        [s["outcome"] or "" for s in journal.steps(result.attempt)]
        + [h["detail"] or "" for h in journal.holders(result.attempt)]
    )
    assert NEW_KEY not in recorded, "credential persisted in the journal"


def test_scrubbing_leaves_the_diagnosis_intact(tmp_path):
    """The control: the reason still has to be readable.

    Redacting the whole refusal would satisfy the leak test while destroying the
    message that tells an operator which upstream refused, which is the entire
    point of capturing it.
    """
    state = FakeState()
    state.api_accepts_write = False
    state.put_status = 400
    state.put_body = {
        "title": "Validation failed",
        "errors": {"apiKey": [f"Value {NEW_KEY} rejected: TooManyRequests"]},
    }
    executor, ctx = _executor(tmp_path, state)
    ctx.minted = Secret(NEW_KEY)
    plan = _plan()
    plan.steps = [step for step in plan.steps if step.kind is not StepKind.MINT]

    result = executor.execute(plan)

    assert "[redacted]" in result.detail
    # `_explain` prefers the first matching error message over the title, so the
    # upstream's own wording survives rather than the generic summary.
    assert "TooManyRequests" in result.detail


def test_the_services_own_words_reach_the_report(tmp_path):
    """A bare "HTTP 400" does not say whether the service refused the value or
    the request was malformed, and those need different fixes."""
    state = FakeState()
    state.api_accepts_write = False
    state.put_status = 400
    state.put_body = {
        "title": "Invalid request Validation failed",
        "errors": {"-- ": ["Unable to connect to indexer: [429:TooManyRequests]"]},
    }
    executor, _ = _executor(tmp_path, state)

    result = executor.execute(_plan())

    assert not result.ok
    assert "TooManyRequests" in result.detail, result.detail


def _no_pacing(**overrides):
    """A RotationContext with the real waits intact, so pacing can be asserted."""
    ctx = RotationContext(
        credential=_credential(), host=HOST, transport=FakeTransport(FakeState()),
        journal=None, vault_value=OLD_KEY,
        settle_timeout=0.0, write_backoff=0.0, **overrides,
    )
    return ctx


def test_holder_writes_are_paced_not_burst(recorded_sleeps, tmp_path):
    """Every write makes the *arr app validate the indexer against its upstream.

    A rotation adds a burst of requests to an upstream the app is already
    hammering with its own background sync. That is what produced the 429 that
    turned into a 30-minute outage, so the writes are spaced - and the spacing is
    asserted rather than assumed.
    """
    state = FakeState()
    executor, ctx = _executor(tmp_path, state)
    ctx.write_interval = 2.0

    executor.execute(_plan())

    paced = [s for s in recorded_sleeps if s == 2.0]
    assert len(paced) >= 2, f"writes were not paced; sleeps recorded: {recorded_sleeps}"


def test_pacing_is_off_when_the_operator_turns_it_off(recorded_sleeps, tmp_path):
    """Zero means the operator chose it, and it is honoured - not overridden."""
    state = FakeState()
    executor, ctx = _executor(tmp_path, state)
    ctx.write_interval = 0.0

    executor.execute(_plan())

    assert not [s for s in recorded_sleeps if s == 2.0]


def test_the_default_pacing_is_not_zero():
    """Zero would be a silent promise that the problem does not exist.

    The burst is what produced the rate limit in the first place, so the shipped
    default has to actually pace. An operator may turn it off deliberately;
    that is a choice, not the out-of-the-box state.
    """
    fields = {f.name: f.default for f in RotationContext.__dataclass_fields__.values()}
    assert fields["write_interval"] > 0, (
        "the default must pace; a silent zero would hide the reason"
    )


def test_execute_refuses_a_blocked_plan_before_it_mints(tmp_path):
    """A plan that already knows it cannot finish must not be started.

    The CLI checks this, but the CLI is the presentation layer. Anything else
    calling the executor - a wrapper, a scheduler, a test harness - would
    otherwise revoke the old key, discover the holder it could not write, and
    report a partial rotation: the new value in the vault and nowhere else.

    Asserted on what did *not* happen rather than on the exception alone,
    because a guard placed after the mint would still raise.
    """
    state = FakeState()
    _, ctx = _executor(tmp_path, state)
    plan = _plan()
    plan.blocked_by.append("credarr has no rotation writer for profilarr.arr_config")
    key_before = dict(state.service_key)
    rows_before = {k: list(v) for k, v in state.rows.items()}

    with pytest.raises(RotationError, match="cannot complete"):
        Executor(ctx, servarr_call=_servarr_call(state)).execute(plan)

    assert state.service_key == key_before, "the mint ran anyway"
    assert state.rows == rows_before, "a holder was written anyway"
    assert state.api_writes == 0, "the service was contacted anyway"
    assert ctx.minted is None


def test_execute_refuses_a_plan_with_no_steps(tmp_path):
    """No steps is the other way a plan can promise nothing and deliver less.

    An empty plan would otherwise mint, propagate to nothing, and report every
    holder as updated - the most complete-looking failure this tool can produce.
    """
    state = FakeState()
    _, ctx = _executor(tmp_path, state)
    plan = RotationPlan(credential=_credential(), host=HOST)

    with pytest.raises(RotationError, match="cannot complete"):
        Executor(ctx, servarr_call=_servarr_call(state)).execute(plan)

    assert ctx.minted is None


def test_an_unreachable_query_auth_call_does_not_quote_the_key():
    """Query auth puts the key in the URL; the message must use the URL without it.

    A message that carries a percent-encoded key would depend on `scrub`
    matching a string that appears in it in a different form.
    """
    class _Refusing:
        def run_python(self, code, *, timeout=None):
            return "\x00-1\x00ConnectionRefused"

    host = HostConfig(
        name="h",
        urls={"jellyfin": "http://127.0.0.1:8096"},
    )

    with pytest.raises(TransportError) as caught:
        real_servarr_call(host, "jellyfin", "GET", "/Auth/Keys?app=x",
                          key="s3cret-key", transport=_Refusing(),
                          auth_transport="query")

    assert "s3cret-key" not in str(caught.value), str(caught.value)
    assert "/Auth/Keys" in str(caught.value), str(caught.value)


def test_an_oversize_api_answer_is_refused_not_buffered() -> None:
    """An ordinary route is a small JSON document. A service or proxy that
    streams forever must fail the call, not exhaust memory."""
    class _Oversize:
        def run_python(self, code, *, timeout=None):
            return "\x00-2\x00"

    host = HostConfig(name="h", urls={"prowlarr": "http://127.0.0.1:9696"})

    with pytest.raises(RotationError) as caught:
        real_servarr_call(host, "prowlarr", "GET", "/indexer",
                          key="stored-key", transport=_Oversize())

    message = str(caught.value)
    assert f"exceeded {MAX_JSON_RESPONSE_BYTES} bytes" in message
    assert "stored-key" not in message


def test_the_generated_probe_bounds_what_it_reads() -> None:
    """The cap must be in the process that reads the socket, not applied after
    the body has already been buffered here."""
    class _Capture:
        def __init__(self):
            self.code = ""

        def run_python(self, code, *, timeout=None):
            self.code = code
            return "\x00200\x00{}"

    transport = _Capture()
    host = HostConfig(name="h", urls={"prowlarr": "http://127.0.0.1:9696"})
    real_servarr_call(host, "prowlarr", "GET", "/indexer",
                      key="stored-key", transport=transport)

    assert f"MAX_RESPONSE_BYTES = {MAX_JSON_RESPONSE_BYTES}" in transport.code
    assert "response.read(MAX_RESPONSE_BYTES + 1)" in transport.code
    assert "response.read()" not in transport.code


def test_the_real_probe_stops_at_the_response_cap() -> None:
    """The cap lives in the process reading the socket, not after buffering."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Oversize(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(MAX_JSON_RESPONSE_BYTES + 2))
            self.end_headers()
            self.wfile.write(b" " * (MAX_JSON_RESPONSE_BYTES + 2))

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Oversize)
    thread = __import__("threading").Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host = HostConfig(
            name="h",
            urls={"prowlarr": f"http://127.0.0.1:{server.server_port}"},
        )
        with pytest.raises(RotationError, match="exceeded"):
            real_servarr_call(
                host, "prowlarr", "GET", "/indexer",
                key="oversize-test-key", transport=LocalTransport(),
            )
    finally:
        server.shutdown()
        server.server_close()


def test_a_plain_bug_inside_a_step_is_reported_not_raised(tmp_path):
    """Only CredctlError carries a hint; the failure handler must not assume one.

    An AttributeError raised while reporting would escape `execute` as a
    traceback - and its chained original could carry an unscrubbed message.
    """
    state = FakeState()
    executor, _ = _executor(tmp_path, state)

    def explode(step):
        raise RuntimeError("boom")

    executor._dispatch = explode

    result = executor.execute(_plan())

    assert not result.ok
    assert "failed: boom" in result.detail, result.detail


class FakePending:
    """The pending slot, in memory, for the backup/restore mint's ordering tests."""

    def __init__(self, values: dict[str, Secret] | None = None) -> None:
        self.values = dict(values or {})
        self.sets: list[tuple[str, str]] = []
        self.clears: list[str] = []

    def get(self, credential: str) -> Secret | None:
        return self.values.get(credential)

    def set(self, credential: str, value: Secret) -> None:
        self.values[credential] = value
        self.sets.append((credential, value.reveal()))

    def clear(self, credential: str) -> None:
        self.values.pop(credential, None)
        self.clears.append(credential)


def _api_xml(key: str) -> str:
    return f"<Config><ApiKey>{key}</ApiKey><Port>8989</Port></Config>"


class ApiMintExecutor(Executor):
    """A backup/restore mint with the service side replaced by ordered verdicts."""

    def __init__(self, ctx, verdicts, backup_xml, restore_status=200):
        self.backup_xml = backup_xml
        self.restore_status = restore_status
        self.verdicts = list(verdicts)
        self.backup_calls = 0
        self.restores: list[bytes] = []
        self.restarts = 0
        super().__init__(
            ctx,
            servarr_backup=self._backup,
            servarr_restore=self._restore,
        )

    def _backup(self, host, service, *, key, transport):
        self.backup_calls += 1
        return self.backup_xml, "backup.zip"

    def _restore(self, host, service, *, key, xml, transport):
        self.restores.append(xml)
        return self.restore_status, None

    def _authenticate_settled(self, service, key):
        return self.verdicts.pop(0)

    def _confirm_old_key_dead(self, service, expected):
        self._ctx.old_key_dead = True

    def _restart_service(self, service, *, key):
        self.restarts += 1

    def _await_restart_key(self, service, *, old_key, new_key):
        new_verdict, new_detail = self.verdicts.pop(0)
        old_verdict, old_detail = self.verdicts.pop(0)
        if new_verdict != "live":
            raise RotationError(
                f"{service}: the service-native restart did not make the "
                f"restored key usable ({new_detail})"
            )
        if old_verdict == "live":
            raise RotationError(
                f"{service}: the old key still authenticates after the restart"
            )
        self._ctx.old_key_dead = old_detail == "HTTP 401"


def _api_context(tmp_path, pending):
    return RotationContext(
        credential=_credential(),
        host=HOST,
        transport=FakeTransport(FakeState()),
        journal=Journal(tmp_path / "j.db"),
        vault_value=OLD_KEY,
        pending=pending,
        settle_timeout=0.0,
    )


def test_a_backup_restore_mint_persists_before_restore_and_restarts_once(tmp_path):
    pending = FakePending()
    ctx = _api_context(tmp_path, pending)
    executor = ApiMintExecutor(
        ctx,
        verdicts=[("live", ""), ("live", ""), ("dead", "HTTP 401")],
        backup_xml=_api_xml(OLD_KEY),
    )

    detail = executor._mint_api(
        Step(StepKind.MINT, "prowlarr", "backup/restore", reversible=False)
    )

    candidate = ctx.minted.reveal()
    assert len(candidate) == 32
    assert pending.sets == [("prowlarr_api_key", candidate)]
    assert executor.backup_calls == 1
    assert len(executor.restores) == 1
    # The injected restore boundary receives config.xml; the helper turns it
    # into a config-only ZIP for the service. That shape is pinned separately.
    assert candidate.encode() in executor.restores[0]
    assert OLD_KEY.encode() not in executor.restores[0]
    assert executor.restarts == 1
    assert ctx.resumed is False
    assert ctx.old_key_dead is True
    assert "restored" in detail


def test_a_dead_parked_candidate_is_not_reported_as_a_resume(tmp_path):
    """A parked candidate means a previous attempt chose a key.

    It does not mean the service already holds that key. This run still
    performs the restore, so the result must not claim "no new key was
    minted" merely because the pending store was non-empty.
    """
    pending = FakePending({"prowlarr_api_key": Secret("pending-value")})
    ctx = _api_context(tmp_path, pending)
    executor = ApiMintExecutor(
        ctx,
        verdicts=[
            ("live", ""), ("dead", "HTTP 401"),
            ("live", ""), ("dead", "HTTP 401"),
        ],
        backup_xml=_api_xml(OLD_KEY),
    )

    executor._mint_api(
        Step(StepKind.MINT, "prowlarr", "backup/restore", reversible=False)
    )

    assert executor.backup_calls == 1
    assert len(executor.restores) == 1
    assert ctx.resumed is False


def test_a_backup_restore_mint_resumes_when_the_pending_key_is_live(tmp_path):
    pending = FakePending({"prowlarr_api_key": Secret("pending-value")})
    ctx = _api_context(tmp_path, pending)
    executor = ApiMintExecutor(
        ctx,
        verdicts=[("dead", "HTTP 401"), ("live", "")],
        backup_xml=_api_xml(OLD_KEY),
    )

    executor._mint_api(
        Step(StepKind.MINT, "prowlarr", "backup/restore", reversible=False)
    )

    assert ctx.minted.reveal() == "pending-value"
    assert ctx.resumed is True
    assert executor.backup_calls == 0
    assert executor.restores == []
    assert executor.restarts == 0


def test_a_backup_restore_mint_restarts_without_reuploading_an_already_restored_config(tmp_path):
    """A crash after the upload but before the restart leaves the candidate in
    config.xml and the old key live. The safe resume is the restart, not a
    second restore."""
    pending = FakePending({"prowlarr_api_key": Secret("pending-value")})
    ctx = _api_context(tmp_path, pending)
    executor = ApiMintExecutor(
        ctx,
        verdicts=[
            ("live", ""),
            ("dead", "HTTP 401"),
            ("live", ""),
            ("dead", "HTTP 401"),
        ],
        backup_xml=_api_xml("pending-value"),
    )

    executor._mint_api(
        Step(StepKind.MINT, "prowlarr", "backup/restore", reversible=False)
    )

    assert ctx.minted.reveal() == "pending-value"
    assert ctx.resumed is True
    assert executor.backup_calls == 1
    assert executor.restores == []
    assert executor.restarts == 1


def test_a_backup_restore_mint_refuses_a_config_holding_a_third_key(tmp_path):
    pending = FakePending({"prowlarr_api_key": Secret("pending-value")})
    ctx = _api_context(tmp_path, pending)
    executor = ApiMintExecutor(
        ctx,
        verdicts=[("live", ""), ("dead", "HTTP 401")],
        backup_xml=_api_xml("some-other-value"),
    )

    with pytest.raises(RotationError, match="neither"):
        executor._mint_api(
            Step(StepKind.MINT, "prowlarr", "backup/restore", reversible=False)
        )

    assert executor.restores == []
    assert executor.restarts == 0
    assert pending.values["prowlarr_api_key"].reveal() == "pending-value"


def test_a_backup_restore_mint_refuses_both_keys_authenticating(tmp_path):
    pending = FakePending({"prowlarr_api_key": Secret("pending-value")})
    ctx = _api_context(tmp_path, pending)
    executor = ApiMintExecutor(
        ctx,
        verdicts=[("live", ""), ("live", "")],
        backup_xml=_api_xml(OLD_KEY),
    )

    with pytest.raises(RotationError, match="both"):
        executor._mint_api(
            Step(StepKind.MINT, "prowlarr", "backup/restore", reversible=False)
        )

    assert executor.backup_calls == 0
    assert executor.restores == []


def test_a_backup_restore_mint_refuses_without_a_pending_store(tmp_path):
    ctx = _api_context(tmp_path, None)
    executor = ApiMintExecutor(
        ctx,
        verdicts=[],
        backup_xml=_api_xml(OLD_KEY),
    )

    with pytest.raises(RotationError, match="pending-secret"):
        executor._mint_api(
            Step(StepKind.MINT, "prowlarr", "backup/restore", reversible=False)
        )

    assert executor.backup_calls == 0


def test_a_backup_restore_mint_keeps_the_pending_value_when_restore_is_refused(tmp_path):
    pending = FakePending()
    ctx = _api_context(tmp_path, pending)
    executor = ApiMintExecutor(
        ctx,
        verdicts=[("live", "")],
        backup_xml=_api_xml(OLD_KEY),
        restore_status=400,
    )

    with pytest.raises(RotationError, match="HTTP 400"):
        executor._mint_api(
            Step(StepKind.MINT, "prowlarr", "backup/restore", reversible=False)
        )

    assert pending.values["prowlarr_api_key"].reveal()
    assert executor.restarts == 0


def test_record_clears_the_pending_value_after_the_canonical_write(tmp_path):
    pending = FakePending({"prowlarr_api_key": Secret("pending-value")})
    ctx = _api_context(tmp_path, pending)
    ctx.minted = Secret("pending-value")
    written: list[str] = []
    ctx.vault_setter = lambda value: written.append(value.reveal())
    executor = ApiMintExecutor(ctx, verdicts=[], backup_xml=_api_xml(OLD_KEY))

    assert executor._record() == "written"
    assert written == ["pending-value"]
    assert pending.clears == ["prowlarr_api_key"]
    assert "prowlarr_api_key" not in pending.values


def test_backup_restore_preflight_passes_when_the_store_holds_the_key_and_pending_slot(tmp_path):
    state = FakeState()
    ctx = _api_context(tmp_path, FakePending())
    executor = Executor(ctx, servarr_call=_servarr_call(state))
    plan = RotationPlan(
        credential=ctx.credential, host=ctx.host, mint_via="backup_restore"
    )
    plan.add(StepKind.MINT, "prowlarr", "backup/restore", reversible=False)

    assert executor.preflight(plan) == []
    assert state.backup_probe_calls == 1


def test_backup_restore_preflight_refuses_when_the_login_hides_the_download(tmp_path):
    """The API answering is not enough: the mint reads config.xml from a web
    route, and that route sits behind the service's UI login when authentication
    is on. The plan must say so before a run creates a backup and dies at the
    download (the measured Radarr 6.4.4 shape: /api/v3 200, /backup/manual 302).
    """
    state = FakeState()
    state.backup_probe_status = 302
    ctx = _api_context(tmp_path, FakePending())
    executor = Executor(ctx, servarr_call=_servarr_call(state))
    plan = RotationPlan(
        credential=ctx.credential, host=ctx.host, mint_via="backup_restore"
    )
    plan.add(StepKind.MINT, "prowlarr", "backup/restore", reversible=False)

    problems = executor.preflight(plan)

    assert any("web UI login" in problem for problem in problems), problems
    assert any("Disabled for Local Addresses" in problem for problem in problems), problems


def test_backup_restore_preflight_flags_a_page_served_for_a_missing_backup(tmp_path):
    """A proxy that answers 200 for everything would make the download a login
    page or an error page; the probe cannot call that route healthy."""
    state = FakeState()
    state.backup_probe_status = 200
    state.backup_probe_body = "<!doctype html><html>sign in</html>"
    ctx = _api_context(tmp_path, FakePending())
    executor = Executor(ctx, servarr_call=_servarr_call(state))
    plan = RotationPlan(
        credential=ctx.credential, host=ctx.host, mint_via="backup_restore"
    )
    plan.add(StepKind.MINT, "prowlarr", "backup/restore", reversible=False)

    problems = executor.preflight(plan)

    assert any("login page" in problem for problem in problems), problems


def test_backup_restore_preflight_resumes_when_the_parked_key_is_live(tmp_path):
    """The crash-after-restart state must plan, not refuse.

    The service is already on the parked key and the store is still on the old
    one; that is exactly the resume the pending store exists for. The stored
    key failing the backup API is evidence of the crash, not a dead end.
    """
    state = FakeState()
    state.service_key["prowlarr"] = NEW_KEY
    pending = FakePending({"prowlarr_api_key": Secret(NEW_KEY)})
    ctx = _api_context(tmp_path, pending)
    executor = Executor(ctx, servarr_call=_servarr_call(state))
    plan = RotationPlan(
        credential=ctx.credential, host=ctx.host, mint_via="backup_restore"
    )
    plan.add(StepKind.MINT, "prowlarr", "backup/restore", reversible=False)

    assert executor.preflight(plan) == []


def test_backup_restore_preflight_refuses_without_a_pending_store(tmp_path):
    state = FakeState()
    ctx = _api_context(tmp_path, None)
    executor = Executor(ctx, servarr_call=_servarr_call(state))
    plan = RotationPlan(
        credential=ctx.credential, host=ctx.host, mint_via="backup_restore"
    )
    plan.add(StepKind.MINT, "prowlarr", "backup/restore", reversible=False)

    problems = executor.preflight(plan)

    assert any("pending-secret" in problem for problem in problems), problems


def test_backup_restore_preflight_refuses_when_the_key_cannot_read_backups(tmp_path):
    state = FakeState()
    state.service_key["prowlarr"] = "some-other-key"
    ctx = _api_context(tmp_path, FakePending())
    executor = Executor(ctx, servarr_call=_servarr_call(state))
    plan = RotationPlan(
        credential=ctx.credential, host=ctx.host, mint_via="backup_restore"
    )
    plan.add(StepKind.MINT, "prowlarr", "backup/restore", reversible=False)

    problems = executor.preflight(plan)

    assert any("backup API" in problem for problem in problems), problems


def test_the_restore_upload_is_a_config_only_zip(tmp_path):
    """The pinned Sonarr release accepts `.xml` at the upload route but treats
    anything that is not a ZIP as a database. Uploading config.xml directly
    overwrote sonarr.db in the live fixture. The only safe shape is a ZIP with
    exactly one config.xml inside it."""
    import threading
    from email import policy
    from email.parser import BytesParser
    from http.server import BaseHTTPRequestHandler, HTTPServer

    seen: dict[str, object] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            message = BytesParser(policy=policy.default).parsebytes(
                b"Content-Type: "
                + self.headers["Content-Type"].encode()
                + b"\r\n\r\n"
                + body
            )
            parts = list(message.iter_parts())
            if len(parts) != 1:
                seen["parts"] = len(parts)
            else:
                part = parts[0]
                seen["filename"] = part.get_filename()
                seen["part_type"] = part.get_content_type()
                seen["archive"] = part.get_payload(decode=True)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"restartRequired": true}')

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host = HostConfig(
            name="local",
            urls={"sonarr": f"http://127.0.0.1:{server.server_port}"},
        )
        status, _ = _servarr_restore_config(
            host,
            "sonarr",
            key="old-key",
            xml=b"<Config><ApiKey>new-key</ApiKey></Config>",
            transport=LocalTransport(),
        )
    finally:
        server.shutdown()
        thread.join()

    assert status == 200
    assert seen["filename"] == "credarr-config.zip"
    assert seen["part_type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(seen["archive"])) as archive:
        assert archive.namelist() == ["config.xml"]
        assert b"new-key" in archive.read("config.xml")
        assert b"sonarr.db" not in b"\n".join(
            name.encode() for name in archive.namelist()
        )


def test_a_redirected_restore_is_not_mistaken_for_success(tmp_path):
    """A login or proxy redirecting the upload must not be followed to a 200
    login page: the caller would read that as an accepted restore, restart, and
    find the old key still live. The redirect is returned as the status."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host = HostConfig(
            name="local",
            urls={"sonarr": f"http://127.0.0.1:{server.server_port}"},
        )
        status, _ = _servarr_restore_config(
            host,
            "sonarr",
            key="old-key",
            xml=b"<Config><ApiKey>new-key</ApiKey></Config>",
            transport=LocalTransport(),
        )
    finally:
        server.shutdown()
        thread.join()

    assert status == 302


def test_a_backup_restore_mint_discards_a_pending_copy_of_the_stored_key(tmp_path):
    """A crash after RECORD can leave the recorded value in the CLI's file
    store, which has no startup prune. Treating it as a second candidate makes
    the run see the same key twice and fail closed for no reason."""
    pending = FakePending({"prowlarr_api_key": Secret(OLD_KEY)})
    ctx = _api_context(tmp_path, pending)
    executor = ApiMintExecutor(
        ctx,
        verdicts=[("live", ""), ("live", ""), ("dead", "HTTP 401")],
        backup_xml=_api_xml(OLD_KEY),
    )

    executor._mint_api(
        Step(StepKind.MINT, "prowlarr", "backup/restore", reversible=False)
    )

    assert pending.clears == ["prowlarr_api_key"]
    assert ctx.minted.reveal() != OLD_KEY
    assert pending.values["prowlarr_api_key"].reveal() == ctx.minted.reveal()


def test_a_backup_restore_mint_refuses_when_the_config_holds_a_lost_value(tmp_path):
    pending = FakePending()
    ctx = _api_context(tmp_path, pending)
    executor = ApiMintExecutor(
        ctx,
        verdicts=[("live", "")],
        backup_xml=_api_xml("a-value-no-store-knows"),
    )

    with pytest.raises(RotationError, match="neither the stored key"):
        executor._mint_api(
            Step(StepKind.MINT, "prowlarr", "backup/restore", reversible=False)
        )

    assert executor.restarts == 0
    assert pending.values["prowlarr_api_key"].reveal() != OLD_KEY


def test_a_backup_restore_mint_refuses_when_the_old_key_survives_the_restart(tmp_path):
    pending = FakePending({"prowlarr_api_key": Secret("pending-value")})
    ctx = _api_context(tmp_path, pending)
    executor = ApiMintExecutor(
        ctx,
        verdicts=[
            ("live", ""),
            ("dead", "HTTP 401"),
            ("live", ""),
            ("live", ""),
        ],
        backup_xml=_api_xml(OLD_KEY),
    )

    with pytest.raises(RotationError, match="old key still"):
        executor._mint_api(
            Step(StepKind.MINT, "prowlarr", "backup/restore", reversible=False)
        )

    assert len(executor.restores) == 1
    assert executor.restarts == 1
    assert pending.values["prowlarr_api_key"].reveal() == "pending-value"


def test_a_backup_delete_failure_fails_closed_without_restoring(tmp_path):
    """The archive holds the still-live key and the whole database. A failure
    to delete it must stop before any restore, not leave a second full copy
    behind while the run continues."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("config.xml", "<Config><ApiKey>old-key</ApiKey></Config>")
    archive_bytes = archive.getvalue()
    created = {"value": False}

    class Handler(BaseHTTPRequestHandler):
        def _json(self, body):
            raw = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path.endswith("/command/7"):
                self._json({"id": 7, "status": "completed"})
                return
            if self.path.endswith("/system/backup"):
                rows = [
                    {"id": 1, "path": "/backup/manual/old.zip", "name": "old.zip"}
                ]
                if created["value"]:
                    rows.append({
                        "id": 2,
                        "path": "/backup/manual/new.zip",
                        "name": "new.zip",
                    })
                self._json(rows)
                return
            if self.path == "/backup/manual/new.zip":
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Length", str(len(archive_bytes)))
                self.end_headers()
                self.wfile.write(archive_bytes)
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            if self.path.endswith("/command"):
                created["value"] = True
                self._json({"id": 7, "status": "queued", "name": "Backup"})
                return
            self.send_response(404)
            self.end_headers()

        def do_DELETE(self):
            self.send_response(500)
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host = HostConfig(
            name="local",
            urls={"prowlarr": f"http://127.0.0.1:{server.server_port}"},
        )
        with pytest.raises(RotationError, match="could not delete"):
            _servarr_backup_config(
                host,
                "prowlarr",
                key="old-key",
                transport=LocalTransport(),
            )
    finally:
        server.shutdown()
        thread.join()

    assert created["value"] is True


def test_the_backup_reader_waits_for_the_backup_command_to_finish():
    """Radarr lists the ZIP while it is still being written.

    The download route opens the file with File.OpenRead; a read during the
    backup command answers 500. The reader must wait for the command's
    completed status, not merely for a new file to appear in the list.
    """
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_STORED) as bundle:
        bundle.writestr("config.xml", "<Config><ApiKey>old-key</ApiKey></Config>")
    archive_bytes = archive.getvalue()
    state = {
        "command_started": False,
        "completed": False,
        "polls": 0,
        "downloads": 0,
        "before_complete": 0,
        "completed_downloads": 0,
    }

    class Handler(BaseHTTPRequestHandler):
        def _json(self, body, status: int = 200) -> None:
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            if self.path.endswith("/system/backup"):
                rows = [{"id": 1, "path": "/backup/manual/old.zip", "name": "old.zip"}]
                if state["command_started"]:
                    rows.append({
                        "id": 2,
                        "path": "/backup/manual/new.zip",
                        "name": "new.zip",
                    })
                self._json(rows)
                return
            if self.path.endswith("/command/7"):
                state["polls"] += 1
                if state["polls"] >= 2:
                    state["completed"] = True
                    self._json({"id": 7, "status": "completed"})
                else:
                    self._json({"id": 7, "status": "started"})
                return
            if self.path == "/backup/manual/new.zip":
                state["downloads"] += 1
                if not state["completed"]:
                    state["before_complete"] += 1
                    self.send_response(500)
                    self.end_headers()
                    return
                state["completed_downloads"] += 1
                if state["completed_downloads"] == 1:
                    self.send_response(500)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Length", str(len(archive_bytes)))
                self.end_headers()
                self.wfile.write(archive_bytes)
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if self.path.endswith("/command"):
                state["command_started"] = True
                self._json(
                    {"id": 7, "status": "queued", "name": "Backup"},
                    status=201,
                )
                return
            self.send_response(404)
            self.end_headers()

        def do_DELETE(self) -> None:
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host = HostConfig(
            name="local",
            urls={"prowlarr": f"http://127.0.0.1:{server.server_port}"},
        )
        xml, name = _servarr_backup_config(
            host, "prowlarr", key="old-key", transport=LocalTransport()
        )
    finally:
        server.shutdown()
        thread.join()

    assert "old-key" in xml
    assert name == "new.zip"
    assert state["polls"] == 2
    assert state["downloads"] == 2, "the 500 download was not retried"
    assert state["before_complete"] == 0, (
        "the backup was downloaded while the backup command was still running"
    )


def test_the_backup_probe_budget_covers_its_internal_waits():
    """The parent must not kill the child before cleanup and diagnosis.

    The script can wait 180s for the command and 120s for the file, then spend
    up to 60s downloading. A parent budget equal to the sum leaves no time for
    listing, extraction, or the DELETE call.
    """
    assert CONFIG_READ_TIMEOUT >= 180 + 120 + 60 + 30


def test_the_generated_backup_probe_bounds_every_read() -> None:
    """The control JSON, the full archive and config.xml all have a ceiling in
    the process that reads the socket."""
    class _Capture:
        def __init__(self):
            self.code = ""

        def run_python(self, code, *, timeout=None):
            self.code = code
            return json.dumps({
                "xml": base64.b64encode(b"<Config/>").decode(),
                "backup": "new.zip",
            })

    transport = _Capture()
    host = HostConfig(
        name="local", urls={"prowlarr": "http://127.0.0.1:9696"}
    )
    _servarr_backup_config(host, "prowlarr", key="old-key", transport=transport)

    assert "response.read(MAX_CONTROL_BYTES + 1)" in transport.code
    assert "total > MAX_BACKUP_BYTES" in transport.code
    assert "member.read(MAX_CONFIG_XML_BYTES + 1)" in transport.code
    assert "archive.read(names[0])" not in transport.code


def test_an_oversized_backup_still_deletes_the_service_copy(monkeypatch) -> None:
    """A size refusal must not leave the full database archive on the service."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_STORED) as bundle:
        bundle.writestr("config.xml", "<Config><ApiKey>old-key</ApiKey></Config>")
        bundle.writestr("database.db", b"x" * 4096)
    archive_bytes = archive.getvalue()
    created = {"value": False}
    deleted = {"value": False}

    class Handler(BaseHTTPRequestHandler):
        def _json(self, body):
            raw = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path.endswith("/command/7"):
                self._json({"id": 7, "status": "completed"})
                return
            if self.path.endswith("/system/backup"):
                rows = [{"id": 1, "path": "/backup/manual/old.zip", "name": "old.zip"}]
                if created["value"]:
                    rows.append(
                        {"id": 2, "path": "/backup/manual/new.zip", "name": "new.zip"}
                    )
                self._json(rows)
                return
            if self.path == "/backup/manual/new.zip":
                self.send_response(200)
                self.send_header("Content-Length", str(len(archive_bytes)))
                self.end_headers()
                self.wfile.write(archive_bytes)
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            created["value"] = True
            self._json({"id": 7, "status": "queued", "name": "Backup"})

        def do_DELETE(self):
            deleted["value"] = True
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setattr("credarr.executor.MAX_BACKUP_BYTES", 1024)
        host = HostConfig(
            name="local",
            urls={"prowlarr": f"http://127.0.0.1:{server.server_port}"},
        )
        with pytest.raises(RotationError, match="backup exceeded 1024 bytes"):
            _servarr_backup_config(
                host, "prowlarr", key="old-key", transport=LocalTransport()
            )
    finally:
        server.shutdown()
        thread.join()

    assert deleted["value"] is True


def test_a_backup_download_hidden_by_the_login_names_the_cause(tmp_path):
    """The measured Radarr 6.4.4 shape with UI authentication on: the API
    answers, the backup is created, and the download is a 302 to the login.
    The error must name that, not collapse into 'could not read config.xml'."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    created = {"value": False}

    class Handler(BaseHTTPRequestHandler):
        def _json(self, body):
            raw = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path.endswith("/command/7"):
                self._json({"id": 7, "status": "completed"})
                return
            if self.path.endswith("/system/backup"):
                rows = []
                if created["value"]:
                    rows.append({
                        "id": 2,
                        "path": "/backup/manual/new.zip",
                        "name": "new.zip",
                    })
                self._json(rows)
                return
            if self.path == "/backup/manual/new.zip":
                self.send_response(302)
                self.send_header("Location", "/login?returnUrl=%2Fbackup")
                self.end_headers()
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            if self.path.endswith("/command"):
                created["value"] = True
                self._json({"id": 7, "status": "queued", "name": "Backup"})
                return
            self.send_response(404)
            self.end_headers()

        def do_DELETE(self):
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host = HostConfig(
            name="local",
            urls={"prowlarr": f"http://127.0.0.1:{server.server_port}"},
        )
        with pytest.raises(RotationError, match="redirected to the service login") as caught:
            _servarr_backup_config(
                host,
                "prowlarr",
                key="old-key",
                transport=LocalTransport(),
            )
    finally:
        server.shutdown()
        thread.join()

    assert "Disabled for Local Addresses" in (caught.value.hint or "")
    assert created["value"] is True


class FailingBackup(ApiMintExecutor):
    def _backup(self, host, service, *, key, transport):
        raise RotationError("the backup API is down")


def test_the_backup_restore_mint_parks_the_value_before_reading_the_backup(tmp_path):
    """The store write is the crash-safety boundary. A backup failure must
    still leave the chosen value parked, or a later attempt has no way to know
    what was chosen."""
    pending = FakePending()
    ctx = _api_context(tmp_path, pending)
    executor = FailingBackup(
        ctx,
        verdicts=[("live", ""), ("dead", "HTTP 401")],
        backup_xml=_api_xml(OLD_KEY),
    )

    with pytest.raises(RotationError, match="backup API is down"):
        executor._mint_api(
            Step(StepKind.MINT, "prowlarr", "backup/restore", reversible=False)
        )

    assert pending.values["prowlarr_api_key"].reveal() != OLD_KEY


def test_execute_routes_the_planned_backup_restore_mint_to_the_api_path(tmp_path):
    """Pins the plan -> executor wiring. The backup/restore tests above call
    `_mint_api` directly, so a routing regression could otherwise stay green."""
    pending = FakePending()
    ctx = _api_context(tmp_path, pending)
    executor = ApiMintExecutor(
        ctx,
        verdicts=[("live", ""), ("live", ""), ("dead", "HTTP 401")],
        backup_xml=_api_xml(OLD_KEY),
    )
    plan = RotationPlan(credential=ctx.credential, host=ctx.host)
    plan.mint_via = "backup_restore"
    plan.add(StepKind.MINT, "prowlarr", "backup/restore", reversible=False)

    result = executor.execute(plan)

    assert result.completed == ["prowlarr"]
    assert executor.backup_calls == 1
    assert len(executor.restores) == 1
    assert ctx.minted is not None


# --- UI credential and manual mint -----------------------------------------


def _with_write(field: str, value: object):
    base = _credential()
    return replace(base, write={**base.write, field: value})


def _ui_context(tmp_path, *, write=None, mint_values=None, pending=None,
                provided=None):
    return RotationContext(
        credential=_with_write("ui_password", "prowlarr_ui_password")
        if write is None else replace(_credential(), write=write),
        host=HOST,
        transport=FakeTransport(FakeState()),
        journal=Journal(tmp_path / "ui.db"),
        vault_value=OLD_KEY,
        provided=provided,
        pending=pending if pending is not None else FakePending(),
        mint_values=(
            {"prowlarr_ui_password": Secret("hunter2")}
            if mint_values is None else mint_values
        ),
        settle_timeout=0.0,
    )


def _ui_plan(ctx):
    plan = RotationPlan(
        credential=ctx.credential, host=ctx.host, mint_via="backup_restore"
    )
    plan.add(StepKind.MINT, "prowlarr", "backup/restore", reversible=False)
    return plan


def test_a_ui_credential_logs_in_and_reopens_the_backup_probe(tmp_path):
    """The API key cannot open the web download; the UI session can.

    The first probe sees the login redirect. The retry must carry the session
    cookie, and a 404 for a name that cannot exist is the healthy answer.
    """
    state = FakeState()
    state.backup_probe_status = 302
    ctx = _ui_context(tmp_path)
    logins = []

    def login(host, service, *, username, password, transport):
        logins.append((service, username, password))
        return {"Cookie": ".AspNetCore.Forms=session"}

    executor = Executor(
        ctx, servarr_call=_servarr_call(state), servarr_login=login
    )

    assert executor.preflight(_ui_plan(ctx)) == []
    assert logins == [("prowlarr", "admin", "hunter2")]
    assert state.probe_headers == [
        None, {"Cookie": ".AspNetCore.Forms=session"}
    ]
    # The host config carries a password hash; only the username crosses.
    assert all("hashed-value" not in str(source) for source in state.sources)


def test_a_ui_credential_uses_basic_auth_without_a_login(tmp_path):
    state = FakeState()
    state.ui_auth_method = "basic"
    ctx = _ui_context(tmp_path)

    def login(*args, **kwargs):  # pragma: no cover - Basic must not log in
        raise AssertionError("Basic auth must not use the Forms login")

    executor = Executor(
        ctx, servarr_call=_servarr_call(state), servarr_login=login
    )
    headers = executor._ui_auth_headers("prowlarr", OLD_KEY)

    expected = base64.b64encode(b"admin:hunter2").decode()
    assert headers == {"Authorization": f"Basic {expected}"}


def test_external_ui_auth_is_refused_with_the_manual_option(tmp_path):
    state = FakeState()
    state.ui_auth_method = "external"
    ctx = _ui_context(tmp_path)
    executor = Executor(ctx, servarr_call=_servarr_call(state))

    with pytest.raises(RotationError, match="external provider") as caught:
        executor._ui_auth_headers("prowlarr", OLD_KEY)

    assert "write.manual_mint" in (caught.value.hint or "")


def test_a_ui_password_without_a_stored_value_is_refused(tmp_path):
    state = FakeState()
    state.backup_probe_status = 302
    ctx = _ui_context(tmp_path, mint_values={})
    executor = Executor(ctx, servarr_call=_servarr_call(state))

    problems = executor.preflight(_ui_plan(ctx))

    assert any("has no stored value" in problem for problem in problems), problems
    assert any("prowlarr_ui_password" in problem for problem in problems), problems


def _options_context(tmp_path, *, write=None, mint_values=None):
    return _ui_context(tmp_path, write=write, mint_values=mint_values)


def test_rotation_options_recommend_backup_when_the_download_is_open(tmp_path):
    state = FakeState()
    ctx = _options_context(
        tmp_path, write={"mechanism": "servarr_command"}, mint_values={}
    )
    executor = Executor(ctx, servarr_call=_servarr_call(state))

    options = executor.rotation_options()

    assert options["applicable"] is True
    assert options["recommended"] == "backup_restore"
    assert options["selected"] == "backup_restore"
    assert options["methods"]["backup_restore"]["available"] is True
    assert options["methods"]["backup_restore"]["ui_password"]["required"] is False
    assert options["methods"]["reconstruct"]["available"] is True
    assert options["methods"]["manual"]["available"] is True
    assert options["methods"]["manual"]["automatic"] is False


def test_rotation_options_point_at_the_password_when_auth_hides_the_download(tmp_path):
    state = FakeState()
    state.backup_probe_status = 302
    ctx = _options_context(
        tmp_path, write={"mechanism": "servarr_command"}, mint_values={}
    )
    executor = Executor(ctx, servarr_call=_servarr_call(state))

    options = executor.rotation_options()

    backup = options["methods"]["backup_restore"]
    assert options["recommended"] == "reconstruct"
    assert backup["available"] is False
    assert backup["ui_password"] == {
        "required": True,
        "configured": False,
        "can_help": True,
        "method": "forms",
    }
    assert "web UI login" in backup["reason"]
    assert options["methods"]["reconstruct"]["available"] is True


def test_rotation_options_see_backup_through_a_working_ui_password(tmp_path):
    state = FakeState()
    state.backup_probe_status = 302
    ctx = _options_context(tmp_path)
    logins = []

    def login(host, service, *, username, password, transport):
        logins.append((service, username, password))
        return {"Cookie": ".AspNetCore.Forms=session"}

    executor = Executor(
        ctx, servarr_call=_servarr_call(state), servarr_login=login
    )

    options = executor.rotation_options()

    assert options["recommended"] == "backup_restore"
    backup = options["methods"]["backup_restore"]
    assert backup["available"] is True
    assert backup["ui_password"]["required"] is True
    assert backup["ui_password"]["configured"] is True
    assert logins == [("prowlarr", "admin", "hunter2")]


def test_rotation_options_refuse_rebuild_for_postgres_and_recommend_manual(tmp_path):
    state = FakeState()
    state.backup_probe_status = 302
    state.database_type = "postgresql"
    ctx = _options_context(
        tmp_path, write={"mechanism": "servarr_command"}, mint_values={}
    )
    executor = Executor(ctx, servarr_call=_servarr_call(state))

    options = executor.rotation_options()

    assert options["recommended"] == "manual"
    assert options["methods"]["backup_restore"]["available"] is False
    assert options["methods"]["reconstruct"]["available"] is False
    assert "Postgres" in options["methods"]["reconstruct"]["reason"]
    assert options["methods"]["manual"]["available"] is True


def test_rotation_options_refuse_rebuild_without_a_database_type(tmp_path):
    state = FakeState()
    state.backup_probe_status = 302
    state.database_type = ""
    ctx = _options_context(
        tmp_path, write={"mechanism": "servarr_command"}, mint_values={}
    )
    executor = Executor(ctx, servarr_call=_servarr_call(state))

    options = executor.rotation_options()

    assert options["recommended"] == "manual"
    assert "databaseType" in options["methods"]["reconstruct"]["reason"]


def test_rotation_options_fall_back_when_a_saved_ui_password_is_wrong(tmp_path):
    state = FakeState()
    state.backup_probe_status = 302
    ctx = _options_context(tmp_path)

    def refused_login(*args, **kwargs):
        raise RotationError(
            "prowlarr: the UI login failed (the service refused the UI login)"
        )

    executor = Executor(
        ctx, servarr_call=_servarr_call(state), servarr_login=refused_login
    )

    options = executor.rotation_options()

    assert options["recommended"] == "reconstruct"
    backup = options["methods"]["backup_restore"]
    assert backup["available"] is False
    assert backup["ui_password"]["configured"] is True
    assert backup["ui_password"]["can_help"] is True
    assert "UI login" in backup["reason"]


def test_rotation_options_are_not_applicable_to_a_fixed_method(tmp_path):
    manifest = Manifest.parse(
        SELF_MANIFEST.replace("servarr_command", "seerr_regenerate"),
        known_targets=REGISTRY_TARGETS,
        known_backends=("ansible-vault",),
    )
    credential = next(iter(manifest.credentials.values()))
    ctx = RotationContext(
        credential=credential,
        host=HOST,
        transport=FakeTransport(FakeState()),
        journal=Journal(tmp_path / "fixed.db"),
        vault_value=OLD_KEY,
    )

    options = Executor(ctx).rotation_options()

    assert options == {
        "applicable": False,
        "service": "sonarr",
        "reason": "this credential has no Servarr-style rotation",
    }


def _manual_context(tmp_path, *, provided=NEW_KEY, pending=None):
    return RotationContext(
        credential=_with_write("manual_mint", True),
        host=HOST,
        transport=FakeTransport(FakeState()),
        journal=Journal(tmp_path / "manual.db"),
        vault_value=OLD_KEY,
        provided=provided,
        pending=pending if pending is not None else FakePending(),
        settle_timeout=0.0,
    )


class ManualMintExecutor(Executor):
    def __init__(self, ctx, verdicts, **kwargs):
        self.verdicts = list(verdicts)
        self.backup_calls = 0
        super().__init__(ctx, **kwargs)

    def _authenticate_settled(self, service, key):
        return self.verdicts.pop(0)

    def _confirm_old_key_dead(self, service, expected):
        self._ctx.old_key_dead = True


def _manual_step():
    return Step(StepKind.MINT, "prowlarr", "manual", reversible=False)


def test_a_manual_mint_accepts_the_supplied_key_and_parks_it(tmp_path):
    ctx = _manual_context(tmp_path)
    pending = ctx.pending
    executor = ManualMintExecutor(
        ctx, verdicts=[("dead", "HTTP 401"), ("live", "")],
    )

    detail = executor._mint_for(_manual_step())

    assert "no backup" in detail
    assert ctx.minted.reveal() == NEW_KEY
    assert pending.sets == [("prowlarr_api_key", NEW_KEY)]
    assert executor.backup_calls == 0
    assert ctx.old_key_dead is True


def test_a_manual_mint_refuses_the_stored_key_as_the_new_one(tmp_path):
    ctx = _manual_context(tmp_path, provided=OLD_KEY)
    executor = ManualMintExecutor(ctx, verdicts=[])

    with pytest.raises(RotationError, match="supplied key is the stored key"):
        executor._mint_for(_manual_step())

    assert ctx.pending.sets == []


def test_a_manual_mint_refuses_while_the_stored_key_still_works(tmp_path):
    ctx = _manual_context(tmp_path, provided="the-third-key")
    executor = ManualMintExecutor(ctx, verdicts=[("live", "HTTP 200")])

    with pytest.raises(RotationError, match="still authenticates"):
        executor._mint_for(_manual_step())

    assert ctx.pending.sets == []


def test_a_manual_mint_refuses_a_supplied_key_the_service_will_not_take(tmp_path):
    ctx = _manual_context(tmp_path, provided="wrong-key")
    executor = ManualMintExecutor(
        ctx, verdicts=[("dead", "HTTP 401"), ("dead", "HTTP 401")],
    )

    with pytest.raises(RotationError, match="does not authenticate"):
        executor._mint_for(_manual_step())

    assert ctx.pending.sets == []


def test_a_manual_mint_needs_a_key_when_nothing_is_parked(tmp_path):
    ctx = _manual_context(tmp_path, provided=None)
    executor = ManualMintExecutor(ctx, verdicts=[])

    with pytest.raises(RotationError, match="needs the service's new key"):
        executor._mint_for(_manual_step())


def test_a_manual_mint_resumes_from_the_parked_key(tmp_path):
    pending = FakePending({"prowlarr_api_key": Secret(NEW_KEY)})
    ctx = _manual_context(tmp_path, provided=None, pending=pending)
    executor = ManualMintExecutor(
        ctx, verdicts=[("dead", "HTTP 401"), ("live", "")],
    )

    detail = executor._mint_for(_manual_step())

    assert "accepted" in detail
    assert ctx.minted.reveal() == NEW_KEY
    assert ctx.resumed is True


def test_manual_mint_preflight_is_ready_before_the_key_exists(tmp_path):
    """The console needs a ready plan to offer the key field.

    The key does not exist at plan time, so a missing supplied value is not a
    preflight failure; the rotate request carries it.
    """
    ctx = _manual_context(tmp_path, provided=None)
    executor = ManualMintExecutor(
        ctx, verdicts=[], servarr_call=_servarr_call(FakeState())
    )

    assert executor.preflight(_ui_plan(ctx)) == []


def test_manual_mint_preflight_verifies_a_supplied_key(tmp_path):
    ctx = _manual_context(tmp_path, provided=NEW_KEY)
    executor = ManualMintExecutor(
        ctx, verdicts=[("dead", "HTTP 401"), ("live", "")],
        servarr_call=_servarr_call(FakeState()),
    )

    assert executor.preflight(_ui_plan(ctx)) == []


def test_a_manual_mint_replaces_a_dead_parked_key(tmp_path):
    """The operator can rotate again after a failed resume.

    A parked key the service no longer accepts is not a resume; the supplied
    key is the one the service now holds. The old/new checks still gate it.
    """
    pending = FakePending({"prowlarr_api_key": Secret("dead-parked-key")})
    ctx = _manual_context(tmp_path, provided=NEW_KEY, pending=pending)
    executor = ManualMintExecutor(
        ctx,
        verdicts=[
            ("dead", "HTTP 401"),  # parked key: dead, so replace it
            ("dead", "HTTP 401"),  # stored key
            ("live", ""),          # supplied key
        ],
    )

    executor._mint_for(_manual_step())

    assert ctx.minted.reveal() == NEW_KEY
    assert pending.values["prowlarr_api_key"].reveal() == NEW_KEY


def test_a_manual_mint_refuses_to_overwrite_a_live_parked_key(tmp_path):
    """Two different working keys are ambiguous; resume the parked one."""
    pending = FakePending({"prowlarr_api_key": Secret("live-parked-key")})
    ctx = _manual_context(tmp_path, provided=NEW_KEY, pending=pending)
    executor = ManualMintExecutor(
        ctx, verdicts=[("live", "HTTP 200")],
    )

    with pytest.raises(RotationError, match="parked a different key"):
        executor._mint_for(_manual_step())

    assert ctx.minted is None


def test_a_declared_ui_password_does_not_log_in_when_the_download_is_open(tmp_path):
    """The UI credential is an aid, not a mandate.

    A stale UI password must not fail a rotation whose download the API key
    already opens (auth off or local bypass). The mint re-probes and only logs
    in on the measured redirect.
    """
    state = FakeState()
    state.backup_probe_status = 404
    ctx = _api_context(tmp_path, FakePending())
    base = ctx.credential
    ctx.credential = replace(
        base, write={**base.write, "ui_password": "prowlarr_ui_password"}
    )
    ctx.mint_values = {"prowlarr_ui_password": Secret("wrong-password")}
    executor = ApiMintExecutor(
        ctx,
        verdicts=[("live", ""), ("live", ""), ("dead", "HTTP 401")],
        backup_xml=_api_xml(OLD_KEY),
    )
    executor._call = _servarr_call(state)
    logins = []
    executor._login = lambda *args, **kwargs: (
        logins.append(1) or {"Cookie": "should-not-be-used"}
    )

    executor._mint_api(
        Step(StepKind.MINT, "prowlarr", "backup/restore", reversible=False)
    )

    assert logins == []
    assert state.backup_probe_calls == 1


def test_a_declared_ui_password_must_have_a_stored_value_even_when_open(tmp_path):
    state = FakeState()
    state.backup_probe_status = 404
    ctx = _ui_context(tmp_path, mint_values={})
    executor = Executor(ctx, servarr_call=_servarr_call(state))

    problems = executor.preflight(_ui_plan(ctx))

    assert any("has no stored value" in problem for problem in problems), problems


def test_a_manual_mint_never_writes_the_supplied_key_to_the_journal(tmp_path):
    """The value is allowed in the pending store and the vault, nowhere else."""
    ctx = _manual_context(tmp_path)
    ctx.vault_setter = lambda value: None
    executor = ManualMintExecutor(
        ctx, verdicts=[("dead", "HTTP 401"), ("live", "")],
    )
    plan = RotationPlan(
        credential=ctx.credential, host=ctx.host, mint_via="provided"
    )
    plan.add(StepKind.MINT, "prowlarr", "manual", reversible=False)
    plan.add(StepKind.RECORD, "a.b", "write the canonical value")

    result = executor.execute(plan)

    assert result.failed is None
    assert result.vault_written is True
    assert NEW_KEY not in str(result)
    assert NEW_KEY not in str(ctx.journal.steps(result.attempt))


# --- reconstructed config restore ------------------------------------------


def _reconstruct_context(tmp_path):
    ctx = _api_context(tmp_path, FakePending())
    base = ctx.credential
    ctx.credential = replace(
        base, write={**base.write, "reconstruct_config": True}
    )
    return ctx


def _reconstruct_plan(ctx):
    plan = RotationPlan(
        credential=ctx.credential, host=ctx.host, mint_via="reconstructed"
    )
    plan.add(StepKind.MINT, "prowlarr", "rebuild config from the API")
    return plan


def test_reconstructed_preflight_reads_the_api_and_never_the_backup(tmp_path):
    state = FakeState()
    ctx = _reconstruct_context(tmp_path)
    executor = Executor(ctx, servarr_call=_servarr_call(state))

    assert executor.preflight(_reconstruct_plan(ctx)) == []
    assert state.backup_probe_calls == 0


def test_reconstructed_preflight_refuses_postgres(tmp_path):
    """The API does not expose Postgres settings; a rebuilt config would drop them."""
    state = FakeState()
    state.database_type = "postgresql"
    ctx = _reconstruct_context(tmp_path)
    executor = Executor(ctx, servarr_call=_servarr_call(state))

    problems = executor.preflight(_reconstruct_plan(ctx))

    assert any("postgres" in problem.lower() for problem in problems), problems
    assert any("write.ui_password" in problem for problem in problems), problems


def test_reconstructed_preflight_refuses_a_missing_critical_field(tmp_path):
    state = FakeState()
    state.omit_host_fields.add("urlBase")
    ctx = _reconstruct_context(tmp_path)
    executor = Executor(ctx, servarr_call=_servarr_call(state))

    problems = executor.preflight(_reconstruct_plan(ctx))

    assert any("urlBase" in problem for problem in problems), problems


def test_the_rebuilt_config_preserves_the_fields_the_api_exposes():
    host = {
        "bindAddress": "*",
        "port": 8989,
        "sslPort": 9898,
        "enableSsl": True,
        "launchBrowser": True,
        "authenticationMethod": "forms",
        "authenticationRequired": "disabledForLocalAddresses",
        "allowedHosts": "",
        "analyticsEnabled": False,
        "logLevel": "debug",
        "logSizeLimit": 1,
        "consoleLogLevel": "",
        "branch": "main",
        "sslCertPath": "/config/cert.pfx",
        "sslCertPassword": "cert&secret",
        "urlBase": "/sonarr",
        "trustedNetworks": "",
        "instanceName": "Sonarr",
        "updateAutomatically": False,
        "updateMechanism": "docker",
        "updateScriptPath": "",
        "proxyEnabled": False,
        "proxyType": "http",
        "proxyHostname": "",
        "proxyPort": 0,
        "proxyUsername": "",
        "proxyPassword": "",
        "proxyBypassFilter": "",
        "proxyBypassLocalAddresses": False,
        "certificateValidation": "enabled",
        "backupFolder": "",
        "backupInterval": 7,
        "backupRetention": 28,
        "trustCgnatIpAddresses": False,
        "username": "admin",
        "password": "a-hashed-value-must-not-cross",
    }

    xml = _config_xml_from_host(host, api_key=NEW_KEY)

    assert f"<ApiKey>{NEW_KEY}</ApiKey>" in xml
    assert "<AuthenticationMethod>Forms</AuthenticationMethod>" in xml
    assert (
        "<AuthenticationRequired>DisabledForLocalAddresses</AuthenticationRequired>"
        in xml
    )
    assert "<EnableSsl>True</EnableSsl>" in xml
    assert "<Port>8989</Port>" in xml
    assert "<UrlBase>/sonarr</UrlBase>" in xml
    assert "<SslCertPassword>cert&amp;secret</SslCertPassword>" in xml
    assert "a-hashed-value-must-not-cross" not in xml
    assert "<Username>" not in xml and "<Password>" not in xml


def test_reconstructed_mint_restores_the_built_config_without_a_backup(tmp_path):
    state = FakeState()
    ctx = _reconstruct_context(tmp_path)
    executor = ApiMintExecutor(
        ctx,
        verdicts=[("live", ""), ("live", ""), ("dead", "HTTP 401")],
        backup_xml=_api_xml(OLD_KEY),
    )
    executor._call = _servarr_call(state)
    executor._backup_config = lambda *args, **kwargs: (
        (_ for _ in ()).throw(AssertionError("the reconstructed path must not backup"))
    )

    detail = executor._mint_api(
        Step(StepKind.MINT, "prowlarr", "rebuild", reversible=False)
    )

    assert "rebuilt config.xml" in detail
    assert executor.backup_calls == 0
    assert len(executor.restores) == 1
    xml = executor.restores[0].decode()
    assert f"<ApiKey>{ctx.minted.reveal()}</ApiKey>" in xml
    assert "<AuthenticationMethod>Forms</AuthenticationMethod>" in xml
    assert "<Port>8989</Port>" in xml
    assert "a-hashed-value" not in xml


def test_a_rejected_reconstructed_restore_keeps_the_old_key_and_parks(tmp_path):
    state = FakeState()
    ctx = _reconstruct_context(tmp_path)
    executor = ApiMintExecutor(
        ctx,
        verdicts=[("live", ""), ("live", ""), ("dead", "HTTP 401")],
        backup_xml=_api_xml(OLD_KEY),
        restore_status=400,
    )
    executor._call = _servarr_call(state)

    with pytest.raises(RotationError, match="reconstructed config restore"):
        executor._mint_api(
            Step(StepKind.MINT, "prowlarr", "rebuild", reversible=False)
        )

    assert executor.restarts == 0
    assert ctx.pending.get("prowlarr_api_key") is not None


def test_reconstructed_preflight_requires_positive_sqlite_evidence(tmp_path):
    """A missing databaseType must refuse, not silently pass.

    Older/renamed builds may omit the field; a no-op Postgres gate would let a
    rebuilt config drop the Postgres connection and come up on SQLite.
    """
    state = FakeState()
    state.database_type = ""
    ctx = _reconstruct_context(tmp_path)
    executor = Executor(ctx, servarr_call=_servarr_call(state))

    problems = executor.preflight(_reconstruct_plan(ctx))

    assert any("databaseType" in problem for problem in problems), problems


def test_reconstructed_mint_refuses_postgres_before_restoring(tmp_path):
    state = FakeState()
    state.database_type = "postgresql"
    ctx = _reconstruct_context(tmp_path)
    executor = ApiMintExecutor(
        ctx,
        verdicts=[("live", ""), ("live", ""), ("dead", "HTTP 401")],
        backup_xml=_api_xml(OLD_KEY),
    )
    executor._call = _servarr_call(state)

    with pytest.raises(RotationError, match="postgres"):
        executor._mint_api(
            Step(StepKind.MINT, "prowlarr", "rebuild", reversible=False)
        )

    assert executor.restores == []
    assert ctx.pending.get("prowlarr_api_key") is not None


def test_reconstructed_preflight_resumes_from_a_live_parked_key(tmp_path):
    """A crash after the restore's restart leaves the stored key dead.

    The parked candidate is the live key; preflight must let the mint's
    candidate-live branch resume instead of refusing the stored key.
    """
    state = FakeState()
    state.service_key["prowlarr"] = NEW_KEY
    ctx = _reconstruct_context(tmp_path)
    ctx.pending = FakePending({"prowlarr_api_key": Secret(NEW_KEY)})
    executor = Executor(ctx, servarr_call=_servarr_call(state))

    assert executor.preflight(_reconstruct_plan(ctx)) == []
