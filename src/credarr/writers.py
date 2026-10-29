"""Where a rotated credential goes, per application.

The executor knows the shape of a rotation - mint, propagate, verify, record -
but not how any particular application stores a key. That difference used to be
hardcoded across the writer: an API path per slot in one dictionary, a
verification query in another, and the field name inline. Adding a service that
was not a Servarr app meant editing all of them, and no test failed if you
forgot one.

A `Holder` is the answer, and it carries two independent strategy names rather
than two types, because what varies per application is the pair:

  * `write`    - how a value reaches the holder: `"servarr_api"` over the
                 Servarr REST API, `"seerr_api"` over Seerr's own settings
                 API, or `"qui_api"` over qui's instance API
  * `readback` - where confirmation comes from: `"process_api"` asking the
                 running process for the value it holds, or `"qui_test"`
                 asking qui to connect to qBittorrent with the stored key

There is no file readback. A Servarr API redacts the value on read, so equality
is not observable through the API; a holder with a measured test route is
confirmed by exercise (`live`), and one without a test route is reported
unproven. Strict API-only means that is the honest ceiling.

`Slot` and `FileHolder` are gone. A type encodes a conclusion, and "API write /
process read-back" is true for Seerr and false for the Servarr apps, so a third
combination would have meant editing the type system. Two data fields keep the
executor free of service-specific branches.

Both sets of strategies live in one registry because the planner asks one
question of it - "does this build know how to write here?" - and a hole in either
answer is a rotation that silently cannot complete.

The Servarr apps remain the reason this module exists. Every indexer and
download-client row holds Prowlarr's key; every applications row holds the key
of the service Prowlarr manages. Getting that direction wrong compares one app's
key against another's and reports drift on a healthy stack.

profilarr is a known *manual* target, not a writer: `profilarr.arr_config`
lives in `targets.py` so a declared copy is validated and named in the plan,
while `holder_for` returns None so no rotation pretends it can write there.
Confirmed on the latest source (`797fb2b`) and the released v2.3.1 image:

  * **There is still no write route to call.** API v1 has `/api/v1/arr` with a
    `GET` only (also `/databases`, `/backups`, `/jobs`, `/status`). The update
    query exists (`arrInstancesQueries.update`), but its only caller is the
    SvelteKit page action `src/routes/arr/[id]/settings/+page.server.ts`.
  * **API-key auth cannot reach that action.** `src/hooks.server.ts` accepts
    `X-Api-Key` only under `/api/v1/`; the page action needs a browser session.
  * **The read cannot confirm a write either.** `toPublicArrInstance` strips
    `api_key`, `basic_auth_username` and `basic_auth_password`. Measured on
    v2.3.1: the synthetic instance returned without any of those fields.
  * The key lives plaintext in `arr_instances.api_key`. The download-backup
    route deletes Arr instances entirely (`backup/sanitize.ts`), so a
    rebuild/restore cannot carry a new key either [V: source].

`PUT /api/v1/arr/{id}` remains upstream issue #401 (milestone 2.x.x, open).
When it lands, this becomes a writer with the API-key mode above; until then
the UI offers the copy as manual and the rotation ends INCOMPLETE after naming
it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Holder:
    """One application, one kind of holder.

    `write` and `readback` name a strategy each, and they are independent axes.
    Servarr writes over an API and is exercised through its own measured test
    route; Seerr writes over an API and reads back from the running process - so
    coupling them into separate types forced a branch for every combination and
    produced the original mistake: "no table, so nothing can be confirmed",
    which was false.

    `auth` says how a credential reaches the application, and is a third axis for
    the same reason. Jellyfin accepts `X-Emby-Token` from v12 by default but
    ignores it, so a credential that arrives there never reaches the check -
    a 401 indistinguishable from a rejected credential.

    strategy keys     "servarr_api" | "seerr_api" | "qui_api"
    readback keys     "process_api" | "qui_test"
    auth keys         "header" | "query" | "bearer"
    """

    system: str
    slot: str
    write: str
    readback: str
    auth_transport: str
    auth_header_name: str
    # write-strategy data
    api_path: str = ""
    field: str = ""
    # readback-strategy data
    readback_path: str = ""
    # The app's own connection-test route, relative to the API version, or
    # empty when no endpoint has been measured for this holder. Measured:
    # Sonarr and Radarr `indexer/test`, Prowlarr `applications/test`, and
    # Sonarr/Radarr `downloadclient/test` for qBittorrent API keys. A missing
    # route is not a credential verdict.
    test_path: str = ""


# Sonarr, Radarr and Prowlarr share a layout: a REST API over a SQLite database
# whose rows carry keys belonging to *other* services. Every indexer and download
# client row holds Prowlarr's key; every applications row holds the key of the
# service Prowlarr manages. Getting that direction wrong compares one app's key
# against another's and reports drift on a healthy stack.
HOLDERS: dict[tuple[str, str], Holder] = {}

# The API version each service is on, and `None` means the routes are not under
# an `/api/{version}` prefix at all. It differs between them - Prowlarr and
# Seerr are v1 where the other two are v3 - so it is a fact about the service,
# not a constant the caller can assume.
#
# None of this says where a new credential comes from. `known_systems` below is
# that narrower question, and `MINT_SOURCES` below it: two maps answer
# two different questions, and conflating them is what let a plan try to run
# `ResetApiKey` against a service with no such command.
#
# Jellyfin is `None` because its API-key routes are `/Auth/Keys`, not
# `/api/v1/Auth/Keys`. Prefixing a version onto it produces a 404 that reads
# like a missing route rather than the wrong one.
API_VERSIONS: dict[str, str | None] = {
    "sonarr": "v3", "radarr": "v3", "prowlarr": "v1", "seerr": "v1",
    "lidarr": "v1", "readarr": "v1", "whisparr": "v3",
    "jellyfin": None, "qbittorrent": "v2", "qui": None,
    # Read-only connection tests only; neither service is a mint source.
    "profilarr": None, "homepage": None,
    # Grafana's routes are /api/... with no version prefix; Arcane's are too.
    "grafana": None, "arcane": None,
    # Gitea's API is /api/v1; readiness and liveness use /api/v1/user, which
    # answers 200 for a live token and 401 otherwise.
    "gitea": "v1",
}

# Where a service reports that it is up, when it is not the Servarr shape.
# Jellyfin has no `/system/status`; `/System/Info/Public` answers without a
# credential, which is exactly what a readiness probe needs.
READINESS_PATHS: dict[str, str] = {
    "jellyfin": "/System/Info/Public",
    # qBittorrent answers its version route with a Bearer API key. The
    # preflight sends the right scheme; this only names the route.
    "qbittorrent": "/app/version",
    # Seerr's public /status route answers without a credential, so it cannot
    # tell a live key from a dead one. The mint's authentication and resume
    # checks need an authenticated route; /auth/me answers 200 with a live key
    # and 401/403 without. (The Services version probe is separate.)
    "seerr": "/auth/me",
    # Grafana's /api/health is public and answers 200 for a dead token, so the
    # liveness route is /api/user: 200 for any valid Bearer token, 401 for a
    # revoked one. Measured on 12.1.1.
    "grafana": "/api/user",
    # Arcane's /api/auth/me is 200 for any live key whatever its scope, 401 for
    # a missing or deleted one. Its /api/health is public, so it cannot be the
    # liveness route. Measured on 2.17.0.
    "arcane": "/api/auth/me",
    # Gitea's /api/v1/user answers 200 for a live token and 401 otherwise.
    "gitea": "/user",
}

@dataclass(frozen=True)
class MintSource:
    """Where a new credential comes from.

    `system`      the service that mints
    `mechanism`    "reset" - the mint destroys the old key immediately, so every
                   holder holds a dead key until reached. "create" - the mint adds
                   a key alongside the old one, so revocation is a later step.
                   "rotate" - qBittorrent's single API key is replaced and the
                   response carries the new value; the old key dies immediately.
                   "regenerate" - Seerr's own single API key is replaced and the
                   response carries the random new value; the old key dies
                   immediately. Measured: the route updates the running process
                   in place, so no restart is needed.
    `auth_transport`
                  how the minting calls authenticate. Jellyfin reads `X-Emby-Token`
                  only with `EnableLegacyAuthorization` enabled, which is off by
                  default from v12, so its key travels in the `ApiKey` query
                  parameter; *arr read the header. Sending the wrong one is a 401
                  that is indistinguishable from a rejected credential.
    `mint_key_source`
                  where the key that authorises the mint is read from. Always
                  "vault": strict API-only means credarr never reads a local
                  service config. Servarr's own value is in the app's working
                  copy, and the backup/restore mint authenticates with it.
    """

    system: str
    mechanism: str
    auth_transport: str
    mint_key_source: str


MINT_SOURCES: dict[str, MintSource] = {}


def _mint_source(system: str, mechanism: str, auth_transport: str,
                 mint_key_source: str) -> None:
    MINT_SOURCES[system] = MintSource(
        system, mechanism, auth_transport, mint_key_source)


# Servarr's mint cannot return the new key, so the backup/restore path chooses
# the value and authenticates with the stored working copy; every mint source
# reads its authorising key from the vault/working copy.
for _system in ("sonarr", "radarr", "prowlarr", "lidarr", "readarr", "whisparr"):
    _mint_source(_system, "reset", "header", "vault")
_mint_source("jellyfin", "create", "query", "vault")
_mint_source("qbittorrent", "rotate", "bearer", "vault")
# Seerr's own key is regenerate-only: POST /settings/main rejects an apiKey
# field as readOnly (HTTP 400 from the OpenAPI validator), and
# POST /settings/main/regenerate returns the random replacement. Measured
# 2026-10-21 on 3.5.0 @ e2f24cb: the running process serves the new key
# immediately, settings.json is saved before the response, and no restart is
# needed. An API_KEY environment variable pins the key, so the executor
# refuses a response that returns the stored value unchanged.
_mint_source("seerr", "regenerate", "header", "vault")

# Grafana has no chosen-value token write: a service-account token's secret is
# generated by Grafana and returned once at creation. The mint is therefore a
# create: the replacement is created under a name in credarr's namespace, the
# holders are written, and the named predecessor is deleted last. Measured on
# 12.1.1 (2026-10-22): a token can create another for its own service account
# when the account's role is Admin; the legacy /api/auth/keys route is 404.
_mint_source("grafana", "grafana_token", "header", "vault")

# Arcane's scoped API keys are the same shape: POST /api/api-keys returns the
# secret once, PUT cannot issue a new one, and a key's own routes are
# session-only, so a key may only mint a replacement if it itself holds
# apikeys:create/list/delete and every permission it grants. Measured on
# 2.17.0 (2026-10-22): the list exposes `keyPrefix` - the first 12 characters
# of the secret - so the credential's own value identifies its row, and the
# replacement copies that row's name and grants. Duplicate names are accepted,
# which is what lets the replacement be created before the predecessor is
# deleted by id; static and environment-pairing keys are protected.
_mint_source("arcane", "arcane_apikey", "header", "vault")

# Gitea's token routes are Basic-auth only: upstream registers
# /users/{username}/tokens under reqBasicOrRevProxyAuth(), so an API token
# cannot list, create or delete tokens - measured on 1.27.2, where a
# write:user token got 401 "auth required". The mint therefore needs the
# user's password through write.mint_with, and discovery works because the
# token list exposes token_last_eight (the last 8 characters of the secret).
_mint_source("gitea", "gitea_token", "header", "vault")


def _holder(system: str, slot: str, **kwargs: str) -> None:
    HOLDERS[(system, slot)] = Holder(system=system, slot=slot, **kwargs)


def _servarr(system: str, slot: str, api_path: str, field: str,
             test_path: str = "") -> None:
    _holder(system, slot, write="servarr_api", readback="",
            auth_transport="header", auth_header_name="X-Api-Key",
            api_path=api_path, field=field, test_path=test_path)


for _service in ("sonarr", "radarr", "prowlarr", "lidarr", "readarr", "whisparr"):
    # The indexer test is measured on Sonarr and Radarr (README). The Servarr
    # siblings share the route, but no live run has exercised it, so they stay
    # exercise-unproven until measured. Prowlarr's own indexer rows are not a
    # holder of its key in the measured topology.
    _servarr(_service, "indexers", "indexer", "apiKey",
             test_path="indexer/test" if _service in {"sonarr", "radarr"} else "")
    # Measured 2026-10-26: with a qBittorrent API key stored in Sonarr
    # 4.0.20.3014 or Radarr 6.4.4.10685, downloadclient/test answers 200 while
    # the key is live and 400 after qBittorrent revokes it. The other *arr
    # builds have no qBittorrent apiKey field, so their route stays unmeasured.
    _servarr(_service, "download_clients", "downloadclient", "apiKey",
             test_path="downloadclient/test"
             if _service in {"sonarr", "radarr"} else "")

# Only Prowlarr has an Applications endpoint. A writer for an endpoint that
# does not exist would plan a propagation step and fail after the old key was
# already revoked.
_servarr("prowlarr", "applications", "applications", "apiKey",
         test_path="applications/test")


# Seerr holds Sonarr, Radarr and Jellyfin keys. All three are updated over its
# settings API - PUT /settings/{service}/{id} for arr rows, POST
# /settings/jellyfin for the single Jellyfin object - and `/settings/{service}`
# returns the running process's in-memory value, unredacted. The write needs
# Seerr's own API key; that is resolved from the runtime store. The slot name
# describes the settings API section it writes, not a local file.
def _seerr() -> None:
    _holder("seerr", "settings_json", write="seerr_api",
            readback="process_api", auth_transport="header",
            auth_header_name="X-API-Key",
            readback_path="/settings/{service}")


_seerr()


# qui is an API-only holder of a qBittorrent API key. The write needs qui's own
# API key (resolved from the runtime store) and the proof is qui's own
# connection test: it decrypts the stored value and asks qBittorrent to accept
# it. The key is encrypted at rest, so there is no plaintext read-back.
def _qui() -> None:
    _holder("qui", "instance", write="qui_api", readback="qui_test",
            auth_transport="header", auth_header_name="X-API-Key",
            api_path="/api/instances",
            readback_path="/api/instances/{id}/test")


_qui()


@dataclass(frozen=True)
class Reissue:
    """A mint whose service generates the secret and returns it once.

    Jellyfin, Grafana, Arcane and Gitea are all this shape, but only the last
    three need per-service routing: Jellyfin's create and read-back are two
    calls to routes the executor already owns. One descriptor per service
    holds everything the shared driver cannot infer - where the rows live, how
    the credential identifies its own row, how the replacement is named, and
    what the revoke sweeps - so a new reissue service is a row here plus, at
    most, a body shape this table cannot express.
    """

    system: str
    # The manifest's `write.mechanism` this row answers to. The mint-source
    # mechanism in `MINT_SOURCES` is a separate string and may differ.
    mechanism: str
    # Discovery: "collection" lists one endpoint (paged), "grafana_account"
    # resolves the token's service account first.
    list_kind: str
    list_path: str = ""
    page_style: str = "start_limit"      # "start_limit" | "page_limit"
    data_field: str = ""                 # "" = bare list; "data" = wrapped
    # How the current row is found: by a fingerprint the value advertises, or
    # by the name the manifest declares (Grafana advertises nothing).
    locate: str = "fingerprint"          # "fingerprint" | "declared_name"
    fingerprint_field: str = ""
    fingerprint_from: str = "prefix"     # "prefix" | "suffix"
    fingerprint_len: int = 0
    # Create/delete.
    create_path: str = ""
    delete_path: str = ""
    body: str = "name"                   # "name" | "permissions" | "scopes"
    response_key_field: str = "key"
    value_prefix: str = ""
    value_len: int = 0
    # Naming and sweeping.
    name_style: str = "keep"             # "keep" | "namespace"
    sweep: str = "same_name"             # "same_name" | "namespace"
    protected_fields: tuple[str, ...] = ()
    protected_hint: str = "a protected row"
    # The refusal sentence when the service refuses the create (403).
    create_denied: str = (
        "the authorising credential must hold the grants it issues"
    )
    # The list's name in "not in the ..." refusals.
    list_label: str = "service's list"
    # Auth: "bearer" and "header" use the credential (or its rotator) directly;
    # "basic" needs write.username plus a password rotator.
    auth: str = "header"
    # Manifest declarations: the name field, the grant list that overrides the
    # copied row, and the fields that are required before a plan can run.
    declared_name_field: str = ""
    require_name: bool = False
    declared_values_field: str = ""
    required_write: tuple[str, ...] = ()
    hints: Mapping[str, str] = field(default_factory=dict)
    # Why the plan orders it this way, shown before approval.
    reason: str = ""


# The three services whose reissue routes are not two calls to a fixed path.
# Measured facts behind each row live in docs/SERVICES.md.
REISSUERS: dict[str, Reissue] = {
    "grafana": Reissue(
        system="grafana",
        mechanism="grafana_service_token",
        list_kind="grafana_account",
        list_path="/api/serviceaccounts/{account}/tokens",
        create_path="/api/serviceaccounts/{account}/tokens",
        delete_path="/api/serviceaccounts/{account}/tokens/{id}",
        locate="declared_name",
        declared_name_field="token_name",
        require_name=True,
        name_style="namespace",
        sweep="namespace",
        auth="bearer",
        response_key_field="key",
        value_prefix="glsa_",
        list_label="service's token list",
        create_denied="creating tokens needs serviceaccounts:write (the "
        "account's Admin role)",
        hints={
            "token_name": "Grafana never returns a token's value on read, so "
            "the named token is the only handle a rotation has for revoking "
            "its predecessor",
        },
        reason="Grafana generates the token secret and returns it once, so "
        "the replacement is created alongside the old one and the old token "
        "is deleted only after every holder is confirmed. The replacement is "
        "named <token_name>.credarr.<unix>; the predecessor and any "
        ".credarr. stray are swept by name.",
    ),
    "arcane": Reissue(
        system="arcane",
        mechanism="arcane_api_key",
        list_kind="collection",
        list_path="/api/api-keys",
        data_field="data",
        fingerprint_field="keyPrefix",
        fingerprint_from="prefix",
        fingerprint_len=12,
        create_path="/api/api-keys",
        delete_path="/api/api-keys/{id}",
        name_style="keep",
        sweep="same_name",
        protected_fields=("isStatic", "isBootstrap"),
        protected_hint="static bootstrap or environment pairing key",
        list_label="service's key list",
        create_denied="the key must hold apikeys:create and every permission "
        "it grants",
        declared_name_field="key_name",
        declared_values_field="permissions",
        body="permissions",
        hints={},
        reason="Arcane returns the key secret once and cannot issue a chosen "
        "value, so the replacement is created alongside the old one and the "
        "old key is deleted only after every holder is confirmed. The old row "
        "is found by the credential's own key prefix; its name and grants are "
        "copied unless the manifest overrides them. Static and "
        "environment-pairing keys are refused before anything is created.",
    ),
    "gitea": Reissue(
        system="gitea",
        mechanism="gitea_token",
        list_kind="collection",
        list_path="/users/{username}/tokens",
        page_style="page_limit",
        fingerprint_field="token_last_eight",
        fingerprint_from="suffix",
        fingerprint_len=8,
        create_path="/users/{username}/tokens",
        delete_path="/users/{username}/tokens/{id}",
        body="scopes",
        response_key_field="sha1",
        value_len=40,
        name_style="namespace",
        sweep="namespace",
        auth="basic",
        list_label="user's token list",
        create_denied="the Basic-auth user must be allowed to create tokens "
        "with the declared scopes",
        declared_name_field="token_name",
        declared_values_field="scopes",
        required_write=("mint_with", "username"),
        hints={
            "mint_with": "Gitea's token routes accept Basic auth only, so a "
            "token cannot mint or delete tokens. Name the credential that "
            "holds the user's password.",
            "username": "the Basic-auth rotator needs the user whose tokens "
            "are managed",
        },
        reason="Gitea returns the token secret once and rejects a duplicate "
        "name, so the replacement is named <name>.credarr.<unix> and the "
        "predecessor plus any credarr-named stray is deleted only after every "
        "holder is confirmed. The predecessor is found by token_last_eight; "
        "its scopes are copied unless the manifest overrides them. Basic auth "
        "comes from write.mint_with, because a token cannot use the token "
        "routes.",
    ),
}

REISSUE_MECHANISMS: dict[str, str] = {
    spec.mechanism: spec.system for spec in REISSUERS.values()
}


def readiness_path(system: str) -> str:
    """Where a service reports that it is serving again.

    Defaults to the Servarr shape, which is what most services here are. Jellyfin
    is the exception and says so in `READINESS_PATHS`: probing
    `/system/status` there is a 404, which reads as "this service is broken"
    rather than "this service is a different shape".
    """
    return READINESS_PATHS.get(system, "/system/status")


def api_version(system: str) -> str | None:
    """The API version for a service, or None when it has no versioned prefix.

    Raises for a service this build does not know.
    """
    try:
        return API_VERSIONS[system]
    except KeyError as exc:
        raise KeyError(system) from exc


def holder_for(system: str, slot: str) -> Holder | None:
    """The holder description, or None when this build has no writer for it.

    One type, three strategy names - see `Holder`. Callers never branch on the
    type because there is nothing to branch on; they ask the named strategy.

    None is a real answer: the planner turns it into a refusal to rotate rather
    than a skip, because a rotation cannot complete while a holder cannot be
    updated, and a silently skipped holder leaves a live service holding a
    revoked key.
    """
    return HOLDERS.get((system, slot))


def known_systems() -> frozenset[str]:
    """Services this build can mint a key *from*.

    One registry, one question. A holder says credarr can write a value into
    something; it says nothing about where a new value comes from, and a mint
    source says nothing about whether anything holds a copy. They have never
    needed the same answer, so they have never needed the same map - and keeping
    them apart is what stopped a plan running `ResetApiKey` against a service with
    no such command.
    """
    return frozenset(MINT_SOURCES)
