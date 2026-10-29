"""Rotation: change a credential, then make every holder accept the new one.

The ordering is the whole problem. A rotation that stops halfway is worse than
no rotation: the new value works in the vault and nowhere else, so the service
it belongs to is broken in a way nobody will connect to the change that caused
it.

So this module plans before it acts. The plan is derived from the manifest
rather than hardcoded, which means a credential added later is rotatable without
touching this file, and a consumer added to a manifest is picked up
automatically rather than silently left behind.

Two facts from the throwaway tests shape this, both learned the hard way:

- `PUT /api/v3/indexer/{id}` **does** write a changed `apiKey`, so the API is
  the write path. That updates the row and the in-memory copy together, so no
  service restart is needed and there is no window where the row and memory
  disagree - which is what a direct SQLite write would create.
- `GET /api/v3/indexer/{id}` **redacts** the key as `********`, so the API
  cannot confirm its own write by equality. Strict API-only has no local
  database readback: a holder with a measured test route is exercised, and one
  without is reported as unproven. A checker that cannot read back what it
  wrote must not pretend that it did.

Nothing here prints a value. Steps describe themselves in terms of fingerprints.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .config import HostConfig
from .model import Credential, Manifest, Target
from .writers import (
    MINT_SOURCES,
    REISSUE_MECHANISMS,
    REISSUERS,
    Reissue,
    api_version,
    holder_for,
)

# How a credential's own value is replaced. Consumers are handled generically
# from the manifest; only the mint step differs per service, so that is the only
# thing a new service has to register.


class StepKind(Enum):
    MINT = "mint"
    PROPAGATE = "propagate"
    RECORD = "record"
    MANUAL = "manual"
    # Deleting a credential the mint created alongside rather than replacing.
    # Separate from PROPAGATE because it happens *after* every holder is
    # confirmed, and dispatching it on a step's text would be guessing.
    REVOKE = "revoke"


@dataclass(frozen=True)
class Step:
    """One action, described well enough to review before it happens."""

    kind: StepKind
    target: str
    detail: str
    reversible: bool = True
    # Why this step exists. A rotation plan that cannot explain its own steps
    # is a plan nobody should approve.
    reason: str = ""

    def __str__(self) -> str:
        # The kind is prefixed when it is not the default "write it", so a
        # revoke or a mint reads as what it is in the plan listing.
        if self.kind is StepKind.MINT:
            return f"{self.target:<34} mint: {self.detail}"
        if self.kind is StepKind.REVOKE:
            return f"{self.target:<34} revoke: {self.detail}"
        if self.kind is StepKind.RECORD:
            return f"{self.target:<34} record: {self.detail}"
        return f"{self.target:<34} {self.detail}"


@dataclass
class RotationPlan:
    credential: Credential
    host: HostConfig
    steps: list[Step] = field(default_factory=list)
    # A rotation is not atomic. Anything that cannot be written back is a
    # dead end, and the plan has to say so rather than discover it halfway.
    blocked_by: list[str] = field(default_factory=list)
    # True when the mint revokes the old credential before any holder is updated.
    #
    # Published rather than implied, because "every holder confirmed" says nothing
    # about *when* they were confirmed. A plan that revokes first has an outage
    # window in which every holder holds a dead key, and the decision record for
    # Sonarr and Radarr requires the opposite ordering. That ordering is not
    # reachable with a Servarr key - the value does not exist until it is minted -
    # so the honest answer is to refuse and to say so here, rather than to let a
    # count of confirmed holders read as "delivered".
    revokes_before_holders: bool = False
    # Set by a mechanism whose mint does not revoke: the mint created a
    # credential rather than replacing one, so revoking the old one is a later
    # step rather than the first. Jellyfin's create, Grafana's token and
    # Arcane's scoped key are all this shape.
    mint_service: str = ""
    revokes_last: bool = False
    # How a Servarr mint obtains the new value. The default is the service's
    # own backup/restore API; `reconstructed` skips the backup download and
    # rebuilds config.xml from /config/host; `provided` is the explicit manual
    # opt-out where the operator rotates the key in the service's own UI and
    # supplies it. The same `MINT_SOURCES` entry drives the planner and the
    # executor, so they cannot choose differently.
    mint_via: str = ""

    @property
    def executable(self) -> bool:
        return not self.blocked_by and bool(self.steps)

    def add(self, kind: StepKind, target: str, detail: str,
            reversible: bool = True, reason: str = "") -> None:
        self.steps.append(Step(kind, target, detail, reversible, reason))


def plan_rotation(credential: Credential, host: HostConfig) -> RotationPlan:
    plan = RotationPlan(credential=credential, host=host)
    _plan_class(plan)

    mechanism = str(credential.write.get("mechanism") or "")
    if mechanism != "servarr_command":
        for field_name in ("manual_mint", "ui_password", "reconstruct_config"):
            if field_name in credential.write:
                plan.blocked_by.append(
                    f"write.{field_name} is only for write.mechanism "
                    "'servarr_command'"
                )
    if mechanism == "servarr_command":
        _plan_servarr(plan)
    elif mechanism == "jellyfin_auth_keys":
        _plan_jellyfin_keys(plan)
    elif mechanism == "qbittorrent_rotate_api":
        _plan_qbittorrent(plan)
    elif mechanism == "seerr_regenerate":
        _plan_seerr_self(plan)
    elif mechanism in REISSUE_MECHANISMS:
        _plan_reissue(plan, REISSUERS[REISSUE_MECHANISMS[mechanism]])
    elif mechanism == "gitea_hook_secret":
        _plan_gitea_hook(plan)
    else:
        plan.blocked_by.append(
            f"no rotation strategy for write.mechanism {mechanism!r}"
        )
        return plan

    _plan_consumers(plan)
    return plan


def _plan_class(plan: RotationPlan) -> None:
    """Refuse only what cannot run at all; let the operator finish the rest.

    Class A and A-unv both run. The plan names every holder this build cannot
    write as a manual step, and the run ends INCOMPLETE until those are done.
    Auto-rotation may run either class and emits `auto_manual` naming the copy
    it left; that is "rotate now, finish by hand", never "rotate and pretend".
    Class B and `never_rotate` still refuse outright: they say the value cannot
    be minted or must not be, which no manual step can repair.
    """
    declared = plan.credential
    if declared.credential_class in ("A", "A-unv") and not declared.never_rotate:
        return
    if declared.credential_class == "B":
        plan.blocked_by.append(
            f"credential is class B: {declared.write.get('mechanism', 'no mechanism')} "
            "is not mintable by this tool, so there is nothing to rotate"
        )
    if declared.never_rotate:
        plan.blocked_by.append(
            "credential is marked never_rotate, which forbids rotation "
            "regardless of its class"
        )


def _plan_servarr(plan: RotationPlan) -> None:
    """The service that mints the value.

    There is an unavoidable window here and the plan says so rather than
    implying the rotation is seamless. Servarr keeps a single API key with no
    way to have two valid at once, so between this step and the last consumer
    being updated, every indexer in Sonarr and Radarr holds a key that no longer
    works. *arr retries indexers, so a brief window is survivable, but it is
    not zero and the plan should not pretend otherwise.
    """
    service = service_for(plan.credential)
    source = MINT_SOURCES.get(service)
    if source is None:
        plan.blocked_by.append(f"unknown service {service!r}")
        return
    if source.mechanism != "reset":
        # The name resolved to a service this build can mint for, but not by a
        # Servarr reset. A jellyfin-named credential declaring servarr_command
        # would otherwise plan a Servarr-style reset against a service that has
        # no such command, and never plan the revoke its create mechanism needs.
        plan.blocked_by.append(
            f"{service!r} mints with the {source.mechanism!r} mechanism, not a "
            "Servarr-style reset, so write.mechanism 'servarr_command' cannot "
            "rotate it"
        )
        return

    write = plan.credential.write
    manual = write.get("manual_mint", False)
    reconstruct = write.get("reconstruct_config", False)
    ui_password = write.get("ui_password")
    problems: list[str] = []
    if not isinstance(manual, bool):
        problems.append("write.manual_mint must be true or false")
    if not isinstance(reconstruct, bool):
        problems.append("write.reconstruct_config must be true or false")
    if ui_password is not None:
        if not isinstance(ui_password, str) or not ui_password.strip():
            problems.append(
                "write.ui_password must name a stored credential holding the "
                "service's UI password"
            )
        elif ui_password.strip() == plan.credential.name:
            problems.append(
                "write.ui_password must not name this credential; the service's "
                "UI password is a different secret from its API key"
            )
        elif _service_from_name(ui_password.strip()) != service:
            problems.append(
                "write.ui_password must name a credential for "
                f"{service!r}; {ui_password.strip()!r} resolves to "
                f"{_service_from_name(ui_password.strip())!r}. Name it "
                f"'{service}_ui_password' so the service-key resolver cannot "
                "mistake it for an API key"
            )
    if manual is True and ui_password is not None:
        problems.append(
            "write.manual_mint and write.ui_password cannot both be declared: "
            "the manual mint is the explicit no-backup/restore path"
        )
    if reconstruct is True and (manual is True or ui_password is not None):
        problems.append(
            "write.reconstruct_config cannot be combined with write.manual_mint "
            "or write.ui_password: it is the automatic no-backup path"
        )
    if problems:
        plan.blocked_by.extend(problems)
        return

    version = api_version(service)
    # Set before the first step is added: the mint is what revokes, so this is a
    # property of the service, not of the plan's later steps.
    plan.revokes_before_holders = True
    if reconstruct is True:
        plan.mint_via = "reconstructed"
        plan.add(
            StepKind.MINT,
            service,
            "read the host config over the API, build config.xml with a chosen "
            "key, restore it, then restart the service",
            reversible=False,
            reason="write.reconstruct_config opts out of the backup download. "
            "GET /config/host supplies the config fields; a config-only ZIP with "
            "a chosen ApiKey is uploaded to the API restore route and the "
            "service restarts itself. The chosen key is parked before the "
            "restore. No backup is read, no UI session or password is used, and "
            "the service's authentication settings are preserved. This is for a "
            "stock SQLite host config: /system/status reporting PostgreSQL (or "
            "not reporting databaseType) is refused, and config keys the API "
            "does not expose (theme, syslog, log rotation, legacy settings) may "
            "reset. AllowedHosts is preserved where the build exposes it; the "
            "pinned Lidarr/Readarr/Whisparr builds have no such setting. There "
            "is no backup to restore.",
        )
        return
    if manual is True:
        # The operator rotates the key in the service's own UI. That revokes the
        # old key immediately, so this is still a revoke-first plan; credarr
        # verifies the supplied key and the death of the stored one before it
        # writes a single holder.
        plan.mint_via = "provided"
        plan.add(
            StepKind.MINT,
            service,
            "use the key rotated in the service's own UI; no backup or "
            "config restore",
            reversible=False,
            reason="write.manual_mint opts out of the backup/restore mint. "
            "Rotate the key in the service's Settings > General page first; the "
            "service revokes the old key at that point. Supply the new key to "
            "the run, which verifies it authenticates and that the stored key "
            "no longer does, parks the supplied value, then writes the holders. "
            "There is no configuration backup to restore if the run stops.",
        )
        return

    # Strict API-only: no config path exists, so the service's own backup and
    # restore API is the default mint. This still replaces the whole config
    # file, so the plan says so before approval.
    plan.mint_via = "backup_restore"
    hint = ""
    if ui_password is not None:
        hint = (
            " The backup download is a web route behind the service's UI login, "
            f"so the run logs in with the credential named by write.ui_password "
            f"({ui_password.strip()!r}) and sends that session to the download."
        )
    plan.add(
        StepKind.MINT,
        service,
        "back up config over the API, restore a chosen key, then restart "
        "the service over its own API",
        reversible=False,
        reason="strict API-only: the service's backup API supplies its "
        "config.xml; the chosen key is persisted in the pending store before a "
        "config-only restore, then POST "
        f"/api/{version}/system/restart asks the service to restart itself. "
        "The restore replaces the whole config file and the temporary "
        "backup is deleted. The restart needs a supervisor that starts the "
        "app again after that call (for example the LinuxServer s6 image); "
        "a bare process without one is not supported." + hint,
    )


def _plan_jellyfin_keys(plan: RotationPlan) -> None:
    """Mint a Jellyfin API key.

    Jellyfin holds many API keys at once, so this is not a reset - it is a
    create. That single difference removes the window every Servarr rotation
    has: the new key is minted while the old one is still valid, propagated,
    confirmed, and only then revoked. `revokes_before_holders` is therefore
    False here, which the plan publishes and the human output does not repeat.

    The key is not returned by the create call (it answers 204), so reading it
    back is a separate step: `GET /Auth/Keys` returns every AccessToken in
    full. Both routes are gated on `RequiresElevation`, which a valid API key
    satisfies outright - "Api keys are unrestricted" in
    Jellyfin.Api/Auth/DefaultAuthorizationPolicy/DefaultAuthorizationHandler.cs.
    """
    service = service_for(plan.credential)
    source = MINT_SOURCES.get(service)
    if source is None or source.mechanism != "create":
        plan.blocked_by.append(
            f"unknown service {service!r} for write.mechanism "
            "'jellyfin_auth_keys'"
        )
        return

    plan.revokes_before_holders = False
    plan.mint_service = service
    plan.revokes_last = True
    plan.add(
        StepKind.MINT,
        service,
        "POST /Auth/Keys?app=<name> to mint, then GET /Auth/Keys to read it",
        reversible=False,
        reason="the new key is created alongside the old one, so minting does "
        "not revoke anything; the old key is deleted at the end, after every "
        "holder has been confirmed",
    )


def _plan_qbittorrent(plan: RotationPlan) -> None:
    """Rotate qBittorrent's single API key.

    `POST /app/rotateAPIKey` replaces the only key and returns the new value.
    The old key stops working immediately, so this is a reset, not a create:
    every holder holds a dead key until it is reached. The response is the only
    copy of the new key, which is why the plan requires the pending store.
    """
    service = service_for(plan.credential)
    source = MINT_SOURCES.get(service)
    if source is None or source.mechanism != "rotate":
        plan.blocked_by.append(
            f"unknown service {service!r} for write.mechanism "
            "'qbittorrent_rotate_api'"
        )
        return
    plan.revokes_before_holders = True
    plan.mint_via = "rotate"
    version = api_version(service)
    plan.add(
        StepKind.MINT,
        service,
        f"POST /api/{version}/app/rotateAPIKey",
        reversible=False,
        reason="qBittorrent has one API key. The response carries the new "
        "value and the old key is revoked immediately, so every holder holds "
        "a dead key until it is reached. The new value is parked in the "
        "pending store before it is used; a crash after the response but "
        "before that write loses the only copy, which is why the pending "
        "store is required.",
    )


def _plan_seerr_self(plan: RotationPlan) -> None:
    """Rotate Seerr's own API key over its settings API.

    Measured on Seerr 3.5.0 (2026-10-21): `POST /settings/main/regenerate`
    replaces the single key and returns the new value in the response. The old
    key stops working immediately, the running process serves the new one
    without a restart, and `settings.json` is saved before the response. The
    response is the only copy of the new key, so it is parked in the pending
    store before anything else touches it.

    There is no chosen-key write to plan: `POST /settings/main` accepts an
    `apiKey` field in the source route, but the OpenAPI request validator
    rejects it because the spec marks it readOnly (HTTP 400). Seerr's own
    `API_KEY` environment variable pins the key; regenerate then returns the
    stored value unchanged, and the executor refuses instead of recording a
    no-op as a rotation.
    """
    service = service_for(plan.credential)
    source = MINT_SOURCES.get(service)
    if source is None or source.mechanism != "regenerate":
        plan.blocked_by.append(
            f"unknown service {service!r} for write.mechanism "
            "'seerr_regenerate'"
        )
        return

    plan.revokes_before_holders = True
    plan.mint_via = "regenerate"
    plan.add(
        StepKind.MINT,
        service,
        "POST /api/v1/settings/main/regenerate",
        reversible=False,
        reason="Seerr has one API key. The regenerate response carries the new "
        "value and the old key is revoked immediately, so the response is the "
        "only copy; it is parked in the pending store before it is used. The "
        "route updates the running process in place: no restart and no file "
        "write. A deployment that sets Seerr's API_KEY environment variable "
        "pins the key, and the run refuses rather than record a no-op.",
    )


def _plan_reissue(plan: RotationPlan, spec: Reissue) -> None:
    """Plan a service-generated secret: create alongside, revoke last.

    The measured differences between services live in `spec` (paths,
    discovery, naming, sweep, protected rows); the shared rules are the
    ordering, the optional declarations, and the refusals. `required_write`
    fields and a required name are refused before the plan can run.
    """
    service = service_for(plan.credential)
    source = MINT_SOURCES.get(service)
    if source is None or source.system != spec.system:
        plan.blocked_by.append(
            f"unknown service {service!r} for write.mechanism "
            f"{MINT_SOURCES[service].mechanism if source else ''!r}"
        )
        return
    write = plan.credential.write
    problems: list[str] = []
    for field_name in spec.required_write:
        value = write.get(field_name)
        if not isinstance(value, str) or not value.strip():
            problems.append(
                f"write.{field_name} is required: "
                f"{spec.hints.get(field_name, 'declare it as a non-empty string')}"
            )
    if spec.declared_name_field:
        value = write.get(spec.declared_name_field)
        if value is not None and (
            not isinstance(value, str) or not value.strip()
        ):
            problems.append(
                f"write.{spec.declared_name_field} must be a non-empty string "
                "when declared"
            )
        elif spec.require_name and value is None:
            problems.append(
                f"write.{spec.declared_name_field} is required: "
                f"{spec.hints.get(spec.declared_name_field, 'declare it as a non-empty string')}"
            )
    if spec.declared_values_field:
        values = write.get(spec.declared_values_field)
        if values is not None and (
            not isinstance(values, list)
            or not values
            or not all(isinstance(item, str) and item.strip() for item in values)
        ):
            problems.append(
                f"write.{spec.declared_values_field} must be a non-empty list "
                "of strings when declared"
            )
    mint_with = write.get("mint_with")
    if mint_with is not None:
        if not isinstance(mint_with, str) or not mint_with.strip():
            problems.append(
                "write.mint_with must be a credential name when declared"
            )
        elif mint_with.strip() == plan.credential.name:
            problems.append(
                "write.mint_with must not name this credential; omit it to "
                "self-rotate"
            )
    if problems:
        plan.blocked_by.extend(problems)
        return

    plan.revokes_before_holders = False
    plan.mint_service = service
    plan.revokes_last = True
    plan.add(
        StepKind.MINT,
        service,
        f"POST {spec.create_path} to mint a replacement for the credential",
        reversible=False,
        reason=spec.reason,
    )


def _plan_gitea_hook(plan: RotationPlan) -> None:
    """Rotate a Gitea webhook secret: a chosen value written over the API.

    Measured on 1.27.2: `PATCH /repos/{owner}/{repo}/hooks/{id}` accepts a
    partial `config.secret` update and answers 200; no read returns the secret;
    `POST .../hooks/{id}/tests` answers 204 and proves a delivery was
    attempted. The old secret dies at the PATCH, so every holder must be
    updated after it - a declared redeploy consumer becomes a manual step and
    the run stays incomplete until the receiver is deployed. Authentication
    needs a Gitea token with `write:repository`, named through
    `write.mint_with`.
    """
    service = service_for(plan.credential)
    if service != "gitea":
        plan.blocked_by.append(
            f"unknown service {service!r} for write.mechanism 'gitea_hook_secret'"
        )
        return
    write = plan.credential.write
    problems: list[str] = []
    mint_with = write.get("mint_with")
    if not isinstance(mint_with, str) or not mint_with.strip():
        problems.append(
            "write.mint_with is required: the hook update needs a Gitea token "
            "with write:repository"
        )
    elif mint_with.strip() == plan.credential.name:
        problems.append(
            "write.mint_with must not name this credential; the secret cannot "
            "authorise the hook API"
        )
    for field_name in ("repo", "hook_url"):
        value = write.get(field_name)
        if not isinstance(value, str) or not value.strip():
            problems.append(
                f"write.{field_name} is required: it identifies the hook to "
                "update"
            )
    if problems:
        plan.blocked_by.extend(problems)
        return

    plan.revokes_before_holders = True
    plan.add(
        StepKind.MINT,
        service,
        f"PATCH /repos/{write['repo']}/hooks/<id> with a chosen secret",
        reversible=False,
        reason="Gitea accepts a partial config.secret update and never "
        "returns the secret, so the value is chosen here and written over the "
        "API; the previous secret dies at that write. The hook is found by "
        "its URL, and a test delivery is attempted afterwards. The receiver's "
        "own copy is a deploy-time value, so a declared redeploy consumer is "
        "a manual step and the run stays incomplete until it is deployed.",
    )


def _plan_consumers(plan: RotationPlan) -> None:
    """Every holder, from the manifest.

    Indirect consumers are listed as manual rather than silently skipped: they
    are rendered from the vault at deploy time, so they need a redeploy, and a
    rotation that forgets them leaves a live service holding a revoked key.
    """
    for consumer in plan.credential.consumers:
        if consumer.indirect:
            plan.add(
                StepKind.MANUAL,
                str(consumer.target),
                f"redeploy so {consumer.target} is rendered from the new value",
                reason="rendered at deploy time; nothing to write directly",
            )
            continue

        target = consumer.target
        described = holder_for(target.system, target.slot)
        if described is None:
            plan.add(
                StepKind.MANUAL,
                str(target),
                f"no API writer for {target.key}: update this copy by hand",
                reason="this build cannot write the holder; the rotation "
                "proceeds and the run stays incomplete until the copy is "
                "updated manually",
            )
            continue

        if described.write == "seerr_api":
            plan.add(
                StepKind.PROPAGATE,
                str(target),
                "PUT the new value to the settings API and read it back from "
                "the running process",
                reason="the API updates the in-memory settings directly, so no "
                "restart and no file write are needed",
            )
            continue

        if described.write == "qui_api":
            plan.add(
                StepKind.PROPAGATE,
                str(target),
                "PUT the new value to the qui instance and confirm with its "
                "connection test",
                reason="qui stores the key encrypted, so its own test is the "
                "process-level proof that the stored value is the live one",
            )
            continue

        # A qualified target names one row, so it is one row however large the
        # declared count is: `count` describes the slot, and writing every row
        # because the count is 10 is exactly what would replace a credential the
        # consumer never claimed.
        count = consumer.count if consumer.count > 1 else 1
        scope = "the named row" if target.qualifier else f"{count} row{'s' if count != 1 else ''}"
        plan.add(
            StepKind.PROPAGATE,
            str(target),
            f"PUT the new value to {scope}, then exercise the holder's own "
            "test route where one is measured, or report the row unproven",
            reason="the API writes the row and the in-memory copy together, so "
            "no restart and no window where they disagree",
        )

    if not plan.credential.vault:
        plan.blocked_by.append(
            "no vault reference, so the new value would exist nowhere durable"
        )
    else:
        plan.add(
            StepKind.RECORD,
            ".".join(plan.credential.vault.path),
            "write the new value to the vault",
            reason="the vault is the canonical copy every redeploy reads from",
        )

    if not plan.revokes_before_holders and plan.revokes_last:
        # Last, and only after every holder is confirmed. Jellyfin holds many
        # API keys at once, so the mint created a second one rather than
        # replacing the first - which means the old one is still live, and a
        # rotation that never deletes it leaves a credential accumulating
        # indefinitely. Deleting it before the holders are confirmed would
        # recreate the window this mechanism exists to avoid. The same step
        # sweeps keys earlier interrupted runs minted under credarr's name;
        # the vault no longer holds their values, so the name is the handle.
        plan.add(
            StepKind.REVOKE,
            plan.mint_service,
            "revoke the previous key and any stray key credarr minted",
            reversible=False,
            reason="the mint created a key rather than replacing one, so the "
            "old key is still valid until this step; it runs last so the "
            "rollback is a confirm-not-a-revocation",
        )


def _service_from_name(name: str) -> str:
    """`prowlarr_api_key` -> `prowlarr`.

    A convenience, not a rule: an explicit `canonical.service` overrides it, and
    a name it does not recognise comes back unchanged for the caller to
    refuse - the planner blocks it as an unknown service rather than guessing
    at one.
    """
    for service in ("sonarr", "radarr", "prowlarr", "lidarr", "readarr",
                    "whisparr", "jellyfin", "qbittorrent", "qui", "seerr",
                    "grafana", "arcane", "gitea"):
        if name.startswith(service):
            return service
    return name


def service_for(credential: Credential) -> str:
    """The service a credential belongs to: `canonical.service`, else its name.

    The one derivation every caller uses - the planner for every mint, and the
    capability report to say which service a credential needs. A second copy
    would let the report and the plan disagree about which service a credential
    is attached to, which reads as a capability that exists where it does not.
    """
    return credential.canonical.get("service") or _service_from_name(credential.name)


def ui_password_names(
    manifest: Manifest, service: str | None = None
) -> set[str]:
    """Credentials declared as a service's UI password, not its API key.

    `write.ui_password` names a password. It must not be mistaken for the
    service's own API key by the holder-key resolver just because its name
    starts with the service (`sonarr_ui_password` -> `sonarr`): a password
    authenticates the web UI, not `/api`, and using it for a holder write would
    fail with a misleading 401. The mint's own value lookup reads it explicitly.

    With `service`, only passwords named by that service's credentials are
    returned. The scoping matters: an erroneous cross-service reference must
    not remove the other service's real API key from the resolver.
    """
    names: set[str] = set()
    for credential in manifest.credentials.values():
        declared = str(credential.write.get("ui_password") or "").strip()
        if declared and (service is None or service_for(credential) == service):
            names.add(declared)
    return names


__all__ = [
    "RotationPlan",
    "Step",
    "StepKind",
    "Target",
    "api_version",
    "holder_for",
    "plan_rotation",
    "service_for",
]
