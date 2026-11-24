"""The request bodies, one shape per write.

These are the HTTP trust boundary: every model refuses an unknown field and
carries the engine's own bounds, so a typo cannot look like a default. Secret
fields have hidden reprs; a validation error must never echo one."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from credarr.model import MAX_EXACT_INT
from credarr_server.auth import MIN_PASSWORD_LENGTH
from credarr_server.scheduler import (
    MAX_AUDIT_INTERVAL_SECONDS,
    MIN_AUDIT_INTERVAL_SECONDS,
)

# A manifest is a few hundred lines of YAML; a megabyte is already absurd, and
# the cap is what keeps a bad upload from being parsed.
MAX_MANIFEST_BYTES = 1024 * 1024
# Tokens and passwords are short. The cap bounds what a write can put in the
# database (characters: it is a pydantic `str` length, not a byte count), not a
# judgement about anyone's key format.
MAX_VALUE_LENGTH = 8192


class ApiKeyBody(BaseModel):
    """The optional origin an automation key is issued with.

    A hook key marks the mutations it makes as `origin=hook`, which sinks
    exclude by default so a hook cannot loop on its own events.
    """

    model_config = ConfigDict(extra="forbid")

    origin: Literal["user", "hook"] = "user"


class SetupBody(BaseModel):
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=1024)


class LoginBody(BaseModel):
    """Login compares any string; the length policy belongs to creation."""

    password: str = Field(max_length=1024)


class PasswordBody(BaseModel):
    """Change the admin password; the current one is the step-up check."""

    current_password: str = Field(max_length=1024)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=1024)


class ValueBody(BaseModel):
    """A pasted credential value. Write-only: nothing reads it back."""

    value: str = Field(min_length=1, max_length=MAX_VALUE_LENGTH)

    @field_validator("value")
    @classmethod
    def _no_surrounding_whitespace(cls, value: str) -> str:
        """Refuse, never mangle.

        Every holdable value in this stack is a token, and a paste carries a
        trailing newline often enough that an audit would read it as drift.
        Trimming it silently would change a secret the operator never typed
        that way; saying so puts the decision back where it belongs.
        """
        if value != value.strip():
            raise ValueError("the value has leading or trailing whitespace")
        return value


class RotateBody(BaseModel):
    """The typed confirmation: the credential's own name, not a boolean.

    A boolean is one click; a name is a sentence the operator had to read. The
    console disables its button until the two match, and this repeats the check
    because the console is not the only caller.

    `take_over` is a second, separate assertion: the unfinished steps of this
    credential belong to a run that is not coming back. It is not the
    confirmation's job to imply it - the console offers it only when there is
    something to take over, and says what it means.

    `manual_value` is the key the operator rotated in the service's own UI for a
    `write.manual_mint` credential. It is a secret, so it is hidden from reprs
    and scrubbed from every event and message; a plan that does not use the
    manual mint refuses it rather than silently ignoring it.
    """

    confirm: str = Field(max_length=256)
    take_over: bool = False
    # Deliberately unconstrained: a validation error for a secret field would
    # echo the input into the 422 body. The route checks blank/length itself
    # and refuses without copying the value into a message.
    manual_value: str | None = Field(default=None, repr=False)


class PlanBody(BaseModel):
    """What the plan endpoint may be told. Read-only, so only one thing."""

    take_over: bool = False


class RevealBody(BaseModel):
    """An explicit reveal of one version stage."""

    model_config = ConfigDict(extra="forbid")

    stage: Literal["CURRENT", "PREVIOUS"] = "CURRENT"


class LifecycleBody(BaseModel):
    """Soft-delete, restore, or the explicit force-delete after recovery."""

    model_config = ConfigDict(extra="forbid")

    action: Literal["soft_delete", "restore", "force_delete"]
    confirm: str = Field(default="", max_length=256)
    reason: str = Field(default="", max_length=256)
    force: bool = False


class AdoptBody(BaseModel):
    """Adopt an externally rotated value, with an explicit proof choice.

    `process_readback` runs the engine audit against the candidate and stores
    nothing unless it proves a match. `none` stores the value as unverified;
    it can never be reported as a match by that fact alone.
    """

    model_config = ConfigDict(extra="forbid")

    value: str = Field(min_length=1, max_length=MAX_VALUE_LENGTH, repr=False)
    confirm: str = Field(max_length=256)
    verify: Literal["none", "process_readback"] = "none"

    @field_validator("value")
    @classmethod
    def _no_surrounding_whitespace(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("the value has leading or trailing whitespace")
        return value


class AuditIntervalBody(BaseModel):
    """The persisted audit cadence, in seconds."""

    model_config = ConfigDict(extra="forbid")

    interval_seconds: float = Field(
        ge=MIN_AUDIT_INTERVAL_SECONDS, le=MAX_AUDIT_INTERVAL_SECONDS
    )
    enabled: bool | None = None


class AutoRotationBody(BaseModel):
    """The per-credential policy write.

    Enabling is a future mutation and therefore requires the same typed-name
    assertion as a manual run; disabling does not. When the credential has
    copies auto cannot finish, `accept_manual` is the explicit acknowledgement
    that the rotation will leave them for a human. The interval is bounded here
    as well as in the store, because the HTTP layer is a trust boundary.
    """

    enabled: bool
    every_days: int | None = Field(default=None, ge=1, le=365)
    confirm: str = Field(default="", max_length=256)
    accept_manual: bool = False


class ServiceBody(BaseModel):
    """One service's deployment facts, as the console edits them."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    kind: str = Field(default="other", max_length=64)
    url: str | None = Field(default=None, max_length=2048)
    notes: str = Field(default="", max_length=2000)


class ServicePatch(BaseModel):
    """A partial edit. A name in the body is refused: delete + create instead.

    A URL change on a service with a stored API key also carries the key again;
    the old key belonged to the old server. The value is write-only and has a
    hidden repr, so a validation error cannot print it.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, max_length=64)
    kind: str | None = Field(default=None, max_length=64)
    url: str | None = Field(default=None, max_length=2048)
    notes: str | None = Field(default=None, max_length=2000)
    credential: str | None = Field(default=None, max_length=64)
    key: str | None = Field(
        default=None, min_length=1, max_length=4096, repr=False
    )


class ServiceTestBody(BaseModel):
    """A URL and key to try, never a write."""

    model_config = ConfigDict(extra="forbid")

    service: str = Field(min_length=1, max_length=64)
    url: str = Field(min_length=1, max_length=2048)
    key: str | None = Field(default=None, max_length=4096)


class VaultBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    backend: str = Field(min_length=1, max_length=64)
    file: str = Field(min_length=1, max_length=4096)
    path: list[str] = Field(default_factory=list)


class HolderBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, max_length=512)
    count: int = Field(default=1, ge=1, le=MAX_EXACT_INT)
    mechanism: str = Field(default="", max_length=256)
    host: str | None = Field(default=None, max_length=512)
    note: str = Field(default="", max_length=2000)


class CredentialBody(BaseModel):
    """A credential declaration; the same shape the manifest parser accepts."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    description: str = Field(default="", max_length=2000)
    credential_class: str = Field(default="B", alias="class", max_length=16)
    max_age_days: int | None = Field(default=None, ge=1, le=MAX_EXACT_INT)
    never_rotate: bool = False
    provisioned: bool = True
    canonical: dict[str, Any] = Field(default_factory=dict)
    write: dict[str, Any] = Field(default_factory=dict)
    vault: VaultBody | None = None
    consumers: list[HolderBody] = Field(default_factory=list)


class CredentialPatch(BaseModel):
    """Partial metadata edit. `name` is only accepted when it matches."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    name: str | None = Field(default=None, max_length=64)
    description: str | None = Field(default=None, max_length=2000)
    credential_class: str | None = Field(default=None, alias="class", max_length=16)
    max_age_days: int | None = Field(default=None, ge=1, le=MAX_EXACT_INT)
    never_rotate: bool | None = None
    provisioned: bool | None = None
    canonical: dict[str, Any] | None = None
    write: dict[str, Any] | None = None
    vault: VaultBody | None = None
    consumers: list[HolderBody] | None = None


class HoldersBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    consumers: list[HolderBody] = Field(default_factory=list)


# CredentialPatch fields that change the rotation plan a resume would follow.
# Metadata (description, provisioned, max_age_days) is deliberately absent.
_ROTATION_FIELDS = frozenset(
    {"credential_class", "never_rotate", "canonical", "write", "vault", "consumers"}
)


class ImportBody(BaseModel):
    """The console's import. Raw YAML remains a legacy replace body."""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["replace", "merge"] = "replace"
    prune: bool = False
    yaml: str = Field(min_length=1)
    confirm: str = Field(default="", max_length=64)


class SyncTargetBody(BaseModel):
    """One compose target on one agent."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    agent_id: str = Field(min_length=1, max_length=64)
    stack_path: str = Field(min_length=1, max_length=1024)
    project_name: str = Field(min_length=1, max_length=64)
    services: list[str] = Field(min_length=1, max_length=64)
    workflow: str = Field(default="compose", max_length=32)
    env_file: str | None = Field(default=None, max_length=1024)
    values: dict[str, str] = Field(default_factory=dict)
    enabled: bool = True


class SyncTargetPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=64)
    agent_id: str | None = Field(default=None, min_length=1, max_length=64)
    stack_path: str | None = Field(default=None, min_length=1, max_length=1024)
    project_name: str | None = Field(default=None, min_length=1, max_length=64)
    services: list[str] | None = Field(default=None, min_length=1, max_length=64)
    workflow: str | None = Field(default=None, max_length=32)
    env_file: str | None = Field(default=None, max_length=1024)
    values: dict[str, str] | None = None
    enabled: bool | None = None


class EnrollmentBody(BaseModel):
    """A one-time agent enrollment token; the token is returned once."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    capabilities: list[str] = Field(default_factory=list, max_length=64)
    ttl_seconds: int = Field(default=600, ge=60, le=3600)


class AgentActionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(default="disabled by the operator", max_length=256)


class NotificationServiceBody(BaseModel):
    """A new notification service, whole.

    The name is the operator's label and part of the API path; the kind picks
    which fields matter. Fields that do not apply to the kind are accepted and
    stored as NULL rather than refused - the form hides them, and a later edit
    should not have to retype anything.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    kind: str = Field(min_length=1, max_length=32)
    enabled: bool = True
    url: str = Field(default="", max_length=1024)
    topic: str | None = Field(default=None, max_length=256)
    token: str | None = Field(default=None, max_length=4096)
    secret: str | None = Field(default=None, max_length=4096)
    auth_header: str | None = Field(default=None, max_length=4096)
    discord_username: str | None = Field(default=None, max_length=256)
    discord_avatar: str | None = Field(default=None, max_length=1024)
    discord_here: bool = False
    smtp_host: str = Field(default="", max_length=255)
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str = Field(default="", max_length=256)
    smtp_from: str = Field(default="", max_length=512)
    smtp_to: str = Field(default="", max_length=4096)
    smtp_tls: str = Field(default="starttls", max_length=16)
    smtp_auth: str = Field(default="auto", max_length=16)
    enabled_types: list[str] = Field(default_factory=list)
    credential_filter: list[str] = Field(default_factory=list)
    allow_hook_origin: bool = False


class NotificationServicePatch(BaseModel):
    """An edit to one service. `model_fields_set` decides what was sent.

    The kind is not patchable: a different mechanism is a different service,
    and its fields, validators and delivery rows are its own. Neither is the
    name - a rename is delete plus create, deliberately, like a credential.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    url: str | None = Field(default=None, max_length=1024)
    topic: str | None = Field(default=None, max_length=256)
    token: str | None = Field(default=None, max_length=4096)
    secret: str | None = Field(default=None, max_length=4096)
    auth_header: str | None = Field(default=None, max_length=4096)
    discord_username: str | None = Field(default=None, max_length=256)
    discord_avatar: str | None = Field(default=None, max_length=1024)
    discord_here: bool | None = None
    smtp_host: str | None = Field(default=None, max_length=255)
    smtp_port: int | None = Field(default=None, ge=1, le=65535)
    smtp_username: str | None = Field(default=None, max_length=256)
    smtp_from: str | None = Field(default=None, max_length=512)
    smtp_to: str | None = Field(default=None, max_length=4096)
    smtp_tls: str | None = Field(default=None, max_length=16)
    smtp_auth: str | None = Field(default=None, max_length=16)
    enabled_types: list[str] | None = None
    credential_filter: list[str] | None = None
    allow_hook_origin: bool | None = None

