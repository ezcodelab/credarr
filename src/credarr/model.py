"""The credential manifest: declared state, parsed and validated.

The manifest is the only input that describes what to check and where. It is
also the only place a typo can hide. A target of "prolarr.applications" - one
letter out - used to print "skip, no read path implemented" and exit clean, which
is indistinguishable from having checked it and found nothing wrong.

So validation here is deliberately unforgiving:

  * an unknown target system or slot is an error, never a skip
  * a manifest version this build does not understand is an error, not a guess
  * a credential whose class promises a rotation age but omits one is an error
  * duplicate YAML keys are an error, because YAML otherwise keeps the last one
    and a copy-paste collision would silently delete a consumer
  * an unknown key anywhere is an error, because a typo'd `consumers` removes
    every holder and the rotation then mints a value it delivers to nobody
  * two credentials may not declare one vault entry, because each credential
    name takes its own rotation lock - two names for one value can double-mint
    the same service
  * `canonical`/`write` hold plain data, because YAML can express shapes
    (tuples, sets, timestamps, non-string keys, recursive aliases, NEL) that
    change value or type on the way back out, or cannot cross the store's JSON
    boundary at all
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from math import isfinite
from pathlib import Path
from typing import Any

import yaml

from .errors import ManifestError

MANIFEST_VERSION = 1

# What a JSON reader (and SQLite) holds exactly. The store carries integers
# through both, so this is the ceiling for every integer in the manifest.
MAX_EXACT_INT = 2**53 - 1

# A system names one service ("sonarr"). A slot names one place a credential can
# live within it ("indexers"). A qualifier picks a single row within that slot
# ("1337x (Prowlarr)"), for consumers that hold several credentials at once.
TARGET_RE = re.compile(
    r"^(?P<system>[A-Za-z0-9_-]+)\.(?P<slot>[A-Za-z0-9_-]+)(?:\[(?P<qualifier>[^\]]+)\])?$"
)
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")

# A is mintable and has a proven write path. A-unv is mintable but not every
# declared holder can be written by the engine: rotation runs, unwritable
# copies become named manual steps, and auto-rotation may run with a manual
# follow-up notification. B cannot be minted.
CREDENTIAL_CLASSES = ("A", "A-unv", "B")

# The accepted key set at each level. Anything else is a typo until proven
# otherwise, and a typo that is ignored is a check that passes by not running.
_TOP_LEVEL_KEYS = frozenset({"version", "credentials"})
_CREDENTIAL_KEYS = frozenset(
    {
        "description",
        "class",
        "max_age_days",
        "never_rotate",
        "provisioned",
        "canonical",
        "vault",
        "write",
        "consumers",
    }
)
_VAULT_KEYS = frozenset({"backend", "file", "path"})
_CONSUMER_KEYS = frozenset({"target", "count", "mechanism", "host", "note"})
_RETIRED_CONSUMER_MECHANISMS = frozenset({"file_unverified", "servarr_db_blob"})


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys."""


def _no_duplicates(loader: _StrictLoader, node: yaml.Node, deep: bool = False) -> dict:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError:
            raise ManifestError(
                f"mapping key at line {key_node.start_mark.line + 1} must be a "
                f"scalar, got {type(key).__name__}"
            ) from None
        if duplicate:
            raise ManifestError(
                f"duplicate key {key!r} at line {key_node.start_mark.line + 1}"
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicates
)


def _load_yaml(text: str, origin: str) -> Any:
    # SafeLoader, with duplicate-key rejection added. Which YAML tags are
    # permitted is unchanged from SafeLoader; only the mapping constructor differs.
    try:
        return yaml.load(text, Loader=_StrictLoader)  # noqa: S506
    except yaml.YAMLError as exc:
        raise ManifestError(f"{origin}: invalid YAML: {exc}") from exc


@dataclass(frozen=True, slots=True)
class Target:
    """A place a credential value can be held."""

    system: str
    slot: str
    qualifier: str | None = None

    @classmethod
    def parse(cls, text: object, *, where: str) -> Target:
        if not isinstance(text, str):
            raise ManifestError(f"{where}: target must be a string, got {type(text).__name__}")
        _reject_nel(text, where, "target")
        match = TARGET_RE.match(text.strip())
        if not match:
            raise ManifestError(
                f"{where}: malformed target {text!r}",
                hint="expected 'system.slot' or 'system.slot[qualifier]', "
                "for example 'sonarr.indexers' or 'seerr.settings_json[sonarr]'",
            )
        if (match["qualifier"] or "").count(":") > 1:
            # A qualifier is `row` or `row:field`, and a second colon fits
            # neither. `[Sonarr:HD]` is a row plus a field, so a row name that
            # itself contains a colon would be read as one of the two - and the
            # audit matcher, which compares the whole `row:field` string, would
            # disagree with the rotation writer about what the target names.
            # One colon is not ambiguous: it is the documented `row:field` form.
            raise ManifestError(
                f"{where}: malformed target qualifier {match['qualifier']!r}",
                hint="a qualifier is 'row' or 'row:field' - 'sonarr.indexers', "
                "'seerr.settings_json[sonarr]' or "
                "'sonarr.download_clients[qBittorrent:password]'",
            )
        return cls(
            system=match["system"].lower(),
            slot=match["slot"].lower(),
            qualifier=match["qualifier"],
        )

    @property
    def key(self) -> str:
        """Identity of the slot, without the row qualifier. Adapters register
        against this."""
        return f"{self.system}.{self.slot}"

    def __str__(self) -> str:
        base = self.key
        return f"{base}[{self.qualifier}]" if self.qualifier else base

    @property
    def row_selector(self) -> RowSelector | None:
        """The row and field this target claims, when it is qualified."""
        return parse_qualifier(self.qualifier)


def split_target(text: str) -> tuple[str, str]:
    """`system.slot[qualifier]` back to (system, slot), dropping the qualifier.

    The qualifier names a row *inside* a slot, never a different slot, so it
    must not take part in a lookup: `prowlarr.applications[Sonarr]` is the
    `applications` slot. Splitting the display string on the first dot instead
    yields `applications[Sonarr]`, which matches no slot - so a plan that
    checked the parsed Target would promise a rotation that execution then
    refuses, after the old key had already been revoked.
    """
    system, _, slot = text.split("[", 1)[0].partition(".")
    return system, slot


@dataclass(frozen=True, slots=True)
class RowSelector:
    """Which row inside a slot a consumer claims, and which field within it.

    `Sonarr` claims the whole row. `qBittorrent:password` claims one credential
    field of it, because a download-client row holds both a password and - in
    newer builds - an API key, so a write that ignored the field half would put
    the password credential into the apiKey column.
    """

    row: str
    field: str | None = None


def parse_qualifier(qualifier: str | None) -> RowSelector | None:
    """The `[Row]` / `[Row:field]` part of a target, or None when unqualified.

    Kept separate from `split_target` because the two answer different questions:
    looking a slot up needs the system and the slot, and *writing* one needs the
    row as well. Reading a qualified target as its bare slot would write every row
    in that slot, and profilarr, seerr and Prowlarr each hold both the Sonarr and
    the Radarr key - so that is handing one service's credential to another.
    """
    if not qualifier:
        return None
    row, _, field = qualifier.partition(":")
    if not row:
        return None
    return RowSelector(row=row, field=field or None)


def parse_row_selector(text: str) -> RowSelector | None:
    """`parse_qualifier` for a whole target string.

    The text always comes from a validated `Target`, so the bracket is balanced.
    """
    _, _, bracketed = text.partition("[")
    return parse_qualifier(bracketed.removesuffix("]") or None)


@dataclass(frozen=True, slots=True)
class VaultRef:
    """Where the canonical copy of a value lives."""

    backend: str
    file: str
    path: tuple[str, ...]

    def navigate(self, document: Any) -> Any:
        """Walk `path` through a parsed document.

        Returns None when any segment is missing, which the caller must treat as
        an error rather than an empty value - a missing key and an empty key are
        different problems and only one of them is a drift.
        """
        node = document
        for segment in self.path:
            if not isinstance(node, Mapping) or segment not in node:
                return None
            node = node[segment]
        return node


@dataclass(frozen=True, slots=True)
class Consumer:
    """One place a copy of a credential is expected to exist."""

    target: Target
    count: int = 1
    mechanism: str = ""
    # None means "the configuration's default host". The manifest should not have
    # to repeat the host name on every consumer just to be checked against it.
    host: str | None = None
    note: str = ""

    @property
    def process_readback(self) -> bool:
        """The running holder's own API must report the value.

        This is the opt-in for a holder that exposes its live state (Seerr's
        settings API today). The audit only reports a match after that read;
        there is no local file to fall back to.
        """
        return self.mechanism == "process_api"

    @property
    def indirect(self) -> bool:
        """A consumer with no API read-back, such as a Homepage label.

        It is a manual copy, not an audit finding: it keeps the fan-out count
        honest and is displayed as `manual`, never as verified. Homepage labels
        are structurally manual even when an older copy left the mechanism
        blank."""
        return self.mechanism == "redeploy" or (
            self.target.system == "homepage" and self.target.slot == "label"
        )


@dataclass(frozen=True, slots=True)
class Credential:
    name: str
    description: str = ""
    credential_class: str = "B"
    max_age_days: int | None = None
    never_rotate: bool = False
    vault: VaultRef | None = None
    consumers: tuple[Consumer, ...] = ()
    provisioned: bool = True
    canonical: Mapping[str, Any] = field(default_factory=dict)
    write: Mapping[str, Any] = field(default_factory=dict)

    @property
    def declared_copies(self) -> int:
        return sum(c.count for c in self.consumers)


@dataclass(frozen=True, slots=True)
class Manifest:
    version: int
    credentials: Mapping[str, Credential]
    origin: Path | None = None

    @classmethod
    def parse(
        cls,
        text: str,
        *,
        origin: Path | None = None,
        known_targets: Iterable[str] = (),
        known_backends: Iterable[str] = (),
    ) -> Manifest:
        """Parse and validate. Pass known_targets/known_backends to enable the
        strict checks; omitting them still checks structure, so unit tests can
        parse a fragment without a registry."""
        origin_label = str(origin) if origin else "<manifest>"
        document = _load_yaml(text, origin_label)
        if document is None:
            raise ManifestError(f"{origin_label}: manifest is empty")
        if not isinstance(document, Mapping):
            raise ManifestError(f"{origin_label}: manifest must be a mapping at the top level")

        version = document.get("version")
        if type(version) is not int or version != MANIFEST_VERSION:
            raise ManifestError(
                f"{origin_label}: manifest version {version!r} is not supported "
                f"(this build understands {MANIFEST_VERSION})",
                hint="a newer manifest may declare targets this build cannot "
                "check, and silently ignoring them would hide drift",
            )

        _reject_unknown_keys(document, _TOP_LEVEL_KEYS, origin_label)
        known_target_set = set(known_targets)
        known_backend_set = set(known_backends)
        raw_credentials = document.get("credentials")
        if raw_credentials is None:
            raise ManifestError(f"{origin_label}: no 'credentials' key")
        if not isinstance(raw_credentials, Mapping):
            raise ManifestError(f"{origin_label}: 'credentials' must be a mapping")

        credentials: dict[str, Credential] = {}
        vault_entries: dict[tuple[str, str, tuple[str, ...]], str] = {}
        for name, spec in raw_credentials.items():
            credential = _parse_credential(
                name, spec, origin_label, known_target_set, known_backend_set
            )
            credentials[name] = credential
            if credential.vault is not None:
                vault = credential.vault
                # Resolved the way the secrets layer resolves it
                # (`secrets.py: _resolve`): an absolute ref stays, a relative
                # one joins the manifest's directory. Textual, not inode-level.
                # shortcut: two symlinks to one vault are not caught; upgrade if
                # a manifest ever reaches a vault through a symlink.
                file = vault.file
                if origin is not None:
                    file = posixpath.join(origin.parent.as_posix(), file)
                entry = (vault.backend, posixpath.normpath(file), vault.path)
                if entry in vault_entries:
                    raise ManifestError(
                        f"{origin_label}: credentials {vault_entries[entry]!r} and "
                        f"{name!r} declare one vault entry "
                        f"({vault.backend} {vault.file} {'/'.join(vault.path)})",
                        hint="one value is one credential: each name takes its own "
                        "rotation lock, so two names can double-mint the service",
                    )
                vault_entries[entry] = name

        # Arcane key names are global, not scoped to a service account, so two
        # credentials that name one key are a hazard the vault-entry check
        # cannot see: each would delete the other's live key on its revoke.
        arcane_names: dict[str, str] = {}
        for name, credential in credentials.items():
            if str(credential.write.get("mechanism") or "") != "arcane_api_key":
                continue
            key_name = credential.write.get("key_name")
            if not isinstance(key_name, str) or not key_name.strip():
                continue  # the planner refuses the missing field in its own words
            key_name = key_name.strip()
            if key_name in arcane_names:
                raise ManifestError(
                    f"{origin_label}: credentials {arcane_names[key_name]!r} and "
                    f"{name!r} both name the Arcane key {key_name!r}",
                    hint="Arcane key names are global, so a rotation of one "
                    "would delete the other's live key. Give each credential "
                    "its own write.key_name.",
                )
            arcane_names[key_name] = name
        return cls(version=version, credentials=credentials, origin=origin)


def _require(mapping: Mapping[str, Any], key: str, where: str) -> Any:
    if key not in mapping:
        raise ManifestError(f"{where}: missing required key {key!r}")
    return mapping[key]


def _reject_unknown_keys(
    mapping: Mapping[str, Any], allowed: frozenset[str], where: str
) -> None:
    unknown = [key for key in mapping if key not in allowed]
    if unknown:
        raise ManifestError(
            f"{where}: unknown key {unknown[0]!r}",
            hint=f"known keys: {', '.join(sorted(allowed))}",
        )


def _reject_nel(text: str, where: str, label: str) -> None:
    """A NEL survives the parse and does not survive the emitter.

    Measured, not assumed: it is a YAML line break, so `safe_dump` writes it
    literally and the reader folds it to a space. It is also the one control
    character that does not round-trip (tab, newline, CR, VT, FF, NUL, DEL and
    the paragraph separators all do), which is why this rejects it and nothing
    else.
    """
    if "\x85" in text:
        raise ManifestError(
            f"{where}: {label} contains a NEL, which folds to a space on the "
            "way back out"
        )


def _plain_str(raw: object, where: str, label: str) -> str:
    text = str(raw).strip()
    _reject_nel(text, where, label)
    return text


def _parse_credential(
    name: object,
    spec: object,
    origin: str,
    known_targets: set[str],
    known_backends: set[str],
) -> Credential:
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise ManifestError(
            f"{origin}: credential name {name!r} must be lowercase letters, "
            "digits, underscores or dashes"
        )
    where = f"{origin}: credential {name!r}"
    if not isinstance(spec, Mapping):
        raise ManifestError(f"{where}: must be a mapping")
    _reject_unknown_keys(spec, _CREDENTIAL_KEYS, where)

    credential_class = spec.get("class", "B")
    if credential_class not in CREDENTIAL_CLASSES:
        raise ManifestError(
            f"{where}: class {credential_class!r} is not one of "
            f"{', '.join(CREDENTIAL_CLASSES)}"
        )

    max_age = spec.get("max_age_days")
    if max_age is not None and (
        not isinstance(max_age, int)
        or isinstance(max_age, bool)
        or not 1 <= max_age <= MAX_EXACT_INT
    ):
        raise ManifestError(
            f"{where}: max_age_days must be a positive integer a JSON reader holds exactly"
        )

    never_rotate = spec.get("never_rotate", False)
    if not isinstance(never_rotate, bool):
        # bool("false") is True, so a quoted "false" used to invert this and
        # silently mark a rotatable credential as never_rotate.
        raise ManifestError(f"{where}: never_rotate must be true or false")
    # Class A and A-unv are the ones we intend to schedule, so they must say how
    # old is too old. B has no schedulable rotation, and saying "180 days" for a
    # signing key that breaks every session on change is worse than saying
    # nothing - so B either names an age or explicitly declines to rotate.
    if credential_class in ("A", "A-unv") and max_age is None:
        raise ManifestError(
            f"{where}: class {credential_class} needs max_age_days",
            hint="these classes are meant to be rotated on a schedule; if this "
            "one genuinely is not, mark it class B",
        )
    if credential_class == "B" and max_age is None and not never_rotate:
        raise ManifestError(
            f"{where}: class B with no max_age_days must set never_rotate: true",
            hint="an age on an unrotatable credential would schedule something "
            "that cannot be automated",
        )

    vault = None
    if "vault" in spec and spec["vault"] is not None:
        vault = _parse_vault(spec["vault"], where, known_backends)

    consumers = _parse_consumers(spec.get("consumers"), where, known_targets)

    provisioned = spec.get("provisioned", True)
    if not isinstance(provisioned, bool):
        raise ManifestError(f"{where}: provisioned must be true or false")

    return Credential(
        name=name,
        description=_plain_str(spec.get("description", ""), where, "description"),
        credential_class=credential_class,
        max_age_days=max_age,
        never_rotate=never_rotate,
        vault=vault,
        consumers=consumers,
        provisioned=provisioned,
        canonical=_as_mapping(spec.get("canonical"), where, "canonical"),
        write=_as_mapping(spec.get("write"), where, "write"),
    )


def _parse_vault(raw: object, where: str, known_backends: set[str]) -> VaultRef:
    if not isinstance(raw, Mapping):
        raise ManifestError(f"{where}: vault must be a mapping")
    _reject_unknown_keys(raw, _VAULT_KEYS, f"{where}: vault")
    backend = _require(raw, "backend", where)
    if not isinstance(backend, str):
        raise ManifestError(f"{where}: vault.backend must be a string")
    if known_backends and backend not in known_backends:
        raise ManifestError(
            f"{where}: unknown vault backend {backend!r}",
            hint=f"known backends: {', '.join(sorted(known_backends))}",
        )
    file = _require(raw, "file", where)
    if not isinstance(file, str) or not file:
        raise ManifestError(f"{where}: vault.file must be a non-empty string")
    _reject_nel(file, where, "vault.file")
    path = _require(raw, "path", where)
    # A list, not a dotted string. A key containing a literal dot would be
    # ambiguous to split on, and there is no reason to create that footgun.
    if isinstance(path, str):
        raise ManifestError(
            f"{where}: vault.path must be a list, not a string",
            hint="write [section, app, key] so keys containing dots stay unambiguous",
        )
    if not isinstance(path, Sequence) or not path or not all(
        isinstance(segment, str) and segment for segment in path
    ):
        raise ManifestError(f"{where}: vault.path must be a non-empty list of strings")
    for segment in path:
        _reject_nel(segment, where, "vault.path")
    return VaultRef(backend=backend, file=file, path=tuple(path))


def _parse_consumers(
    raw: object, where: str, known_targets: set[str]
) -> tuple[Consumer, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise ManifestError(f"{where}: consumers must be a list")

    consumers: list[Consumer] = []
    seen_targets: set[str] = set()
    for index, item in enumerate(raw):
        at = f"{where}: consumer #{index + 1}"
        if not isinstance(item, Mapping):
            raise ManifestError(f"{at}: must be a mapping")
        _reject_unknown_keys(item, _CONSUMER_KEYS, at)
        target = Target.parse(_require(item, "target", at), where=at)
        if str(target) in seen_targets:
            raise ManifestError(
                f"{at}: duplicate target {str(target)!r}",
                hint="declare a copy once; use count for several rows in that "
                "slot, and a qualifier to name a different row",
            )
        seen_targets.add(str(target))
        if known_targets and target.key not in known_targets:
            raise ManifestError(
                f"{at}: unknown target {target.key!r}",
                hint="this build has no writer or readable API for that slot. "
                "Remove the consumer - an unchecked target that looks checked "
                "is worse than a missing one.",
            )
        count = item.get("count", 1)
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or not 1 <= count <= MAX_EXACT_INT
        ):
            raise ManifestError(
                f"{at}: count must be a positive integer a JSON reader holds exactly"
            )
        mechanism = _plain_str(item.get("mechanism", ""), at, "mechanism")
        if mechanism in _RETIRED_CONSUMER_MECHANISMS:
            raise ManifestError(
                f"{at}: mechanism {mechanism!r} is retired",
                hint="strict API-only: use 'process_api' for a running-process "
                "readback, 'redeploy' for a rendered value, or no mechanism "
                "for an API-written holder.",
            )
        consumers.append(
            Consumer(
                target=target,
                count=count,
                mechanism=mechanism,
                host=_plain_str(item["host"], at, "host") if item.get("host") else None,
                note=_plain_str(item.get("note", ""), at, "note"),
            )
        )
    return tuple(consumers)


def _as_mapping(raw: object, where: str, key: str) -> Mapping[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        raise ManifestError(f"{where}: {key} must be a mapping")
    _parse_data(raw, where, key, set())
    return raw


def _parse_data(value: object, where: str, label: str, seen: set[int]) -> None:
    """`canonical`/`write` values must be plain data.

    The store carries these through JSON and the emitter writes back what the
    parser read, and every YAML-only shape fails differently: `!!pairs` and
    `!!omap` load as tuples and come back as lists, `!!set` iteration order
    varies per process (two exports of one model, two files), an unquoted date
    loads as a date object, a recursive alias is not equal to itself, a NEL
    folds to a space, and a non-string key comes back from JSON as a string.
    Reject them here rather than meet them in a diff.
    """
    if value is None or isinstance(value, (bool, int, float, str)):
        if value is None or isinstance(value, bool):
            return
        if isinstance(value, int):
            if abs(value) > MAX_EXACT_INT:
                raise ManifestError(
                    f"{where}: {label} must be an integer a JSON reader holds exactly"
                )
            return
        if isinstance(value, float):
            if not isfinite(value):
                raise ManifestError(f"{where}: {label} must be a finite number")
            return
        _reject_nel(value, where, label)
        return
    if isinstance(value, list):
        if id(value) in seen:
            raise ManifestError(f"{where}: {label} is a recursive alias")
        seen.add(id(value))
        for index, item in enumerate(value):
            _parse_data(item, where, f"{label}[{index}]", seen)
        seen.discard(id(value))
        return
    if isinstance(value, Mapping):
        if id(value) in seen:
            raise ManifestError(f"{where}: {label} is a recursive alias")
        seen.add(id(value))
        for name, item in value.items():
            if not isinstance(name, str):
                raise ManifestError(
                    f"{where}: {label} keys must be strings, got {name!r}",
                    hint="the store carries these mappings through JSON, where "
                    "a non-string key comes back as a string",
                )
            _parse_data(item, where, f"{label}.{name}", seen)
        seen.discard(id(value))
        return
    raise ManifestError(
        f"{where}: {label} must be plain data",
        hint=f"got {type(value).__name__}; canonical and write hold strings, "
        "finite numbers, booleans, null, lists and string-keyed mappings - "
        "quote a date or timestamp that is meant as text",
    )
