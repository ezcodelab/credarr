"""The manifest emitter: the parsed model back to YAML text.

The store imports and exports manifests as text, so this round trip has to be
exact both ways: `Manifest.parse(emit_manifest(m))` must equal `m` under the
same strict loader and target registry the audit uses, and emitting one
`Manifest` twice must produce byte-identical text - an export that reshuffles
itself on every write is a diff nobody can read.

What the model cannot hold does not survive: comments and formatting are gone
by the time a manifest is a `Manifest`, so they are gone from its text too.
What it does hold is written back, including the free-form `canonical` and
`write` mappings, which pass through as parsed. A hand-built `Manifest` is
written back as-is: the emitter serializes, it does not validate, and the
round-trip guarantee holds for models the parser built.

Defaults are omitted rather than spelled out - a file that says
`provisioned: true` on every entry reads as if the flag meant something. The
two exceptions are `class` and a consumer's `count`: hand-written manifests
show both, and an export should read next to the file it came from.
"""

from __future__ import annotations

from typing import Any

import yaml

from .model import Consumer, Credential, Manifest, VaultRef


def emit_manifest(manifest: Manifest) -> str:
    """The manifest as YAML, ready to be read back by `Manifest.parse`."""
    document = {
        "version": manifest.version,
        "credentials": {
            name: _credential_spec(credential)
            for name, credential in manifest.credentials.items()
        },
    }
    return yaml.safe_dump(
        document, sort_keys=False, default_flow_style=False, allow_unicode=True
    )


def _credential_spec(credential: Credential) -> dict[str, Any]:
    """Fixed key order, so two exports of the same state are the same file."""
    spec: dict[str, Any] = {}
    if credential.description:
        spec["description"] = credential.description
    spec["class"] = credential.credential_class
    if credential.max_age_days is not None:
        spec["max_age_days"] = credential.max_age_days
    if not credential.provisioned:
        spec["provisioned"] = False
    if credential.never_rotate:
        spec["never_rotate"] = True
    if credential.canonical:
        spec["canonical"] = dict(credential.canonical)
    if credential.vault is not None:
        spec["vault"] = _vault_spec(credential.vault)
    if credential.write:
        spec["write"] = dict(credential.write)
    if credential.consumers:
        spec["consumers"] = [_consumer_spec(consumer) for consumer in credential.consumers]
    return spec


def _vault_spec(vault: VaultRef) -> dict[str, Any]:
    # A list, not a dotted string: a key containing a literal dot has no
    # unambiguous split point, and the parser rejects the string form.
    return {"backend": vault.backend, "file": vault.file, "path": list(vault.path)}


def _consumer_spec(consumer: Consumer) -> dict[str, Any]:
    spec: dict[str, Any] = {"target": str(consumer.target), "count": consumer.count}
    if consumer.mechanism:
        spec["mechanism"] = consumer.mechanism
    if consumer.host is not None:
        spec["host"] = consumer.host
    if consumer.note:
        spec["note"] = consumer.note
    return spec
