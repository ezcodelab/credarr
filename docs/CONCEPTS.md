# Concepts

## Holder map

One credential declares its canonical value, the service that issues it
(`canonical.service`, else the name), and the copies other services hold
(`consumers`, each a `target` like `sonarr.indexers` plus a `count`). The
audit compares each copy against the canonical value over that service's own
API. There is no config path, host bind, or file read anywhere in the
product; a declared service without a URL is reported as missing one.

## Audit statuses

Per holder; a credential takes the worst of its *comparable* consumers:

| Status | Meaning |
| --- | --- |
| `match` | The holder's own API returned a value equal to the canonical one. |
| `live` | The holder's own test accepted the stored value, but the value was not read back. Acceptance, not equality. Never becomes `match` or a finding. |
| `manual` | A configured copy with no API read-back (e.g. a Homepage label). Excluded from the credential verdict; all-manual reports `match`. |
| `unverifiable` | Not compared: URL or service key missing, API redacts the value, or the answer could not be counted. |
| `drift` | Compared and different. Always a real finding. |
| `missing` | Declared in the manifest, found nowhere. |
| `absent` | Declared but intentionally unprovisioned. |

## Reason codes

Every result also carries a stable `reason` code beside the `detail`
sentence. The console maps codes to fix hints without parsing English; `detail`
stays the operator's explanation and is never replaced by the code. History
written before codes existed reads `""` and falls back to sentence matching.

| Code | Fix |
| --- | --- |
| `match`, `live` | No action. `live` is acceptance, not equality. |
| `manual_copy`, `manual_only`, `no_holders` | No action. Deploy-time copy or empty holder set. |
| `not_provisioned` | Provision the key, then audit again. |
| `no_canonical`, `value_missing` | No value stored yet. Add the key on its app page, then audit again. |
| `no_service_key` | The copy's own service key is not configured. Add it on that app page. |
| `no_url` | The copy's service has no URL. Add it on that app page. |
| `no_readback` | This copy cannot be read back by this build; update it by hand after a rotation. |
| `target_unqualified` | The copy needs a qualified target naming one row or section. |
| `row_missing` | The service has no row with the declared name. Add/rename the row there, or remove the copy. |
| `field_missing` | The target does not expose the declared field. Check the copy's target. |
| `count_mismatch` | The live row count differs from the declared count. Set the count to the live number. |
| `unreachable` | Check the service's URL and that its API is answering. |
| `liveness_rejected` | The service rejected the stored value. Rotate again to write the current value. |
| `liveness_inconclusive` | The service could not prove the stored value. Check the service. |
| `value_drift` | Compared and different. A real finding. |

## Classes

`A` and `A-unv` both rotate; a copy this build cannot write becomes a named
MANUAL step and the run ends `INCOMPLETE` (exit 1) until a human confirms it.
`B` and `never_rotate` refuse at plan time (exit 5): no manual step can mint
a value that cannot be minted.

## Exit codes

0–5 are a public interface: 0 clean (the summary may still be
`unverifiable`/`live`), 1 incomplete/drift/manual outstanding, 3
misconfigured, 4 host unreachable/partial coverage, 5 rotation refused. Never
merge them.

## Rotation order

preflight → mint → propagate and verify per holder → record → revoke last.
`revokes_before_holders=true` is the honest statement for Servarr: the mint
replaces the key before holders are written, so an interrupted run leaves
holders on a dead key. Never auto-rerun an interrupted rotation. Resume or
abandon it instead. Values are wrapped server-side and never reach output, logs, events,
or notifications; `--json` emits JSON only.
