# State machines

Status: audited 2026-11-07 against `9a58260` + the fixes in this change.
This document is the single inventory of credarr's explicit and implicit state
machines. It records the states, the invariants the code relies on, the
transitions it implements, and every reachable invalid state or transition we
could confirm. Fixed findings name their regression test; deferred findings
name the decision they need.

Source of truth is the code. Line numbers are from this revision and will drift;
the function names are the stable reference.

## How to read this

- **Explicit** means a column, enum, literal vocabulary, or a transition table
  in code (for example `attempts.outcome`, `Status`, `event_deliveries.state`).
- **Implicit** means a state that exists only as a combination of values and
  guards (for example "the credential lease is stale", "the pending value is the
  recorded one", "the last audit is fresh enough for auto").
- **Invariant** means a property a correct run must never violate. A confirmed
  violation is an issue below, not a style note.
- **Reachable** means a sequence exists through the public routes, the CLI, the
  scheduler, or a crash/retry of those paths. Tests or a script demonstrate it.
- **Issue IDs** are `SM-n`. A fixed issue names its regression test. A deferred
  issue names the product decision or the one-way door it crosses.

## Index

| # | Machine | Kind | Code | Issues |
| --- | --- | --- | --- | --- |
| 1 | Credential rotation lease | explicit table + implicit liveness | `journal.py` | SM-9 (accepted) |
| 2 | Rotation attempt | explicit column | `journal.py` | SM-1, SM-1d, SM-10 |
| 3 | Rotation step | explicit column | `journal.py` | SM-1, SM-1b |
| 4 | Pending secret | explicit table + implicit ownership | `pending.py`, `store.py` | SM-2, SM-2b |
| 5 | Holder outcome | explicit vocabulary | `executor.py` | SM-4 |
| 6 | Executor run and recovery | implicit lifecycle | `executor.py`, `facade.py` | SM-1, SM-1c, SM-2, SM-2b, SM-9, SM-10 |
| 7 | Auto-rotation policy | explicit table + implicit gate | `auto_rotation.py`, `store.py` | SM-3 |
| 8 | Audit run and status ledger | explicit columns + derived status | `audit.py`, `audit_log.py` | — |
| 9 | Notification delivery | explicit column | `notifier.py` | — |
| 10 | Admin lockout and sessions | explicit table + implicit expiry | `auth.py` | SM-6 |
| 11 | Topology import and working copies | implicit merge lifecycle | `store.py`, `app.py` | SM-3, SM-7, SM-8 |
| 12 | Loop health | implicit thread state | `app.py`, `scheduler.py` | SM-5 |

---

## 1. Credential rotation lease

One row in `locks`, keyed by credential (or by the reserved `STACK_LOCK` name).
The lease is advisory and time-bounded: a killed process cannot release it, so
it becomes reclaimable after `stale_after` (default 900 s).

### States

| State | Representation |
| --- | --- |
| free | no row for the credential |
| held | row with `acquired_at` within `stale_after` |
| stale | row with `acquired_at` older than `stale_after` |
| lost | the token in this process no longer matches the row |

### Invariants

1. At most one owner token per credential. `try_acquire` uses
   `BEGIN IMMEDIATE`, so the check/reclaim/insert is one write transaction.
2. Ownership is the token, never pid/host. `release`, `renew`, `holds`, and
   `assert_held` all compare the token (`journal.py:203-315`).
3. A live holder renews at `stale_after / 3`; a merely slow holder keeps its
   lease. A wedged holder cannot (`lock`, `journal.py:318-360`).
4. Reclaiming a stale lease is unconditional, but a stale holder's later
   release/renew cannot touch the replacement (`release`, `renew`).
5. Checking ownership is read-only; it must not extend the lease
   (`holds`, tested by `test_ownership_check_is_read_only`).
6. The lease alone cannot make a service write atomic with the check. This is a
   known limitation, not a claim of safety (SM-9).

### Transitions

| From | Event | To | Guard / effect |
| --- | --- | --- | --- |
| free | `try_acquire` | held | insert row with a fresh token |
| held | `renew` | held | token matches; `acquired_at = now` |
| held | `release` | free | token matches; row deleted |
| held | time passes without renew | stale | `now - acquired_at > stale_after` |
| stale | `try_acquire` | held (new token) | delete old row, insert new token |
| held | another acquirer after stale | lost | old token can no longer renew/release |
| lost | `assert_held` | run stops | raises `JournalLocked` |

### Reachable invalid states

- **SM-9 (accepted limitation): the check-write gap.** The fence runs before a
  step or row write, not atomically with it. A process that loses the lease
  between the check and the service call still performs that one write. This is
  pinned by `test_CHARACTERISATION_the_check_does_not_fence_the_write_it_guards`
  in `tests/test_concurrency.py`. A real fencing token carried to the service is
  not built; every holder would have to enforce it. The **final report** is
  fenced separately (SM-1c): a run that loses the lease after its last step
  returns a failed result and leaves the attempt open instead of claiming
  success.
- No invalid *lease* transition was found: concurrent acquirers produce exactly
  one winner (`test_concurrent_acquirers_get_exactly_one_winner`).

---

## 2. Rotation attempt

One row in `attempts` per `Executor.execute` call. The attempt is the durable
statement "a run started", even if it died before its first step.

### States

| State | Representation |
| --- | --- |
| open | `finished_at IS NULL` |
| completed | `outcome = 'completed'` |
| failed | `outcome = 'failed'` |
| abandoned | `outcome LIKE 'abandoned%'` (`reclaim_stale`/`take_over`/`abandon`) |

### Invariants

1. An attempt is opened before the first step and is the only safe guide after a
   crash (`begin`, `journal.py:392`).
2. An open attempt blocks an unattended retry even when it has no unfinished
   step (kill between `begin` and the first step) (`open_attempts`).
3. A terminal attempt is immutable. `finish` only updates a row whose
   `finished_at IS NULL` (`journal.py:501-508`).
4. A takeover or reclaim closes the attempt with an `abandoned` outcome; a
   zombie owner must not turn that into `completed`.
5. `last_success` counts only a completed attempt with no manual, unfinished,
   failed, abandoned, or `written` holder. `last_rotation` additionally allows
   manual and `written` work that the operator was already told about, and an
   abandoned attempt whose RECORD step finished (the key did change; only the
   attempt close was lost).
6. Callers classify a stored outcome with `journal.outcome_state`, never by a
   prefix of their own. `Outcome.INTERRUPTED` is `outcome IS NULL`, not a
   stored word; the three abandoned sentences all classify as `ABANDONED`.

### Transitions

| From | Event | To | Guard / effect |
| --- | --- | --- | --- |
| — | `begin` | open | insert `started_at` |
| open | last step succeeds | completed | `finish('completed')`, only if still open |
| open | a step raises | failed | `finish('failed')`, only if still open |
| open | `reclaim_stale` (step older than cutoff) | abandoned | closes stale steps and attempts with no pending step |
| open | `take_over` (operator says the run is dead) | abandoned | closes all unfinished steps for that credential |
| open | `abandon` (operator closes the record without a new run) | abandoned | same close, different sentence; no replacement run |
| open | process killed | open | no finish row; the crash evidence |
| completed/failed/abandoned | any later `finish` | unchanged | `finished_at` guard wins |

### Reachable invalid states

- **SM-1 (fixed): a zombie could overwrite a takeover.** Before the guard,
  `step_finished` and `finish` updated unconditionally. A run whose lease was
  reclaimed could wake up and turn `abandoned` into `ok`/`completed`; then
  `last_rotation` reported a superseded run as delivered. Reproduced with a
  direct `Journal` sequence (takeover, then zombie `step_finished` + `finish`).
  Fixed in `journal.py:427-443` and `journal.py:501-508`.
  Regression: `test_a_takeover_cannot_be_overwritten_by_the_run_it_replaced`.
- **SM-1b (fixed): a zombie could open a step in a closed attempt.** The
  executor records `step_started` before checking the lease. If the attempt was
  already taken over, that insert re-blocked the credential with a step no live
  run owned. `step_started` now refuses a closed attempt and refuses to replace
  an existing ordinal (`journal.py:385-425`).
  Regression: `test_a_zombie_cannot_open_a_step_in_a_closed_attempt`.
- **SM-1d (fixed): a zombie could add holder rows to a closed attempt.**
  `record_holder` wrote unconditionally, and the executor calls it on the
  failure and final-fence paths. A run that lost a takeover could therefore
  claim a holder was `confirmed` in an attempt it no longer owned, and
  `last_rotation` reads holder rows on an abandoned attempt whose RECORD
  finished. The insert is now conditional on the attempt still being open
  (`journal.py:460-478`).
  Regression: `test_a_closed_attempt_rejects_holder_rows`.
- **SM-10 (fixed): an unresumable unfinished run had no operator exit.** The
  recovery-baseline guards refuse edits while a run is unfinished, and
  `take_over` only helps if a new plan can run. When the service is unreachable
  - exactly when the operator needs to correct the value - the credential was
  wedged: paste refused, take-over refused, no way to clear the record.
  `Journal.abandon` closes the unfinished steps and attempt without starting a
  replacement run and without touching stored or parked values; `POST
  /credentials/{name}/rotation/abandon` exposes it under the credential lease
  (a live run still answers 409), `credarr rotate <name> --abandon` is the same
  action with the server down (it takes the instance lock), and the console
  offers it in the unfinished-run banner, including the case where every step
  finished but the attempt never closed. Regressions:
  `test_an_unfinished_rotation_can_be_abandoned_without_a_new_run`,
  `test_abandon_refuses_a_live_rotation`,
  `test_the_cli_abandons_an_unfinished_rotation_without_a_plan`.

---

## 3. Rotation step

One row per `(attempt, ordinal)` in `steps`. A step is written as started
*before* its side effect and finished *after* it.

### States

| State | Representation |
| --- | --- |
| started | `finished_at IS NULL` |
| ok | `outcome = 'ok'` |
| noted | manual step (`outcome = 'noted'`) |
| written | value recorded (`outcome = 'written'`, or a pending-cleanup sentence) |
| failed | `outcome LIKE 'failed%'` |
| abandoned | `outcome LIKE 'abandoned%'` |

### Invariants

1. Start-before-run, finish-after-run. A start without a finish is an
   interrupted rotation (`journal.py:385-425`).
2. `(attempt_id, ordinal)` is written once. Retrying the same ordinal would
   erase the evidence of the first attempt.
3. A closed attempt accepts no new step and no new holder row.
4. A step that a takeover marked abandoned is final; the old owner's finish
   cannot rewrite it.
5. The failure detail is scrubbed before it is journaled (`executor.py` failure
   handler); no value, fingerprint, or token enters `outcome`.
6. A completed step is `outcome_state(...) is Outcome.COMPLETED`. A successful
   step stores its own description, so the absence of a keyword is not the
   absence of success — `outcome = ''` is a completion too.

### Transitions

| From | Event | To | Guard / effect |
| --- | --- | --- | --- |
| — | `step_started` | started | attempt open and ordinal absent |
| started | dispatch returns | ok / written / noted | `step_finished` only while `finished_at IS NULL` |
| started | dispatch raises | failed | same conditional finish |
| started | takeover/reclaim older than cutoff | abandoned | closes the record |
| started | process killed | started | stays pending; blocks a retry |
| abandoned | zombie `step_finished` | unchanged | `finished_at IS NULL` guard |

### Reachable invalid states

Covered by SM-1/SM-1b. No other reachable step transition was found.

---

## 4. Pending secret

The chosen value a pending-backed mint must not lose: Servarr backup/restore,
qBittorrent rotate, SABnzbd reset, Bazarr rotate, Seerr regenerate, and the
explicit manual mint. It is stored beside the surface's canonical store
(`state/pending.db` for the CLI, `app.db` for the server).

### States

| State | Representation |
| --- | --- |
| absent | no row |
| parked | row whose value is not canonical yet |
| recorded-copy | row equal to the canonical value (clear was missed) |
| orphan | row for a credential no longer declared |
| cleared | no row after RECORD or `prune_pending` |

### Invariants

1. Park before mutation. The candidate is persisted before the service is
   changed (`_mint_api`, `_mint_qbittorrent`, etc.).
2. The pending value is never canonical until RECORD writes it. RECORD is the
   only step that moves the canonical copy.
3. A parked value that differs from the canonical value is recovery state, not
   garbage. Only an exact match is pruned (`TopologyStore.prune_pending`).
4. A crash after RECORD may leave a copy equal to canonical; it is safe to prune.
5. The value never enters a message, event, or journal row.

### Transitions

| From | Event | Result |
| --- | --- | --- |
| absent | mint chooses a candidate | parked |
| parked | resume finds candidate live | stays parked; mint continues with it |
| parked | RECORD writes canonical | cleared (or recorded-copy if clear failed) |
| recorded-copy | startup `prune_pending` | cleared |
| parked | topology no longer declares the credential | orphan, then pruned |
| parked | candidate equals current canonical | cleared as a recorded copy |

### Reachable invalid states

- **SM-2 (fixed): a crash after RECORD could mint again.** If the process died
  after RECORD wrote the canonical value but before the attempt finished, the
  next run saw the new key as `vault_value`, found no or an equal pending value,
  and entered the normal mint path. For a pending-backed mint that revokes the
  canonical key at the mint, it generated a third key and revoked the one every
  holder had just received. Reproduced with `Executor.execute` and a seeded
  open attempt whose RECORD step was finished or reclaimed.
  Fixed by `_resume_after_record` (`executor.py:1009-1080`): when the previous
  attempt reached RECORD, the mint is pending-backed, the parked value is absent
  or equal to canonical, and the canonical value authenticates at the issuer,
  the run loads the dead attempt's holder rows, skips every step before RECORD,
  and finishes from RECORD. The canonical value is used as the minted value; no
  service mutation happens. A RECORD that finished `failed` does not count as
  reached; the parked/canonical comparison is the backstop. An already-abandoned
  attempt is resumed only by an explicit takeover; a plain later Rotate is a new
  rotation. `last_rotation` counts an abandoned attempt whose RECORD step
  finished, so auto does not mint a second key while an explicit manual run
  still does.
  Regressions:
  `test_a_crash_after_record_resumes_without_minting_again`,
  `test_a_crash_before_record_completes_the_parked_key_without_a_backup`,
  `test_a_crash_after_record_with_the_parked_key_clears_it_without_minting`,
  `test_a_plain_run_after_an_abandoned_record_still_mints`,
  `test_an_abandoned_attempt_that_finished_record_counts_as_a_rotation`.
- **SM-2b (fixed): reissue mints re-mint after RECORD.** Grafana, Arcane,
  Gitea and the Gitea hook create the replacement alongside the predecessor and
  revoke last. A crash after RECORD used to re-mint a third secret and sweep
  the first two by name: safe-ish, but unnecessary and dependent on each
  service's sweep rule. The mint now parks the value it created and records the
  service-side row handle (`steps.handle`) as soon as the create answers,
  before the step finishes and before RECORD; it records the predecessor's row
  id (`steps.predecessor`) before the create, so a resumed revoke still finds
  the predecessor after an operator rename. A later run adopts the parked
  value when the handle is on the previous mint step and the value still
  authenticates, and the revoke deletes the predecessor by id and by
  name/namespace. Both are row ids, never secrets. A kill between the create
  response and the park write loses the only copy (the service returns it
  once); that run falls back to the normal mint path, and the lost successor is
  swept by name. Jellyfin records no handle and deliberately re-mints and
  sweeps by name (its revoke needs none). A resumed revoke has no predecessor
  value to prove dead (RECORD already moved the canonical copy), so it proves
  the revoke by re-listing the service and asserting no recorded predecessor or
  matching name remains; the by-value 401 proof runs on a fresh rotation.
  Regressions:
  `test_a_crash_after_record_resumes_a_reissue_without_minting`,
  `test_a_mint_that_died_before_its_step_adopts_the_parked_row`,
  `test_a_reissue_without_a_recorded_handle_re_mints`.
- **SM-2c (accepted): qBittorrent response-before-park window.** If the process
  is killed between the rotate response and the pending write, the only copy of
  the new key is lost. The code refuses to rotate without a pending store and
  says so; no local file fallback exists.

---

## 5. Holder outcome

One row per `(attempt, target, label)` in `holders`, plus the in-memory
`HolderOutcome` list in the executor.

### States

| State | Meaning |
| --- | --- |
| `already-current` | the holder already held the new value; nothing written |
| `written` | the API accepted the write; no proof that the running process uses it |
| `confirmed` | the holder's own API read the value back equal, or its measured test accepted it with the old issuer key proven dead |
| `failed` | the write was refused, could not be read, or exhausted retries |
| `not-reached` | an earlier step failed; this holder was never tried |

### Invariants

1. Every declared holder in a failed run has a row. Silence about a holder is
   the most damaging outcome (`_mark_unreached`).
2. `written` is a transient, not a success. `ExecutionResult.clean` is false for
   `written`, `failed`, `not-reached`, or any manual step.
3. `last_success` excludes `written`; `last_rotation` accepts it because the key
   did rotate and the operator was told the copy is unproven.
4. `confirmed` requires equality or the three exercise facts: new key works, old
   key dead, holder accepts the stored value. A `written` row never silently
   becomes `confirmed`.
5. No value or fingerprint is stored in `holders`.

### Transitions

| From | Event | To | Guard |
| --- | --- | --- | --- |
| — | preflight | already-current | no write needed |
| — | write accepted | written | API 200/201/202 |
| written | read-equal or exercise proves it | confirmed | old issuer key dead for exercise-only |
| — | refusal / unreadable resource / retry exhaustion | failed | bounded retries, scrubbed detail |
| — | earlier step failed | not-reached | no call made |

### Reachable invalid states

- **SM-4 (fixed): retry exhaustion left no holder row.** A transient refusal
  (429/500/502/503/504) retried four times and then raised a step-level error
  without appending a `failed` holder. The operator saw the step but not which
  row it could not write, and `holders` under-reported the damage. Reproduced
  with a fake service returning HTTP 500 and `WRITE_ATTEMPTS` exhausted.
  Fixed in `_propagate` (exhaustion, missing field, unaddressable slot).
  Regression: `test_a_transient_write_exhaustion_names_the_row_that_failed`.
- No other missing-holder path was found for a holder that was actually
  attempted; the list/read failures that happen before a row is known are
  reported at step level.

---

## 6. Executor run and recovery

The executor is the only component that mutates services and the canonical
store. Its implicit lifecycle is the one the other machines exist to protect.

### States

| State | Representation |
| --- | --- |
| planned | a `RotationPlan` with no side effect yet |
| preflighted | read-only checks passed; still no side effect |
| open attempt | journal row started, steps as they run |
| recovered | the run reclaimed/took over a dead attempt and is continuing |
| recorded | RECORD wrote the canonical value |
| terminal | attempt completed or failed; holders mirrored into the journal |

### Invariants

1. `plan.executable` is checked before `begin`; a plan that cannot complete
   opens no attempt (`execute`, `executor.py:1074`).
2. The credential lease is held for the whole run (`facade.execute`).
3. Reclaim/takeover happens before `begin`; a resumed mint re-derives from the
   service and the pending store, never from memory.
4. The order is preflight → mint → propagate/verify per holder → record →
   revoke last. A failure stops the run and records the holder state; it never
   auto-reruns.
5. The fence runs before every step, every row write, and the final completion
   report (SM-9 accepts the remaining service-write gap).
6. RECORD is last before REVOKE. A crash after RECORD is a completion, not a
   reason to mint again (SM-2).

### Transitions

| From | Event | To | Effect |
| --- | --- | --- | --- |
| planned | `preflight` | preflighted | read-only service probes |
| preflighted | `execute` | open attempt | reclaim stale steps, take over if asked, `begin` |
| open attempt | step succeeds | next step | `step_finished` |
| open attempt | step raises | failed attempt | record failure, mark unreached holders |
| open attempt | last step succeeds | completed attempt | RECORD written, holders mirrored |
| open attempt | crash | open attempt | next run must reclaim/take over |
| open attempt | previous run reached RECORD | recovered | skip pre-RECORD steps, finish from RECORD |
| completed/failed | next run | new attempt | normal due/manual path |

### Reachable invalid states

SM-1, SM-1b, SM-2, SM-9. No additional executor-level illegal transition was
confirmed.

---

## 7. Auto-rotation policy

One row per credential in `auto_rotation`. The policy is deployment state, not
topology; it survives re-imports for names that still exist.

### States

| State | Representation |
| --- | --- |
| off | no row, or `enabled = 0` |
| enabled | `enabled = 1`, `paused = 0` |
| paused | `enabled = 1`, `paused = 1`; needs a human |
| started | `last_outcome = 'started'` while a run is open |
| succeeded | `last_outcome = 'succeeded'` |
| manual | `last_outcome = 'manual'`; key rotated, a copy is owed |
| interrupted | `last_outcome = 'interrupted'`, `paused = 1` |
| blocked | `last_outcome = 'blocked'`; transient gate, not paused |

### Invariants

1. Due time is `max(last completed rotation, enabled_at) + every_days`. Manual,
   CLI and console rotations all move the same watermark.
2. Enabling from off or paused resets `enabled_at` and clears the pause; it
   cannot fire in the same request.
3. The gate requires a fresh completed audit with exact credential/holder
   coverage, `MATCH` or `LIVE` for every proven copy, no real finding, no
   unfinished step anywhere, no open attempt anywhere, a clean plan/preflight,
   and no manual mint.
4. A manual or unproven copy still rotates; the policy stays enabled and emits
   `auto_manual`.
5. A failure or interruption pauses. Only an explicit re-enable clears it.
6. A disable during a pass wins: the worker re-reads the policy before planning
   and before execute, and a stack-lock conflict writes no policy outcome.

### Transitions

| From | Event | To | Guard |
| --- | --- | --- | --- |
| off | enable | enabled | typed name, interval, `accept_manual` if needed, no open attempt for the name |
| enabled | due + gate passes | started → succeeded/manual | audit fresh, stack and journal clear |
| enabled | due + gate blocks | blocked | transient; retry on cadence |
| enabled | run fails/interrupted | paused | executor failure, startup reconciliation |
| enabled | disable | off | operator |
| paused | enable | enabled | explicit re-enable; resets baseline and clears pause |
| paused | any due check | paused | no run |

### Reachable invalid states

- **SM-3 (fixed, shared with topology): changing the recovery baseline during an
  unfinished run.** A stale lease let the value paste route (and an URL move)
  proceed while a dead run's steps were open. Pasting the key the service
  already held made the next run treat the new key as the old one and mint
  again; moving the service URL made a resume target a different destination.
  The same value write is reachable through the service patch's key re-send
  branch, so it takes the same guard. Fixed by `value_change_guard`
  (`app.py:929-975`), the URL-move journal check (`app.py:2215-2235`), and the
  guard on `patch_service`'s key branch (`app.py:2208`). Regressions:
  `test_a_value_change_is_refused_while_an_unfinished_rotation_exists`,
  `test_a_url_move_refuses_an_unfinished_rotation_without_a_parked_key`,
  `test_a_service_key_resend_is_refused_while_a_rotation_is_unfinished`.
- **SM-7 (fixed): holder/vault/write/class edits during a stale unfinished run.**
  `patch_credential` and `put_holders` take only the stack lease, so after a
  crash an operator could change a credential's holder set, class, vault or mint
  configuration and change what the resume is recovering toward. Those fields
  now take `rotation_edit_guard` (`app.py:955-975`); metadata that changes no
  step (description, notes, `provisioned`, `max_age_days`) stays editable.
  Regression: `test_a_plan_change_is_refused_while_an_unfinished_rotation_exists`.
- No policy transition that produces `enabled + paused` or a same-request run
  was found; the stack lease orders disable against a pass.

---

## 8. Audit run and status ledger

The audit ledger is append-only history plus a derived "last state". It is not
a mutable status row.

### States

| Object | States |
| --- | --- |
| audit run | failed-before-audit (`exit_status IS NULL`), completed (`exit_status` set) |
| credential | `match`, `drift`, `missing`, `error`, `absent`, `unverifiable`, `live`, `indirect` |
| consumer | `match`, `drift`, `missing`, `error`, `unverifiable`, `live`, `indirect` |
| event | `drift`, `unverifiable`, `recovered`, plus action kinds (`auto_*`, `rotation_*`, `test`) |

### Invariants

1. A run, its credential rows, its consumer rows and any derived event commit
   in one transaction. A crash leaves the previous state.
2. `last_run` is the newest attempt; `last_audit` is the newest attempt with a
   status. A failed attempt blocks auto even though the older completed audit
   still has states.
3. The first recorded status is a baseline, not an event. The same status is
   not an event. A transition into `live` is not a recovery event.
4. `drift` covers every problem status; `unverifiable` is distinct; `recovered`
   only leaves a problem or unverifiable state.
5. A scoped check (`record_check`) never becomes `last_audit`; auto requires
   stack coverage.

### Transitions (credential status → event)

| Previous | Current | Event |
| --- | --- | --- |
| none | any | none (baseline) |
| same | same | none |
| any | `live` | none |
| any non-problem | `drift`/`missing`/`error` | `drift` |
| any non-problem | `unverifiable` | `unverifiable` |
| problem | `unverifiable` | `unverifiable` |
| problem or `unverifiable` | non-problem, non-live | `recovered` |
| problem | `live` | none (liveness is not equality) |

### Reachable invalid states

None confirmed. The transaction boundary is the reason: there is no half-written
run to read, and the failure path writes a run with no credential rows rather
than inventing statuses.

---

## 9. Notification delivery

One row per `(event, sink)` in `event_deliveries`, created lazily by the first
attempt.

### States

| State | Representation |
| --- | --- |
| absent | no row; the event has not been tried for this sink |
| pending | `state = 'pending'`, `next_attempt_at <= now` |
| delivered | terminal success |
| failed | terminal after `MAX_ATTEMPTS` (10) |

### Invariants

1. One row per event and sink; attempts increment in one `BEGIN IMMEDIATE`
   transaction, so two readers cannot both "win" the same attempt.
2. A delivered or failed row is never picked up again. Only pending rows with a
   due `next_attempt_at` are selected.
3. A new service has an `updated_at` floor; it does not replay the ledger. A
   service edit moves the floor, so an old pending row it no longer covers is
   not reported as pending.
4. Silent event kinds never create delivery rows.
5. The payload carries names, statuses and the scrubbed audit sentence; never a
   value or fingerprint.

### Transitions

| From | Event | To | Effect |
| --- | --- | --- | --- |
| absent | tick, send accepted | delivered | `delivered_at = now` |
| absent | tick, send refused | pending or failed | attempts 1..9 pending; attempt 10 failed |
| pending | due, send accepted | delivered | terminal |
| pending | due, send refused | pending or failed | capped exponential backoff |
| pending | service floor moves past it | not selected | stats stop counting it as pending |
| failed/delivered | any tick | unchanged | terminal |

### Reachable invalid states

None confirmed. The notifier's process lock and the `BEGIN IMMEDIATE` attempt
counter close the retry races; `test_a_failed_delivery_is_retried_with_backoff`
and the duplicate-tick tests pin the boundary.

---

## 10. Admin lockout and sessions

### Lockout states

| State | Representation |
| --- | --- |
| open | no row or fewer than `MAX_LOGIN_FAILURES` (5) recent failures |
| counting | `failures` 1..4 within the 15-minute window |
| locked | `locked_until > now` |
| reset | window elapsed or lockout expired; next failure starts at 1 |

### Session states

| State | Representation |
| --- | --- |
| live | `revoked_at IS NULL`, `now < idle_expires_at`, `now < absolute_expires_at` |
| renewed | live and less than half the idle window remains; idle expiry slides |
| expired | either expiry reached; the row is revoked on the next use |
| revoked | `revoked_at` set by logout, revoke, password change, or expiry |

### Invariants

1. Only hashes of session tokens and API keys are stored; the raw token is
   returned once.
2. Both expiries are enforced server-side, not by the cookie.
3. A revoked row never authenticates. The conditional update closes the
   revoke-during-authenticate race.
4. `change_password` revokes every session except the caller's, then rotates the
   caller's token and CSRF value in the same transaction.
5. Sign-in and password change share one lock, so a sign-in cannot verify the
   old digest across a committed change.

### Transitions

| From | Event | To | Effect |
| --- | --- | --- | --- |
| open | wrong password | counting/reset | increment or start at 1 |
| counting | 5th wrong password | locked | `locked_until = now + 5 min` |
| locked | attempt before expiry | locked | `LoginLocked` |
| locked | attempt after expiry | reset | next failure starts at 1 |
| open | correct password | open | clear failures, issue session |
| live | request before expiry | live/renewed | `last_seen_at`, maybe slide idle expiry |
| live | request at/after expiry | revoked | return None |
| live | logout/revoke | revoked | conditional update |
| live | password change | revoked except caller | caller row rotated in place |

### Reachable invalid states

- **SM-6 (fixed): old password could win a race with `change_password`.**
  `login` read the old digest and spent argon2 time verifying it while
  `change_password` updated the digest. A sign-in that started before the
  change could return success after the change committed, creating a session
  for the old password. Reproduced with a blocked `verify_password` and a
  concurrent change. Fixed by taking `AdminAuth._login_lock` in
  `change_password` (`auth.py:289-316`).
  Regression: `test_a_password_change_cannot_race_a_sign_in_that_is_verifying`.
- No other auth transition was confirmed invalid. The expiry and revoke races
  are closed by conditional updates.

---

## 11. Topology import and working copies

The manifest is declared state; `working_copies` is the runtime canonical. Import
is the only path that can move names, values, policies and holders together.

### States

| Object | States |
| --- | --- |
| import | replace, merge, merge+prune |
| credential name | survives, added, removed |
| working copy | survives (same name), orphaned, pruned |
| pending secret | survives (same name), orphaned, pruned |
| auto policy | survives (same name), orphaned, pruned |
| holder row | replaced with the imported declaration |

### Invariants

1. Import is one transaction. A parse or write failure leaves the previous
   topology in place.
2. Replace deletes every credential and re-inserts the file. Working copies and
   policies survive only for names the file still declares.
3. Merge upserts by name; `prune` removes names the file omits and then prunes
   their values and policies.
4. A credential's working copy is not a vault read at runtime; it is the
   credential's canonical value for audit and rotation.
5. `delete_credential` blocks while that credential has an unfinished step or
   open attempt; the URL move has the same rule.
6. `patch_credential` warns when the issuer changes but keeps existing holders.

### Transitions

| From | Event | To | Effect |
| --- | --- | --- | --- |
| declared | import replace/merge | declared (new) | upsert row and holders |
| declared | import replace/merge without prune | declared (kept) | values/policies survive by name |
| declared | prune or replace omitting name | removed | holders cascade; value/pending/policy pruned |
| value present | name survives | value present | working copy preserved |
| value present | name removed | value gone | pruned |
| policy present | name survives | policy present | enabled/paused/interval preserved |
| policy present | name removed | policy gone | pruned |
| declared | URL move | declared | journal must be clear; key re-entered for the new destination |

### Reachable invalid states

- **SM-3 (fixed): URL move during an unfinished run.** Covered above. The route
  now checks the unwindowed journal, not only the pending store.
- **SM-7 (fixed): holder/vault/write/class edits during a stale unfinished run.**
  Covered above.
- **SM-8 (fixed): a surviving name can change issuer while keeping its working
  copy.** Replace/merge preserves `working_copies` by name, so an imported
  declaration that derives a different service keeps the old service's key as
  the canonical value for the new issuer. The copy is kept (clearing it is
  destructive); the import response now carries an `issuer_changed` warning
  naming both services, next to the existing `audit_only` warning
  (`app.py:900-938`). The console renders it as its own sentence.
  Regression: `test_import_warns_when_a_surviving_name_changes_issuer` and the
  `importWarningLines` unit test.

---

## 12. Loop health

Two daemon loops plus the auto worker: the audit scheduler, the notification
delivery loop, and auto-rotation.

### States

| Object | States |
| --- | --- |
| scheduler | started/running, stopped, failed |
| delivery | started/running, stopped, failed |
| auto | started/running, stopped, failed, not needed (no enabled policy) |
| health | ok, degraded (loop not running), degraded (loop failure), degraded (auto needed but not running) |

### Invariants

1. A loop that cannot write its durable state stops and reports the failure;
   continuing would serve a dashboard nobody can trust.
2. `/health` is degraded if either the audit or delivery loop is not alive, if
   either has a recorded failure, if auto has a failure, or if any policy is
   enabled and auto is not running.
3. A due auto-rotation still gets its own audit even when scheduled audits are
   disabled. A blocked due retries on the configured interval, not forever and
   not in a spin.

### Transitions

| From | Event | To | Effect |
| --- | --- | --- | --- |
| stopped | `start` | running | thread starts |
| running | normal `stop` | stopped | health degrades during shutdown |
| running | unrecordable failure | failed | `failure` set; health 503 |
| running | audit wakes | running | one audit, then wait |
| disabled schedule + due auto | blocked audit | retry after `interval` | new in SM-5 |
| no enabled policy | auto stopped | health ok | auto is not required |

### Reachable invalid states

- **SM-5 (fixed): a blocked due could sleep forever with audits disabled.**
  `_wait_seconds` returned `None` when `audit_wait` was `None` and the due was
  already past, so a due auto-rotation blocked by an unfinished run was never
  retried until an unrelated wake. Fixed in `scheduler.py:112-121` by using the
  configured interval as the retry cadence.
  Regression: `test_a_disabled_schedule_still_retries_a_blocked_due`.
- No health transition was found that reports `ok` while a required loop is
  dead; the tests for `/health` and the loop failures cover the branches.

---

## Issue register (ranked by impact)

| ID | Severity | Impact | Evidence | Status | Regression |
| --- | --- | --- | --- | --- | --- |
| SM-1 | Critical | A zombie owner overwrites a takeover; `last_rotation` lies and a superseded run looks delivered | direct journal sequence; `journal.py:427`, `:501` | Fixed | `test_a_takeover_cannot_be_overwritten_by_the_run_it_replaced` |
| SM-1b | High | A zombie inserts a step into a closed attempt, re-blocking the credential | direct journal sequence; `journal.py:385` | Fixed | `test_a_zombie_cannot_open_a_step_in_a_closed_attempt` |
| SM-1c | High | A zombie that loses the lease after its last step reports success for work it no longer owns | final fence at `executor.py` completion | Fixed | `test_a_lease_lost_after_the_last_step_is_not_reported_as_success` |
| SM-2 | Critical | A crash after RECORD re-mints a pending-backed credential and revokes the key holders just received | executor reproduction with a seeded RECORD attempt | Fixed | 3 tests in `tests/test_executor.py` |
| SM-6 | High | Old password can authenticate after a password change commits | blocked-verify race in `auth.py` | Fixed | `test_a_password_change_cannot_race_a_sign_in_that_is_verifying` |
| SM-3 | High | Pasting a value (three routes) or moving a service URL during a stale unfinished run changes the recovery baseline/destination | route sequence; `app.py` value, patch-service and URL guards | Fixed | 3 API tests |
| SM-5 | Medium | A blocked auto due never retries when scheduled audits are off | `Scheduler._wait_seconds` returns `None` | Fixed | `test_a_disabled_schedule_still_retries_a_blocked_due` |
| SM-4 | Medium | Retry exhaustion omits the failed holder row; the operator cannot tell which copy is dead | fake service HTTP 500 × 4 | Fixed | `test_a_transient_write_exhaustion_names_the_row_that_failed` |
| SM-2b | Medium | Reissue mints re-minted after RECORD and relied on the sweep | `_reissue_mint` / `_reissue_revoke`; `steps.handle`; `steps.predecessor`; parked value | Fixed | 3 tests in `tests/test_grafana_arcane.py` |
| SM-7 | Medium | Holder/vault/write/class edits were allowed during a stale unfinished run | `patch_credential`, `put_holders` took only the stack lease | Fixed | `test_a_plan_change_is_refused_while_an_unfinished_rotation_exists` |
| SM-8 | Medium | A surviving name can change issuer while keeping the old working copy | `_replace`/`_merge` preserve values by name; only `patch_credential` warned | Fixed as a warning | `test_import_warns_when_a_surviving_name_changes_issuer` |
| SM-1d | Low | A zombie could add holder rows to a closed attempt | `record_holder` wrote unconditionally | Fixed | `test_a_closed_attempt_rejects_holder_rows` |
| SM-10 | Medium | An unresumable unfinished run had no operator exit; the value guard wedged it | no abandon path in the journal, API or CLI | Fixed | 3 tests |
| SM-9 | Accepted | The lease fence is not atomic with the service write | `test_CHARACTERISATION_the_check_does_not_fence_the_write_it_guards` | Accepted limitation | characterization test |
| SM-2c | Accepted | qBittorrent response-before-park loses the only copy on a kill | code comment in `_mint_qbittorrent` | Accepted: no file fallback | — |

### Grouping of fixes

- **A. Journal and recovery (`SM-1`, `SM-1b`, `SM-1c`, `SM-1d`, `SM-2`,
  `SM-2b`)** — terminal rows are immutable; a closed attempt accepts no step or
  holder row; the completion report is fenced; a run that reached RECORD
  finishes instead of minting a second key, and a reissue mint carries the row
  handle that lets it finish without a third secret.
- **B. Recovery-baseline mutations (`SM-3`, `SM-7`, `SM-10`)** — the value, the
  service URL, holders, class, vault and mint mechanism are frozen while a run
  is unfinished; metadata that changes no step stays editable, and Abandon is
  the exit when no resume can run.
- **C. Holder reporting (`SM-4`)** — every attempted holder has an outcome,
  including the row whose retries ran out.
- **D. Scheduler liveness (`SM-5`)** — a blocked due retries on the configured
  cadence even with scheduled audits off.
- **E. Auth serialization (`SM-6`)** — sign-in and password change share one
  lock.
- **F. Topology identity (`SM-8`)** — an issuer change keeps the working copy
  but names both services in the import warning.

## Residual risks

1. **A secret returned once (SM-2c and the reissue create-to-park gap).** Some
   services answer a rotate/create with the only copy of the new value. If the
   process is killed after that response and before the value is parked, no
   recovery can recover it: the next run mints again and the service's sweep
   removes the lost row. The window is one HTTP response wide and cannot be
   closed without a service that returns the value again. This is a limitation
   of the measured contracts, not an unhandled state.
2. **Fencing (SM-9).** The lease check is not atomic with the service write.
   Closing it needs a fencing token accepted by every holder, which is a
   service-contract change; no measured holder exposes one. The final report is
   fenced, and every write is preceded by a check, so the exposure is one
   write after a lease loss.

Both are limits of the measured service contracts, not unhandled states: every
attempt this build writes records its handle and predecessor id before the
irreversible step, and every recovery path either resumes from them or fails
closed.
