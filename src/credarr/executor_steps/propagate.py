"""The propagate step drivers, behind `Executor`.

The methods are move-only from the executor; `self` is the same object, so
the journal, the bound transport and the rotation context are the ones the
orchestrator created.
"""

from __future__ import annotations

import copy
import time

from credarr.errors import ConfigError, RotationError, TransportError
from credarr.model import split_target
from credarr.redact import scrub
from credarr.rotate import Step
from credarr.writers import Holder, holder_for, known_systems, seerr_row

from .support import (
    MAX_WRITE_INTERVAL,
    SEERR_READBACK_INTERVAL,
    SEERR_READBACK_TIMEOUT,
    WRITE_ATTEMPTS,
    _explain,
    classify_refusal,
    log_line,
)
from .types import HolderOutcome


class PropagateSteps:
    def _propagate(self, step: Step) -> str:
        """Write the new key to every declared copy, then exercise the holder.

        "Every declared copy" is not every row the API lists. A qualified target
        names one row inside its slot, and Seerr and Prowlarr each hold both the
        Sonarr and the Radarr key - so a write that ignored the qualifier would
        hand Sonarr's new credential to Radarr's copy, replacing a working one
        with a revoked key. See `_select_rows`.
        """
        system, slot = split_target(step.target)
        described = holder_for(system, slot)
        if described is None:
            raise RotationError(
                f"{step.target}: no writer known for that slot",
                hint=f"known: {', '.join(sorted(known_systems()))}",
            )
        if described.write == "bazarr_api":
            return self._propagate_bazarr(step, described)
        if described.write == "seerr_api":
            return self._propagate_seerr(step, described)
        if described.write == "qui_api":
            return self._propagate_qui(step, described)
        api_path = described.api_path
        if self._ctx.minted is None:
            raise RotationError(
                f"nothing to propagate for {step.target}: no key was minted",
                hint="this means the mint step did not run; refusing to write a "
                "stale value over a working one",
            )

        status, rows = self._call(
            self._ctx.host, system, "GET", f"/{api_path}",
            key=self._service_key(system),
            transport=self._ctx.transport,
        )
        if status != 200 or not isinstance(rows, list):
            raise RotationError(
                f"could not list {step.target} (HTTP {status})",
                hint="authenticating with the *new* key; if this fails with 401 "
                "the service did not actually rotate",
            )
        try:
            rows = self._select_rows(step.target, rows)
        except RotationError as exc:
            # The step failed before naming any row; "all" is the honest label
            # for a slot that could not be addressed at all.
            self._ctx.holders.append(
                HolderOutcome(step.target, "all", "failed", str(exc))
            )
            raise

        target_field = self._resolve_field(step)
        written = 0
        interval = self._ctx.write_interval
        # Row label -> (verdict, detail) from the holder's own test. Kept for
        # the promotion pass, which decides whether the write is confirmed.
        exercises: dict[str, tuple[str, str]] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            label = str(row.get("id"))
            # The list endpoint redacts apiKey as "********", exactly as it
            # redacts on a single GET of some other resources. Building the PUT
            # from the list therefore writes the redaction back, which is
            # rejected with 400 - and the id-only list is all that is needed to
            # find the resources to fetch properly.
            status, resource = self._call(
                self._ctx.host, system, "GET", f"/{api_path}/{row.get('id')}",
                key=self._service_key(system),
                transport=self._ctx.transport,
            )
            if status != 200 or not isinstance(resource, dict):
                self._ctx.holders.append(
                    HolderOutcome(step.target, label, "failed",
                                  f"could not read the resource (HTTP {status})")
                )
                raise RotationError(
                    f"{step.target} id={row.get('id')}: could not read the "
                    f"resource (HTTP {status})"
                )

            if not self._ctx.holders and interval > 0:
                log_line(f"      pacing {interval:g}s between holder writes")
            if self._ctx.holders and interval > 0:
                time.sleep(interval)
            attempt = 1
            while attempt <= WRITE_ATTEMPTS:
                # Deep, not shallow: `fields` is a list of dicts, so a shallow
                # copy would mutate the fetched `resource` below and the
                # exercise would send the new key instead of the stored value.
                payload = copy.deepcopy(resource)
                payload["id"] = resource.get("id")
                wrote_target = False
                for field_ in payload.get("fields") or []:
                    if field_.get("name") == target_field:
                        field_["value"] = self._ctx.minted.reveal()
                        wrote_target = True
                if not wrote_target:
                    # A 202 for a PUT that changes nothing is the same silent
                    # success as writing the mask back: the row keeps the old
                    # (revoked) key and the promotion pass can only report it
                    # after the fact. Refuse before the request, naming the drift.
                    detail = (
                        f"the resource has no {target_field!r} field"
                    )
                    self._ctx.holders.append(
                        HolderOutcome(step.target, label, "failed", detail)
                    )
                    raise RotationError(
                        f"{step.target} id={row.get('id')}: {detail}",
                        hint="the service's row shape changed, or the field name "
                        "is wrong; refusing a PUT that would change nothing",
                    )
                # The fence, per row rather than per step. A propagation step writes
                # sixteen rows; checking only at the step boundary would let a
                # process that lost the lease keep writing for the rest of it.
                if self._ctx.lease_check is not None:
                    self._ctx.lease_check()

                status, refusal = self._call(
                    self._ctx.host, system, "PUT", f"/{api_path}/{row.get('id')}",
                    body=payload, key=self._service_key(system),
                    transport=self._ctx.transport,
                )
                if status not in (200, 201, 202):
                    verdict, reason = classify_refusal(status, refusal)
                    # Scrubbed before it is logged, journaled or reported. The
                    # refusal text comes from the service, and a validation error
                    # that echoes the submitted resource is carrying the very
                    # credential being rotated.
                    reason = scrub(reason, self._ctx.minted, self._ctx.vault_value)
                    if verdict in ("transient", "unknown"):
                        # Upstream is rate-limiting or timing out. Widen the
                        # gap for every row after this one rather than retry
                        # this row four times against a limiter that has
                        # already said no.
                        interval = min(interval * 2 or MAX_WRITE_INTERVAL,
                                       MAX_WRITE_INTERVAL)
                        log_line(
                            f"      upstream refused: widening the gap between "
                            f"writes to {interval:g}s"
                        )
                        if attempt < WRITE_ATTEMPTS:
                            delay = self._ctx.write_backoff * (2 ** (attempt - 1))
                            log_line(
                                f"      {step.target}[{label}] {verdict}: "
                                f"{reason[:80]} - retry {attempt + 1} in {delay}s"
                            )
                            time.sleep(delay)
                            attempt += 1
                            continue
                        self._ctx.holders.append(
                            HolderOutcome(step.target, label, "failed", reason)
                        )
                        raise RotationError(
                            f"{step.target} id={row.get('id')} still failing after "
                            f"{WRITE_ATTEMPTS} attempts: {reason}",
                            hint="the upstream indexer service is the bottleneck, "
                            "not this tool. Nothing was written to the remaining "
                            "holders; re-run to converge from here.",
                        )
                if status not in (200, 201, 202):
                    # The RESPONSE is what explains a refusal. Explaining the
                    # request payload tells you nothing - it has no title or errors
                    # to read - which is why the first version of this fix changed
                    # the capture and left the output exactly as before.
                    # Same scrubbing as the retry path above: this detail is
                    # recorded per holder in the journal, so it outlives the run.
                    detail = scrub(
                        _explain(refusal) or f"API returned {status}",
                        self._ctx.minted, self._ctx.vault_value,
                    )
                    self._ctx.holders.append(
                        HolderOutcome(step.target, label, "failed", detail)
                    )
                    raise RotationError(
                        f"{step.target} id={row.get('id')} refused the write: {detail}",
                        hint="the service's own validation message is above; a 400 "
                        "here is usually a malformed request rather than a "
                        "refused credential",
                    )
                break
            # Ask the app that owns the row to use its stored value. The payload
            # is the pre-write GET, mask intact, so the test reads the value the
            # process stored - not the one this run just supplied. One call per
            # written row; a failed test leaves the row unproven.
            exercises[label] = self._exercise(described, system, resource)
            written += 1
            # "written" deliberately means only that the API accepted. It is not
            # evidence the value was stored, and reporting it as "updated" would
            # claim a certainty nobody has.
            self._ctx.holders.append(HolderOutcome(step.target, label, "written"))

        # Promote each written row only when the holder's own test accepted the
        # stored value and the old issuer key is confirmed dead. There is no
        # local read-equal; anything weaker stays "written" and says so.
        promoted: list[HolderOutcome] = []
        for holder in self._ctx.holders:
            if holder.target != step.target or holder.outcome != "written":
                promoted.append(holder)
                continue
            verdict, exercise_detail = exercises.get(
                holder.label, ("unsupported", "")
            )
            # Only the protocol's three facts can make the test's acceptance
            # mean equality: the new key authenticates (done at mint), the old
            # key is dead, and the holder accepts the stored value.
            if verdict == "accepted" and self._ctx.old_key_dead is True:
                promoted.append(HolderOutcome(
                    step.target, holder.label, "confirmed", exercise_detail,
                    "exercised",
                ))
            elif verdict == "accepted":
                promoted.append(HolderOutcome(
                    step.target, holder.label, "written",
                    "the holder's own test accepts the stored value, but the "
                    "issuer's old key is still live or its revocation could "
                    "not be confirmed; equality is not proven",
                ))
            elif verdict == "rejected":
                promoted.append(HolderOutcome(
                    step.target, holder.label, "written",
                    "the API accepted the write, but the holder's own test "
                    "rejects the stored value; a stale process or a 401 access "
                    f"layer looks the same ({exercise_detail})",
                ))
            else:
                reason = (
                    "no exercise endpoint is measured for this holder"
                    if verdict == "unsupported"
                    else f"the holder's own test was inconclusive ({exercise_detail})"
                )
                promoted.append(HolderOutcome(
                    step.target, holder.label, "written",
                    f"the API accepted the write; the holder's API exposes no "
                    f"readable copy and {reason}; the value is not proven",
                ))
        self._ctx.holders = promoted
        self._journal_holders()

        if not written:
            return "0 row(s) written; there was nothing to verify"
        confirmed = sum(
            1 for h in self._ctx.holders
            if h.target == step.target and h.outcome == "confirmed"
        )
        if confirmed == written:
            return f"{written} row(s) written, verified by exercise"
        return (
            f"{written} row(s) written, not proven: the holder's API exposes "
            f"no equality readback and {written - confirmed} row(s) lack an "
            "exercise confirmation"
        )

    def _propagate_bazarr(self, step: Step, holder: Holder) -> str:
        """Write a Sonarr/Radarr key into Bazarr's settings and read it back.

        Bazarr's settings endpoint is a form POST, and its GET returns the
        value the running process holds under `sonarr.apikey` / `radarr.apikey`,
        so the confirmation is a process read-equal rather than a file read or
        a guessed test route. Measured on 1.6.2.
        """
        if self._ctx.minted is None:
            raise RotationError(
                f"nothing to propagate for {step.target}: no key was minted",
                hint="this means the mint step did not run; refusing to write a "
                "stale value over a working one",
            )
        row = self._row_name(step.target)
        if row is None:
            raise RotationError(
                f"{step.target}: does not name which Bazarr settings section "
                "to write. Bazarr holds both Sonarr and Radarr keys, so the "
                "target needs a row qualifier"
            )
        minted = self._ctx.minted.reveal()
        try:
            try:
                api_key = self._service_key(holder.system)
            except (ConfigError, TransportError) as exc:
                raise RotationError(
                    f"cannot read {holder.system}'s own API key ({exc})",
                    hint="store Bazarr's own key before rotating a credential "
                    "it holds",
                ) from exc
            if not api_key:
                raise RotationError(
                    f"no API key for {holder.system!r}; nothing could "
                    "authenticate the settings write",
                    hint="store Bazarr's own key before rotating a credential "
                    "it holds",
                )

            status, before = self._call(
                self._ctx.host, holder.system, "GET", holder.readback_path,
                key=api_key, auth_header=holder.auth_header_name,
                auth_transport=holder.auth_transport,
                transport=self._ctx.transport,
            )
            if status != 200 or not isinstance(before, dict):
                raise RotationError(
                    f"could not read Bazarr's {row} settings (HTTP {status})",
                    hint="the old key is already revoked; restore access and "
                    "re-run to finish",
                )
            section = before.get(row)
            if not isinstance(section, dict):
                raise RotationError(
                    f"Bazarr has no {row} settings entry, so there is nothing "
                    "to update",
                    hint="the old key is already revoked; restore the settings, "
                    "then re-run to finish",
                )

            field = holder.field.format(service=row)
            # Bazarr's dynaconf coerces an all-numeric form value to int and
            # answers 406. A real 32-hex key is all digits about 3e-7 of the
            # time; that write fails loudly rather than reporting confirmed.
            status, _ = self._call(
                self._ctx.host, holder.system, "POST", holder.api_path,
                body={field: minted}, key=api_key,
                auth_header=holder.auth_header_name,
                auth_transport=holder.auth_transport,
                transport=self._ctx.transport,
                content_type="application/x-www-form-urlencoded",
            )
            if status not in (200, 204):
                raise RotationError(
                    f"Bazarr refused the {row} settings write (HTTP {status})",
                    hint="the mint already ran and the old key is revoked. "
                    "Re-run once the settings API accepts the write.",
                )
            status, after = self._call(
                self._ctx.host, holder.system, "GET", holder.readback_path,
                key=api_key, auth_header=holder.auth_header_name,
                auth_transport=holder.auth_transport,
                transport=self._ctx.transport,
            )
            if status != 200 or not isinstance(after, dict):
                raise RotationError(
                    f"Bazarr would not read its {row} settings back "
                    f"(HTTP {status})",
                    hint="the old key is already revoked; restore access and "
                    "re-run to finish",
                )
            observed = (after.get(row) or {}).get(holder.readback_field)
            if observed != minted:
                raise RotationError(
                    f"Bazarr's running process does not report the new {row} "
                    "key",
                    hint="the write was accepted but the process value differs; "
                    "re-run once the settings API settles",
                )
        except RotationError as exc:
            self._ctx.holders.append(
                HolderOutcome(step.target, row, "failed", str(exc))
            )
            raise
        self._ctx.holders.append(
            HolderOutcome(step.target, row, "confirmed", "", "read-equal")
        )
        return (
            f"written to bazarr.settings[{row}] over the API and confirmed "
            "against the running Bazarr"
        )

    def _propagate_seerr(self, step: Step, holder: Holder) -> str:
        """Write a Seerr-held key over its settings API and read it back.

        Arr rows use PUT /settings/{service}/{id}; Jellyfin is a single object
        and uses POST /settings/jellyfin. Both update the running process
        directly, so no restart or file write is involved. Seerr's own API key
        authenticates the call and is read from the runtime store, never from a
        settings file.
        """
        if self._ctx.minted is None:
            raise RotationError(
                f"nothing to propagate for {step.target}: no key was minted",
                hint="this means the mint step did not run; refusing to write a "
                "stale value over a working one",
            )
        row = self._row_name(step.target)
        if row is None:
            raise RotationError(
                f"{step.target}: does not name which holder to write. Seerr "
                "holds several services' credentials, so the target needs a row "
                "qualifier"
            )
        minted = self._ctx.minted.reveal()
        # The target already names the row; repeating it in the label prints
        # `[qBittorrent][qBittorrent]` in the report.
        label = ""
        try:
            try:
                api_key = self._service_key(holder.system)
            except (ConfigError, TransportError) as exc:
                raise RotationError(
                    f"cannot read {holder.system}'s own API key ({exc})",
                    hint="store Seerr's own key before rotating a credential "
                    "it holds",
                ) from exc
            if not api_key:
                raise RotationError(
                    f"no API key for {holder.system!r}; nothing could "
                    "authenticate the settings write",
                    hint="store Seerr's own key before rotating a credential "
                    "it holds",
                )

            instance, label = self._seerr_instance(holder, row, api_key)
            spec = seerr_row(row)
            # Server-owned fields are read-only in Seerr's schema; sending one
            # back is a validation error. The row table names them per shape.
            update = {
                k: v for k, v in instance.items() if k not in spec.drop_fields
            }
            update["apiKey"] = minted
            instance_id = instance.get("id")
            if spec.write_method == "PUT":
                if instance_id is None:
                    raise RotationError(
                        f"the {row} instance has no id, so the write cannot "
                        "be addressed",
                        hint="the settings section changed shape; nothing was "
                        "written to it",
                    )
                for key, value in spec.write_defaults:
                    update.setdefault(key, value)
            status, _ = self._call(
                self._ctx.host, holder.system, spec.write_method,
                spec.write_path.format(service=row, id=instance_id),
                body=update, key=api_key,
                auth_header=holder.auth_header_name,
                auth_transport=holder.auth_transport,
                transport=self._ctx.transport,
            )
            if status != 200:
                raise RotationError(
                    f"Seerr refused the {row} settings write (HTTP {status})",
                    hint="the mint already ran and the old key is revoked. "
                    "Re-run once the settings API accepts the write.",
                )
            self._await_seerr_key(holder, row, api_key, minted)
        except RotationError as exc:
            # A refusal must reach the report as this holder's failure, not as
            # an unattempted step.
            self._ctx.holders.append(
                HolderOutcome(step.target, label, "failed", str(exc))
            )
            raise
        self._ctx.holders.append(
            HolderOutcome(step.target, label, "confirmed", "", "read-equal")
        )
        return (
            f"written to {holder.system}.{holder.slot}[{row}] over the API "
            f"and confirmed against the running {holder.system}"
        )

    def _seerr_instance(
        self, holder: Holder, row: str, api_key: str
    ) -> tuple[dict, str]:
        """The one settings object this target names, and its display label."""
        status, body = self._call(
            self._ctx.host, holder.system, "GET",
            holder.readback_path.format(service=row), key=api_key,
            auth_header=holder.auth_header_name,
            auth_transport=holder.auth_transport,
            transport=self._ctx.transport,
        )
        if status != 200:
            raise RotationError(
                f"could not read Seerr's {row} settings (HTTP {status})",
                hint="the old key is already revoked; restore access and "
                "re-run to finish",
            )
        if seerr_row(row).readback_shape == "object":
            if not isinstance(body, dict) or not body:
                raise RotationError(
                    "Seerr has no Jellyfin settings object, so there is "
                    "nothing to update",
                    hint="the old key is already revoked; restore the Jellyfin "
                    "settings, then re-run to finish",
                )
            return body, str(body.get("name") or "Jellyfin")
        if not isinstance(body, list):
            raise RotationError(
                f"Seerr returned an unexpected settings shape for {row!r}",
                hint="the old key is already revoked; nothing was written",
            )
        if not body:
            raise RotationError(
                f"the settings section holds no {row} instances, so there is "
                "nothing to update",
                hint="the old key is already revoked; restore the instance, "
                "then re-run to finish",
            )
        if len(body) > 1:
            raise RotationError(
                f"the settings section holds {len(body)} {row} instances and "
                "this build can update exactly one",
                hint="which instance holds this credential is not in the "
                "manifest, so nothing was written",
            )
        instance = body[0]
        if not isinstance(instance, dict):
            raise RotationError(
                f"the {row} settings row is not an object",
                hint="the old key is already revoked; nothing was written",
            )
        return instance, str(instance.get("name", row))

    def _await_seerr_key(
        self, holder: Holder, row: str, api_key: str, minted: str
    ) -> None:
        """Wait for the running process to report the value just written."""
        deadline = time.time() + SEERR_READBACK_TIMEOUT
        last = "no read-back completed"
        while True:
            try:
                status, body = self._call(
                    self._ctx.host, holder.system, "GET",
                    holder.readback_path.format(service=row), key=api_key,
                    auth_header=holder.auth_header_name,
                    auth_transport=holder.auth_transport,
                    transport=self._ctx.transport,
                )
            except TransportError as exc:
                last = f"{type(exc).__name__}: {exc}"
            else:
                if status == 200 and self._seerr_holds(body, row, minted):
                    return
                last = f"HTTP {status}"
            if time.time() >= deadline:
                break
            time.sleep(SEERR_READBACK_INTERVAL)
        raise RotationError(
            f"the settings API accepted the write, but the running process "
            f"did not report the new {row} key within "
            f"{SEERR_READBACK_TIMEOUT}s ({last})",
            hint="the old key is already revoked. Re-run once Seerr is "
            "responsive; this run has not recorded the new value.",
        )

    @staticmethod
    def _seerr_holds(body: object, row: str, minted: str) -> bool:
        if seerr_row(row).readback_shape == "object":
            return isinstance(body, dict) and body.get("apiKey") == minted
        return (
            isinstance(body, list)
            and bool(body)
            and all(
                isinstance(item, dict) and item.get("apiKey") == minted
                for item in body
            )
        )

    def _propagate_qui(self, step: Step, holder: Holder) -> str:
        """Write a qBittorrent API key into one qui instance and test it.

        qui stores instance credentials encrypted, so there is no plaintext
        read-back. The proof is qui's own `POST /instances/{id}/test`: qui
        decrypts the stored value and asks qBittorrent to accept it, which is
        stronger than a disk read because it exercises the running process.
        """
        if self._ctx.minted is None:
            raise RotationError(
                f"nothing to propagate for {step.target}: no key was minted",
                hint="this means the mint step did not run; refusing to write "
                "a stale value over a working one",
            )
        row = self._row_name(step.target)
        if row is None:
            raise RotationError(
                f"{step.target}: does not name which qui instance to write",
                hint="qui can hold several instances, so the target needs a "
                "row qualifier",
            )
        minted = self._ctx.minted.reveal()
        # The target already names the row; repeating it in the label prints
        # `[qBittorrent][qBittorrent]` in the report.
        label = ""
        try:
            try:
                api_key = self._service_key(holder.system)
            except (ConfigError, TransportError) as exc:
                raise RotationError(
                    f"cannot read {holder.system}'s own API key ({exc})",
                    hint="store qui's own key before rotating a credential it "
                    "holds",
                ) from exc
            if not api_key:
                raise RotationError(
                    f"no API key for {holder.system!r}; nothing could "
                    "authenticate the instance write",
                    hint="store qui's own key before rotating a credential it "
                    "holds",
                )

            status, rows = self._call(
                self._ctx.host, holder.system, "GET", holder.api_path,
                key=api_key, auth_header=holder.auth_header_name,
                auth_transport=holder.auth_transport,
                transport=self._ctx.transport,
            )
            if status != 200 or not isinstance(rows, list):
                raise RotationError(
                    f"could not list qui instances (HTTP {status})",
                    hint="the old qBittorrent key is already revoked; restore "
                    "qui access and re-run to finish",
                )
            matches = [
                item for item in rows
                if isinstance(item, dict) and item.get("name") == row
            ]
            if not matches:
                raise RotationError(
                    f"qui has no instance named {row!r}, so there is nothing "
                    "to update",
                    hint="the old key is already revoked; restore the instance, "
                    "then re-run to finish",
                )
            if len(matches) > 1:
                raise RotationError(
                    f"qui has {len(matches)} instances named {row!r}",
                    hint="which one holds this credential is ambiguous, so "
                    "nothing was written",
                )
            instance = matches[0]
            instance_id = instance.get("id")
            if instance_id is None:
                raise RotationError(
                    f"the qui instance {row!r} has no id, so the write cannot "
                    "be addressed",
                    hint="the instance shape changed; nothing was written",
                )
            host = instance.get("host")
            if not isinstance(host, str) or not host:
                raise RotationError(
                    f"the qui instance {row!r} has no host, so the write cannot "
                    "be addressed",
                    hint="the instance shape changed; nothing was written",
                )
            update = {
                "name": instance.get("name") or row,
                "host": host,
                "username": instance.get("username") or "",
                "apiKey": minted,
            }
            status, _ = self._call(
                self._ctx.host, holder.system, "PUT",
                f"{holder.api_path}/{instance_id}", body=update, key=api_key,
                auth_header=holder.auth_header_name,
                auth_transport=holder.auth_transport,
                transport=self._ctx.transport,
            )
            if status != 200:
                raise RotationError(
                    f"qui refused the {row} instance write (HTTP {status})",
                    hint="the mint already ran and the old key is revoked. "
                    "Re-run once qui accepts the write.",
                )
            self._await_qui_test(holder, instance_id, api_key)
        except RotationError as exc:
            self._ctx.holders.append(
                HolderOutcome(step.target, label, "failed", str(exc))
            )
            raise
        self._ctx.holders.append(
            HolderOutcome(step.target, label, "confirmed", "", "exercised")
        )
        return (
            f"written to {holder.system}.{holder.slot}[{row}] over the API "
            f"and confirmed by {holder.system}'s own connection test"
        )

    def _await_qui_test(
        self, holder: Holder, instance_id: object, api_key: str
    ) -> None:
        """Wait for qui to connect with the stored value."""
        deadline = time.time() + SEERR_READBACK_TIMEOUT
        last = "no connection test completed"
        while True:
            try:
                status, body = self._call(
                    self._ctx.host, holder.system, "POST",
                    holder.readback_path.format(id=instance_id), key=api_key,
                    auth_header=holder.auth_header_name,
                    auth_transport=holder.auth_transport,
                    transport=self._ctx.transport,
                )
            except TransportError as exc:
                last = f"{type(exc).__name__}: {exc}"
            else:
                if (
                    status == 200
                    and isinstance(body, dict)
                    and body.get("connected") is True
                ):
                    return
                if isinstance(body, dict) and body.get("error"):
                    last = scrub(str(body["error"]),
                                 self._ctx.minted, self._ctx.vault_value)
                else:
                    last = f"HTTP {status}"
            if time.time() >= deadline:
                break
            time.sleep(SEERR_READBACK_INTERVAL)
        raise RotationError(
            f"qui accepted the instance write, but its connection test did not "
            f"confirm the new key within {SEERR_READBACK_TIMEOUT}s ({last})",
            hint="the old key is already revoked. Re-run once qui and "
            "qBittorrent are responsive; this run has not recorded the new "
            "value.",
        )
