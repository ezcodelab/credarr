"""The revoke step drivers, behind `Executor`.

The methods are move-only from the executor; `self` is the same object, so
the journal, the bound transport and the rotation context are the ones the
orchestrator created.
"""

from __future__ import annotations

import urllib.parse

from credarr.errors import RotationError
from credarr.rotate import Step
from credarr.writers import MINT_SOURCES, REISSUERS


class RevokeSteps:
    def _revoke_for(self, step: Step) -> str:
        """Dispatch the revoke step to the mechanism that planned it."""
        if step.target in REISSUERS:
            return self._reissue_revoke(step)
        mechanism = MINT_SOURCES[step.target].mechanism
        if mechanism == "create":
            return self._revoke_jellyfin(step)
        raise RotationError(
            f"{step.target}: no revoke implementation for mechanism {mechanism!r}",
            hint="the plan added a revoke step this build cannot run; nothing "
            "was changed by it",
        )

    def _revoke_jellyfin(self, step: Step) -> str:
        """Delete the key this rotation replaced.

        Reached only from the plan's final REVOKE step, and arriving here
        means every holder was confirmed - the mint created a key rather than
        replacing one, so the old one is still live and a rotation that never
        deletes it leaves a credential accumulating indefinitely.

        Authenticated by the key this run minted: it is the credential every
        holder now carries, the old key is only the target, and deleting the
        target does not touch its successor - so a rerun of this step is safe.

        It also sweeps what interrupted runs before it left behind. A run that
        died between its mint and its revoke leaves a key whose value the
        vault never recorded, so no value match can identify it; the sweep
        goes by name instead - `credarr-<credential>`, the namespace this
        build mints under. That is the one place this module trusts a name
        over a value, and it is deliberate: the alternative is dead keys
        accumulating forever. A key a human created under exactly that name is
        indistinguishable from a stray and is swept with it.

        It fails loudly, and deliberately. The rotation itself succeeded, but a
        credential this build replaced is still valid - which is the drift this
        tool exists to surface. Reporting success over a live stale key would
        be the exact failure this whole project refuses.
        """
        minted = self._ctx.minted
        if minted is None:
            raise RotationError(
                f"{step.target}: nothing was minted by this run, so the revoke "
                "has no key to authenticate with",
                hint="the revoke follows the mint by construction; re-run "
                "the rotation to resume from where it stopped",
            )
        # `minted` is a Secret; the transport takes the plain value, as every
        # other call site does.
        minting = minted.reveal()
        # The vault value is captured once, when the context was built, and the
        # vault is only written at the RECORD step - so this is still the key
        # that was replaced even though the vault has since moved on.
        target = self._ctx.vault_value
        if target is None:
            raise RotationError(
                f"{step.target}: the vault holds no value for this credential, "
                "so the key that was replaced cannot be identified",
                hint="the rotation is complete and every holder is confirmed; "
                "the previous key is still valid and must be revoked by hand "
                "from Jellyfin's dashboard",
            )
        status, body = self._call(
            self._ctx.host, step.target, "GET", "/Auth/Keys",
            key=minting,
            auth_transport=MINT_SOURCES[step.target].auth_transport,
            transport=self._ctx.transport,
        )
        items = body.get("Items") if isinstance(body, dict) else None
        if status != 200 or not isinstance(items, list):
            # Shape as well as status: a 200 whose body is not a listing is
            # not evidence that there is no old key to revoke.
            raise RotationError(
                f"{step.target}: could not list keys to find the old one "
                f"(HTTP {status})",
                hint="the rotation is complete and every holder is confirmed; "
                "the previous key is still valid and can be revoked from "
                "Jellyfin's dashboard",
            )
        app = self._jellyfin_app_name()
        doomed = [item for item in items if isinstance(item, dict)
                  and item.get("AccessToken") == target]
        # Strays: keys a dead run minted under credarr's own name, whose
        # values the vault never recorded. The minted key carries the same
        # name and is excluded by value - a sweep that took it would break
        # every holder the run just confirmed. A row without a token cannot
        # authenticate, so it is skipped, exactly as the value match skips it.
        strays = [item for item in items if isinstance(item, dict)
                  and item.get("AppName") == app
                  and item.get("AccessToken")
                  and item.get("AccessToken") not in (target, minting)]
        if not doomed and not strays:
            # Not an error: it was revoked already, or the vault held a value
            # this Jellyfin never knew. Nothing to do either way.
            return f"{step.target}: no previous key left to revoke"
        leftovers = []
        for item in (*doomed, *strays):
            # Every match, not the first. Real tokens are unique, so a second
            # match means the key list is corrupted - and stopping at the
            # first would leave a live key behind either way.
            status, _ = self._call(
                self._ctx.host, step.target, "DELETE",
                f"/Auth/Keys/{urllib.parse.quote(item['AccessToken'])}",
                key=minting,
                auth_transport=MINT_SOURCES[step.target].auth_transport,
                transport=self._ctx.transport,
            )
            if status != 204:
                leftovers.append(item.get("AppName", "unnamed"))
        if leftovers:
            raise RotationError(
                f"{step.target}: {len(leftovers)} key(s) could not be "
                f"revoked ({', '.join(leftovers)})",
                hint="the rotation itself succeeded - every holder is "
                "confirmed and the vault holds the new value. What is wrong is "
                "that a key this run was to delete is still live, which is "
                "drift this tool is built to surface rather than swallow. "
                "Revoke it from Jellyfin's dashboard.",
            )
        # The DELETE returns a status code; the listing is the fact. A 204 that
        # did not remove the row would otherwise be reported as a clean revoke
        # over a key that still authenticates - the stale credential this step
        # exists to prove gone.
        status, body = self._call(
            self._ctx.host, step.target, "GET", "/Auth/Keys",
            key=minting,
            auth_transport=MINT_SOURCES[step.target].auth_transport,
            transport=self._ctx.transport,
        )
        remaining = body.get("Items") if isinstance(body, dict) else None
        if status != 200 or not isinstance(remaining, list):
            raise RotationError(
                f"{step.target}: could not list keys to confirm the revoke "
                f"(HTTP {status})",
                hint="the DELETE was accepted, but whether it removed the old "
                "key is now unknown. The rotation itself succeeded - every "
                "holder is confirmed and the vault holds the new value - so "
                "check Jellyfin's key list and delete any stale key by hand.",
            )
        if any(isinstance(item, dict) and item.get("AccessToken") == target
               for item in remaining):
            raise RotationError(
                f"{step.target}: the previous key survived its deletion; it is "
                "still live",
                hint="the rotation itself succeeded - every holder is confirmed "
                "and the vault holds the new value - but the old key still "
                "authenticates. Delete it from Jellyfin's dashboard.",
            )
        if any(isinstance(item, dict) and item.get("AccessToken")
               and item.get("AppName") == app
               and item.get("AccessToken") != minting for item in remaining):
            raise RotationError(
                f"{step.target}: a key left by an interrupted run survived its "
                "deletion; it is still live",
                hint="the rotation itself succeeded - every holder is confirmed "
                "and the vault holds the new value - but a key credarr minted "
                "in an earlier run still authenticates. Delete it from "
                "Jellyfin's dashboard.",
            )
        done = []
        if doomed:
            done.append(f"revoked {len(doomed)} previous key(s)")
        if strays:
            done.append(f"swept {len(strays)} stray key(s) left by "
                        "interrupted runs")
        return f"{step.target}: " + " and ".join(done)
