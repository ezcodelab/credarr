<script>
  import { tick } from "svelte";
  import { api, ApiError, auditStack, elapsed, errorText } from "./api.js";
  import Banner from "./Banner.svelte";
  import {
    dryRunSentence,
    failureLines,
    isLoginBlock,
    manualTargets,
  } from "./apps.js";
  import { copyLabel, bannerLine, credentialTitle, friendlyReason, refusalLines, splitLoginWall } from "./names.js";
  import {
    clearManualTracker,
    pruneManualTracker,
    trackManual,
  } from "./manualTracker.js";
  import { serviceById } from "./setupCatalog.js";

  // The rotation result surface on the app page. It owns no buttons: the
  // header holds Plan / Check / Rotate / Replace key, and calls in through the
  // registration below. A plan is read-only; a run changes live services; an
  // unfinished step of this app turns the run into the resume path. The armed
  // confirm state lives here so a row switch disarms it, and the header reads
  // it through the same binding.
  let {
    row,
    pending = [],
    armed = $bindable(false),
    planBusy = $bindable(false),
    runBusy = $bindable(false),
    onrefresh,
    onsignout,
    ondone = null,
    onready = null,
    onplan = null,
  } = $props();

  let plan = $state(null);
  let run = $state(null);
  let rotationError = $state("");
  let auditError = $state("");
  let section = $state(null);
  // The key the operator rotated in the service's own UI, for a manual mint.
  // It lives only here, never in storage or a toast, and is cleared on every
  // submit; the engine parks it and never returns it.
  let manualKey = $state("");
  let manualOpen = $state(false);
  let manualInput = $state(null);
  let manualFollowUp = $state(null);
  let manualConfirmed = $state(false);
  let manualShape = "";
  // The post-run audit is a second stack-wide read. It still runs, but it no
  // longer holds the rotate button after the run's own answer is in hand.
  let auditBusy = $state(false);
  const pendingHere = $derived(
    pending.filter((step) => step.credential === row?.name),
  );
  // The reset key is the name, not the row object: a refresh after a run
  // rebuilds the row, and resetting on that would erase the run the operator
  // just asked for.
  const rowName = $derived(row?.name ?? "");
  // A rotate response that did not run carries the plan's own fields, so one
  // renderer covers "here is the plan" and "this is why it refused".
  const answer = $derived(run ?? plan);
  const planPayload = $derived(answer && !answer.run ? answer : null);
  const runResult = $derived(answer?.run ?? null);
  // `clean` alone is not finished: a run can verify every holder and still
  // leave steps only a human can take. Those keep the panel open and say so.
  const finished = $derived(
    !!runResult && runResult.clean && (runResult.manual?.length ?? 0) === 0,
  );
  const manualPlanLabels = $derived([
    ...new Set(
      (planPayload?.steps ?? [])
        .filter((step) => step?.kind === "manual")
        .map((step) => copyLabel(step.target)),
    ),
  ]);

  // The plan, in operator words: a dry run over every declared copy. Slugs
  // stay out; the engine's own refusal and preflight sentences stay in.
  function serviceOfTarget(target) {
    const head = String(target ?? "").split("[", 1)[0].split("(", 1)[0];
    const [service] = head.split(".");
    return serviceById(service)?.label ?? service;
  }

  // The credential's own service, for naming the login that blocks the
  // backup. Same derivation the credential view uses.
  const ownerService = $derived(
    serviceById(row?.canonical?.service ?? String(row?.name ?? "").replace(/_api_key$/, ""))?.label ??
      credentialTitle(row?.name ?? ""),
  );

  // The credential's own names, for banner lines that repeat the page: a
  // leading service prefix is stripped only when it names one of these.
  const ownerId = $derived(
    row?.canonical?.service ?? String(row?.name ?? "").replace(/_api_key$/, ""),
  );
  const ownNames = $derived([ownerId, ownerService, row?.name ?? ""]);

  // Plan-failure lines: one refusal fact per line, with the redundant class
  // and never_rotate reasons collapsed. Empty lines never render.
  const blockedLines = $derived(
    refusalLines(planPayload?.blocked_by ?? [], ownNames),
  );
  const problemLines = $derived(
    wallSplit.rest
      .map((problem) => bannerLine(friendlyReason(problem), ownNames))
      .filter(Boolean),
  );

  // A UI-login preflight failure gets one plain pointer before the engine's
  // sentences: the section below lists the ways forward, this banner does
  // not repeat them. The wall itself is not listed: it names every option
  // at once, and the pointer plus Connection cover all of them.
  const loginBlocked = $derived(
    isLoginBlock([...(planPayload?.blocked_by ?? []), ...(planPayload?.problems ?? [])]),
  );
  const wallSplit = $derived(splitLoginWall(planPayload?.problems ?? []));

  // A finished run says where the key went, once, in one sentence — the same
  // banner pattern as a failure, not a pill per holder.
  const rotatedServices = $derived([
    ...new Set([
      ownerService,
      ...(runResult?.holders ?? [])
        .filter((holder) =>
          ["confirmed", "already-current"].includes(holder.outcome),
        )
        .map((holder) => serviceOfTarget(holder.target))
        .filter(Boolean),
    ]),
  ]);
  const rotatedSentence = $derived(
    `The new key is in use in ${rotatedServices.join(", ")}.`,
  );

  // Whether this run needs the operator's key: the plan says so, or a rotate
  // already answered that it does. The key travels only as `manual_value` in
  // the rotate body, never in a URL, storage, toast or log.
  const manualMode = $derived(planPayload?.manual_mint === true || manualOpen);

  // What the dry run checked, in the banner's own words. A refused plan or
  // an empty answer gets no sentence; those branches carry their own banner.
  const planSentence = $derived(dryRunSentence(planPayload));

  $effect(() => {
    // A different credential is a different rotation: a plan read for the last
    // one must never be shown, or run, against this one.
    void rowName;
    plan = null;
    run = null;
    armed = false;
    rotationError = "";
    manualKey = "";
    manualOpen = false;
    manualConfirmed = false;
    manualFollowUp = null;
    manualShape = "";
  });

  $effect(() => {
    // The reminder belongs to the declared manual copies, not to the
    // credential name forever. Reconcile it on load and whenever a holder is
    // added or removed so a stale Homepage reminder cannot survive next to a
    // fully measured Seerr holder. `row` is read here at the current shape;
    // the shape guard keeps a refresh of the same holders from resetting the
    // reminder the operator is working through.
    if (!row || !rowName) return;
    const targets = manualTargets(row);
    const shape = `${rowName}\u0000${[...targets].sort().join("\u0000")}`;
    if (shape === manualShape) return;
    manualShape = shape;
    manualFollowUp = pruneManualTracker(rowName, targets);
  });

  // The header owns the buttons, so the triggers are handed up at setup
  // rather than reached for through the component instance. The latest
  // answer also goes up, so the credential view can hang engine refusals
  // under the field that can fix them.
  onready?.({ startPlan: planRotation, doRotate: rotate, openManualKey });

  // The manual key field, opened without firing: the saved manual opt-in
  // means the key comes from the operator, so the first press asks for it
  // instead of arming. Its own submit is the explicit confirmation.
  async function openManualKey() {
    if (!row) return;
    manualOpen = true;
    rotationError = "";
    await tick();
    manualInput?.focus({ preventScroll: true });
  }

  $effect(() => {
    onplan?.(answer);
  });

  $effect(() => {
    // Unsetting the manual opt-in closes the key field: there is no key to
    // ask for anymore. The field only ever opens on a saved opt-in, so this
    // never cuts a live flow short.
    if (!row?.write?.manual_mint) {
      manualOpen = false;
      manualKey = "";
    }
  });

  // shortcut: a plan or a rotate that never answers leaves its button busy
  // until a reload; both legitimately take as long as the stack takes, so
  // neither carries a timeout.
  async function planRotation() {
    if (!row) return;
    planBusy = true;
    rotationError = "";
    try {
      plan = await api(`/credentials/${encodeURIComponent(row.name)}/plan`, {
        method: "POST",
        body: { take_over: pendingHere.length > 0 },
      });
      run = null;
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else rotationError = errorText(failure);
    } finally {
      planBusy = false;
    }
  }

  async function rotate(manualSubmit = false) {
    if (!row || runBusy) return;
    // A manual mint runs on the operator's key, which does not exist until
    // they rotate in the service's UI: the armed press opens the key field,
    // and only that form's submit fires. The plan stays enabled with no key;
    // the server refuses an empty submit, not the console.
    if (planPayload?.manual_mint === true && !manualSubmit) {
      manualOpen = true;
      rotationError = "";
      await tick();
      manualInput?.focus({ preventScroll: true });
      return;
    }
    run = null;
    runBusy = true;
    rotationError = "";
    auditError = "";
    try {
      run = await api(`/credentials/${encodeURIComponent(row.name)}/rotate`, {
        method: "POST",
        body: {
          confirm: row.name,
          take_over: pendingHere.length > 0,
          ...(manualMode ? { manual_value: manualKey } : {}),
        },
      });
      armed = false;
      manualConfirmed = false;
      if (runResult?.manual?.length) {
        manualFollowUp = trackManual(
          row.name,
          runResult.attempt,
          runResult.manual,
        );
      } else if (runResult && !runResult.failed) {
        manualFollowUp = clearManualTracker(row.name);
      }
      // Show the run's own result and the new stored key first. The audit is
      // a second stack-wide pass; it still runs below so the copy rows show
      // the run's result, but it must not keep "Rotating…" on screen.
      await onrefresh();
      if (runResult) void refreshAfterRotation();
      // A finished run tells the caller, which is where the dialog lives; the
      // credential page has nothing to announce, it is already the verdict.
      if (finished) ondone?.(runResult);
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else {
        const message = errorText(failure);
        // The plan changed under the key form: what was a manual mint no
        // longer is, so the plan on screen is stale. Re-read it.
        if (/does not use a manual mint/.test(message)) await planRotation();
        // A rotate fired without the plan (or before it answered) on a
        // manual mint: open the key field instead of leaving a bare 400.
        else if (/manual mint needs the key/.test(message)) manualOpen = true;
        rotationError = message;
      }
    } finally {
      manualKey = "";
      runBusy = false;
    }
  }

  async function refreshAfterRotation() {
    auditBusy = true;
    auditError = "";
    try {
      await auditStack();
      await onrefresh();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        onsignout();
        return;
      }
      auditError = errorText(failure);
    } finally {
      auditBusy = false;
    }
  }

  function confirmManual() {
    if (!manualFollowUp || !manualConfirmed) return;
    manualFollowUp = clearManualTracker(row.name);
    manualConfirmed = false;
  }

  function clearFollowUp() {
    manualFollowUp = clearManualTracker(row.name);
    manualConfirmed = false;
  }

</script>

<div id="rotation" bind:this={section} class="rotation-panel">
  {#if pendingHere.length > 0}
    <Banner tone="danger" title="A rotation of this app did not finish.">
      <p>
        It stopped in {serviceOfTarget(pendingHere[0].target)}
        {elapsed(pendingHere[0].seconds_ago)} ago. Continuing below takes those
        steps over and resumes the service's observed state instead of minting
        again. A live run keeps the lock.
      </p>
    </Banner>
  {/if}
  {#if rotationError}<Banner tone="danger">{rotationError}</Banner>{/if}
  {#if auditBusy}
    <p class="muted" role="status">Refreshing copy status after the run…</p>
  {/if}
  {#if auditError}
    <Banner tone="warn" title="The rotation finished, but the audit could not run.">
      {auditError} The next audit will try again.
    </Banner>
  {/if}
  {#if runBusy && !runResult}
    <p class="muted" role="status">Rotating…</p>
  {/if}

  {#if planBusy && !planPayload}
    <p class="muted">Planning…</p>
  {/if}

  {#if planPayload}
    {#if planPayload.blocked_by?.length > 0}
      <Banner tone="danger" title="This key cannot be rotated yet.">
        {#each blockedLines as line, index (index)}
          <p>{line}</p>
        {/each}
      </Banner>
    {:else if planPayload.problems?.length > 0}
      <Banner tone="danger" title="The checks failed; nothing was changed.">
        {#if loginBlocked}
          {@const loginPointer = `The backup needs ${ownerService}'s UI login. Choose an option in Connection, then run again.`}
          <p>{loginPointer}</p>
        {/if}
        {#each problemLines as line, index (index)}
          <p>{line}</p>
        {/each}
      </Banner>
    {:else if manualPlanLabels.length}
      <Banner tone="warn" title="Ready to rotate.">
        {manualPlanLabels.join(", ")} will need manual confirmation after the
        key rotates.
      </Banner>
    {:else if planSentence}
      <Banner tone="ok" title="Ready to rotate.">
        {planSentence}
      </Banner>
    {/if}
  {/if}

  {#if manualOpen}
    {@const manualWarning = "The old key is already dead — it was replaced in the service's Settings > General page. The key pasted here is the only working one, and there is no backup to restore if this run stops."}
    <div class="confirm-box">
      <label class="field">
        Key from the service's Settings page
        <input
          type="password"
          bind:this={manualInput}
          bind:value={manualKey}
          autocomplete="new-password"
          spellcheck="false"
          aria-label="Key from the service's Settings page"
        />
      </label>
      <p class="field-help">{manualWarning}</p>
      <div class="toolbar">
        <button
          class="primary"
          type="button"
          onclick={() => rotate(true)}
          disabled={runBusy}
        >
          {runBusy ? "Rotating…" : "Rotate with this key"}
        </button>
      </div>
    </div>
  {/if}

  {#if runResult}
    {#if runResult.failed}
      <Banner tone="danger" title="This run stopped before it finished.">
        {#each failureLines(runResult, ownNames) as line (line)}
          <p>{line}</p>
        {/each}
        <p class="muted">Later steps did not run. Fix the cause, then run again.</p>
      </Banner>
    {:else}
      <Banner tone="ok" title="Rotation complete.">
        {rotatedSentence}
      </Banner>
      {#if runResult.manual?.length > 0 && manualFollowUp}
        <Banner tone="warn" title="Manual rotation required.">
          The key rotated. Confirm the manual copies below when they are updated.
        </Banner>
      {/if}
    {/if}
    {#if runResult.resumed}
      <p class="muted">
        No new key was minted: the service already held one, so this run
        continued from there.
      </p>
    {/if}
  {/if}

  {#if manualFollowUp && Object.keys(manualFollowUp.targets).length > 0}
    <section class="confirm-box" aria-labelledby="manual-follow-up-title">
      <h4 id="manual-follow-up-title">Manual rotation</h4>
      <p class="field-help">
        Credarr cannot verify these copies: {Object.keys(manualFollowUp.targets)
          .map((target) => copyLabel(target))
          .join(", ")}. Manual rotation is required. Confirm rotation below or
        clear reminder.
      </p>
      <label class="setup-check">
        <input type="checkbox" bind:checked={manualConfirmed} />
        I rotated the key and updated these copies.
      </label>
      <div class="toolbar">
        <button
          class="primary"
          type="button"
          disabled={!manualConfirmed}
          onclick={confirmManual}
        >
          Confirm rotation
        </button>
        <button type="button" onclick={clearFollowUp}>Clear reminder</button>
      </div>
    </section>
  {/if}
</div>
