<script>
  import { api, ApiError, errorText, timestamp } from "./api.js";
  import Banner from "./Banner.svelte";
  import StatusPill from "./StatusPill.svelte";
  import {
    manualCopyLabels,
    manualOnlyCopyLabels,
    unprovenCopyLabels,
  } from "./apps.js";
  import { autoInfo } from "./status.js";
  import { toast } from "./toast.js";

  // Deployment policy, separate from a manual run. Enabling authorises future
  // mutations; it never rotates by itself.
  const WRITE_TIMEOUT = 10_000;

  let { row, onrefresh, onsignout, manual = false } = $props();

  // Initialised once per mount, not in an effect: the card remounts per app
  // through {#key row.name}, so the mount value is always the current app's.
  let everyDays = $state(
    row.auto_rotation?.every_days ? String(row.auto_rotation.every_days) : "",
  );
  let busy = $state(false);
  let action = $state("");
  let error = $state("");
  let acceptedManual = $state(false);

  const policy = $derived(row.auto_rotation ?? {});
  const info = $derived(autoInfo(policy));
  const manualCopyNames = $derived(manualCopyLabels(row));
  const manualOnlyNames = $derived(manualOnlyCopyLabels(row));
  const unprovenCopyNames = $derived(unprovenCopyLabels(row));
  const needsManualConsent = $derived(
    manualCopyNames.length > 0 && (!policy.enabled || policy.paused),
  );

  // One save for enable, re-enable and cadence edits: the endpoint upserts,
  // so changing the days never needs a disable first.
  async function savePolicy(event) {
    event.preventDefault();
    if (busy || everyDays === "" || manual) return;
    if (needsManualConsent && !acceptedManual) {
      error = "Confirm the manual copies before enabling auto-rotation.";
      return;
    }
    busy = true;
    action = "save";
    error = "";
    try {
      await api(`/credentials/${encodeURIComponent(row.name)}/auto-rotation`, {
        method: "PUT",
        body: {
          enabled: true,
          every_days: Number(everyDays),
          confirm: row.name,
          accept_manual: needsManualConsent && acceptedManual,
        },
        timeout: WRITE_TIMEOUT,
      });
      everyDays = String(Number(everyDays));
      acceptedManual = false;
      await onrefresh();
      toast();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else error = errorText(failure);
    } finally {
      busy = false;
      action = "";
    }
  }

  async function disable() {
    if (busy) return;
    busy = true;
    action = "disable";
    error = "";
    try {
      await api(`/credentials/${encodeURIComponent(row.name)}/auto-rotation`, {
        method: "PUT",
        body: { enabled: false },
        timeout: WRITE_TIMEOUT,
      });
      acceptedManual = false;
      await onrefresh();
      toast();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else error = errorText(failure);
    } finally {
      busy = false;
      action = "";
    }
  }
</script>

<section class="card section auto-card">
  <div class="section-head">
    <div>
      <h3>Auto-rotation</h3>
      <p class="muted">
        Off by default. A fresh stack-wide audit can start a due rotation; manual
        copies are notified. It never resumes an interrupted run.
      </p>
    </div>
    <StatusPill status={info.status} label={info.label} title={info.why} />
  </div>



  {#if error}<Banner tone="danger">{error}</Banner>{/if}

  {#if manual}
    <Banner tone="warn" title="This key rotates by hand.">
      <p>
        Auto-rotation cannot supply a key you rotate in the service UI. Use the
        rotation panel, or choose backup or rebuild in Connection.
      </p>
    </Banner>
  {/if}

  {#if manualCopyNames.length}
    <Banner tone="warn" title="Some copies need follow-up.">
      {#if manualOnlyNames.length}
        <p>{manualOnlyNames.join(", ")} need a manual step.</p>
      {/if}
      {#if unprovenCopyNames.length}
        <p>
          {unprovenCopyNames.join(", ")} {unprovenCopyNames.length === 1 ? "is" : "are"}
          written automatically, but cannot be verified automatically.
        </p>
      {/if}
      {#if needsManualConsent}
        <label class="setup-check">
          <input type="checkbox" bind:checked={acceptedManual} />
          I understand these copies need follow-up.
        </label>
      {/if}
    </Banner>
  {/if}

  {#if policy.paused}
    <Banner tone="danger" title="Auto-rotation is paused.">
      {policy.last_detail || "An unattended run did not finish."}
      Resolve it in the rotation panel above, then save. Saving resets the
      schedule and does not resume the run.
    </Banner>
  {/if}

  {#if policy.enabled && !policy.paused && policy.next_due_at}
    <p class="muted">Next due {timestamp(policy.next_due_at)}.</p>
  {/if}
  {#if policy.last_check_at}
    <p class="muted">
      Last checked {timestamp(policy.last_check_at)}: {policy.last_outcome ?? "—"}
      {#if policy.last_detail}· {policy.last_detail}{/if}
    </p>
  {/if}
  <form class="auto-form" onsubmit={savePolicy}>
    <div class="field-grid">
      <label class="field">
        <span>Rotate at most every</span>
        <span class="inline-input">
          <input
            type="number"
            min="1"
            max="365"
            bind:value={everyDays}
            aria-label="Days between automatic rotations"
            disabled={manual}
          />
          <span>days</span>
        </span>
      </label>
    </div>
    <div class="toolbar">
      {#if policy.enabled && !policy.paused}
        <button onclick={disable} disabled={busy} type="button">
          {action === "disable" ? "Disabling…" : "Disable auto-rotation"}
        </button>
      {/if}
      <span class="spacer"></span>
      <button
        class="primary"
        type="submit"
        disabled={busy || everyDays === "" || manual || (needsManualConsent && !acceptedManual)}
      >
        {policy.enabled && !policy.paused
          ? action === "save"
            ? "Saving…"
            : "Save"
          : action === "save"
            ? "Enabling…"
            : "Enable auto-rotation"}
      </button>
    </div>
  </form>
</section>
