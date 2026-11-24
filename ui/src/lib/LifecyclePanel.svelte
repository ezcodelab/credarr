<script>
  import { onMount } from "svelte";
  import { api, ApiError, errorText, timestamp } from "./api.js";
  import Banner from "./Banner.svelte";
  import StatusPill from "./StatusPill.svelte";

  let { name, onrefresh = null, onsignout = null } = $props();

  let state = $state(null);
  let loading = $state(true);
  let busy = $state(false);
  let error = $state("");
  let message = $state("");
  let confirm = $state("");
  let force = $state(false);

  async function load() {
    loading = true;
    error = "";
    try {
      state = await api(`/credentials/${encodeURIComponent(name)}/lifecycle`, {
        timeout: 10_000,
      });
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout?.();
      else error = errorText(failure);
    } finally {
      loading = false;
    }
  }

  async function act(action) {
    if (busy) return;
    busy = true;
    error = "";
    message = "";
    try {
      await api(`/credentials/${encodeURIComponent(name)}/lifecycle`, {
        method: "POST",
        body: { action, confirm, reason: "", force },
        timeout: 15_000,
      });
      message =
        action === "restore"
          ? "Restored. The stored value is usable again."
          : action === "soft_delete"
            ? "Soft-deleted. The value is unusable until restored or purged."
            : "Purged. Ciphertext and topology are gone.";
      confirm = "";
      force = false;
      await load();
      await onrefresh?.();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout?.();
      else error = errorText(failure);
    } finally {
      busy = false;
    }
  }

  onMount(load);
</script>

<section class="card section" id="danger">
  <div class="section-head">
    <div>
      <h3>Delete or recover</h3>
      <p class="muted">
        Soft delete keeps the encrypted value for the recovery window. Purge is
        permanent and removes it from Credarr. The live service is not changed.
      </p>
    </div>
  </div>
  {#if error}<Banner tone="danger">{error}</Banner>{/if}
  {#if message}<Banner tone="ok">{message}</Banner>{/if}
  {#if loading}
    <p class="muted">Reading recovery state…</p>
  {:else if state?.lifecycle}
    <div class="toolbar">
      <StatusPill status="unverifiable" label="soft-deleted" />
      <span class="muted">
        Recovery ends {timestamp(state.lifecycle.purge_after)}. Reveal, rotate,
        adopt and sync are refused until restored.
      </span>
    </div>
    <label class="field">
      Type the credential name to purge
      <input bind:value={confirm} autocomplete="off" spellcheck="false" />
    </label>
    <div class="toolbar">
      <button type="button" onclick={() => act("restore")} disabled={busy}>Restore</button>
      <span class="spacer"></span>
      <label class="check">
        <input type="checkbox" bind:checked={force} />
        I understand this purge is permanent
      </label>
      <button
        class="danger"
        type="button"
        onclick={() => act("force_delete")}
        disabled={busy || !force || confirm.trim() !== name}
      >
        Purge permanently
      </button>
    </div>
  {:else}
    <label class="field">
      Type the credential name to soft-delete
      <input bind:value={confirm} autocomplete="off" spellcheck="false" />
    </label>
    <div class="toolbar">
      <button
        class="danger"
        type="button"
        onclick={() => act("soft_delete")}
        disabled={busy || confirm.trim() !== name}
      >
        Soft-delete this key
      </button>
    </div>
  {/if}
</section>
