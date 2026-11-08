<script>
  import { api, ApiError, elapsed, errorText } from "./api.js";
  import Banner from "./Banner.svelte";
  import { serviceOfTarget } from "./names.js";

  // The page-level recovery banner for one app. It sits under the header, not
  // inside the rotation card: an unfinished run changes what the whole page
  // means, and the primary action (Resume rotation) stays in the action bar
  // above it. Abandon is the one action that belongs to the explanation.
  let {
    row,
    pending = [],
    attempts = [],
    onrefresh,
    onsignout,
  } = $props();

  let abandonBusy = $state(false);
  let abandonError = $state("");

  const pendingHere = $derived(
    pending.filter((step) => step.credential === row?.name),
  );
  const attemptHere = $derived(
    attempts.filter((attempt) => attempt.credential === row?.name),
  );
  const unfinishedHere = $derived(
    pendingHere.length > 0 || attemptHere.length > 0,
  );

  async function abandon() {
    if (!row || abandonBusy) return;
    abandonBusy = true;
    abandonError = "";
    try {
      await api(
        `/credentials/${encodeURIComponent(row.name)}/rotation/abandon`,
        { method: "POST" },
      );
      await onrefresh?.();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else abandonError = errorText(failure);
    } finally {
      abandonBusy = false;
    }
  }
</script>

{#if unfinishedHere}
  <Banner tone="danger" role="alert" title="A rotation of this app did not finish.">
    {#if pendingHere.length > 0}
      <p>
        It stopped in {serviceOfTarget(pendingHere[0].target)}
        {elapsed(pendingHere[0].seconds_ago)} ago. Resume rotation above
        continues the earlier mint instead of making a second key; a live run
        keeps the lock.
      </p>
    {:else}
      <p>
        Every step finished, but the run never closed its record. Rotate above
        starts a new run; Abandon clears the record without touching the
        service.
      </p>
    {/if}
    <p class="field-help">
      Abandon closes the record without touching the service: nothing is
      minted or revoked, and you can rotate again later. Use it when the
      service is unreachable and a resume cannot run.
    </p>
    {#snippet actions()}
      <button
        type="button"
        onclick={abandon}
        disabled={abandonBusy}
      >
        {abandonBusy ? "Abandoning…" : "Abandon this run"}
      </button>
    {/snippet}
  </Banner>
{/if}

{#if abandonError}<Banner tone="danger">{abandonError}</Banner>{/if}
