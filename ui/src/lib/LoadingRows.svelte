<script>
  let { label = "Reading…", rows = 3, panel = false, kind = "table" } = $props();
</script>

<div class="loading-rows loading-{kind}" class:apps-loading={kind === "apps"} class:panel role="status">
  <span class="sr-only">{label}</span>
  {#if kind === "apps"}
    <div aria-hidden="true">
      {#each Array.from({ length: rows }) as _, index (index)}
        <div class="apps-loading-row">
          <span class="skeleton apps-loading-key"></span>
          <span class="skeleton apps-loading-title"></span>
          <span class="skeleton apps-loading-state"></span>
        </div>
      {/each}
    </div>
  {:else if kind === "activity"}
    <div class="loading-ledger" aria-hidden="true">
      {#each Array.from({ length: rows }) as _, index (index)}
        <div class="loading-ledger-row">
          <span class="skeleton"></span>
          <span class="skeleton short"></span>
          <span class="skeleton short"></span>
          <span class="skeleton"></span>
          <span class="skeleton short"></span>
        </div>
      {/each}
    </div>
  {:else}
    <div class="check-skeleton" aria-hidden="true">
      {#each Array.from({ length: rows }) as _, index (index)}
        <div class="skeleton-row">
          <span class="skeleton"></span>
          <span class="skeleton short"></span>
          <span class="skeleton"></span>
        </div>
      {/each}
    </div>
  {/if}
</div>
