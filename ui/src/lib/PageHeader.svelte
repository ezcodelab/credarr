<script>
  // Page titles share one hierarchy: one h1, an optional sentence about the
  // job, and the actions that belong to the page.
  let { title, description = "", actions = null } = $props();
</script>

<header class="page-header">
  <div class="page-heading">
    <h1>{title}</h1>
    {#if description}<p class="page-desc">{description}</p>{/if}
  </div>
  {#if actions}
    <div class="page-actions">{@render actions()}</div>
  {/if}
</header>
