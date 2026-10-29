<script>
  import Icon from "./Icon.svelte";

  // Empty is a state with a next action, not a blank table that reads as calm.
  let { title, icon = "import", children, actions = null } = $props();
</script>

<section class="empty">
  <span class="empty-icon" aria-hidden="true"><Icon name={icon} size={20} /></span>
  <h2>{title}</h2>
  {@render children?.()}
  {#if actions}
    <div class="empty-actions">{@render actions()}</div>
  {/if}
</section>
