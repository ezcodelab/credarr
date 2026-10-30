<script>
  import { activity } from "./activity.js";

  // `holding` keeps the line on for work that is not one request: the audit
  // job polls, so between polls the request count drops to zero.
  let { holding = false } = $props();
</script>

<div class="activity-bar" class:active={holding || $activity > 0} aria-hidden="true">
  <span></span>
</div>
{#if holding || $activity > 0}
  <span class="sr-only" role="status">Working…</span>
{/if}
