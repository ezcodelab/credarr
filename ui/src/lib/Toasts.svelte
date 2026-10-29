<script>
  import { toasts } from "./toast.js";
</script>

<div class="toasts" aria-live="polite">
  {#each $toasts as item (item.id)}
    <div class="toast">{item.message}</div>
  {/each}
</div>
