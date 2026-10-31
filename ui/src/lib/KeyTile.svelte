<script>
  import Icon from "./Icon.svelte";
  import { statusInfo } from "./status.js";

  // The app's identity anchor: a key in a quiet tile with a status dot.
  // Decorative; the adjacent status word carries the meaning.
  let { status = null, size = "md" } = $props();

  const info = $derived(statusInfo(status));
</script>

<span class="key-tile {size}" aria-hidden="true">
  <Icon name="key" size={size === "lg" ? 21 : 16} />
  <span class="key-tile-dot {info.tone}"></span>
</span>
