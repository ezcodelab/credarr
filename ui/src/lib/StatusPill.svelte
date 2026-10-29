<script>
  import { statusInfo } from "./status.js";

  // The status word is always visible; the dot is a second cue, never the only
  // one. `tone` exists for states that are not engine statuses (stack health),
  // while the raw status class stays on the element for stable selectors.
  let { status = null, label = "", tone = "", size = "", title = "" } = $props();

  const info = $derived(statusInfo(status));
  const text = $derived(label || info.label);
  const colour = $derived(tone || info.tone);
  const hint = $derived(title || info.why);
</script>

<span class="pill {status ?? 'none'} {colour} {size}" title={hint || undefined}>
  {text}
</span>
