<script>
  import Icon from "./Icon.svelte";

  // A banner is an announcement, not a form section: one tone, one icon, the
  // sentence, and the actions that resolve it. `role="alert"` is reserved for
  // states that interrupt the operator (a rotation that did not finish).
  let { tone = "info", title = "", role = "status", children, actions = null } = $props();

  const icons = { danger: "alert", warn: "alert", ok: "check", info: "info", quiet: "info" };
  const icon = $derived(icons[tone] ?? "info");
</script>

<div class="banner banner-{tone}" role={role} aria-live={role === "alert" ? "assertive" : "polite"}>
  <span class="banner-icon" aria-hidden="true"><Icon name={icon} size={15} /></span>
  <div class="banner-body">
    {#if title}<strong>{title}</strong>{/if}
    {@render children?.()}
  </div>
  {#if actions}
    <div class="banner-actions">{@render actions()}</div>
  {/if}
</div>
