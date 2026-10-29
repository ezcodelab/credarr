<script>
  import { onMount } from "svelte";
  import Icon from "./Icon.svelte";

  // One dialog shell: a dimmed, blurred page behind a panel that closes on
  // Escape or a click outside. `children` is the content; the caller decides
  // when the dialog exists.
  let { title, onclose, children } = $props();

  let dialog;

  onMount(() => {
    const previous = document.activeElement;
    // A child may already have put the cursor where it belongs. Moving it to
    // the dialog would throw that intent away, so only claim focus when the
    // dialog has none.
    if (!dialog.contains(document.activeElement)) dialog.focus();
    return () => previous?.focus?.();
  });

  function focusable() {
    return [
      ...dialog.querySelectorAll(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ),
    ];
  }

  function keydown(event) {
    if (event.key === "Escape") {
      onclose();
      return;
    }
    if (event.key !== "Tab") return;
    const items = focusable();
    if (items.length === 0) {
      event.preventDefault();
      dialog.focus();
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    if (event.shiftKey && (document.activeElement === first || document.activeElement === dialog)) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }
</script>

<svelte:window onkeydown={keydown} />

<div
  class="overlay"
  role="presentation"
  onclick={(event) => event.target === event.currentTarget && onclose()}
>
  <div
    class="dialog"
    role="dialog"
    aria-modal="true"
    aria-label={title}
    tabindex="-1"
    bind:this={dialog}
  >
    <header>
      <h2>{title}</h2>
      <button class="icon" aria-label="Close" onclick={onclose}>
        <Icon name="close" size={16} />
      </button>
    </header>
    <div class="body">{@render children()}</div>
  </div>
</div>
