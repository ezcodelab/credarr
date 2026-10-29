<script>
  import Modal from "./Modal.svelte";

  // The one confirmation dialog. Typed names are gone: the dialog names what
  // is deleted, the confirm button turns red, and the API's own confirm value
  // (the slug) is sent by the caller, never typed by the operator.
  let {
    title,
    message = "",
    confirmText = "Delete",
    busy = false,
    onconfirm,
    oncancel,
  } = $props();

  let confirmButton = $state(null);
</script>

<Modal title={title} onclose={oncancel}>
  {#if message}<p class="muted">{message}</p>{/if}
  <div class="toolbar">
    <button type="button" onclick={oncancel} disabled={busy}>Cancel</button>
    <span class="spacer"></span>
    <button
      class="danger"
      type="button"
      bind:this={confirmButton}
      onclick={onconfirm}
      disabled={busy}
    >
      {busy ? "Working…" : confirmText}
    </button>
  </div>
</Modal>
