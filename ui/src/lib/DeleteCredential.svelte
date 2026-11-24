<script>
  import { api, ApiError, errorText } from "./api.js";
  import Banner from "./Banner.svelte";
  import ConfirmDialog from "./ConfirmDialog.svelte";

  let { name, onrefresh = null, onsignout = null } = $props();

  let open = $state(false);
  let busy = $state(false);
  let error = $state("");

  async function remove() {
    if (busy) return;
    busy = true;
    error = "";
    try {
      await api(
        `/credentials/${encodeURIComponent(name)}?confirm=${encodeURIComponent(name)}`,
        { method: "DELETE" },
      );
      open = false;
      await onrefresh?.();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout?.();
      else error = errorText(failure);
    } finally {
      busy = false;
    }
  }
</script>

<section class="card section" id="danger">
  <div class="section-head">
    <div>
      <h3>Delete</h3>
      <p class="muted">Removes this key from Credarr only. The live service is not changed.</p>
    </div>
  </div>
  {#if error}<Banner tone="danger">{error}</Banner>{/if}
  <div class="toolbar">
    <button class="danger" type="button" onclick={() => (open = true)} disabled={busy}>
      Delete this app key
    </button>
  </div>
</section>

{#if open}
  <ConfirmDialog
    title={`Delete ${name} from Credarr?`}
    message="Removes the declaration, copies, policy and stored copy from Credarr. The secret in the live service stays where it is."
    confirmText="Delete"
    busy={busy}
    onconfirm={remove}
    oncancel={() => (open = false)}
  />
{/if}
