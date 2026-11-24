<script>
  import { api, ApiError, errorText } from "./api.js";
  import Modal from "./Modal.svelte";

  let { name, disabled = false } = $props();

  let open = $state(false);
  let confirmed = $state(false);
  let stage = $state("CURRENT");
  let busy = $state(false);
  let error = $state("");
  let value = $state("");
  let version = $state("");
  let remaining = $state(0);
  let copied = $state(false);
  let timer = null;

  function stop() {
    if (timer) clearInterval(timer);
    timer = null;
  }

  function close() {
    stop();
    open = false;
    confirmed = false;
    value = "";
    version = "";
    remaining = 0;
    error = "";
    copied = false;
  }

  function startTtl(seconds) {
    stop();
    remaining = Number(seconds) || 30;
    timer = setInterval(() => {
      remaining -= 1;
      if (remaining <= 0) close();
    }, 1000);
  }

  async function reveal() {
    if (!confirmed || busy) return;
    busy = true;
    error = "";
    value = "";
    try {
      const answer = await api(`/credentials/${encodeURIComponent(name)}/reveal`, {
        method: "POST",
        body: { stage },
        timeout: 15_000,
      });
      value = answer?.value ?? "";
      version = answer?.version ?? "";
      startTtl(answer?.expires_in);
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) return;
      error = errorText(failure);
    } finally {
      busy = false;
    }
  }

  async function copy() {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      copied = true;
    } catch {
      copied = false;
    }
  }

  $effect(() => () => stop());
</script>

<button type="button" onclick={() => (open = true)} {disabled}>Reveal</button>

{#if open}
  <Modal title={`Reveal ${name}`} onclose={close}>
    {#if !value}
      <p class="muted">
        Revealing a stored value is audited: the credential, version, stage and
        your admin session are recorded. The value is returned once, kept in
        this dialog only, and cleared automatically.
      </p>
      <label class="field">
        Stage
        <select bind:value={stage}>
          <option value="CURRENT">Current</option>
          <option value="PREVIOUS">Previous</option>
        </select>
      </label>
      <label class="check">
        <input type="checkbox" bind:checked={confirmed} />
        I understand this reveal will be audited
      </label>
      {#if error}<p class="error">{error}</p>{/if}
      <div class="toolbar">
        <button type="button" onclick={close}>Cancel</button>
        <span class="spacer"></span>
        <button class="primary" type="button" onclick={reveal} disabled={!confirmed || busy}>
          {busy ? "Revealing…" : "Reveal value"}
        </button>
      </div>
    {:else}
      <p class="muted">
        {stage} version {version.slice(0, 12)}. This value clears in
        <strong class="tabular">{remaining}s</strong>.
      </p>
      <input
        class="secret"
        readonly
        value={value}
        autocomplete="off"
        spellcheck="false"
        aria-label="Revealed credential value"
        onfocus={(event) => event.currentTarget.select()}
      />
      {#if error}<p class="error">{error}</p>{/if}
      <div class="toolbar">
        <button type="button" onclick={close}>Close</button>
        <span class="spacer"></span>
        <button type="button" onclick={copy}>{copied ? "Copied" : "Copy"}</button>
      </div>
    {/if}
  </Modal>
{/if}
