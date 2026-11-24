<script>
  import { api, ApiError, errorText } from "./api.js";

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

  function keydown(event) {
    if (event.key === "Escape" && open) close();
  }

  $effect(() => () => stop());
</script>

<svelte:window onkeydown={keydown} />

<div class="reveal-wrap">
  <button
    type="button"
    aria-expanded={open}
    onclick={() => (open ? close() : (open = true))}
    {disabled}
  >
    Reveal
  </button>

  {#if open}
    <div class="reveal-panel" role="dialog" aria-label={`Reveal ${name}`}>
      <div class="reveal-head">
        <strong>{value ? "Revealed value" : "Reveal value"}</strong>
        <button class="link" type="button" onclick={close}>Close</button>
      </div>
      {#if !value}
        <p class="muted">Audited. Clears after 30 seconds.</p>
        <div class="reveal-controls">
          <select bind:value={stage} aria-label="Version stage">
            <option value="CURRENT">Current</option>
            <option value="PREVIOUS">Previous</option>
          </select>
          <label class="check">
            <input type="checkbox" bind:checked={confirmed} />
            I understand this is audited
          </label>
        </div>
        {#if error}<p class="error">{error}</p>{/if}
        <div class="reveal-actions">
          <span class="spacer"></span>
          <button
            class="primary"
            type="button"
            onclick={reveal}
            disabled={!confirmed || busy}
          >
            {busy ? "Revealing…" : "Reveal value"}
          </button>
        </div>
      {:else}
        <p class="muted tabular">
          {stage} · {version.slice(0, 8)} · {remaining}s
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
        <div class="reveal-actions">
          <span class="spacer"></span>
          <button type="button" onclick={copy}>{copied ? "Copied" : "Copy"}</button>
          <button type="button" onclick={close}>Hide</button>
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .reveal-wrap {
    position: relative;
    display: inline-flex;
  }
  .reveal-panel {
    position: absolute;
    top: calc(100% + 0.4rem);
    right: 0;
    z-index: 60;
    width: min(24rem, calc(100vw - 2rem));
    padding: 0.75rem;
    border: 1px solid var(--line);
    border-radius: var(--radius);
    background: var(--panel);
    box-shadow: var(--shadow);
    text-align: left;
  }
  .reveal-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
    margin-bottom: 0.35rem;
  }
  .reveal-panel .muted {
    margin: 0 0 0.55rem;
    font-size: 0.8rem;
  }
  .reveal-controls {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  .reveal-controls select {
    max-width: 8rem;
  }
  .reveal-actions {
    display: flex;
    align-items: center;
    gap: 0.45rem;
    margin-top: 0.6rem;
  }
  .reveal-panel .secret {
    width: 100%;
    font-size: 0.8rem;
  }
  .link {
    padding: 0;
    border: 0;
    background: none;
    color: var(--dim);
    font-size: 0.8rem;
  }
  @media (max-width: 640px) {
    .reveal-panel {
      right: auto;
      left: 0;
    }
  }
</style>
