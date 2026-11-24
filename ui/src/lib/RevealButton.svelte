<script>
  import { api, ApiError, errorText } from "./api.js";

  let { name, disabled = false } = $props();

  let value = $state("");
  let busy = $state(false);
  let error = $state("");
  let timer = null;

  function stop() {
    if (timer) clearInterval(timer);
    timer = null;
  }

  function hide() {
    stop();
    value = "";
    error = "";
  }

  async function reveal() {
    if (busy) return;
    busy = true;
    error = "";
    stop();
    try {
      const answer = await api(`/credentials/${encodeURIComponent(name)}/reveal`, {
        method: "POST",
        body: { stage: "CURRENT" },
        timeout: 15_000,
      });
      value = answer?.value ?? "";
      if (value) {
        timer = setTimeout(hide, Math.max(1, Number(answer?.expires_in) || 30) * 1000);
      }
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) return;
      error = errorText(failure);
    } finally {
      busy = false;
    }
  }

  $effect(() => () => stop());
</script>

<div class="reveal-inline">
  <button
    type="button"
    onclick={value ? hide : reveal}
    disabled={disabled || busy}
    title={value ? "Hide the revealed value" : "Reveal the current value"}
  >
    {busy ? "…" : value ? "Hide" : "Reveal"}
  </button>
  {#if value}
    <input
      class="secret reveal-value"
      readonly
      value={value}
      autocomplete="off"
      spellcheck="false"
      aria-label="Revealed credential value"
      onfocus={(event) => event.currentTarget.select()}
    />
  {/if}
  {#if error}<span class="error reveal-error">{error}</span>{/if}
</div>

<style>
  .reveal-inline {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    min-width: 0;
  }
  .reveal-value {
    width: 14rem;
    max-width: calc(100vw - 12rem);
    font-size: 0.8rem;
  }
  .reveal-error {
    max-width: 18rem;
    font-size: 0.78rem;
  }
</style>
