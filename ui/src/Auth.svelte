<script>
  // First run / sign in. One admin (DECISIONS): setup is open until it is
  // taken, and the answer to "is it taken" is the only public payload here.
  import { api, ApiError } from "./lib/api.js";
  import Icon from "./lib/Icon.svelte";

  let { mode, ondone } = $props();
  let password = $state("");
  let confirm = $state("");
  let reveal = $state(false);
  let error = $state("");
  let busy = $state(false);

  async function submit(event) {
    event.preventDefault();
    error = "";
    if (mode === "setup" && password !== confirm) {
      error = "The two passwords differ.";
      return;
    }
    busy = true;
    try {
      const path = mode === "setup" ? "/auth/setup" : "/auth/login";
      await api(path, { method: "POST", body: { password } });
      password = confirm = "";
      await ondone();
    } catch (failure) {
      error = failure instanceof ApiError ? failure.message : String(failure);
    } finally {
      busy = false;
    }
  }
</script>

<main class="center">
  <div class="auth-card">
    <div class="auth-brand">
      <span class="brand-mark"><Icon name="shield" size={18} /></span>
      <div>
        <h1>credarr</h1>
        <p>credential audit and rotation</p>
      </div>
    </div>

    {#if mode === "setup"}
      <h2>Set the admin password</h2>
      <p class="muted">One admin. Twelve characters minimum, and no reset.</p>
    {:else}
      <h2>Sign in</h2>
    {/if}

    <form onsubmit={submit}>
      <label class="field">
        <span>{mode === "setup" ? "New password" : "Password"}</span>
        <input
          type={reveal ? "text" : "password"}
          bind:value={password}
          autocomplete={mode === "setup" ? "new-password" : "current-password"}
          required
        />
      </label>
      {#if mode === "setup"}
        <label class="field">
          <span>Repeat password</span>
          <input
            type={reveal ? "text" : "password"}
            bind:value={confirm}
            autocomplete="new-password"
            required
          />
        </label>
      {/if}
      <button
        type="button"
        class="link"
        onclick={() => (reveal = !reveal)}
      >
        {reveal ? "Hide passwords" : "Show passwords"}
      </button>
      <button class="primary" type="submit" disabled={busy}>
        {busy
          ? mode === "setup"
            ? "Creating…"
            : "Signing in…"
          : mode === "setup"
            ? "Create the admin"
            : "Sign in"}
      </button>
    </form>

    {#if error}<p class="error" role="alert">{error}</p>{/if}
  </div>
</main>
