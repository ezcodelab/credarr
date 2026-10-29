<script>
  import { api, ApiError, errorText } from "./api.js";
  import Banner from "./Banner.svelte";
  import { importWarningLines, plainEngineText } from "./names.js";

  // The manifest's one door into the store: replace, not merge. The text is
  // the declared state, so the warning says what replace means for the values
  // already stored, and the strict parse stays the server's - a manifest the
  // CLI would refuse is refused here with the same sentence.
  const IMPORT_TIMEOUT = 15_000;

  let { onimported, onsignout } = $props();

  let text = $state("");
  let busy = $state(false);
  let message = $state("");
  let error = $state("");
  let warningLines = $state([]);
  let continueAfterImport = $state(false);
  let armed = $state(false);

  async function loadFile(event) {
    const [file] = event.currentTarget.files ?? [];
    if (file) text = await file.text();
  }

  async function submit(event) {
    event.preventDefault();
    if (busy || text.trim() === "" || !armed) return;
    busy = true;
    error = "";
    message = "";
    warningLines = [];
    continueAfterImport = false;
    try {
      const answer = await api("/topology/import", {
        method: "POST",
        body: { mode: "replace", yaml: text, confirm: "replace" },
        timeout: IMPORT_TIMEOUT,
      });
      // The text is the manifest and the file is where it belongs; a browser
      // tab holding it after the write serves nothing.
      text = "";
      armed = false;
      message = `Imported ${answer.credentials} ${answer.credentials === 1 ? "credential" : "credentials"}. The next audit compares the stack against them.`;
      warningLines = importWarningLines(answer.warnings);
      // Show the warning before leaving the import surface; a caller may
      // unmount this component as soon as the import is complete.
      continueAfterImport = warningLines.length > 0;
      if (!continueAfterImport) await onimported();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else error = errorText(failure);
    } finally {
      busy = false;
    }
  }

  async function finishImport() {
    continueAfterImport = false;
    await onimported();
  }
</script>

<form class="import" onsubmit={submit}>
  <label for="manifest">Manifest YAML</label>
  <textarea
    id="manifest"
    bind:value={text}
    rows="12"
    spellcheck="false"
    placeholder={"version: 1\ncredentials:\n  example_api_key:\n    class: A\n    consumers:\n      - target: sonarr.indexers"}
  ></textarea>
  <div class="toolbar">
    <input
      type="file"
      accept=".yaml,.yml,text/yaml"
      onchange={loadFile}
      aria-label="Load a manifest file"
    />
    <div class="spacer"></div>
    <label class="setup-check">
      <input type="checkbox" bind:checked={armed} disabled={busy} />
      I understand this replaces the declared topology
    </label>
    <button
      class="primary"
      type="submit"
      disabled={busy || text.trim() === "" || !armed}
    >
      {busy ? "Importing…" : "Import"}
    </button>
  </div>
  {#if message}<Banner tone="ok">{message}</Banner>{/if}
  {#if warningLines.length}
    <Banner tone="warn" title="Imported, but some keys are audit-only.">
      {#each warningLines as line (line)}<p>{line}</p>{/each}
      {#if continueAfterImport}
        {#snippet actions()}
          <button type="button" onclick={finishImport}>Continue</button>
        {/snippet}
      {/if}
    </Banner>
  {/if}
  {#if error}<Banner tone="danger">{plainEngineText(error)}</Banner>{/if}
</form>
