<script>
  import { onMount } from "svelte";
  import { api, ApiError, errorText } from "../lib/api.js";
  import Banner from "../lib/Banner.svelte";
  import { importWarningLines } from "../lib/names.js";

  // Import is a migration/backup door, not the only way to build a topology.
  // The console writes credentials and services through their own APIs; this
  // page carries the text projection.
  let { onrefresh, onsignout } = $props();

  let text = $state("");
  let exported = $state("");
  let mode = $state("replace");
  let armed = $state(false);
  let busy = $state(false);
  let message = $state("");
  let error = $state("");
  let warningLines = $state([]);

  async function loadExport() {
    try {
      const response = await fetch("/api/v1/topology/export");
      if (response.status === 401) {
        onsignout();
        return;
      }
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      exported = await response.text();
    } catch (failure) {
      error = errorText(failure);
    }
  }

  onMount(loadExport);

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
    try {
      const answer = await api("/topology/import", {
        method: "POST",
        body: { mode, yaml: text, confirm: mode },
        timeout: 20_000,
      });
      message =
        `${answer.mode} import: ${answer.credentials} credentials, ` +
        `${answer.holders} holders` +
        (answer.removed ? `, ${answer.removed} removed` : "") +
        ".";
      warningLines = importWarningLines(answer.warnings);
      armed = false;
      text = "";
      await Promise.all([onrefresh(), loadExport()]);
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else error = errorText(failure);
    } finally {
      busy = false;
    }
  }

  function download() {
    const blob = new Blob([exported], { type: "application/yaml" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "credentials.yaml";
    link.click();
    URL.revokeObjectURL(url);
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(exported);
      message = "Manifest copied.";
    } catch {
      error = "the browser refused clipboard access";
    }
  }
</script>

{#if message}<Banner tone="ok">{message}</Banner>{/if}
{#if warningLines.length}
  <Banner tone="warn" title="Imported, but some keys are audit-only.">
    {#each warningLines as line (line)}<p>{line}</p>{/each}
  </Banner>
{/if}
{#if error}<Banner tone="danger">{error}</Banner>{/if}

<section class="card section">
  <div class="section-head">
    <div><h3>Import</h3></div>
  </div>
  <form class="import" onsubmit={submit}>
    <div class="toolbar">
      <select bind:value={mode} disabled={busy} aria-label="Import mode">
        <option value="replace">Replace</option>
        <option value="merge">Merge</option>
      </select>
      <input
        type="file"
        accept=".yaml,.yml,text/yaml"
        onchange={loadFile}
        disabled={busy}
        aria-label="Load a manifest file"
      />
      <span class="spacer"></span>
      <label class="setup-check">
        <input type="checkbox" bind:checked={armed} disabled={busy} />
        {mode === "replace"
          ? "I understand this replaces the declared topology"
          : "I understand this merges into the declared topology"}
      </label>
      <button
        class="primary"
        type="submit"
        disabled={busy || text.trim() === "" || !armed}
      >
        {busy ? "Importing…" : "Import"}
      </button>
    </div>
    <textarea
      class="export-text"
      rows="16"
      bind:value={text}
      disabled={busy}
      spellcheck="false"
      aria-label="Manifest YAML"
      placeholder="version: 1&#10;credentials: …"
    ></textarea>
  </form>
</section>

<section class="card section">
  <div class="section-head">
    <div><h3>Export</h3></div>
    <button onclick={loadExport}>Refresh</button>
    <button onclick={download} disabled={!exported}>Download</button>
    <button onclick={copy} disabled={!exported}>Copy</button>
  </div>
  <textarea
    class="export-text"
    readonly
    value={exported}
    aria-label="Exported manifest"
  ></textarea>
</section>
