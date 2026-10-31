<script>
  import Banner from "../lib/Banner.svelte";
  import EmptyState from "../lib/EmptyState.svelte";
  import KeyTile from "../lib/KeyTile.svelte";
  import PageHeader from "../lib/PageHeader.svelte";
  import StatusPill from "../lib/StatusPill.svelte";
</script>

<svelte:head><title>credarr design system</title></svelte:head>

<main class="ds-page">
  <header class="ds-head">
    <div>
      <p class="ds-kicker">Internal · development only</p>
      <h1>Credarr design system</h1>
      <p class="ds-lede">
        The living reference for the console. It uses the real tokens and
        components; if this page and a screen disagree, the screen is wrong.
      </p>
    </div>
    <a class="ds-back" href="/">Back to the console</a>
  </header>

  <section class="ds-section" aria-labelledby="ds-tokens">
    <h2 id="ds-tokens">Ink and surface</h2>
    <p class="ds-note">
      Surfaces step by luminance. One cool accent marks interaction; green,
      amber and red are reserved for state. No hue gradients, glows or
      decorative shadows.
    </p>
    <div class="ds-swatches">
      {#each [
        ["bg", "--bg"],
        ["surface", "--panel"],
        ["raised", "--panel-2"],
        ["well", "--well"],
        ["border", "--line-strong"],
        ["accent", "--accent"],
        ["ok", "--ok"],
        ["warn", "--warn"],
        ["bad", "--bad"],
      ] as [label, token] (token)}
        <div class="ds-swatch">
          <span class="ds-chip" style={`background: var(${token})`}></span>
          <span>{label}</span>
          <code>{token}</code>
        </div>
      {/each}
    </div>
  </section>

  <section class="ds-section" aria-labelledby="ds-type">
    <h2 id="ds-type">Type</h2>
    <p class="ds-note">
      One sans for the interface, one mono for values, times and keys. Hierarchy
      comes from size and colour before weight.
    </p>
    <div class="ds-type">
      <h1>Apps</h1>
      <h2>A rotation did not finish</h2>
      <h3>Connection</h3>
      <p>Body copy sits at 14px with a 1.6 line height. It should read as a sentence, not a label.</p>
      <p class="muted">Secondary copy names a cause, a consequence or a next step.</p>
      <p class="ds-mono">10/31/2026, 8:49:23 PM · sonarr_api_key</p>
    </div>
  </section>

  <section class="ds-section" aria-labelledby="ds-status">
    <h2 id="ds-status">Status marks</h2>
    <p class="ds-note">
      A word with a dot. The word carries the meaning; the dot is a second cue.
      Never use colour alone, and never put every state in a pill.
    </p>
    <div class="ds-row">
      {#each ["match", "live", "drift", "missing", "unverifiable", "manual", "no_holders", "none", "enabled", "off", "paused"] as status (status)}
        <StatusPill {status} />
      {/each}
    </div>
  </section>

  <section class="ds-section" aria-labelledby="ds-keys">
    <h2 id="ds-keys">Key tiles</h2>
    <p class="ds-note">
      The app's identity anchor. The dot is decorative; the adjacent status word
      is the accessible signal.
    </p>
    <div class="ds-row">
      <KeyTile status="match" />
      <KeyTile status="drift" />
      <KeyTile status="unverifiable" />
      <KeyTile status="manual" />
      <KeyTile status="match" size="lg" />
      <KeyTile status="drift" size="lg" />
    </div>
  </section>

  <section class="ds-section" aria-labelledby="ds-buttons">
    <h2 id="ds-buttons">Controls</h2>
    <p class="ds-note">
      One primary action per section. Secondary actions are quiet; destructive
      actions are red and named. Touch targets grow on small screens.
    </p>
    <div class="ds-row">
      <button class="primary">Run audit</button>
      <button>Refresh</button>
      <button class="danger">Delete this app key</button>
      <button disabled>Disabled</button>
      <button class="link">A quiet link</button>
    </div>
    <div class="ds-form">
      <label class="field">
        URL (required)
        <input placeholder="http://sonarr:8989" />
      </label>
      <label class="field">
        API key
        <input type="password" placeholder="••••••••" />
      </label>
      <label class="field">
        Rotation
        <select><option>Backup &amp; restore</option></select>
      </label>
    </div>
  </section>

  <section class="ds-section" aria-labelledby="ds-messages">
    <h2 id="ds-messages">Messages</h2>
    <p class="ds-note">
      Banners interrupt only for a state that changes the meaning of the page.
      Routine success is a toast; a field error stays at the field.
    </p>
    <Banner tone="danger" role="alert" title="A rotation did not finish.">
      <p>Prowlarr API Key stopped 6 seconds ago. Resume it before relying on these copies.</p>
    </Banner>
    <Banner tone="warn" title="No drift found, but not every copy was compared.">
      <p>Sonarr could not read one copy back. This is not a match.</p>
    </Banner>
    <Banner tone="ok" title="No findings.">
      <p>Every readable copy matched; every exercised copy was accepted by its service.</p>
    </Banner>
  </section>

  <section class="ds-section" aria-labelledby="ds-empty">
    <h2 id="ds-empty">Empty states</h2>
    <p class="ds-note">An empty state names what is missing and the one next action.</p>
    <EmptyState title="No apps yet" icon="import">
      <p>Nothing is declared yet. An empty store is not a clean audit: nothing is measured.</p>
    </EmptyState>
  </section>

  <section class="ds-section" aria-labelledby="ds-table">
    <h2 id="ds-table">Ledger rows</h2>
    <p class="ds-note">
      The same grammar as the Apps ledger: identity, state, evidence, action.
      On narrow screens a row becomes a small card; column labels survive as
      inline labels rather than disappearing.
    </p>
    <div class="apps-ledger">
      <div class="apps-ledger-head" aria-hidden="true">
        <span>App</span><span>State</span><span>Copies</span><span></span>
      </div>
      <div class="card app-card" role="link" tabindex="0" aria-label="Open Sonarr API Key">
        <div class="app-main">
          <KeyTile status="match" />
          <div class="app-title">
            <h3>Sonarr API Key</h3>
            <p class="app-url">http://127.0.0.1:8989</p>
          </div>
        </div>
        <div class="app-state">
          <div class="app-status-line"><StatusPill status="match" /></div>
          <p class="status-why">The stored value and the observed copy agree.</p>
        </div>
        <div class="app-copies"><p class="app-copy-line">Used in: Seerr, Homepage</p></div>
        <span class="app-open">›</span>
      </div>
      <div class="card app-card" role="link" tabindex="0" aria-label="Open Prowlarr API Key">
        <div class="app-main">
          <KeyTile status="unverifiable" />
          <div class="app-title">
            <h3>Prowlarr API Key</h3>
            <p class="app-url">http://127.0.0.1:9696</p>
          </div>
        </div>
        <div class="app-state">
          <div class="app-status-line"><StatusPill status="unverifiable" /></div>
          <p class="status-why">The audit could not compare a value. This is not a match.</p>
        </div>
        <div class="app-copies"><p class="app-copy-line">Used in: Sonarr</p></div>
        <span class="app-open">›</span>
      </div>
    </div>
  </section>

  <section class="ds-section" aria-labelledby="ds-header">
    <h2 id="ds-header">Page header</h2>
    <p class="ds-note">One h1, one sentence of context, one group of actions.</p>
    <PageHeader title="Apps" description="Where each credential lives, whether every copy agrees, and what a rotation would touch." />
  </section>
</main>

<style>
  .ds-page {
    max-width: 1080px;
    margin: 0 auto;
    padding: 2rem 2rem 5rem;
  }
  .ds-head {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 1rem;
    flex-wrap: wrap;
    padding-bottom: 1.5rem;
    margin-bottom: 1.5rem;
    border-bottom: 1px solid var(--line);
  }
  .ds-kicker {
    margin: 0 0 0.35rem;
    color: var(--dim-2);
    font-size: 0.7rem;
    font-weight: 600;
  }
  .ds-lede {
    max-width: 62ch;
    margin: 0.4rem 0 0;
    color: var(--dim);
  }
  .ds-back { font-size: 0.8rem; }
  .ds-section { margin: 2rem 0; }
  .ds-section h2 { margin: 0 0 0.25rem; font-size: 1.1rem; }
  .ds-note {
    max-width: 76ch;
    margin: 0 0 0.9rem;
    color: var(--dim);
    font-size: 0.82rem;
  }
  .ds-swatches {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(9rem, 1fr));
    gap: 0.6rem;
  }
  .ds-swatch {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    padding: 0.65rem;
    border: 1px solid var(--line);
    border-radius: var(--radius-sm);
    background: var(--panel);
    font-size: 0.76rem;
  }
  .ds-chip {
    height: 2rem;
    border-radius: 5px;
    border: 1px solid var(--line-strong);
  }
  .ds-swatch code { align-self: flex-start; font-size: 0.68rem; }
  .ds-type { display: flex; flex-direction: column; gap: 0.25rem; }
  .ds-type h1, .ds-type h2, .ds-type h3, .ds-type p { margin: 0; }
  .ds-type h1 { margin-top: 0.3rem; }
  .ds-mono { font-family: var(--font-mono); font-size: 0.76rem; color: var(--dim); }
  .ds-row {
    display: flex;
    align-items: center;
    gap: 0.8rem;
    flex-wrap: wrap;
    margin: 0.6rem 0;
  }
  .ds-form {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr));
    gap: 0.85rem;
    margin-top: 1rem;
  }
  @media (max-width: 720px) {
    .ds-page { padding: 1.25rem 1rem 3rem; }
  }
</style>
