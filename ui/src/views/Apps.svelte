<script>
  import { onMount, tick } from "svelte";
  import {
    api,
    ApiError,
    createOrUpdate,
    errorText,
    serviceDefinitions,
    timestamp,
  } from "../lib/api.js";
  import Banner from "../lib/Banner.svelte";
  import EmptyState from "../lib/EmptyState.svelte";
  import Icon from "../lib/Icon.svelte";
  import PageHeader from "../lib/PageHeader.svelte";
  import StatusPill from "../lib/StatusPill.svelte";
  import TopologyImport from "../lib/TopologyImport.svelte";
  import { toast } from "../lib/toast.js";
  import {
    buildApps,
    copyNames,
    missingCopyServices,
    titleOfCredential,
    titleOfService,
  } from "../lib/apps.js";
  import { serviceById, SERVICE_CATALOG, defaultPort } from "../lib/setupCatalog.js";
  import {
    credentialPayload,
    newCredential,
    newHolder,
    serviceKind,
    serviceUrlError,
    suggestionsFor,
  } from "../lib/setup.js";
  import {
    credentialReason,
    fixHint,
    stackHealth,
    statusOf,
    statusRank,
  } from "../lib/status.js";

  // Apps is the console's home: one card per app, each card the credential
  // joined to its service. Connecting, testing, storing a key and watching
  // copies happen here; the detail page is for rotation and surgery.
  let {
    status,
    credentials,
    busy,
    onrun,
    onrefresh,
    onopen,
    onsetup = null,
    onsignout,
  } = $props();

  const READ_TIMEOUT = 10_000;

  let definitions = $state([]);
  let servicesLoading = $state(true);
  let servicesError = $state("");
  let query = $state("");
  let showAdd = $state(false);
  let addService = $state("");
  let addUrl = $state("");
  let addKey = $state("");
  let addBusy = $state(false);
  let addError = $state("");
  let tests = $state({});
  let keyInputs = $state({});
  let urlInputs = $state({});
  let keyBusy = $state("");
  let actionError = $state("");

  const rows = $derived(credentials?.credentials ?? []);
  const observed = $derived(credentials?.observed_run ?? null);
  const topology = $derived(status?.topology ?? { imported: false });
  const health = $derived(stackHealth(status, credentials));
  const joined = $derived(buildApps({ credentials: rows, definitions }));
  const availableServices = $derived(
    SERVICE_CATALOG.filter(
      (service) =>
        !service.holderOnly &&
        !joined.apps.some((app) => app.id === service.id) &&
        !joined.unconnected.some((item) => item.id === service.id),
    ),
  );

  const visibleApps = $derived(
    [...joined.apps]
      .filter((app) => {
        const needle = query.trim().toLowerCase();
        if (!needle) return true;
        return `${app.title} ${app.id} ${app.row.status ?? ""}`.toLowerCase().includes(needle);
      })
      .sort(
        (a, b) =>
          statusRank(a.row.status) - statusRank(b.row.status) ||
          a.title.localeCompare(b.title),
      ),
  );

  function failed(failure) {
    if (failure instanceof ApiError && failure.status === 401) onsignout();
    else actionError = errorText(failure);
  }

  async function loadServices() {
    servicesLoading = true;
    servicesError = "";
    try {
      definitions = await serviceDefinitions({ timeout: 60_000 });
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else servicesError = errorText(failure);
    } finally {
      servicesLoading = false;
    }
  }

  onMount(loadServices);

  async function refreshAll() {
    await Promise.all([onrefresh(), loadServices()]);
  }

  // The probe needs the service id; the result belongs to one card, keyed by
  // credential name so two keys for one service never share a verdict.
  async function testConnection(serviceId, url, key = "", stateKey = null) {
    const slot = stateKey ?? serviceId;
    tests[slot] = { busy: true, ok: false, detail: "" };
    try {
      const answer = await api("/services/test", {
        method: "POST",
        body: { service: serviceId, url: url.trim(), key: key.trim() || null },
        timeout: 20_000,
      });
      tests[slot] = {
        busy: false,
        ok: Boolean(answer?.ok),
        detail:
          answer?.detail ??
          (answer?.ok ? "Connection accepted." : "The service refused the test."),
      };
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        onsignout();
        return;
      }
      tests[slot] = { busy: false, ok: false, detail: errorText(failure) };
    }
  }

  function prefilledConsumers(owner, serviceIds) {
    const consumers = [];
    for (const suggestion of suggestionsFor(owner)) {
      if (!suggestion.writer) continue;
      if (!serviceIds.includes(suggestion.service)) continue;
      consumers.push(
        newHolder(suggestion.service, suggestion.slot, suggestion.qualifier ?? ""),
      );
    }
    return consumers;
  }

  // Connect an app end to end: the service definition, its credential with
  // the usual copies, then the key itself. One call per resource, in that
  // order; a failure names the step instead of leaving half a stack.
  async function connectApp(id, url, key, { serviceExists = false } = {}) {
    const cleanUrl = url.trim();
    const urlIssue = serviceUrlError(cleanUrl);
    if (urlIssue) throw new Error(`${titleOfService(id)}: ${urlIssue}`);
    if (serviceExists) {
      // A seeded definition can exist with no credential; adding the app must
      // attach to it and apply the URL, not POST the same name into a 409.
      await api(`/services/${encodeURIComponent(id)}`, {
        method: "PATCH",
        body: { url: cleanUrl },
        timeout: READ_TIMEOUT,
      });
    } else {
      // A retry after the key write failed finds the service already created;
      // patching it applies the current URL instead of failing on 409.
      await createOrUpdate(
        "/services",
        { name: id, kind: serviceKind(id), url: cleanUrl },
        { timeout: READ_TIMEOUT },
      );
    }
    const draft = {
      services: [...new Set([...definitions.map((item) => item.name), id])],
      credentials: rows,
    };
    const credential = newCredential(draft, id);
    credential.consumers = prefilledConsumers(id, draft.services);
    const created = await createOrUpdate("/credentials", credentialPayload(credential), {
      timeout: READ_TIMEOUT,
    });
    const name = created?.name ?? credential.name;
    if (key.trim()) {
      await api(`/credentials/${encodeURIComponent(name)}/value`, {
        method: "PUT",
        body: { value: key.trim() },
        timeout: READ_TIMEOUT,
      });
    }
    return name;
  }

  async function submitAdd(event) {
    event.preventDefault();
    if (addBusy || !addService) return;
    addBusy = true;
    addError = "";
    try {
      const serviceExists = definitions.some(
        (item) => item.name === addService,
      );
      await connectApp(addService, addUrl, addKey, { serviceExists });
      addService = "";
      addUrl = "";
      addKey = "";
      showAdd = false;
      toast();
      await Promise.all([onrefresh(), loadServices()]);
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else addError = errorText(failure);
    } finally {
      addBusy = false;
    }
  }

  async function connectExisting(item) {
    const key = (keyInputs[item.id] ?? "").trim();
    const url = (urlInputs[item.id] ?? item.url ?? "").trim();
    keyBusy = item.id;
    actionError = "";
    try {
      await connectApp(item.id, url, key, { serviceExists: true });
      keyInputs[item.id] = "";
      delete urlInputs[item.id];
      toast();
      await Promise.all([onrefresh(), loadServices()]);
    } catch (failure) {
      failed(failure);
    } finally {
      keyBusy = "";
    }
  }

  // A copy whose service is not connected cannot be looked for. The fix is
  // the Add form with that service preselected: it collects the URL the
  // server requires instead of posting a definition that is refused.
  let addSelect = $state(null);

  function openAddFor(serviceId) {
    actionError = "";
    addService = serviceId;
    showAdd = true;
    tick().then(() => {
      document.getElementById("apps-add")?.scrollIntoView({ block: "start" });
      addSelect?.focus({ preventScroll: true });
    });
  }

</script>

<PageHeader title="Apps">
  {#snippet actions()}
    <button onclick={refreshAll} disabled={busy}>Refresh</button>
    {#if topology.imported}
      <button onclick={() => (showAdd = !showAdd)}>Add app</button>
    {/if}
    <button class="primary" onclick={onrun} disabled={busy || !topology.imported}>
      {busy ? "Auditing…" : "Run audit"}
    </button>
  {/snippet}
</PageHeader>

{#if actionError}<Banner tone="danger">{actionError}</Banner>{/if}

<section class="health-card {health.tone}" aria-live="polite">
  <div class="health-kicker">
    <span>Stack health</span>
  </div>
  <h2 class="health-title">{health.title}</h2>
  <p class="health-why">{health.why}</p>
  {#if status?.last_audit}
    <div class="health-meta">
      <span>Last run <strong>{timestamp(status.last_audit.finished_at)}</strong></span>
    </div>
  {/if}
</section>

{#if !topology.imported}
  <EmptyState title="No apps yet" icon="import">
    <p>
      Nothing is declared yet. An empty store is not a clean audit: nothing is
      measured.
    </p>
    {#snippet actions()}
      <button class="primary" onclick={() => (showAdd = true)}>Add an app</button>
      {#if onsetup}
        <button onclick={onsetup}>Resume setup</button>
      {/if}
    {/snippet}
  </EmptyState>
  <section class="card section">
    <TopologyImport onimported={onrefresh} {onsignout} />
  </section>
{/if}

{#if showAdd}
  <section class="card section" id="apps-add" aria-labelledby="apps-add-title">
      <div class="section-head">
        <div><h3 id="apps-add-title">Connect an app</h3></div>
        <button type="button" onclick={() => (showAdd = false)}>Close</button>
      </div>
      {#if availableServices.length === 0}
        <p class="muted">Every known service already has a key.</p>
      {:else}
        {#if addError}<Banner tone="danger">{addError}</Banner>{/if}
        <form onsubmit={submitAdd}>
          <div class="field-grid align-start">
            <label class="field">
              App (required)
              <select
                bind:value={addService}
                bind:this={addSelect}
                disabled={addBusy}
                aria-label="App"
              >
                <option value="">Choose an app…</option>
                {#each availableServices as service (service.id)}
                  <option value={service.id}>{service.label}</option>
                {/each}
              </select>
            </label>
            <label class="field">
              URL (required)
              <input
                bind:value={addUrl}
                placeholder={addService ? `http://${addService}:${defaultPort(addService)}` : "http://sonarr:8989"}
                autocomplete="off"
                spellcheck="false"
                disabled={addBusy}
              />
            </label>
            <label class="field">
              API key (optional)
              <input
                type="password"
                bind:value={addKey}
                autocomplete="off"
                spellcheck="false"
                disabled={addBusy}
              />
            </label>
          </div>
          <div class="toolbar">
            <button
              type="button"
              onclick={() => testConnection(addService, addUrl, addKey, `add:${addService}`)}
              disabled={addBusy || !addService || !addUrl.trim() || tests[`add:${addService}`]?.busy}
            >
              {tests[`add:${addService}`]?.busy ? "Testing…" : "Test"}
            </button>
            {#if tests[`add:${addService}`]?.detail}
              <span class={tests[`add:${addService}`].ok ? "muted" : "error"}>
                {tests[`add:${addService}`].detail}
              </span>
            {/if}
            <span class="spacer"></span>
            <button class="primary" type="submit" disabled={addBusy || !addService || !addUrl.trim()}>
              {addBusy ? "Connecting…" : "Connect"}
            </button>
          </div>
        </form>
        <p class="field-help">
          The usual copies are watched automatically. Add the key now or later;
          either way the next audit explains what it could not compare.
        </p>
      {/if}
    </section>
  {/if}

  {#if servicesError}
    <Banner tone="warn" title="Could not read service connections.">
      {servicesError}
      <p class="muted">Keys and statuses are current; service URLs are missing.</p>
    </Banner>
  {/if}

  {#if topology.imported}
  <div class="table-tools">
    <label class="search">
      <Icon name="search" size={15} />
      <input
        bind:value={query}
        type="search"
        placeholder="Filter apps…"
        aria-label="Filter apps"
      />
    </label>
    <span class="count">{visibleApps.length} of {joined.apps.length}</span>
  </div>

  {#if servicesLoading}
    <p class="muted">Reading service connections…</p>
  {:else}
    <div class="apps-grid">
      {#each visibleApps as app (app.name)}
        {@const copies = copyNames(app.row)}
        {@const missing = missingCopyServices(app.row, definitions)}
        <div
          class="card app-card"
          role="link"
          tabindex="0"
          aria-label={`Open ${app.title}`}
          onclick={() => onopen(app.name)}
          onkeydown={(event) => {
            // A key pressed inside a nested button belongs to that button.
            if (event.target !== event.currentTarget) return;
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              onopen(app.name);
            }
          }}
        >
          <div class="section-head">
            <div>
              <h3 id={`app-${app.name}`}>{app.title}</h3>
              <p class="muted">{app.url || "no URL yet"}</p>
            </div>
            <div class="toolbar">
              <StatusPill status={app.row.status ?? statusOf(app.row)} />
              {#if app.manualCopies.length}
                <StatusPill
                  status="manual"
                  label="manual"
                  title={`Manual copies: ${app.manualCopies.join(", ")}`}
                />
              {/if}
              {#if !app.stored}
                <StatusPill status="none" label="no key yet" />
              {/if}
            </div>
          </div>

          <p class="status-why">
            {#if app.row.status}
              {app.row.detail || credentialReason(app.row, observed)}
            {:else}
              {credentialReason(app.row, observed)}
            {/if}
          </p>
          {#if fixHint(app.row)}
            <p class="status-why">{fixHint(app.row)}</p>
          {/if}

          <p class="muted">{copies.length ? `Used in: ${copies.join(", ")}` : "Nothing holds this key yet."}</p>

          {#if missing.length && !servicesError}
            <p class="field-warn">
              {missing.map(titleOfService).join(", ")} holds a copy but is not
              connected. Connect it below to watch those copies.
            </p>
          {/if}
          {#if missing.length && !servicesError}
            <div class="toolbar">
              {#each missing.filter((serviceId) => !servicesError) as serviceId (serviceId)}
                <button
                  onclick={(event) => {
                    event.stopPropagation();
                    openAddFor(serviceId);
                  }}
                >
                  Connect {titleOfService(serviceId)}
                </button>
              {/each}
            </div>
          {/if}
        </div>
      {/each}
    </div>

    {#if joined.unconnected.length}
      <section class="card section" aria-labelledby="apps-unconnected-title">
        <div class="section-head">
          <div><h3 id="apps-unconnected-title">Not connected</h3></div>
        </div>
        {#each joined.unconnected as item (item.id)}
          <div class="app-line">
            <strong>{item.title}</strong>
            {#if serviceById(item.id)}
              <input
                value={urlInputs[item.id] ?? item.url ?? ""}
                oninput={(event) => (urlInputs[item.id] = event.currentTarget.value)}
                autocomplete="off"
                spellcheck="false"
                aria-label={`Set the ${item.title} URL`}
                placeholder="http://sonarr:8989"
              />
              <input
                type="password"
                bind:value={keyInputs[item.id]}
                autocomplete="new-password"
                spellcheck="false"
                aria-label={`Set the ${item.title} key`}
                placeholder="paste the API key"
              />
              <button
                onclick={() => connectExisting(item)}
                disabled={keyBusy === item.id || !(urlInputs[item.id] ?? item.url ?? "").trim()}
              >
                {keyBusy === item.id ? "Connecting…" : "Connect"}
              </button>
            {:else}
              <span class="muted">not in the catalog</span>
            {/if}
          </div>
        {/each}
      </section>
    {/if}

    {#if joined.unassigned.length}
      <section class="card section" aria-labelledby="apps-unassigned-title">
        <div class="section-head">
          <div><h3 id="apps-unassigned-title">Needs attention</h3></div>
        </div>
        {#each joined.unassigned as row (row.name)}
          <div class="app-line">
            <strong>{titleOfCredential(row)}</strong>
            <span class="muted">This key does not match any known app.</span>
            <button onclick={() => onopen(row.name)}>Open</button>
          </div>
        {/each}
      </section>
    {/if}
  {/if}
  {/if}
