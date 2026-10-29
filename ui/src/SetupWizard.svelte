<script>
  import { onMount, tick } from "svelte";
  import {
    api,
    ApiError,
    auditStack,
    createOrUpdate,
    errorText,
    serviceDefinitions,
    timestamp,
  } from "./lib/api.js";
  import Banner from "./lib/Banner.svelte";
  import Icon from "./lib/Icon.svelte";
  import StatusPill from "./lib/StatusPill.svelte";
  import TopologyImport from "./lib/TopologyImport.svelte";
  import { credentialReason, fixHint, statusOf } from "./lib/status.js";
  import {
    SERVICE_CATALOG,
    WRITE_MECHANISMS,
    defaultCredentialName,
    defaultPort,
    describeHolder,
    mechanismOptions,
    serviceById,
    targetString,
  } from "./lib/setupCatalog.js";
  import { credentialTitle, plainEngineText } from "./lib/names.js";
  import {
    clearDraft,
    credentialField,
    credentialPayload,
    draftFromTopology,
    emptyDraft,
    ensureService,
    holderField,
    holderMeta,
    holderTarget,
    loadDraft,
    mechanismOf,
    newCredential,
    newHolder,
    prefillHolders,
    removeService,
    resetForOwner,
    saveDraft,
    serviceFact,
    serviceFactValue,
    serviceKind,
    serviceUrlError,
    serviceUsage,
    storageAvailable,
    suggestionsFor,
    targetIsRepeatable,
    toYaml,
    uniqueCredentialName,
    validateDraft,
  } from "./lib/setup.js";

  // The first-run path: admin password (Auth) -> this wizard -> the console.
  // The server's `topology.imported` is the completion signal, not a draft
  // flag; a reload after import therefore lands on the normal Overview.
  let { onfinish, onskip = null, onsignout, mode = "create", fresh = false } = $props();
  const editing = $derived(mode === "edit");

  const STEPS = [
    {
      label: "Connect",
      description:
        "Pick the apps in this stack. Each one needs its URL and API key.",
    },
    {
      label: "Copies",
      description:
        "Which copies of each key to watch, and whether to rotate automatically.",
    },
    {
      label: "Review",
      description: "Review what the console will create.",
    },
    {
      label: "Done",
      description:
        "Runs by itself after setup. A key with no stored value reads as unverifiable, not match.",
    },
  ];

  const READ_TIMEOUT = 10_000;
  const DISCOVERY_TIMEOUT = 15_000;

  let step = $state(0);
  let draft = $state(emptyDraft());
  let loaded = $state(false);
  let restored = $state(false);
  let loadedFromTopology = $state(false);
  let loadError = $state("");
  let draftAvailable = $state(true);
  let attempted = $state(false);
  let stepHeading = $state(null);
  let errorSummary = $state(null);
  let saveTimer = 0;
  // Service keys live only in this component and only until the topology is
  // created. They are deliberately not part of `draft`, which is serialised.
  let serviceKeys = $state({});
  let serviceTests = $state({});
  // Auto-rotation chosen in the wizard, keyed by credential id. Wizard-only:
  // the store has its own policy row, applied after the topology is created.
  let autoPolicies = $state({});
  let autoPolicyError = $state("");

  const validation = $derived(validateDraft(draft));
  const manifestYaml = $derived(
    validation.manifest ? toYaml(validation.manifest) : "",
  );
  const counts = $derived(validation.counts);
  function serviceHasStoredKey(serviceId) {
    return draft.credentials.some(
      (credential) => credential.owner === serviceId && credential.stored === true,
    );
  }

  const missingKeyServices = $derived(
    editing
      ? []
      : draft.services.filter((id) => !(serviceKeys[id] ?? "").trim()),
  );
  const stepIssues = $derived([
    ...issuesFor(step, attempted, validation),
    ...(step === 0 && attempted
      ? missingKeyServices.map(
          (id) => `Enter the API key for ${serviceById(id)?.label ?? id}.`,
        )
      : []),
  ]);

  let discovery = $state(null);
  let discoveryBusy = $state(false);
  let discoveryError = $state("");
  let discoveryNote = $state("");

  let imported = $state(false);
  let importedCount = $state(0);
  let importing = $state(false);
  let importError = $state("");
  let auditRun = $state(null);
  let auditRows = $state([]);
  let auditObserved = $state(null);
  let auditRowsError = $state("");
  let auditError = $state("");
  let auditBusy = $state(false);
  let auditSeq = 0;

  const auditStored = $derived(auditRows.filter((row) => row.stored).length);
  const auditLimited = $derived(
    auditRows.some(
      (row) =>
        (row.consumers?.length ?? 0) === 0 ||
        ["unverifiable", "live", "indirect", "absent"].includes(
          row.status,
        ),
    ),
  );
  const auditTitle = $derived(
    auditTitleFor(auditRun, auditStored, auditLimited, auditRows.length),
  );
  const auditTone = $derived(
    auditToneFor(auditRun, auditStored, auditLimited),
  );

  function issuesFor(current, wasAttempted, result) {
    if (current === 0) return wasAttempted ? result.services : [];
    if (current === 1) {
      if (!wasAttempted) return [];
      const issues = [...result.services, ...result.credentials];
      if (Object.keys(result.errors).length > 0) {
        issues.push("Fix the fields marked below.");
      }
      return issues;
    }
    if (current === 2) {
      return result.ok
        ? []
        : [
            "The draft still has errors. Go back to Copies and fix them before creating the topology.",
          ];
    }
    return [];
  }

  function auditTitleFor(run, stored, limited, rows) {
    if (!run) return "";
    if (run.exit_status === "match" && stored > 0 && !limited) {
      return "Audit complete: every declared copy matches.";
    }
    if (["drift", "missing", "error"].includes(run.exit_status)) {
      return "Audit found copies that need attention.";
    }
    if (rows === 0) {
      return "Audit finished, but the server returned no app rows.";
    }
    return "Audit complete; some copies could not be compared.";
  }

  function auditToneFor(run, stored, limited) {
    if (!run) return "quiet";
    if (run.exit_status === "match" && stored > 0 && !limited) return "ok";
    if (["drift", "missing", "error"].includes(run.exit_status)) return "danger";
    return "warn";
  }

  function describedBy(key, extra = "") {
    const ids = [];
    if (validation.errors[key]) ids.push(`${key}-error`);
    if (extra) ids.push(extra);
    return ids.length ? ids.join(" ") : undefined;
  }

  function targetErrorId(credential, holder) {
    return `${holderField(credential, holder, "target")}-error`;
  }

  function availableSuggestions(credential) {
    const present = new Set(
      credential.consumers.map((holder) => holderTarget(holder)),
    );
    const claimed = new Set(
      draft.credentials
        .filter((item) => item.id !== credential.id)
        .flatMap((item) =>
          item.consumers.map((holder) => holderTarget(holder)),
        ),
    );
    return suggestionsFor(credential.owner).filter((suggestion) => {
      const identity = targetString(suggestion);
      return (
        !present.has(identity) &&
        (!claimed.has(identity) || targetIsRepeatable(identity))
      );
    });
  }

  async function focusStep() {
    await tick();
    stepHeading?.focus();
  }

  async function focusError() {
    await tick();
    if (errorSummary) {
      errorSummary.focus();
      return;
    }
    document.querySelector('[aria-invalid="true"]')?.focus();
  }

  function browserStorage() {
    try {
      return globalThis.localStorage;
    } catch {
      return null;
    }
  }

  function saveNow() {
    if (imported) return;
    draftAvailable = saveDraft(browserStorage(), draft, step);
  }

  $effect(() => {
    if (!loaded || imported) return;
    // Reading these fields is the point: any draft or step change schedules a
    // save. The key and every credential value live outside this object.
    JSON.stringify({
      step,
      services: draft.services,
      credentials: draft.credentials,
    });
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      draftAvailable = saveDraft(browserStorage(), draft, step);
    }, 250);
    return () => clearTimeout(saveTimer);
  });

  // A typed service key belongs to one credential, chosen once: the
  // default-named credential when it exists, otherwise one this wizard creates.
  // Never "the first credential of that service" - in edit mode that could be
  // an unrelated credential whose value would then be overwritten.
  let serviceCredentialIds = $state({});

  function serviceCredentialFor(serviceId) {
    const id = serviceCredentialIds[serviceId];
    const remembered = id
      ? draft.credentials.find((credential) => credential.id === id)
      : null;
    if (remembered) return remembered;
    return (
      draft.credentials.find(
        (credential) => credential.name === defaultCredentialName(serviceId),
      ) ?? null
    );
  }

  // A credential for one *arr almost always feeds Prowlarr and/or Seerr. Those
  // rows are filled in when the credential is created, but only for services
  // this operator selected: guessing an app into the stack would be worse than
  // an empty holder list. Deploy-time-only targets (Homepage labels) are never
  // guessed: this build cannot read the deployed copy back, and declaring one
  // would block the clean-audit gate for a copy nobody asserted.
  function setServiceKey(serviceId, value) {
    serviceKeys[serviceId] = value;
    if (!value.trim()) return;
    let credential = serviceCredentialFor(serviceId);
    if (!credential) {
      credential = newCredential(draft, serviceId);
      credential.description = `The API key for ${serviceById(serviceId)?.label ?? serviceId}.`;
      draft.credentials = [...draft.credentials, credential];
      attempted = false;
    }
    serviceCredentialIds[serviceId] = credential.id;
  }

  async function testService(serviceId) {
    const fact = serviceFactValue(draft, serviceId);
    const issue = serviceUrlError(fact.url);
    if (issue) {
      serviceTests[serviceId] = { busy: false, ok: false, detail: issue };
      return;
    }
    serviceTests[serviceId] = { busy: true, ok: false, detail: "" };
    try {
      const answer = await api("/services/test", {
        method: "POST",
        body: {
          service: serviceId,
          url: fact.url.trim(),
          key: serviceKeys[serviceId]?.trim() || null,
        },
        timeout: 20_000,
      });
      serviceTests[serviceId] = {
        busy: false,
        ok: Boolean(answer?.ok),
        detail: answer?.detail ?? (answer?.ok ? "Connection accepted." : "The service refused the test."),
      };
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        onsignout?.();
        return;
      }
      serviceTests[serviceId] = {
        busy: false,
        ok: false,
        detail: errorText(failure),
      };
    }
  }

  async function storeServiceKeys() {
    for (const [serviceId, value] of Object.entries(serviceKeys)) {
      const text = value.trim();
      if (!text) continue;
      const credential = serviceCredentialFor(serviceId);
      if (!credential) {
        // The operator typed a key, then removed its credential. Failing the
        // save is the only honest outcome: clearing the field is visible, a
        // silent "Topology saved" with an unrooted key is not.
        const label = serviceById(serviceId)?.label ?? serviceId;
        throw new Error(
          `The ${label} key has no credential to store it; add a credential for it, or clear the key.`,
        );
      }
      await api(`/credentials/${encodeURIComponent(credential.name)}/value`, {
        method: "PUT",
        body: { value: text },
        timeout: READ_TIMEOUT,
      });
      serviceKeys[serviceId] = "";
    }
  }

  async function loadLiveDraft() {
    loadError = "";
    try {
      const [definitions, credentialsAnswer] = await Promise.all([
        serviceDefinitions({ timeout: READ_TIMEOUT }),
        api("/credentials", { timeout: READ_TIMEOUT }),
      ]);
      draft = draftFromTopology(
        definitions,
        credentialsAnswer?.credentials ?? [],
      );
      // Services is step 0; reopening the editor must not land on Credentials.
      step = 0;
      loadedFromTopology = true;
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        onsignout?.();
        return;
      }
      loadError = errorText(failure);
    } finally {
      loaded = true;
      focusStep();
    }
  }

  onMount(() => {
    const storage = browserStorage();
    draftAvailable = storageAvailable(storage);
    // A re-run starts over: the saved step belongs to a draft the operator
    // walked away from, not to the topology being edited now.
    const saved = fresh ? null : loadDraft(storage);
    if (saved) {
      draft = saved.draft;
      step = saved.step;
      restored = true;
      loaded = true;
      focusStep();
      return;
    }
    if (editing) {
      loadLiveDraft();
      return;
    }
    loaded = true;
    focusStep();
  });

  function advance(next) {
    step = next;
    attempted = false;
    saveNow();
    focusStep();
  }

  function goNext() {
    if (step === 0) {
      if (validation.services.length > 0 || draft.services.length === 0) {
        attempted = true;
        focusError();
        return;
      }
      if (missingKeyServices.length > 0) {
        attempted = true;
        focusError();
        return;
      }
      // Copies are proposed only when the operator leaves Connect, not while
      // they are still trying services. That keeps an accidental selection
      // removable without first hunting through Copies.
      if (!editing) {
        for (const credential of draft.credentials) prefillHolders(draft, credential);
      }
      advance(1);
      return;
    }
    if (step === 1) {
      if (!validation.ok) {
        attempted = true;
        focusError();
        return;
      }
      advance(2);
    }
  }

  function goBack() {
    if (importing || step <= 0 || step >= 3) return;
    importError = "";
    step -= 1;
    attempted = false;
    saveNow();
    focusStep();
  }

  function handleSubmit(event) {
    event.preventDefault();
    if (step === 2) {
      createTopology();
      return;
    }
    goNext();
  }

  function skipSetup() {
    if (imported) return;
    saveNow();
    onskip?.();
  }

  function leave() {
    saveNow();
    onsignout?.();
  }

  function finish(view = "apps") {
    onfinish?.(view);
  }

  function importedTopology() {
    clearDraft(browserStorage());
    finish("overview");
  }

  function toggleService(serviceId, checked) {
    if (checked) {
      ensureService(draft, serviceId);
    } else {
      if (!removeService(draft, serviceId)) return;
      delete serviceKeys[serviceId];
      delete serviceTests[serviceId];
      delete serviceCredentialIds[serviceId];
      for (const id of Object.keys(autoPolicies)) {
        if (!draft.credentials.some((credential) => credential.id === id)) {
          delete autoPolicies[id];
        }
      }
    }
    attempted = false;
  }

  function useProposal(proposal) {
    const service = serviceById(proposal.system);
    if (!service) {
      discoveryNote = `This build has no catalog entry for ${proposal.system}. Add it to the manifest manually.`;
      return;
    }
    ensureService(draft, service.id);
    discoveryNote = `${service.label} is selected as a service. This did not add a credential or a holder.`;
    attempted = false;
  }

  async function scanDocker() {
    discoveryBusy = true;
    discoveryError = "";
    discoveryNote = "";
    try {
      const answer = await api("/discovery", { timeout: DISCOVERY_TIMEOUT });
      discovery = answer;
      if (answer?.error) {
        discoveryError = answer.error;
      } else if (answer?.enabled === false) {
        discoveryNote =
          answer.note ??
          "Docker discovery is off. Set CREDARR_DOCKER_URL to a read-only socket proxy to propose undeclared services.";
      } else if (!answer?.proposals?.length) {
        discoveryNote = "No undeclared services were proposed.";
      }
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        onsignout?.();
        return;
      }
      discoveryError = errorText(failure);
    } finally {
      discoveryBusy = false;
    }
  }

  function addCredential() {
    // A credential belongs to a key-issuing app; one is created per connected
    // app automatically, and this is only for an extra key.
    const owner =
      draft.services.find((id) => serviceById(id)?.mint) ??
      draft.services[0] ??
      SERVICE_CATALOG.find((service) => service.mint)?.id ??
      SERVICE_CATALOG[0].id;
    ensureService(draft, owner);
    const credential = newCredential(draft, owner);
    draft.credentials = [...draft.credentials, credential];
    prefillHolders(draft, credential);
    attempted = false;
    tick().then(() =>
      document.getElementById(`setup-credential-${credential.id}`)?.focus(),
    );
  }

  // Gitea credentials choose how they rotate; anything else has one method.
  // "stored" is a password the tool never changes, so it becomes class B.
  function chooseMechanism(credential, value) {
    if (value === "stored") {
      credential.mechanism = "stored";
      credential.class = "B";
      credential.max_age_days = null;
      credential.never_rotate = true;
      credential.fields = {};
      if (
        credential.owner === "gitea" &&
        credential.name.replace(/_\d+$/, "") === "gitea_api_key"
      ) {
        credential.name = uniqueCredentialName(
          draft.credentials.filter((other) => other.id !== credential.id),
          "gitea_admin_password",
        );
      }
      return;
    }
    resetForOwner(credential, credential.owner);
    credential.mechanism = value;
  }

  function removeCredential(credential) {
    delete autoPolicies[credential.id];
    draft.credentials = draft.credentials.filter(
      (item) => item.id !== credential.id,
    );
  }

  function setCount(holder, value) {
    holder.count = value === "" ? null : Number(value);
  }

  function addHolder(credential, suggestion = null) {
    const chosen = suggestion ?? availableSuggestions(credential)[0];
    if (!chosen) return;
    // The service is not selected here: a copy for an app outside the stack is
    // flagged in its row with an "add it" action, never silently selected.
    credential.consumers = [
      ...credential.consumers,
      newHolder(chosen.service, chosen.slot, chosen.qualifier ?? ""),
    ];
    attempted = false;
  }

  // The row's "add it" action: select the service, then land where its URL
  // goes. A service without a URL cannot be looked for, so adding it without
  // showing the URL field would strand the operator a step later.
  function addServiceAndGo(serviceId) {
    if (serviceById(serviceId)?.holderOnly) return;
    ensureService(draft, serviceId);
    advance(0);
    tick().then(() => {
      const field = document.getElementById(`service-url-${serviceId}`);
      field?.scrollIntoView({ block: "center" });
      field?.focus({ preventScroll: true });
    });
  }

  function removeHolder(credential, holder) {
    credential.consumers = credential.consumers.filter(
      (item) => item.id !== holder.id,
    );
  }

  function changeHolderService(credential, holder, event) {
    const serviceId = event.currentTarget.value;
    holder.service = serviceId;
    holder.slot = serviceById(serviceId)?.targets?.[0]?.slot ?? "";
    attempted = false;
  }

  function changeHolderSlot(credential, holder, event) {
    holder.slot = event.currentTarget.value;
    attempted = false;
  }

  async function loadAuditRows() {
    try {
      const data = await api("/credentials", { timeout: READ_TIMEOUT });
      auditRows = Array.isArray(data?.credentials) ? data.credentials : [];
      auditObserved = data?.observed_run ?? null;
      auditRowsError = "";
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        onsignout?.();
        return;
      }
      auditRowsError = errorText(failure);
    }
  }

  // serviceKind lives in setup.js: the Apps view creates service definitions
  // too, and the mapping must not drift between the two.

  // The wizard's auto-rotation choices are applied after every key
  // exists. A failure here is a warning, not a failed setup: the topology is
  // already written, and the operator can fix the policy on the app page.
  async function applyAutoRotations() {
    autoPolicyError = "";
    for (const credential of draft.credentials) {
      const policy = autoPolicies[credential.id];
      if (!policy?.enabled) continue;
      if (!serviceById(credential.owner)?.mint) continue;
      try {
        await api(
          `/credentials/${encodeURIComponent(credential.name)}/auto-rotation`,
          {
            method: "PUT",
            body: {
              enabled: true,
              every_days: Math.max(1, Number(policy.days) || 30),
              confirm: credential.name,
            },
            timeout: READ_TIMEOUT,
          },
        );
      } catch (failure) {
        if (failure instanceof ApiError && failure.status === 401) {
          onsignout?.();
          return;
        }
        const label = credentialTitle(credential.name);
        autoPolicyError = `${label}: ${errorText(failure)}`;
      }
    }
  }

  async function createTopology() {
    if (importing || imported) return;
    if (!validation.ok) {
      attempted = true;
      focusError();
      return;
    }
    importing = true;
    importError = "";
    try {
      const definitions = await serviceDefinitions({ timeout: READ_TIMEOUT });
      const existingServices = new Set(definitions.map((item) => item.name));
      for (const id of draft.services) {
        const fact = serviceFact(draft, id);
        const payload = { kind: serviceKind(id) };
        if (fact.url.trim()) payload.url = fact.url.trim();
        if (existingServices.has(id)) {
          await api(`/services/${encodeURIComponent(id)}`, {
            method: "PATCH",
            body: payload,
            timeout: READ_TIMEOUT,
          });
        } else {
          // A retry after a later write failed finds this row already created;
          // the 409 is answered by patching it to the current draft.
          await createOrUpdate(
            "/services",
            { name: id, ...payload },
            { timeout: READ_TIMEOUT },
          );
        }
      }
      for (const credential of draft.credentials) {
        const body = credentialPayload(credential);
        if (credential.base) {
          // Only a credential this draft read from the live topology is
          // patched. A name that merely happens to exist is a collision, and a
          // POST refuses it (409) instead of overwriting its declaration.
          const { name, ...metadata } = body;
          await api(`/credentials/${encodeURIComponent(name)}`, {
            method: "PATCH",
            body: metadata,
            timeout: READ_TIMEOUT,
          });
        } else {
          // Same retry rule as services: a 409 means an earlier attempt made
          // this credential, so patch it rather than reporting it forever.
          await createOrUpdate("/credentials", body, {
            timeout: READ_TIMEOUT,
          });
        }
      }
      // Values are written only after every key exists. A failure here
      // leaves the topology in place and the typed keys in memory for a retry.
      await storeServiceKeys();
      imported = true;
      importedCount = counts.credentials;
      clearDraft(browserStorage());
      step = 3;
      await focusStep();
      // A first-time setup runs the audit by itself: the point is to see the
      // stack's real state. An edit does not: an audit can start a due
      // auto-rotation, and changing a URL must not silently trigger one.
      if (!editing) {
        await applyAutoRotations();
        await runFirstAudit();
      }
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        onsignout?.();
      } else {
        importError = errorText(failure);
      }
    } finally {
      importing = false;
    }
  }

  async function runFirstAudit() {
    if (auditBusy || !imported) return;
    const seq = ++auditSeq;
    auditBusy = true;
    auditError = "";
    auditRowsError = "";
    auditRun = null;
    auditRows = [];
    try {
      const answer = await auditStack();
      if (seq !== auditSeq) return;
      auditRun = answer?.last_run ?? null;
      if (!auditRun) {
        throw new Error(
          "the server completed the request but returned no audit run",
        );
      }
      try {
        const data = await api("/credentials", { timeout: READ_TIMEOUT });
        if (seq !== auditSeq) return;
        auditRows = Array.isArray(data?.credentials) ? data.credentials : [];
        auditObserved = data?.observed_run ?? null;
      } catch (failure) {
        if (seq !== auditSeq) return;
        if (failure instanceof ApiError && failure.status === 401) {
          onsignout?.();
          return;
        }
        auditRowsError = errorText(failure);
      }
    } catch (failure) {
      if (seq !== auditSeq) return;
      if (failure instanceof ApiError && failure.status === 401) {
        onsignout?.();
      } else {
        auditError = errorText(failure);
      }
    } finally {
      if (seq === auditSeq) auditBusy = false;
    }
  }
</script>

{#snippet errorFor(key)}
  {#if validation.errors[key]}
    <p class="field-error" id={`${key}-error`}>{validation.errors[key]}</p>
  {/if}
{/snippet}

{#snippet warningFor(key)}
  {#if validation.warnings[key]}
    <p class="field-warn">{validation.warnings[key]}</p>
  {/if}
{/snippet}


{#snippet servicesStep()}
  <fieldset class="setup-services">
    <legend class="sr-only">Services in this stack</legend>
    {#each SERVICE_CATALOG.filter((service) => !service.holderOnly) as service (service.id)}
      {@const inUse = serviceUsage(draft, service.id)}
      {@const selected = draft.services.includes(service.id)}
      {@const fact = serviceFactValue(draft, service.id)}
      <div
        class="setup-service-card"
        class:selected
        class:locked={selected && inUse > 0}
      >
      <label
        class="setup-service"
      >
        <input
          type="checkbox"
          checked={selected}
          disabled={selected && inUse > 0}
          onchange={(event) =>
            toggleService(service.id, event.currentTarget.checked)}
        />
        <span class="setup-service-body">
          <span class="setup-service-top">
            <span class="setup-service-name">{service.label}</span>
          </span>
          {#if selected && inUse > 0}
            <span class="setup-service-inuse">
              Used by {inUse}
              {inUse === 1 ? "key or copy" : "keys or copies"}.
              Remove {inUse === 1 ? "it" : "them"} in Copies first.
            </span>
          {/if}
        </span>
      </label>
      {#if selected}
        <div class="setup-service-facts">
          <label class="field">
            URL
            <input
              id={`service-url-${service.id}`}
              bind:value={fact.url}
              placeholder={`http://${service.id}:${defaultPort(service.id)}`}
              autocomplete="off"
              spellcheck="false"
              aria-invalid={attempted && serviceUrlError(fact.url) ? "true" : undefined}
              aria-describedby={attempted && serviceUrlError(fact.url)
                ? `service-url-${service.id}-error`
                : undefined}
            />
          </label>
          <label class="field">
            API key
            <input
              type="password"
              value={serviceKeys[service.id] ?? ""}
              placeholder={serviceHasStoredKey(service.id) ? "••••••••••••••••" : ""}
              oninput={(event) =>
                setServiceKey(service.id, event.currentTarget.value)}
              autocomplete="off"
              spellcheck="false"
              required={!editing}
              aria-invalid={attempted && !editing && !(serviceKeys[service.id] ?? "").trim()
                ? "true"
                : undefined}
              aria-describedby={attempted && !editing && !(serviceKeys[service.id] ?? "").trim()
                ? `service-key-${service.id}-error`
                : undefined}
            />
          </label>
          {#if attempted && !editing && !(serviceKeys[service.id] ?? "").trim()}
            <p class="field-error" id={`service-key-${service.id}-error`}>
              Enter the API key for {service.label}.
            </p>
          {/if}
          <div class="setup-service-test">
            <button
              type="button"

              onclick={() => testService(service.id)}
              disabled={serviceTests[service.id]?.busy}
            >
              {serviceTests[service.id]?.busy ? "Testing…" : "Test connection"}
            </button>
          </div>
          {#if serviceTests[service.id]?.detail}
            <p class={serviceTests[service.id].ok ? "field-help" : "field-error"}>
              {serviceTests[service.id].detail}
            </p>
          {/if}
          {#if attempted && serviceUrlError(fact.url)}
            <p class="field-error" id={`service-url-${service.id}-error`}>
              {serviceUrlError(fact.url)}
            </p>
          {/if}
        </div>
      {/if}
      </div>
    {/each}
  </fieldset>

  <details class="setup-discovery">
    <summary>Docker discovery (optional, read-only)</summary>
    <p class="muted">
      A scan proposes running services; it never writes topology. Copy a
      proposed URL into the field above.
    </p>
    <button
      type="button"

      onclick={scanDocker}
      disabled={discoveryBusy}
    >
      {discoveryBusy ? "Scanning…" : "Scan Docker"}
    </button>
    {#if discoveryNote}<p class="muted" role="status">{discoveryNote}</p>{/if}
    {#if discoveryError}
      <Banner tone="warn" title="Docker discovery failed.">
        {discoveryError}
      </Banner>
    {/if}
    {#if discovery?.proposals?.length}
      <ul class="setup-proposals">
        {#each discovery.proposals as proposal (proposal.container)}
          <li>
            <div class="setup-proposal-head">
              <strong>{proposal.system}</strong>
              <span class="muted">{proposal.container} · {proposal.image}</span>
            </div>
            <p class="muted">{proposal.url ?? "no URL proposed"}</p>
            {#if proposal.duplicate}
              <p class="field-warn">
                More than one container matched; select the service once.
              </p>
            {/if}
            <button
              type="button"

              onclick={() => useProposal(proposal)}
              disabled={draft.services.includes(proposal.system)}
            >
              {draft.services.includes(proposal.system)
                ? "Already selected"
                : "Select this service"}
            </button>
          </li>
        {/each}
      </ul>
    {/if}
  </details>

  {#if !editing}
    <details class="setup-advanced">
      <summary>Already have a manifest? Import a full topology</summary>
      <p class="muted">
        Skips the guided steps. Importing replaces the declared topology; values
        for names it still declares are kept. API keys for scripts are created
        later in Settings.
      </p>
      <TopologyImport onimported={importedTopology} {onsignout} />
    </details>
  {/if}
{/snippet}

{#snippet credentialsStep()}
  {#if draft.credentials.length === 0}
    <p class="muted">No keys yet. Go back and connect an app.</p>
  {/if}

  {#each draft.credentials as credential (credential.id)}
    {@const suggestions = availableSuggestions(credential)}
    {@const methodOptions = mechanismOptions(credential.owner)}
    {@const method = mechanismOf(credential)}
    {@const methodSpec = WRITE_MECHANISMS[method]}
    <section
      class="setup-credential"
      aria-labelledby={`setup-credential-${credential.id}`}
    >
      <header class="setup-credential-head">
        <div>
          <h3 id={`setup-credential-${credential.id}`} tabindex="-1">
            {credential.name ? credentialTitle(credential.name) : "New key"}
          </h3>
          <p class="muted">
            {serviceById(credential.owner)?.label ?? credential.owner}
          </p>
        </div>
        <button
          type="button"

          onclick={() => removeCredential(credential)}
          aria-label={`Remove ${credentialTitle(credential.name) || "credential"}`}
        >
          Remove
        </button>
      </header>

      {#if methodOptions.length > 1}
        <div class="setup-method">
          <label class="field">
            Rotation method
            <select
              value={method}
              onchange={(event) => chooseMechanism(credential, event.currentTarget.value)}
              aria-label="Rotation method"
            >
              {#each methodOptions as option (option)}
                <option value={option}>
                  {option === "stored"
                    ? "Stored password (never rotates)"
                    : (WRITE_MECHANISMS[option]?.label ?? option)}
                </option>
              {/each}
            </select>
          </label>
          {#if method === "stored"}
            <p class="field-help">
              A password or secret Credarr never changes. Other keys can mint
              with it; paste its value on the app page after setup.
            </p>
          {/if}
        </div>
      {/if}

      {#if methodSpec}
        {#if methodSpec.note}<p class="field-help">{methodSpec.note}</p>{/if}
        {#if methodSpec.fields.length}
          <div class="field-grid">
            {#each methodSpec.fields as field (field.key)}
              <div>
                {#if field.credential}
                  <label class="field">
                    {field.label} (required)
                    <select
                      value={credential.fields?.[field.key] ?? ""}
                      onchange={(event) =>
                        (credential.fields[field.key] = event.currentTarget.value)}
                      aria-label={field.label}
                    >
                      <option value="">Choose…</option>
                      {#each draft.credentials.filter(
                        (other) => other.id !== credential.id && other.name,
                      ) as other (other.id)}
                        <option value={other.name}>
                          {credentialTitle(other.name)} ({other.name})
                        </option>
                      {/each}
                    </select>
                    <span class="field-help">{field.help}</span>
                  </label>
                {:else}
                  <label class="field">
                    {field.label}{field.required ? " (required)" : ""}
                    <input
                      value={credential.fields?.[field.key] ?? ""}
                      oninput={(event) =>
                        (credential.fields[field.key] = event.currentTarget.value)}
                      placeholder={field.placeholder ?? ""}
                      autocomplete="off"
                      spellcheck="false"
                      aria-label={field.label}
                    />
                    <span class="field-help">{field.help}</span>
                  </label>
                {/if}
                {@render errorFor(credentialField(credential, `write.${field.key}`))}
              </div>
            {/each}
          </div>
        {/if}
      {/if}

      <div class="setup-holders">
        <div class="setup-holders-head">
          <p class="muted">Where copies of this key live.</p>
          {#if suggestions.length}
            <button
              type="button"

              onclick={() => addHolder(credential, suggestions[0])}
            >
              Add copy
            </button>
          {/if}
        </div>

        {#if credential.consumers.length === 0}
          <p class="muted">
            Nothing holds this key yet. Add one if another app stores a copy.
          </p>
        {/if}

        {#each credential.consumers as holder (holder.id)}
          {@const target = holderMeta(holder)}
          <div class="setup-holder">
            <div class="setup-holder-head">
              <div>
                <strong>{target?.label ?? holderTarget(holder)}</strong>
                {#if !target?.writer}
                  <div class="muted">Credarr can read this copy but not change it.</div>
                {/if}
              </div>
              <button
                type="button"
                onclick={() => removeHolder(credential, holder)}
                aria-label={`Remove holder ${holderTarget(holder)}`}
              >
                Remove
              </button>
            </div>

            {#if !serviceById(holder.service)?.holderOnly && !draft.services.includes(holder.service)}
              <p class="field-warn">
                {serviceById(holder.service)?.label ?? holder.service} is not in this stack, so credarr cannot look for this copy yet.
              </p>
              <div class="toolbar">
                <button type="button" onclick={() => addServiceAndGo(holder.service)}>
                  Add {serviceById(holder.service)?.label ?? holder.service} to the stack
                </button>
              </div>
            {/if}

            <details class="setup-advanced">
              <summary>Advanced</summary>
              <div class="field-grid align-start">
                <div>
                  <label class="field">
                    Service
                    <select
                      value={holder.service}
                      onchange={(event) =>
                        changeHolderService(credential, holder, event)}
                      aria-invalid={validation.errors[
                        holderField(credential, holder, "service")
                      ]
                        ? "true"
                        : undefined}
                      aria-describedby={describedBy(
                        holderField(credential, holder, "service"),
                      )}
                    >
                      {#each SERVICE_CATALOG.filter(
                        (service) => service.targets.length,
                      ) as service (service.id)}
                        <option value={service.id}>{service.label}</option>
                      {/each}
                    </select>
                  </label>
                  {@render errorFor(
                    holderField(credential, holder, "service"),
                  )}
                </div>

                <div>
                  <label class="field">
                    Location
                    <select
                      value={holder.slot}
                      onchange={(event) =>
                        changeHolderSlot(credential, holder, event)}
                      aria-invalid={validation.errors[
                        holderField(credential, holder, "target")
                      ]
                        ? "true"
                        : undefined}
                      aria-describedby={validation.errors[
                        holderField(credential, holder, "target")
                      ]
                        ? targetErrorId(credential, holder)
                        : undefined}
                    >
                      {#each serviceById(holder.service)?.targets ?? [] as slotTarget (slotTarget.slot)}
                        <option value={slotTarget.slot}>
                          {slotTarget.label}
                        </option>
                      {/each}
                    </select>
                  </label>
                </div>

                <div>
                  <label class="field">
                    Row (optional)
                    <input
                      value={holder.qualifier}
                      oninput={(event) =>
                        (holder.qualifier = event.currentTarget.value)}
                      placeholder="Sonarr or qBittorrent:password"
                      autocomplete="off"
                      spellcheck="false"
                      aria-invalid={validation.errors[
                        holderField(credential, holder, "qualifier")
                      ]
                        ? "true"
                        : undefined}
                      aria-describedby={describedBy(
                        holderField(credential, holder, "qualifier"),
                        validation.errors[
                          holderField(credential, holder, "target")
                        ]
                          ? targetErrorId(credential, holder)
                          : "",
                      )}
                    />
                  </label>
                  {@render errorFor(
                    holderField(credential, holder, "qualifier"),
                  )}
                </div>

                <div>
                  <label class="field">
                    Copies
                    <input
                      type="number"
                      min="1"
                      step="1"
                      value={holder.count ?? ""}
                      oninput={(event) =>
                        setCount(holder, event.currentTarget.value)}
                      aria-invalid={validation.errors[
                        holderField(credential, holder, "count")
                      ]
                        ? "true"
                        : undefined}
                      aria-describedby={describedBy(
                        holderField(credential, holder, "count"),
                      )}
                    />
                  </label>
                  {@render errorFor(holderField(credential, holder, "count"))}
                </div>
              </div>
              <p class="field-help">
                {describeHolder(holder, serviceById(credential.owner)?.label ?? credential.owner)}
              </p>
            </details>
            {@render errorFor(holderField(credential, holder, "target"))}
          </div>
        {/each}

        {#if suggestions.length}
          <div class="setup-suggestions">
            <p class="field-help">Common copies:</p>
            <div class="setup-suggestion-row">
              {#each suggestions as suggestion (suggestion.key + suggestion.qualifier)}
                <button
                  type="button"

                  onclick={() => addHolder(credential, suggestion)}
                >
                  + {suggestion.label}
                </button>
              {/each}
            </div>
          </div>
        {/if}
      </div>

      {#if !editing && serviceById(credential.owner)?.mint}
        <div class="setup-auto">
          <label class="setup-check">
            <input
              type="checkbox"
              checked={autoPolicies[credential.id]?.enabled ?? false}
              onchange={(event) => {
                autoPolicies[credential.id] = {
                  enabled: event.currentTarget.checked,
                  days: autoPolicies[credential.id]?.days ?? 30,
                };
              }}
            />
            Rotate this key automatically
          </label>
          {#if autoPolicies[credential.id]?.enabled}
            <label class="field">
              Every
              <input
                type="number"
                min="1"
                max="365"
                value={autoPolicies[credential.id]?.days ?? 30}
                oninput={(event) => {
                  autoPolicies[credential.id] = {
                    enabled: true,
                    days: Number(event.currentTarget.value) || 30,
                  };
                }}
              />
              days
            </label>
          {/if}
          <p class="field-help">
            A fresh stack-wide audit can start a due rotation; manual
            copies are notified. It never resumes an interrupted run. The key
            must be stored.
          </p>
        </div>
      {/if}

      {@render warningFor(credentialField(credential, "holders"))}
    </section>
  {/each}

  <div class="setup-add-row">
    <button type="button" class="primary" onclick={addCredential}>
      Add credential
    </button>
  </div>
{/snippet}

{#snippet reviewStep()}
  {#if !validation.ok}
    <Banner tone="danger" title="This draft is not ready to create.">
      <p>Fix the errors in Copies, then review again.</p>
    </Banner>
  {:else}
    <div class="setup-review-stats">
      <div><strong>{counts.credentials}</strong><span>credentials</span></div>
      <div><strong>{counts.copies}</strong><span>copies</span></div>
      <div><strong>{counts.services}</strong><span>services</span></div>
    </div>

    <section class="setup-review" aria-labelledby="setup-review-services">
      <h3 id="setup-review-services">Services</h3>
      {#each draft.services as id (id)}
        {@const fact = serviceFactValue(draft, id)}
        <div class="setup-review-row">
          <div class="setup-review-name">
            <strong>{serviceById(id)?.label ?? id}</strong>
          </div>
          <span class="muted">{fact.url || "no URL"}</span>
        </div>
      {/each}
    </section>

    <section class="setup-review" aria-labelledby="setup-review-credentials">
      <h3 id="setup-review-credentials">Keys and copies</h3>
      {#each draft.credentials as credential (credential.id)}
        <div class="setup-review-row">
          <div class="setup-review-name">
            <strong>{credentialTitle(credential.name)}</strong>
            <span class="muted">
              {serviceById(credential.owner)?.label ?? credential.owner}
            </span>
          </div>
          <div class="setup-review-holders">
            {#if credential.consumers.length}
              {#each credential.consumers as holder (holder.id)}
                <span class="setup-review-holder">
                  <strong>{holderMeta(holder)?.label ?? holderTarget(holder)}</strong>
                </span>
              {/each}
            {:else}
              <span class="muted">No copies</span>
            {/if}
          </div>
        </div>
      {/each}
    </section>

    <details class="setup-advanced">
      <summary>Manifest preview</summary>
      <p class="muted">The manifest the console will build. Values are added later.</p>
      <pre class="setup-yaml"><code>{manifestYaml}</code></pre>
    </details>
  {/if}

  {#if importError}
    <Banner tone="danger" title="Setup did not finish.">
      {plainEngineText(importError)}
      <p class="muted">
        The draft is still here. Retrying updates existing rows instead of
        duplicating them; reload if the request timed out.
      </p>
    </Banner>
  {/if}
{/snippet}

{#snippet auditStep()}
  <Banner tone="ok" title={editing ? "Topology saved." : "Topology created."}>
    {importedCount} {importedCount === 1 ? "credential" : "credentials"} declared;
    the browser draft was cleared.
  </Banner>

  {#if autoPolicyError}
    <Banner tone="warn" title="Auto-rotation was not enabled.">
      {autoPolicyError}
      <p class="muted">Enable it later on the app page. Everything else was saved.</p>
    </Banner>
  {/if}

  {#if auditRun}
    <Banner tone={auditTone} title={auditTitle}>
      <div class="setup-run-line">
        <span>Finished {timestamp(auditRun.finished_at)}</span>
        <StatusPill
          status={auditRun.exit_status}
          label={auditRun.exit_status ?? "no result"}
        />
      </div>
      {#if auditRun.detail}<p class="muted">{auditRun.detail}</p>{/if}
    </Banner>
  {:else if auditBusy}
    <Banner tone="info" title="Auditing…">
      Waiting for the run. This can take as long as the stack takes.
    </Banner>
  {:else if auditError}
    <Banner tone="danger" title="The audit could not run.">
      {auditError}
    </Banner>
  {:else}
    <p class="muted">
      No values were collected by this wizard, so credentials without a stored
      value will read as unverifiable.
    </p>
  {/if}

  {#if auditRowsError}
    <Banner tone="warn" title="Could not read the current credential rows.">
      {auditRowsError}
      <p class="muted">
        The audit can still run; the credential table is missing until the read
        succeeds.
      </p>
    </Banner>
  {/if}

  {#if !auditRun && auditRows.length}
    <section class="setup-audit-preview" aria-labelledby="setup-audit-preview-title">
      <h3 id="setup-audit-preview-title">Declared credentials</h3>
      <ul class="setup-audit-list">
        {#each auditRows as row (row.name)}
          <li>
            <strong>{credentialTitle(row.name)}</strong>
            {#if !row.stored}
              <StatusPill status="none" label="no value" />
            {/if}
            <span class="muted">
              {row.consumers?.length ?? 0}
              {(row.consumers?.length ?? 0) === 1 ? "copy" : "copies"}
            </span>
          </li>
        {/each}
      </ul>
      {#if auditStored === 0}
        <p class="muted">
          No values stored; every credential will read as unverifiable.
        </p>
      {:else}
        <p class="muted">
          {auditStored} of {auditRows.length} credential values are stored; the
          audit can only compare those.
        </p>
      {/if}
    </section>
  {/if}

  {#if auditRun}
    <section class="setup-audit-results" aria-labelledby="setup-audit-results-title">
      <h3 id="setup-audit-results-title">Audit result</h3>
      {#if auditRows.length}
        <div class="setup-table-wrap">
          <table>
            <caption class="sr-only">Audit results</caption>
            <thead>
              <tr>
                <th>Credential</th>
                <th>Status</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {#each auditRows as row (row.name)}
                <tr>
                  <td><strong>{credentialTitle(row.name)}</strong></td>
                  <td><StatusPill status={statusOf(row)} /></td>
                  <td>
                    {credentialReason(row, auditObserved)}
                    {#if fixHint(row)}
                      <div class="muted">{fixHint(row)}</div>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {:else}
        <p class="muted">
          The run finished, but the server returned no credential rows.
        </p>
      {/if}

      {#if auditStored === 0 && auditRows.length}
        <Banner tone="info" title="No API keys are stored yet.">
          The audit had nothing to compare, so every key reads as unverifiable.
          Add each key on its app page, then audit again.
        </Banner>
      {:else if auditStored < auditRows.length}
        <p class="muted">
          {auditRows.length - auditStored}
          {auditRows.length - auditStored === 1 ? "key has" : "keys have"}
          no stored value, so they could not be compared. Add them on their
          app pages, then run an audit again.
        </p>
      {/if}
    </section>
  {/if}

  <div class="setup-actions">
    {#if auditBusy}
      <span class="muted">Auditing…</span>
      <span class="spacer"></span>
      <button type="button" class="primary" disabled>Run first audit</button>
    {:else if auditRun}
      <button type="button" class="link" onclick={runFirstAudit}>
        Run audit again
      </button>
      <span class="spacer"></span>
      <button type="button" class="primary" onclick={() => finish("apps")}>
        Go to Apps
      </button>
    {:else if auditError}
      <button type="button" class="link" onclick={() => finish("apps")}>
        Go to Apps
      </button>
      <span class="spacer"></span>
      <button type="button" class="primary" onclick={runFirstAudit}>
        Retry audit
      </button>
    {:else}
      <span class="spacer"></span>
      <button type="button" class="link" onclick={runFirstAudit}>
        Run an audit
      </button>
      <button type="button" class="primary" onclick={() => finish("apps")}>
        Go to Apps
      </button>
    {/if}
  </div>
{/snippet}

<main class="setup" id="main-content">
  <div class="setup-shell">
    <header class="setup-head">
      <div class="setup-brand">
        <span class="brand-mark" aria-hidden="true"><Icon name="shield" size={18} /></span>
        <span>credarr</span>
      </div>
      <div class="setup-head-actions">
        {#if onskip && step < 3}
          <button type="button" class="link" onclick={skipSetup}>
            Skip for now
          </button>
        {/if}
        <button type="button" class="link" onclick={leave}>Sign out</button>
      </div>
    </header>

    <div class="setup-intro">
      <h1>{editing ? "Update your stack" : "Set up your stack"}</h1>
    </div>

    <ol class="setup-progress" aria-label="Setup progress">
      {#each STEPS as item, index}
        <li
          class:done={index < step}
          class:current={index === step}
          aria-current={index === step ? "step" : undefined}
        >
          <span class="setup-step-number" aria-hidden="true">
            {index < step ? "✓" : index + 1}
          </span>
          <span class="setup-step-label">{item.label}</span>
          {#if item.optional}
            <span class="setup-step-optional">optional</span>
          {/if}
        </li>
      {/each}
    </ol>

    <p class="setup-save-note">
      {#if draftAvailable}
        Draft saved in this browser. Never secrets or API keys.
      {:else}
        Not saving a draft. Keep this tab open.
      {/if}
    </p>

    {#if loadError}
      <Banner tone="danger" title="Could not read the current topology.">
        {loadError}
        <p class="muted">
          Start from an empty draft or use Import / Export; nothing was changed.
        </p>
      </Banner>
    {/if}

    {#if restored && !imported}
      <Banner tone="quiet" title="Resumed the saved setup draft.">
        <span class="muted">Non-secret fields only.</span>
        {#snippet actions()}
          <button type="button" onclick={() => (restored = false)}>
            Dismiss
          </button>
        {/snippet}
      </Banner>
    {/if}

    {#if loadedFromTopology && !imported}
      <Banner tone="quiet" title="Editing the current topology.">
        <span class="muted">
          Only catalog services and credentials are shown. Removing one here
          does not delete it from the store; values are kept.
        </span>
      </Banner>
    {/if}

    <section class="setup-card" aria-labelledby="setup-step-title">
      <header class="setup-card-head">
        <h2 id="setup-step-title" tabindex="-1" bind:this={stepHeading}>
          {STEPS[step].label}
        </h2>
        <p class="muted">{STEPS[step].description}</p>
      </header>

      {#if step < 3}
        <form class="setup-form" onsubmit={handleSubmit} novalidate>
          {#if stepIssues.length}
            <div
              class="setup-alert"
              role="alert"
              tabindex="-1"
              bind:this={errorSummary}
            >
              <strong>Check this step.</strong>
              {#each stepIssues as issue}
                <p>{issue}</p>
              {/each}
            </div>
          {/if}

          {#if step === 0}
            {@render servicesStep()}
          {:else if step === 1}
            {@render credentialsStep()}
          {:else if step === 2}
            {@render reviewStep()}
          {/if}

          <div class="setup-actions">
            {#if step > 0}
              <button type="button" onclick={goBack} disabled={importing}>
                Back
              </button>
            {/if}
            <span class="spacer"></span>
            <button
              class="primary"
              type="submit"
              disabled={step === 2 ? importing || !validation.ok : false}
            >
              {#if step === 0}
                Continue
              {:else if step === 1}
                Review topology
              {:else if step === 2}
                {importing ? "Saving…" : "Save"}
              {/if}
            </button>
          </div>
        </form>
      {:else}
        {@render auditStep()}
      {/if}
    </section>
  </div>
</main>
