<script>
  import { onMount } from "svelte";
  import {
    api,
    ApiError,
    errorText,
    serviceDefinitions,
    timestamp,
  } from "../lib/api.js";
  import AutoRotationCard from "../lib/AutoRotationCard.svelte";
  import Banner from "../lib/Banner.svelte";
  import ConfirmDialog from "../lib/ConfirmDialog.svelte";
  import EmptyState from "../lib/EmptyState.svelte";
  import HoldersTable from "../lib/HoldersTable.svelte";
  import PageHeader from "../lib/PageHeader.svelte";
  import RotationPanel from "../lib/RotationPanel.svelte";
  import StatusPill from "../lib/StatusPill.svelte";
  import { checkStatus, statusInfo } from "../lib/status.js";
  import { toast } from "../lib/toast.js";

  import { bannerLine, credentialTitle, copyLabel, friendlyReason, plainEngineText, reasonsForField } from "../lib/names.js";
  import { countProposals, parseCopyCount } from "../lib/apps.js";
  import { WRITE_MECHANISMS, defaultPort, describeHolder, serviceById, targetByKey, targetString } from "../lib/setupCatalog.js";
  import {
    serviceKind,
    serviceUrlError,
    suggestionsFor,
  } from "../lib/setup.js";


  // One app in full. The header holds the four actions (plan, check, rotate,
  // replace) as ordinary buttons; the sections below are where they land.
  // Each app mounts this view fresh, keys are reached from Apps or the menu,
  // and new keys are created by connecting an app, the wizard, or an import.
  const WRITE_TIMEOUT = 10_000;

  let {
    data,
    name,
    rotation = null,
    rotationFocus = 0,
    onrefresh,
    onapps,
    onsignout,
  } = $props();

  let secret = $state("");
  let connBusy = $state(false);
  let checkBusy = $state(false);
  let checkError = $state("");
  let checks = $state([]);
  let checksLoading = $state(true);
  let checksRead = 0;
  let checksError = $state("");
  let message = $state("");
  let error = $state("");

  const rows = $derived(data?.credentials ?? []);
  const observed = $derived(data?.observed_run ?? null);
  const row = $derived(rows.find((entry) => entry.name === name) ?? rows[0] ?? null);

  // Editable state is synced at explicit points - mount, app switch, save -
  // never in a guard-variable effect: an effect that both reads and writes
  // its guard does not reliably re-fire, and stale copies here would be
  // written back over the live topology.
  let holderBusy = $state(false);
  let holderError = $state("");
  let addingCopy = $state(false);
  let copyService = $state("");
  let copyTarget = $state("");
  let removeTargets = $state([]);

  // The usual copies for this key, minus what is already declared. Only the
  // registry's suggestions are offered - never bare slots, which read as
  // "Prowlarr applications" next to "Prowlarr applications [Sonarr]" and mean
  // nothing to anyone choosing where this key goes.
  function copyOptionsFor(serviceId) {
    const seen = new Set((row?.consumers ?? []).map((holder) => holder.target));
    const out = [];
    for (const item of suggestionsFor(ownerId)) {
      if (item.service !== serviceId) continue;
      const identity = targetString(item);
      if (seen.has(identity)) continue;
      out.push({
        value: identity,
        label: item.label,
        service: item.service,
        slot: item.slot,
        qualifier: item.qualifier ?? "",
        mechanism: targetByKey(identity)?.mechanism ?? "",
      });
    }
    return out;
  }

  // Services that still have a copy left to declare, in catalog order. The
  // Add button dies with this list, the way Add Service dies when every
  // notification type is configured.
  const copyServices = $derived(
    [...new Set(suggestionsFor(ownerId).map((item) => item.service))].filter(
      (serviceId) => copyOptionsFor(serviceId).length > 0,
    ),
  );

  const copyOptions = $derived(copyService ? copyOptionsFor(copyService) : []);
  const copyChoice = $derived(
    copyOptions.find((option) => option.value === copyTarget) ?? null,
  );
  // The choice in the copy's own words, the same sentence the wizard shows:
  // where the key will live, named the way that screen names it.
  const copySentence = $derived(
    copyChoice
      ? describeHolder(
          {
            service: copyChoice.service,
            slot: copyChoice.slot,
            qualifier: copyChoice.qualifier,
          },
          serviceById(ownerId)?.label ?? ownerId,
        )
      : "",
  );
  // One service, one choice: linking an app adds the copy it actually holds,
  // and a lone option is already chosen. Rotation still writes every declared
  // copy in a single run; this form only decides which copies exist.
  function chooseService(serviceId) {
    copyService = serviceId;
    const options = copyOptionsFor(serviceId);
    copyTarget = options.length === 1 ? options[0].value : "";
  }

  function openCopyForm() {
    holderError = "";
    copyTarget = "";
    chooseService(copyServices[0] ?? "");
    addingCopy = true;
  }

  function closeCopyForm() {
    addingCopy = false;
    copyService = "";
    copyTarget = "";
  }

  async function addCopyFromForm() {
    if (!row || holderBusy || !copyTarget) return;
    const saved = await writeCopies((consumers) => {
      if (consumers.some((holder) => holder.target === copyTarget)) return consumers;
      return [
        ...consumers,
        {
          target: copyTarget,
          count: 1,
          mechanism: copyChoice?.mechanism ?? "",
          host: null,
          note: "",
        },
      ];
    });
    if (saved) closeCopyForm();
  }

  // Copies write through immediately, the way notification services do: there
  // is one table, always the saved state, and no staged copy to forget to
  // save. The list changing is the answer; the toast is dull by design.
  function storedCopies() {
    return (row?.consumers ?? []).map((holder) => ({
      target: holder.target,
      count: holder.count ?? 1,
      mechanism: holder.mechanism ?? "",
      host: holder.host ?? null,
      note: holder.note ?? "",
    }));
  }

  async function writeCopies(next) {
    if (!row || holderBusy) return false;
    holderBusy = true;
    holderError = "";
    try {
      await api(`/credentials/${encodeURIComponent(row.name)}/holders`, {
        method: "PUT",
        body: { consumers: next(storedCopies()) },
        timeout: WRITE_TIMEOUT,
      });
      toast();
      await onrefresh();
      return true;
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else holderError = errorText(failure);
      return false;
    } finally {
      holderBusy = false;
    }
  }

  const removeServiceLabel = $derived(
    removeTargets.length
      ? (serviceById(String(removeTargets[0]).split("[", 1)[0].split(".")[0])?.label ??
        String(removeTargets[0]))
      : "",
  );

  async function removeCopiesNow() {
    if (!removeTargets.length) return;
    const gone = new Set(removeTargets);
    const saved = await writeCopies((consumers) =>
      consumers.filter((holder) => !gone.has(holder.target)),
    );
    if (saved) removeTargets = [];
  }

  // The operator confirms the live number; the audit did the counting. Uses
  // the same atomic holders write as every other copy edit.
  async function setCopyCount(target, count) {
    const next = parseCopyCount(count);
    if (next === null) {
      holderError = "A copy count must be a whole number of at least one.";
      return false;
    }
    holderError = "";
    return writeCopies((consumers) =>
      consumers.map((holder) =>
        holder.target === target ? { ...holder, count: next } : holder,
      ),
    );
  }

  // The latest plan's refuse/fail sentences, for hanging engine refusals
  // under the rotation-method field that can fix them. The panel reports;
  // this page places.
  let planReasons = $state([]);

  // The console infers the rotation method from the service's own answer.
  // Backup & restore is the default; the fallback card appears only when
  // that path cannot run. A config rebuild is one explicit button, never a
  // silent switch, because it can reset settings the API does not expose.
  let rotationOptions = $state(null);
  let optionsBusy = $state(false);
  let fallbackBusy = $state(false);
  let fallbackError = $state("");
  let uiSecret = $state("");
  // Dismissing the warning hides the header, not the fallback: the buttons
  // stay. Mount-scoped, so switching apps brings it back.
  let fallbackDismissed = $state(false);

  const serviceLabel = $derived(serviceById(ownerId)?.label ?? ownerId);
  const backupInfo = $derived(rotationOptions?.methods?.backup_restore ?? null);
  const reconstructInfo = $derived(rotationOptions?.methods?.reconstruct ?? null);
  // The local-auth directions only help when a UI login is the blocker;
  // anything else already says where to look.
  const loginNeeded = $derived(
    (backupInfo?.ui_password ?? {}).required === true &&
      backupInfo.ui_password.method !== "external",
  );
  const selectedMethod = $derived(
    rotationOptions?.selected ?? rotationMethodOf(row?.write),
  );
  const ownNames = $derived([ownerId, serviceLabel, row?.name ?? ""]);

  function rotationMethodOf(write) {
    if (write?.manual_mint) return "manual";
    if (write?.reconstruct_config) return "reconstruct";
    return "backup_restore";
  }

  const fallbackNeeded = $derived(
    rotationOptions?.applicable === true && backupInfo?.available === false,
  );
  const restoreAvailable = $derived(
    rotationOptions?.applicable === true &&
      backupInfo?.available === true &&
      selectedMethod !== "backup_restore",
  );

  const backupReason = $derived.by(() => {
    if (!backupInfo || backupInfo.available) return "";
    const login = backupInfo.ui_password ?? {};
    if (login.required) {
      if (login.method === "external") {
        return `${serviceLabel} uses an external sign-in; credarr can't open its backup download.`;
      }
      if (login.configured) {
        return `The saved UI password didn't open ${serviceLabel}'s backup download.`;
      }
      return `${serviceLabel} asks for a UI sign-in before it will download a backup.`;
    }
    const reason = String(backupInfo.reason ?? "");
    if (/no url configured/.test(reason)) {
      return `Add ${serviceLabel}'s URL above and save it first.`;
    }
    if (/could not be reached during preflight/.test(reason)) {
      return `${serviceLabel} couldn't be reached. Check its URL and that it is running.`;
    }
    if (/the stored key does not authorize the backup API/.test(reason)) {
      return `The stored key can't read ${serviceLabel}'s backups. Paste a live key above.`;
    }
    if (/\/system\/backup returned HTTP/.test(reason)) {
      return `${serviceLabel} didn't answer its backup API. Check that it is up.`;
    }
    return bannerLine(friendlyReason(reason), ownNames);
  });

  const rebuildReason = $derived.by(() => {
    if (!reconstructInfo || reconstructInfo.available) return "";
    const reason = String(reconstructInfo.reason ?? "");
    if (/no url configured/.test(reason)) {
      return `Add ${serviceLabel}'s URL above and save it first.`;
    }
    if (/could not be reached during preflight/.test(reason)) {
      return `${serviceLabel} couldn't be reached.`;
    }
    if (/reports .*postgres/i.test(reason)) {
      return `The service uses PostgreSQL; a rebuilt config would lose its database settings.`;
    }
    if (/did not report databaseType/i.test(reason)) {
      return `The service didn't report its database type, so a rebuild isn't safe.`;
    }
    if (/\/config\/host did not expose/i.test(reason)) {
      return `The service's API didn't expose the config fields a rebuild needs.`;
    }
    if (/stored key does not authenticate/i.test(reason)) {
      return `The stored key doesn't authenticate. Paste a live key above.`;
    }
    if (/stored key does not authorize \/config\/host/i.test(reason)) {
      return `The stored key can't read the service's config. Paste a live key above.`;
    }
    return bannerLine(friendlyReason(reason), ownNames);
  });

  async function loadRotationOptions() {
    rotationOptions = null;
    fallbackError = "";
    if (
      !row ||
      !row.stored ||
      row.class === "B" ||
      row.never_rotate ||
      serviceKind(ownerId) !== "servarr"
    ) {
      return;
    }
    optionsBusy = true;
    try {
      rotationOptions = await api(
        `/credentials/${encodeURIComponent(row.name)}/rotation-options`,
        { timeout: WRITE_TIMEOUT },
      );
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        onsignout();
        return;
      }
      // A missing URL or an unreachable service already has its place in the
      // plan. The fallback card is for a measured method, not a guess.
    } finally {
      optionsBusy = false;
    }
  }

  function writeForMethod(method) {
    const write = { ...(row?.write ?? {}) };
    delete write.manual_mint;
    delete write.reconstruct_config;
    delete write.ui_password;
    if (method === "reconstruct") write.reconstruct_config = true;
    if (method === "manual") write.manual_mint = true;
    return write;
  }

  async function saveMethod(method) {
    if (!row || fallbackBusy) return;
    fallbackBusy = true;
    fallbackError = "";
    try {
      await api(`/credentials/${encodeURIComponent(row.name)}`, {
        method: "PATCH",
        body: { write: writeForMethod(method) },
        timeout: WRITE_TIMEOUT,
      });
      toast();
      await onrefresh();
      await loadRotationOptions();
      // A save re-arms the warning if the fallback persists: dismissal
      // hides this warning, not the next one.
      fallbackDismissed = false;
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else fallbackError = errorText(failure);
    } finally {
      fallbackBusy = false;
    }
  }

  async function saveUiPassword() {
    const value = uiSecret.trim();
    if (!row || !value || fallbackBusy) return;
    fallbackBusy = true;
    fallbackError = "";
    try {
      const pwName = `${ownerId}_ui_password`;
      try {
        await api("/credentials", {
          method: "POST",
          body: {
            name: pwName,
            description: `${serviceLabel} UI password, for the backup login`,
            never_rotate: true,
          },
          timeout: WRITE_TIMEOUT,
        });
      } catch (failure) {
        if (!(failure instanceof ApiError && failure.status === 409)) throw failure;
      }
      await api(`/credentials/${encodeURIComponent(pwName)}/value`, {
        method: "PUT",
        body: { value },
        timeout: WRITE_TIMEOUT,
      });
      const write = writeForMethod("backup_restore");
      write.ui_password = pwName;
      await api(`/credentials/${encodeURIComponent(row.name)}`, {
        method: "PATCH",
        body: { write },
        timeout: WRITE_TIMEOUT,
      });
      uiSecret = "";
      toast();
      await onrefresh();
      await loadRotationOptions();
      // A save re-arms the warning if the fallback persists: dismissal
      // hides this warning, not the next one.
      fallbackDismissed = false;
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else fallbackError = errorText(failure);
    } finally {
      fallbackBusy = false;
    }
  }

  let url = $state("");
  let urlLoaded = $state("");
  let urlDirty = $state(false);
  let urlRead = 0;
  let urlLoadError = $state("");
  let urlError = $state("");
  let urlTest = $state(null);
  let definitionMissing = $state(false);

  let clearArmed = $state(false);
  let deleteOpen = $state(false);
  let dangerBusy = $state(false);
  let dangerError = $state("");

  const ownerId = $derived(
    row?.canonical?.service ?? String(row?.name ?? "").replace(/_api_key$/, ""),
  );
  const title = $derived(credentialTitle(row?.name ?? ""));

  // Each app mounts this view fresh (the shell keys it by name), so there is
  // no stale key, URL or message to reset when arriving from another app.
  onMount(() => {
    loadConnection();
    loadRotationOptions();
  });

  // Load when the app is known, and again after a full audit. A scoped check
  // refreshes its own history directly; it does not move `observed`.
  $effect(() => {
    void row?.name;
    void observed?.id;
    if (row) void loadChecks();
  });

  async function loadChecks() {
    if (!row) {
      checks = [];
      checksLoading = false;
      return;
    }
    const read = ++checksRead;
    checksLoading = true;
    checksError = "";
    try {
      const answer = await api(
        `/audit?only=${encodeURIComponent(row.name)}&limit=20`,
        { timeout: WRITE_TIMEOUT },
      );
      if (read !== checksRead) return;
      checks = Array.isArray(answer?.checks) ? answer.checks : [];
    } catch (failure) {
      if (read !== checksRead) return;
      if (failure instanceof ApiError && failure.status === 401) {
        onsignout();
        return;
      }
      checksError = errorText(failure);
    } finally {
      if (read === checksRead) checksLoading = false;
    }
  }

  function checkDetail(check) {
    const detail = String(check?.detail ?? "");
    if (
      check?.reason === "no_canonical" ||
      detail === "no canonical reference in the manifest"
    ) {
      return "No value stored yet.";
    }
    return friendlyReason(detail) || statusInfo(check?.status).why;
  }

  async function checkApp() {
    if (!row || checkBusy) return;
    checkBusy = true;
    checkError = "";
    try {
      // No timeout: this is a full holder exercise for one app, not a local
      // read. It is not a stack audit and never moves the stack headline.
      await api(`/audit?only=${encodeURIComponent(row.name)}`, {
        method: "POST",
      });
      await loadChecks();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else checkError = errorText(failure);
    } finally {
      checkBusy = false;
    }
  }

  async function loadConnection() {
    const read = ++urlRead;
    urlLoaded = "";
    urlLoadError = "";
    definitionMissing = false;
    if (!row) return;
    try {
      const definitions = await serviceDefinitions({ timeout: WRITE_TIMEOUT });
      if (read !== urlRead) return;
      const definition = definitions.find(
        (item) => item.name === ownerId,
      );
      const saved = definition ? (definition.url ?? "") : "";
      // The read can land after the operator starts typing. Keep their edit
      // and make it the value Save compares against, rather than replacing it
      // with the URL that was saved a moment ago.
      if (!urlDirty) url = saved;
      urlLoaded = saved;
      definitionMissing = !definition;
    } catch (failure) {
      if (read !== urlRead) return;
      if (failure instanceof ApiError && failure.status === 401) {
        onsignout();
        return;
      }
      // Blank is not an answer: say the URL was not read and offer the read
      // again, so an unloaded field is never mistaken for a saved empty one.
      urlLoadError = errorText(failure);
    }
  }

  // Plan / Check / Rotate live in the header; the rotation panel
  // below is the result surface. Rotation is one run over every copy, so the
  // header acts while the panel reports.
  let panelApi = $state(null);
  let rotationArmed = $state(false);
  let planBusy = $state(false);
  let runBusy = $state(false);
  let rotateBtn = $state(null);
  let handledFocus = 0;

  const pendingHere = $derived(
    (rotation?.pending ?? []).filter((step) => step.credential === row?.name),
  );

  $effect(() => {
    if (rotationFocus <= handledFocus) return;
    handledFocus = rotationFocus;
    rotateBtn?.focus({ preventScroll: true });
  });

  function scrollToRotation() {
    document.getElementById("rotation-card")?.scrollIntoView({ block: "start" });
  }

  function planRotation() {
    panelApi?.startPlan();
    scrollToRotation();
  }

  function pressRotate() {
    if (runBusy) return;
    // A saved manual opt-in opens the key field on the first press: there
    // is no stored key to arm against, and the form's own submit confirms.
    if (!rotationArmed && row?.write?.manual_mint === true) {
      panelApi?.openManualKey();
      scrollToRotation();
      return;
    }
    if (rotationArmed) {
      // Keep the page where the operator pressed. The header button carries
      // the running state; scrolling to the result panel is only useful for
      // a plan or the manual-key form.
      panelApi?.doRotate();
    } else {
      rotationArmed = true;
    }
  }

  async function saveConnection() {
    if (!row || connBusy) return;
    const trimmedUrl = url.trim();
    const keyText = secret.trim();
    const normalizedUrl = (value) => value.replace(/\/+$/, "");
    const urlChanged = normalizedUrl(trimmedUrl) !== normalizedUrl(urlLoaded);
    // An unchanged URL is not re-validated: a key-only save on a service
    // with no URL yet must not trip over the URL field.
    if (urlChanged) {
      const urlIssue = serviceUrlError(trimmedUrl);
      if (urlIssue) {
        urlError = urlIssue;
        return;
      }
    }
    if (urlChanged && row.stored && !keyText) {
      // The old key belongs to the old server. Profilarr's destination guard
      // in operator words: make the re-entry explicit, not a silent redirect.
      urlError =
        "This key is stored for the old URL. Paste it again to confirm the new URL.";
      return;
    }
    if (!urlChanged && !keyText) return;
    connBusy = true;
    urlError = "";
    message = "";
    error = "";
    let keyMovedWithUrl = false;
    try {
      if (urlChanged) {
        if (definitionMissing) {
          await api("/services", {
            method: "POST",
            body: { name: ownerId, kind: serviceKind(ownerId), url: trimmedUrl },
            timeout: WRITE_TIMEOUT,
          });
          definitionMissing = false;
        } else if (row.stored) {
          await api(`/services/${encodeURIComponent(ownerId)}`, {
            method: "PATCH",
            body: {
              url: trimmedUrl,
              credential: row.name,
              key: keyText,
            },
            timeout: WRITE_TIMEOUT,
          });
          keyMovedWithUrl = true;
          secret = "";
        } else {
          await api(`/services/${encodeURIComponent(ownerId)}`, {
            method: "PATCH",
            body: { url: trimmedUrl },
            timeout: WRITE_TIMEOUT,
          });
        }
        urlLoaded = trimmedUrl;
        urlDirty = false;
        // A read that started before this save must not put the old URL back.
        urlRead += 1;
      }
      if (keyText && !keyMovedWithUrl) {
        await api(`/credentials/${encodeURIComponent(row.name)}/value`, {
          method: "PUT",
          body: { value: keyText },
          timeout: WRITE_TIMEOUT,
        });
        // The value is not kept anywhere in the view after the write: a
        // browser that can still read it back would defeat "write-only".
        secret = "";
      }
      toast();
      await onrefresh();
      await loadRotationOptions();
      // A save re-arms the warning if the fallback persists: dismissal
      // hides this warning, not the next one.
      fallbackDismissed = false;
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else urlError = errorText(failure);
    } finally {
      connBusy = false;
    }
  }

  async function testUrl() {
    // No gate on the empty field: the endpoint falls back to the stored key,
    // so Test works the way a Servarr app tests the key it already holds. The
    // value never comes back; only the verdict does.
    urlTest = { busy: true, ok: false, detail: "" };
    try {
      const answer = await api("/services/test", {
        method: "POST",
        body: { service: ownerId, url: url.trim(), key: secret || null },
        timeout: 20_000,
      });
      urlTest = {
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
      urlTest = { busy: false, ok: false, detail: errorText(failure) };
    }
    // A test can change eligibility: disabling local auth in the service
    // turns the backup path green, so the fallback card re-reads the service.
    if (row) await loadRotationOptions();
  }

  async function clearValue() {
    if (!row || dangerBusy) return;
    dangerBusy = true;
    dangerError = "";
    try {
      await api(`/credentials/${encodeURIComponent(row.name)}/value`, {
        method: "DELETE",
      });
      clearArmed = false;
      message = "Stored key cleared. The service itself was not changed.";
      await onrefresh();
      await loadRotationOptions();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else dangerError = errorText(failure);
    } finally {
      dangerBusy = false;
    }
  }

  async function deleteCredential() {
    if (!row || dangerBusy) return;
    dangerBusy = true;
    dangerError = "";
    try {
      await api(
        `/credentials/${encodeURIComponent(row.name)}?confirm=${encodeURIComponent(row.name)}`,
        { method: "DELETE" },
      );
      deleteOpen = false;
      toast();
      await onrefresh();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else dangerError = errorText(failure);
    } finally {
      dangerBusy = false;
    }
  }

</script>

{#if rows.length === 0}
  <PageHeader title="Apps" />
  <EmptyState title="No apps yet" icon="import">
    <p>Nothing is declared yet.</p>
    {#snippet actions()}
      <button onclick={onapps}>Back to Apps</button>
    {/snippet}
  </EmptyState>
{:else if row}
  <PageHeader title={title} description={row.description}>
    {#snippet actions()}
      <span class="muted">
        {#if observed}
          Last observed {timestamp(observed.finished_at)}
        {:else}
          Not observed yet
        {/if}
      </span>
      <button type="button" onclick={planRotation} disabled={planBusy}>
        {planBusy ? "Planning…" : "Plan"}
      </button>
      <button type="button" onclick={checkApp} disabled={checkBusy}>
        {checkBusy ? "Checking…" : "Check"}
      </button>
      <button
        class="primary"
        type="button"
        bind:this={rotateBtn}
        onclick={pressRotate}
        disabled={runBusy || planBusy}
      >
        {runBusy
          ? "Rotating…"
          : rotationArmed
            ? "Confirm rotation"
            : pendingHere.length > 0
              ? "Resume rotation"
              : "Rotate"}
      </button>
    {/snippet}
  </PageHeader>

  {#if checkError}<Banner tone="danger">{checkError}</Banner>{/if}

  <div id="rotation-card">
    <RotationPanel
      {row}
      pending={rotation?.pending ?? []}
      bind:armed={rotationArmed}
      bind:planBusy
      bind:runBusy
      {onrefresh}
      {onsignout}
      onready={(api) => (panelApi = api)}
      onplan={(answer) => {
        planReasons = answer ? [...(answer.blocked_by ?? []), ...(answer.problems ?? [])] : [];
      }}
    />
  </div>

  <section class="card section" id="connection">
    <div class="section-head">
      <div>
        <h3>Connection</h3>
      </div>
    </div>
    {#if urlLoadError}
      <Banner tone="danger" title="Could not read the saved connection.">
        {urlLoadError}
        <p class="muted">The saved URL was not loaded. Retry before changing it.</p>
        {#snippet actions()}
          <button type="button" onclick={loadConnection}>Retry</button>
        {/snippet}
      </Banner>
    {/if}
    {#if urlError}<Banner tone="danger">{plainEngineText(urlError)}</Banner>{/if}
    {#if message}<Banner tone="ok">{message}</Banner>{/if}
    {#if error}<Banner tone="danger">{error}</Banner>{/if}
    <div class="field-grid">
      <label class="field">
        URL (required)
        <input
          bind:value={url}
          oninput={() => (urlDirty = true)}
          placeholder={ownerId ? `http://${ownerId}:${defaultPort(ownerId)}` : "http://sonarr:8989"}
          autocomplete="off"
          spellcheck="false"
        />
      </label>
      <label class="field">
        API key
        <input
          id="connection-key"
          type="password"
          bind:value={secret}
          autocomplete="new-password"
          spellcheck="false"
          aria-label="API key"
          placeholder={row.stored ? "••••••••••••••••" : "paste the API key"}
          disabled={connBusy || (row.write?.manual_mint === true && !urlDirty)}
        />
      </label>
    </div>
    {#if row.stored && !secret}
      <p class="field-help">A key is stored. Paste a new one only to replace it.</p>
    {/if}
    {#if serviceKind(ownerId) === "servarr" && row.class !== "B" && !row.never_rotate}
      {#if optionsBusy && !rotationOptions}
        <p class="field-help">Checking how this key can rotate…</p>
      {:else if fallbackNeeded}
        <div class="confirm-box">
          {#if !fallbackDismissed}
            <Banner tone="warn" title="Backup & restore isn't available.">
              <p>{backupReason}</p>
              {#if loginNeeded}
                <p>
                  In {serviceLabel} &gt; Settings &gt; General, set
                  Authentication to Disabled for Local Addresses (or None).
                </p>
              {/if}
              {#snippet actions()}
                <button type="button" onclick={() => (fallbackDismissed = true)}>
                  Close
                </button>
              {/snippet}
            </Banner>
          {/if}
          {#if backupInfo?.ui_password?.can_help}
            <p class="field-help">
              Save {serviceLabel}'s UI password to keep the backup path. It is
              stored like any other credential and is never shown again.
            </p>
            <div class="toolbar">
              <label class="field">
                UI password
                <input
                  type="password"
                  bind:value={uiSecret}
                  autocomplete="new-password"
                  spellcheck="false"
                  aria-label="UI password"
                  placeholder={backupInfo.ui_password.configured ? "••••••••••••••••" : ""}
                  disabled={fallbackBusy}
                />
              </label>
              <button
                class="primary"
                type="button"
                onclick={saveUiPassword}
                disabled={fallbackBusy || !uiSecret.trim()}
              >
                {fallbackBusy ? "Saving…" : "Save"}
              </button>
            </div>
          {/if}
          {#if reconstructInfo?.available}
            <p class="field-help">
              Rebuild the config from the API. No backup is read; theme, syslog
              and log rotation may reset. PostgreSQL is not supported.
            </p>
            <button
              type="button"
              class={selectedMethod === "reconstruct" ? "primary" : ""}
              onclick={() => saveMethod("reconstruct")}
              disabled={fallbackBusy || selectedMethod === "reconstruct"}
            >
              Use config rebuild
            </button>
          {:else if rebuildReason}
            <p class="field-help">A config rebuild isn't possible: {rebuildReason}</p>
          {/if}
          <p class="field-help">
            Rotate the key in {serviceLabel}, then paste it here. This cannot run
            automatically.
          </p>
          <button
            type="button"
            class={selectedMethod === "manual" ? "primary" : ""}
            onclick={() => saveMethod("manual")}
            disabled={fallbackBusy || selectedMethod === "manual"}
          >
            Rotate the key myself
          </button>
          {#if fallbackError}<Banner tone="danger">{plainEngineText(fallbackError)}</Banner>{/if}
        </div>
      {:else if restoreAvailable}
        <div class="confirm-box">
          <p>
            <strong>Backup & restore is available.</strong>
            This key is set to {selectedMethod === "reconstruct"
              ? "rebuild the config"
              : "be rotated by hand"}.
          </p>
          <button
            type="button"
            onclick={() => saveMethod("backup_restore")}
            disabled={fallbackBusy}
          >
            {fallbackBusy ? "Saving…" : "Use backup & restore"}
          </button>
        </div>
      {/if}
    {/if}
    <div class="toolbar">
      <button type="button" onclick={testUrl} disabled={urlTest?.busy || !url.trim()}>
        {urlTest?.busy ? "Testing…" : "Test"}
      </button>
      {#if urlTest?.detail}
        <span class={urlTest.ok ? "muted" : "error"}>{urlTest.detail}</span>
      {/if}
      <span class="spacer"></span>
      {#if row.stored}
        <button
          class={clearArmed ? "danger" : ""}
          type="button"
          onclick={() => (clearArmed ? clearValue() : (clearArmed = true))}
          disabled={dangerBusy || connBusy}
        >
          {dangerBusy ? "Clearing…" : clearArmed ? "Confirm clear" : "Clear key"}
        </button>
      {/if}
      <button
        class="primary"
        type="button"
        onclick={saveConnection}
        disabled={connBusy || (url === urlLoaded && !secret.trim())}
      >
        {connBusy ? "Saving…" : "Save"}
      </button>
    </div>
  </section>

  <section class="card section" id="check-history">
    <div class="section-head">
      <div><h3>Check history</h3></div>
      <button type="button" onclick={loadChecks} disabled={checksLoading}>
        {checksLoading ? "Reading…" : "Refresh"}
      </button>
    </div>
    {#if checksError}<Banner tone="danger">{checksError}</Banner>{/if}
    {#if checks.length > 0}
      <table>
        <caption class="sr-only">Checks and stack audits for this app</caption>
        <thead>
          <tr>
            <th>When</th>
            <th>Result</th>
            <th>Source</th>
            <th>What happened</th>
          </tr>
        </thead>
        <tbody>
          {#each checks as check}
            <tr>
              <td class="muted time">{timestamp(check.at)}</td>
              <td><StatusPill status={checkStatus(check.status, row)} /></td>
              <td class="muted">
                {check.source === "audit" ? "Stack audit" : "Check"}
              </td>
              <td class="muted">{checkDetail(check)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {:else if checksLoading}
      <p class="muted">Reading checks…</p>
    {:else}
      <p class="muted">
        No checks yet. Use Check to test this app without auditing the whole
        stack.
      </p>
    {/if}
  </section>

  {#if WRITE_MECHANISMS[row.write?.mechanism]}
    {@const methodSpec = WRITE_MECHANISMS[row.write.mechanism]}
    <section class="card section" id="rotation-method">
      <div class="section-head">
        <div><h3>Rotation method</h3></div>
      </div>
      <p><strong>{methodSpec.label}.</strong> {methodSpec.about}</p>
      {#if methodSpec.fields.length}
        <table>
          <caption class="sr-only">Rotation settings for this key</caption>
          <tbody>
            {#each methodSpec.fields as field (field.key)}
              <tr>
                <td><strong>{field.label}</strong></td>
                <td>
                  {#if row.write?.[field.key]}
                    <code>{row.write[field.key]}</code>
                  {:else}
                    <span class="muted">not set</span>
                  {/if}
                  {#each reasonsForField(planReasons, field.key) as reason (reason)}
                    <div class="status-why">{friendlyReason(reason)}</div>
                  {/each}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>
  {/if}

  {#key row.name}
    <AutoRotationCard
      {row}
      {onrefresh}
      {onsignout}
      manual={row.write?.manual_mint === true}
    />
  {/key}

  <section class="card section">
    <div class="section-head">
      <div><h3>Used in</h3></div>
      {#if !addingCopy}
        <button
          class="primary"
          type="button"
          onclick={openCopyForm}
          disabled={holderBusy || copyServices.length === 0}
        >
          Add copy
        </button>
      {/if}
    </div>
    {#if holderError}<Banner tone="danger">{holderError}</Banner>{/if}
    {#if addingCopy}
      <p class="muted">
        <button class="link" type="button" onclick={closeCopyForm}>Used in</button>
        / New
      </p>
      <h4>New copy</h4>
      <div class="field-grid align-start">
        <label class="field">
          Service
          <select
            bind:value={copyService}
            onchange={(event) => chooseService(event.currentTarget.value)}
            aria-label="Service"
          >
            {#each copyServices as serviceId (serviceId)}
              <option value={serviceId}>
                {serviceById(serviceId)?.label ?? serviceId}
              </option>
            {/each}
          </select>
        </label>
        <label class="field">
          Copy
          <select bind:value={copyTarget} aria-label="Copy">
            <option value="">Choose…</option>
            {#each copyOptions as option (option.value)}
              <option value={option.value}>{option.label}</option>
            {/each}
          </select>
          {#if copySentence}<span class="field-help">{copySentence}</span>{/if}
        </label>
      </div>
      <div class="toolbar">
        <button type="button" onclick={closeCopyForm} disabled={holderBusy}>Cancel</button>
        <button
          class="primary"
          type="button"
          onclick={addCopyFromForm}
          disabled={holderBusy || !copyService || !copyTarget}
        >
          {holderBusy ? "Adding…" : "Add copy"}
        </button>
      </div>
    {:else}
      <HoldersTable
        consumers={row.consumers}
        owner={serviceById(ownerId)?.label ?? ownerId}
        busy={holderBusy}
        onremove={(targets) => (removeTargets = targets)}
        oncount={setCopyCount}
      />
      {@const proposals = countProposals(row.consumers)}
      {#if proposals.length}
        <div class="holder-proposals">
          {#each proposals as proposal (proposal.target)}
            {@const proposalText = `${copyLabel(proposal.target)}: the API lists ${proposal.observed} ${proposal.observed === 1 ? "row" : "rows"} but ${proposal.count} ${proposal.count === 1 ? "is" : "are"} declared.`}
            <p class="field-warn">
              {proposalText}
              <button
                type="button"
                onclick={() => setCopyCount(proposal.target, proposal.observed)}
                disabled={holderBusy}
              >
                Set count to {proposal.observed}
              </button>
            </p>
          {/each}
        </div>
      {/if}
    {/if}
  </section>

  {#if removeTargets.length}
    <ConfirmDialog
      title="Remove copy"
      message={`Remove ${removeTargets.length === 1 ? "the" : `all ${removeTargets.length}`} ${removeServiceLabel} ${removeTargets.length === 1 ? "copy" : "copies"} of this key? Rotation will no longer write ${removeTargets.length === 1 ? "it" : "them"}. The live service is not changed.`}
      confirmText="Remove"
      busy={holderBusy}
      onconfirm={removeCopiesNow}
      oncancel={() => (removeTargets = [])}
    />
  {/if}

  <section class="card section">
    <div class="section-head">
      <div><h3>Delete</h3></div>
    </div>
    {#if dangerError}<Banner tone="danger">{dangerError}</Banner>{/if}
    <div class="toolbar">
      <button
        class="danger"
        type="button"
        onclick={() => (deleteOpen = true)}
        disabled={dangerBusy}
      >
        Delete this app key
      </button>
    </div>
  </section>
{/if}

{#if deleteOpen && row}
  <ConfirmDialog
    title={`Delete ${title}?`}
    message="Removes the declaration, copies, policy and stored key. No live service changes."
    confirmText={dangerBusy ? "Deleting…" : "Delete"}
    busy={dangerBusy}
    onconfirm={deleteCredential}
    oncancel={() => (deleteOpen = false)}
  />
{/if}
