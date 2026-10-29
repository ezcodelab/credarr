<script>
  import { onMount } from "svelte";
  import {
    api,
    ApiError,
    auditStack,
    clearCsrfToken,
    elapsed,
    errorText,
    setCsrfToken,
    setTimeZone,
    waitForAudit,
  } from "./lib/api.js";
  import Banner from "./lib/Banner.svelte";
  import Icon from "./lib/Icon.svelte";
  import Toasts from "./lib/Toasts.svelte";
  import { clearToasts } from "./lib/toast.js";
  import { credentialTitle } from "./lib/names.js";
  import Auth from "./Auth.svelte";
  import SetupWizard from "./SetupWizard.svelte";
  import Apps from "./views/Apps.svelte";
  import AppDetail from "./views/AppDetail.svelte";
  import Activity from "./views/Activity.svelte";
  import Settings from "./views/Settings.svelte";

  // The shell: three areas, no engine vocabulary. Apps is the home (one card
  // per app and its key), Activity is the audit and what changed, Settings is
  // everything configurable. Services, Credentials, Overview and Events are
  // not separate pages: the console joins the resources instead.
  const NAV = [
    { id: "apps", label: "Apps", icon: "apps" },
    { id: "activity", label: "Activity", icon: "activity" },
    { id: "settings", label: "Settings", icon: "settings" },
  ];

  // Settings is one page; its menu entries scroll to a section, so the two
  // lists have to name the same sections.
  const SETTINGS_SECTIONS = [
    { id: "security", label: "Security" },
    { id: "audit", label: "Audit schedule" },
    { id: "keys", label: "API keys" },
    { id: "notifications", label: "Notifications" },
    { id: "topology", label: "Import / Export" },
  ];
  const DROPDOWNS = ["apps", "settings"];

  const SETUP_SKIP_KEY = "credarr.setup.skipped";

  function readSetupSkip() {
    try {
      return globalThis.sessionStorage?.getItem(SETUP_SKIP_KEY) === "1";
    } catch {
      return false;
    }
  }

  function writeSetupSkip() {
    try {
      globalThis.sessionStorage?.setItem(SETUP_SKIP_KEY, "1");
    } catch {
      // A browser that refuses session storage has no skip to remember.
    }
  }

  function clearSetupSkip() {
    try {
      globalThis.sessionStorage?.removeItem(SETUP_SKIP_KEY);
    } catch {
      // Nothing to clear.
    }
  }

  let phase = $state("loading"); // loading | unreachable | setup | login | ready
  let boot = $state("");
  // The first-run wizard is shown only when the server says the topology has
  // never been imported. A skip is per browser tab, and the saved draft is the
  // resume path; neither is a server-side "setup complete" flag.
  let setupActive = $state(false);
  let setupFresh = $state(false);
  let setupSkipped = $state(false);
  let setupMode = $state("create");
  let view = $state("apps"); // apps | app | activity | settings
  // Which app the detail view shows; "" falls back to the first.
  let credentialName = $state("");
  let actor = $state("");
  let status = $state(null);
  let credentials = $state(null);
  let busy = $state(false);
  let actionError = $state("");
  // The background audit this tab is already polling. A refresh that sees the
  // same active job must not start a second poll.
  let resumedJob = "";
  // The run the operator just asked for, so the answer is visible even when
  // every row has nothing to compare. Cleared on the next explicit run.
  // Bumped when the interrupted-rotation banner opens the detail view; it
  // scrolls to and focuses the rotation form.
  let rotationFocus = $state(0);
  // The sidebar's dropdowns. One state per section, because a name picked in
  // Apps must not collapse the menu the operator is browsing.
  let open = $state({ apps: false, settings: false });
  // Picked from the Settings menu: which section the view scrolls to.
  let settingsSection = $state("");
  // The sidebar is an off-canvas drawer below tablet width.
  let navOpen = $state(false);

  // The sidebar's children, from the payloads the shell already holds. Apps
  // come from the store's rows; services not yet joined to a key appear in
  // the Apps hub itself, not here.
  function subnav(item) {
    if (item.id === "apps")
      return (credentials?.credentials ?? []).map((row) => ({
        id: row.name,
        label: credentialTitle(row.name),
      }));
    if (item.id === "settings") return SETTINGS_SECTIONS;
    return [];
  }

  function childActive(parent, child) {
    if (parent === "apps")
      return (
        view === "app" &&
        (credentialName || credentials?.credentials?.[0]?.name) === child
      );
    if (parent === "settings") return view === "settings" && settingsSection === child;
    return false;
  }

  // An unfinished rotation is the one state that must be seen before anything
  // else is run: the engine refuses a new run until the step is old enough to
  // be presumed dead, and then takes over from observed state instead of
  // minting again.
  const rotationPending = $derived(status?.rotation?.pending ?? []);
  const rotationNames = $derived([
    ...new Set(rotationPending.map((step) => step.credential)),
  ]);

  // The two reads are the console's whole state; a hung one must not hold the
  // screen on "Loading…" forever.
  const READ_TIMEOUT = 10_000;

  // "" when both reads landed; otherwise the sentence to show. A 401 signs out
  // instead of reporting: that is a session ending, not a failure of the BFF.
  async function load() {
    try {
      const [nextStatus, nextCredentials] = await Promise.all([
        api("/status", { timeout: READ_TIMEOUT }),
        api("/credentials", { timeout: READ_TIMEOUT }),
      ]);
      // A 200 with no readable body is not a state, and rendering the shell
      // over it would show the empty-store screen for a store nobody read.
      if (!nextStatus || !nextCredentials) {
        return "the server sent no readable response";
      }
      setTimeZone(nextStatus.timezone);
      status = nextStatus;
      credentials = nextCredentials;
      return "";
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        signedOut();
        return "";
      }
      if (failure?.name === "TimeoutError")
        return `the server did not answer within ${READ_TIMEOUT / 1000} seconds`;
      return errorText(failure);
    }
  }

  function signedOut() {
    clearCsrfToken();
    clearToasts();
    status = null;
    credentials = null;
    // A new session must not greet the operator with the last one's audit
    // banner or a stale failure.
    actionError = "";
    view = "apps";
    credentialName = "";
    rotationFocus = 0;
    settingsSection = "";
    navOpen = false;
    open = { apps: false, settings: false };
    setupActive = false;
    setupSkipped = false;
    clearSetupSkip();
    phase = "login";
  }

  function closeNav() {
    navOpen = false;
  }

  function onKeydown(event) {
    if (event.key === "Escape" && navOpen) closeNav();
  }

  function navigate(target) {
    // A nav click is not a request for the rotation form; only the
    // interrupted-rotation banner bumps the focus counter.
    rotationFocus = 0;
    settingsSection = "";
    clearToasts();
    view = target;
    closeNav();
  }

  // A top-level item with children both navigates and opens: the menu is how
  // the operator gets into the section, and the children are how they pick
  // something inside it.
  function navigateParent(item) {
    rotationFocus = 0;
    if (DROPDOWNS.includes(item.id)) open[item.id] = !open[item.id];
    if (item.id === "apps" && view === "app") {
      // The detail page belongs to Apps: the parent goes home.
      settingsSection = "";
      clearToasts();
      view = "apps";
      closeNav();
      return;
    }
    if (view === item.id) return;
    if (item.id === "settings") settingsSection = "";
    clearToasts();
    view = item.id;
    if (!DROPDOWNS.includes(item.id)) closeNav();
  }

  function navigateChild(parent, child) {
    rotationFocus = 0;
    if (parent === "apps") {
      credentialName = child;
      clearToasts();
      view = "app";
      closeNav();
      return;
    }
    settingsSection = child;
    clearToasts();
    view = "settings";
    closeNav();
  }

  // A fresh sign-in reads the actor: the login response does not carry it, and
  // the footer exists to name who is signed in. The boot probe already read it
  // and passes it in, so the console does not ask twice.
  async function signedIn(known = "") {
    // The shell only exists over a payload: rendering it with `status: null`
    // would show the empty-store screen, which is a statement about a store
    // nobody has read yet.
    phase = "loading";
    try {
      if (!known) {
        const me = await api("/auth/me");
        actor = me.actor;
        setCsrfToken(me.csrf);
      }
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        signedOut();
        return;
      }
      // The session is what matters; an actor read that failed is not a reason
      // to refuse the console. The footer shows an empty name instead.
    }
    const failure = await load();
    if (phase === "login") return;
    boot = failure;
    phase = failure ? "unreachable" : "ready";
    if (failure) {
      setupActive = false;
      return;
    }
    const imported = status?.topology?.imported === true;
    if (imported) {
      clearSetupSkip();
      setupSkipped = false;
      setupActive = false;
    } else {
      setupMode = "create";
      setupSkipped = readSetupSkip();
      setupActive = !setupSkipped;
    }
    if (status?.audit_job?.job_id) void resumeAudit(status.audit_job);
  }

  async function refresh() {
    actionError = "";
    const failure = await load();
    if (failure) actionError = failure;
    if (!failure && status?.topology?.imported === true) {
      clearSetupSkip();
      setupSkipped = false;
      setupActive = false;
    }
    if (!failure && status?.audit_job?.job_id) {
      void resumeAudit(status.audit_job);
    }
    // Deleting the open app must not leave the menu pointing at a name that
    // no longer exists while the detail silently falls back to the first row.
    if (
      view === "app" &&
      credentialName &&
      !(credentials?.credentials ?? []).some((row) => row.name === credentialName)
    ) {
      credentialName = credentials?.credentials?.[0]?.name ?? "";
    }
  }

  function skipSetup() {
    setupSkipped = true;
    setupActive = false;
    writeSetupSkip();
    view = "apps";
  }

  function resumeSetup(fresh = false) {
    setupMode = status?.topology?.imported ? "edit" : "create";
    setupFresh = fresh;
    setupSkipped = false;
    clearSetupSkip();
    setupActive = true;
  }

  async function resetTopology() {
    // The topology is already erased by the caller; show the first-run wizard
    // even if the follow-up read is slow or fails.
    setupMode = "create";
    setupFresh = true;
    setupSkipped = false;
    clearSetupSkip();
    setupActive = true;
    await refresh();
  }

  async function finishSetup(target = "apps") {
    setupActive = false;
    setupSkipped = false;
    clearSetupSkip();
    clearToasts();
    rotationFocus = 0;
    credentialName = "";
    // Older callers say "overview"/"credential"; both mean Apps now.
    view = target === "credential" || target === "app" ? "app" : "apps";
    await refresh();
  }

  function openCredential(name) {
    credentialName = name;
    rotationFocus = 0;
    open.apps = true;
    clearToasts();
    view = "app";
    closeNav();
  }

  function rotateCredential(name) {
    credentialName = name;
    rotationFocus += 1;
    open.apps = true;
    clearToasts();
    view = "app";
    closeNav();
  }

  async function runAudit() {
    busy = true;
    actionError = "";
    const trouble = (failure) => {
      actionError = failure
        ? "Lost contact with the server; still watching the audit. Reload to resume it."
        : "";
    };
    try {
      // The audit is a server-side job; this promise polls its job id. A
      // dropped tunnel does not lose the run or leave the button wedged.
      const answer = await auditStack({ onTrouble: trouble });
      const next = await api("/credentials", { timeout: READ_TIMEOUT });
      if (!answer || !next) {
        throw new Error("the server sent no readable response");
      }
      status = answer;
      credentials = next;
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) signedOut();
      else actionError = errorText(failure);
    } finally {
      busy = false;
    }
  }

  async function resumeAudit(job) {
    if (busy || !job?.job_id || resumedJob === job.job_id) return;
    resumedJob = job.job_id;
    busy = true;
    actionError = "";
    const trouble = (failure) => {
      actionError = failure
        ? "Lost contact with the server; still watching the audit. Reload to resume it."
        : "";
    };
    try {
      const answer = await waitForAudit(job.job_id, { onTrouble: trouble });
      const next = await api("/credentials", { timeout: READ_TIMEOUT });
      if (!answer || !next) {
        throw new Error("the server sent no readable response");
      }
      status = answer;
      credentials = next;
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) signedOut();
      else actionError = errorText(failure);
    } finally {
      if (resumedJob === job.job_id) resumedJob = "";
      busy = false;
    }
  }

  async function signOut() {
    try {
      await api("/auth/logout", { method: "POST" });
    } catch {
      // Signing out locally is the honest outcome either way.
    }
    signedOut();
  }

  // The boot probe: is there a session, and is the BFF answering at all?
  async function probe() {
    phase = "loading";
    try {
      const me = await api("/auth/me");
      actor = me.actor;
      setCsrfToken(me.csrf);
      await signedIn(actor);
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        try {
          phase = (await api("/auth/state")).needs_setup ? "setup" : "login";
        } catch (down) {
          boot = down.message ?? String(down);
          phase = "unreachable";
        }
      } else {
        boot = errorText(failure);
        phase = "unreachable";
      }
    }
  }

  // A tab left open must not lose its session to the idle window while the
  // operator is looking at it. A cheap /auth/me every few minutes slides the
  // server-side idle timer. A 401 still ends the session (the absolute cap is
  // server policy), and nothing is written to storage.
  const KEEPALIVE_MS = 5 * 60 * 1000;
  let keepaliveTimer = 0;

  function startKeepalive() {
    clearInterval(keepaliveTimer);
    keepaliveTimer = setInterval(async () => {
      if (document.visibilityState !== "visible" || phase !== "ready") return;
      try {
        await api("/auth/me");
      } catch (failure) {
        if (failure instanceof ApiError && failure.status === 401) signedOut();
      }
    }, KEEPALIVE_MS);
  }

  onMount(() => {
    probe();
    startKeepalive();
    return () => clearInterval(keepaliveTimer);
  });
</script>

<svelte:head><title>credarr</title></svelte:head>
<svelte:window onkeydown={onKeydown} />

<a class="skip" href="#main-content">Skip to content</a>

{#if phase === "loading"}
  <main class="center">
    <div class="auth-card"><p class="muted">Loading…</p></div>
  </main>
{:else if phase === "unreachable"}
  <main class="center">
    <div class="auth-card">
      <h1>credarr</h1>
      <p class="error" role="alert">The console could not read its state: {boot}</p>
      <p class="muted">Check the <code>credarr-server</code> log for this container.</p>
      <button class="primary" onclick={probe}>Try again</button>
    </div>
  </main>
{:else if phase !== "ready"}
  <Auth mode={phase} ondone={signedIn} />
{:else if setupActive}
  <SetupWizard
    mode={setupMode}
    fresh={setupFresh}
    onfinish={finishSetup}
    onskip={skipSetup}
    onsignout={signOut}
  />
{:else}
  <div class="shell">
    <div class="mobile-bar">
      <button
        class="icon"
        aria-label={navOpen ? "Close navigation" : "Open navigation"}
        aria-controls="sidebar"
        aria-expanded={navOpen}
        onclick={() => (navOpen = !navOpen)}
      >
        <Icon name={navOpen ? "close" : "menu"} size={18} />
      </button>
      <div class="brand">
        <span class="brand-mark"><Icon name="shield" size={16} /></span>
        credarr
      </div>
    </div>

    {#if navOpen}
      <button class="nav-backdrop" aria-label="Dismiss navigation" onclick={closeNav}></button>
    {/if}

    <aside id="sidebar" class:open={navOpen}>
      <div class="brand">
        <span class="brand-mark"><Icon name="shield" size={18} /></span>
        <span>credarr</span>
      </div>
      <nav aria-label="Primary">
        {#each NAV as item (item.id)}
          {@const children = subnav(item)}
          <button
            class:active={view === item.id || (item.id === "apps" && view === "app")}
            aria-current={view === item.id || (item.id === "apps" && view === "app") ? "page" : undefined}
            aria-expanded={children.length ? open[item.id] : undefined}
            onclick={() => navigateParent(item)}
          >
            <span class="nav-icon" aria-hidden="true"><Icon name={item.icon} size={17} /></span>
            {item.label}
            {#if item.id === "apps" && rotationPending.length > 0}
              <span class="nav-badge" aria-hidden="true">{rotationPending.length}</span>
            {/if}
            {#if children.length}
              <span class="nav-caret" aria-hidden="true">{open[item.id] ? "▾" : "▸"}</span>
            {/if}
          </button>
          {#if children.length && open[item.id]}
            <div class="nav-sub">
              {#each children as child (child.id)}
                <button
                  class:active={childActive(item.id, child.id)}
                  title={child.label}
                  onclick={() => navigateChild(item.id, child.id)}
                >
                  {child.label}
                </button>
              {/each}
            </div>
          {/if}
        {/each}
      </nav>
      <footer>
        <div class="app-name">
          credarr <span class="muted">v{status?.version ?? "—"}</span>
        </div>
        <div class="footer-actor">
          <Icon name="shield" size={13} />
          <span class="muted">{actor}</span>
        </div>
        <button onclick={signOut}>Sign out</button>
      </footer>
    </aside>

    <main class="main" id="main-content">
      <div class="page">
        {#if status && !status.scheduler.running}
          <Banner tone="warn" title="The audit loop is not running.">
            {status.scheduler.failure ?? "It never started."}
            Data below is as old as the last recorded run.
          </Banner>
        {/if}
        {#if rotationPending.length > 0}
          <Banner tone="danger" role="alert" title="A rotation did not finish.">
            <p>
              {rotationNames.map(credentialTitle).join(", ")} stopped
              {elapsed(rotationPending[0].seconds_ago)} ago. Resume from the app
              page; it continues the earlier mint instead of making a second
              key. A live run keeps the lock.
            </p>
            <p class="muted">Audits never restart it.</p>
            {#snippet actions()}
              {#each rotationNames as name (name)}
                {#if credentials?.credentials.some((row) => row.name === name)}
                  <button onclick={() => rotateCredential(name)}>Resume {credentialTitle(name)}</button>
                {/if}
              {/each}
            {/snippet}
          </Banner>
        {/if}
        {#if actionError}
          <Banner tone="danger">{actionError}</Banner>
        {/if}
        {#if view === "apps"}
          <Apps
            {status}
            {credentials}
            {busy}
            onrun={runAudit}
            onrefresh={refresh}
            onopen={openCredential}
            onsetup={() => resumeSetup(false)}
            onsignout={signedOut}
          />
        {:else if view === "activity"}
          <Activity
            {status}
            onapps={() => navigate("apps")}
            onsettings={() => navigate("settings")}
            onsignout={signedOut}
          />
        {:else if view === "settings"}
          <Settings
            section={settingsSection}
            onrefresh={refresh}
            onreopen={() => resumeSetup(true)}
            onreset={resetTopology}
            onsignout={signedOut}
          />
        {:else}
          {#key credentialName}
          <AppDetail
            data={credentials}
            name={credentialName}
            rotation={status?.rotation ?? null}
            {rotationFocus}
            onrefresh={refresh}
            onapps={() => navigate("apps")}
            onsignout={signedOut}
          />
          {/key}
        {/if}
      </div>
      <Toasts />
    </main>
  </div>
{/if}
