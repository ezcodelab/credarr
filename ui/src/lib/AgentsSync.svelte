<script>
  import { onMount } from "svelte";
  import { api, ApiError, errorText, timestamp } from "./api.js";
  import Banner from "./Banner.svelte";

  let { onsignout = null } = $props();

  let agents = $state([]);
  let targets = $state([]);
  let jobs = $state([]);
  let sync = $state(null);
  let plane = $state(null);
  let loading = $state(true);
  let error = $state("");
  let message = $state("");

  let enrollName = $state("");
  let enrollCaps = $state("compose");
  let token = $state("");
  let enrollBusy = $state(false);
  let revokeArmed = $state("");

  let targetName = $state("");
  let targetAgent = $state("");
  let targetPath = $state("");
  let targetProject = $state("");
  let targetServices = $state("");
  let targetBusy = $state(false);

  async function load() {
    loading = true;
    error = "";
    try {
      const [agentAnswer, targetAnswer, jobAnswer] = await Promise.all([
        api("/agents", { timeout: 10_000 }),
        api("/sync/targets", { timeout: 10_000 }),
        api("/sync/jobs?limit=10", { timeout: 10_000 }),
      ]);
      agents = agentAnswer?.agents ?? [];
      sync = agentAnswer?.sync ?? null;
      plane = agentAnswer?.control_plane ?? null;
      targets = targetAnswer?.targets ?? [];
      jobs = jobAnswer?.jobs ?? [];
      if (!targetAgent && agents.length) targetAgent = agents[0].id;
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout?.();
      else error = errorText(failure);
    } finally {
      loading = false;
    }
  }

  async function enroll(event) {
    event.preventDefault();
    if (enrollBusy || !enrollName.trim()) return;
    enrollBusy = true;
    error = "";
    token = "";
    try {
      const answer = await api("/agents/enrollment", {
        method: "POST",
        body: {
          name: enrollName.trim(),
          capabilities: enrollCaps
            .split(",")
            .map((item) => item.trim())
            .filter(Boolean),
        },
      });
      token = answer?.token ?? "";
      enrollName = "";
      message = "Enrollment token created. It is shown once.";
      await load();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout?.();
      else error = errorText(failure);
    } finally {
      enrollBusy = false;
    }
  }

  async function addTarget(event) {
    event.preventDefault();
    if (targetBusy) return;
    targetBusy = true;
    error = "";
    try {
      await api("/sync/targets", {
        method: "POST",
        body: {
          name: targetName.trim(),
          agent_id: targetAgent,
          stack_path: targetPath.trim(),
          project_name: targetProject.trim(),
          services: targetServices
            .split(",")
            .map((item) => item.trim())
            .filter(Boolean),
          workflow: "compose",
          enabled: true,
        },
      });
      targetName = "";
      targetPath = "";
      targetProject = "";
      targetServices = "";
      message = "Target saved.";
      await load();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout?.();
      else error = errorText(failure);
    } finally {
      targetBusy = false;
    }
  }

  async function revoke(agent) {
    if (revokeArmed !== agent.id) {
      revokeArmed = agent.id;
      return;
    }
    try {
      await api(`/agents/${encodeURIComponent(agent.id)}`, { method: "DELETE" });
      revokeArmed = "";
      await load();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout?.();
      else error = errorText(failure);
    }
  }

  async function cancel(job) {
    try {
      await api(`/sync/jobs/${encodeURIComponent(job.id)}/cancel`, { method: "POST" });
      await load();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout?.();
      else error = errorText(failure);
    }
  }

  onMount(load);
</script>

<section class="card section" id="settings-agents">
  <div class="section-head">
    <div>
      <h3>Agents &amp; sync</h3>
      <p class="muted">
        The BFF never runs Docker. Agents pull signed work over mTLS, read the
        shared vault tree, and report one boolean per service.
      </p>
    </div>
    <button type="button" onclick={load} disabled={loading}>Refresh</button>
  </div>
  {#if error}<Banner tone="danger">{error}</Banner>{/if}
  {#if message}<Banner tone="ok">{message}</Banner>{/if}
  {#if loading}
    <p class="muted">Reading agents…</p>
  {:else}
    {#if plane}
      <p class="muted">
        Control plane: {plane.enabled ? `listening on ${plane.host}:${plane.port}` : "not listening"}.
        TLS {plane.tls}, group {plane.group ?? "unknown"}.
        {#if plane.ca}CA: <code>{plane.ca}</code>{/if}
      </p>
    {/if}
    {#if sync && !sync.tree_configured}
      <Banner tone="danger" title="No shared vault tree">
        Set <code>CREDARR_VAULT_TREE</code> and restart before creating a target.
        Agents fail closed without it.
      </Banner>
    {/if}

    <h4>Agents</h4>
    {#if agents.length === 0}
      <p class="muted">No agent has enrolled.</p>
    {:else}
      <table class="table">
        <thead><tr><th>Name</th><th>State</th><th>Certificate</th><th></th></tr></thead>
        <tbody>
          {#each agents as agent (agent.id)}
            <tr>
              <td>{agent.name}</td>
              <td>{agent.status}{agent.rootful ? " · rootful" : ""}</td>
              <td>{agent.certificate_expires_at ? timestamp(agent.certificate_expires_at) : "none"}</td>
              <td>
                {#if agent.status !== "revoked"}
                  <button class="danger" type="button" onclick={() => revoke(agent)}>
                    {revokeArmed === agent.id ? "Confirm revoke" : "Revoke"}
                  </button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}

    <form class="toolbar" onsubmit={enroll}>
      <label class="field">
        Agent name
        <input bind:value={enrollName} placeholder="media-host" autocomplete="off" />
      </label>
      <label class="field">
        Capabilities
        <input bind:value={enrollCaps} placeholder="compose" autocomplete="off" />
      </label>
      <button type="submit" disabled={enrollBusy || !enrollName.trim()}>
        {enrollBusy ? "Creating…" : "Create enrollment token"}
      </button>
    </form>
    {#if token}
      <p class="muted">Token (shown once):</p>
      <input class="secret" readonly value={token} autocomplete="off" spellcheck="false" />
    {/if}

    <h4>Targets</h4>
    {#if targets.length === 0}
      <p class="muted">No target is declared.</p>
    {:else}
      <table class="table">
        <thead><tr><th>Name</th><th>Agent</th><th>Stack</th><th>Services</th><th>On</th></tr></thead>
        <tbody>
          {#each targets as target (target.id)}
            <tr>
              <td>{target.name}</td>
              <td>{agents.find((item) => item.id === target.agent_id)?.name ?? target.agent_id}</td>
              <td>{target.project_name} · {target.stack_path}</td>
              <td>{target.services.join(", ")}</td>
              <td>{target.enabled ? "yes" : "no"}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}

    <form class="field-grid" onsubmit={addTarget}>
      <label class="field">
        Target name
        <input bind:value={targetName} placeholder="media" autocomplete="off" />
      </label>
      <label class="field">
        Agent
        <select bind:value={targetAgent}>
          {#each agents as agent (agent.id)}
            <option value={agent.id}>{agent.name}</option>
          {/each}
        </select>
      </label>
      <label class="field">
        Stack path
        <input bind:value={targetPath} placeholder="/srv/media" autocomplete="off" />
      </label>
      <label class="field">
        Project
        <input bind:value={targetProject} placeholder="media" autocomplete="off" />
      </label>
      <label class="field">
        Services
        <input bind:value={targetServices} placeholder="sonarr, seerr" autocomplete="off" />
      </label>
      <div class="toolbar">
        <button
          type="submit"
          disabled={targetBusy || !sync?.tree_configured || !targetAgent || !targetName.trim() || !targetPath.trim() || !targetProject.trim()}
        >
          {targetBusy ? "Saving…" : "Add target"}
        </button>
      </div>
    </form>

    <h4>Recent deliveries</h4>
    {#if jobs.length === 0}
      <p class="muted">No delivery job yet.</p>
    {:else}
      <table class="table">
        <thead><tr><th>Credential</th><th>State</th><th>Attempts</th><th>Result</th><th></th></tr></thead>
        <tbody>
          {#each jobs as job (job.id)}
            <tr>
              <td>{job.credential}</td>
              <td>{job.state}</td>
              <td class="tabular">{job.attempts}/{job.max_attempts}</td>
              <td>{job.last_error || "—"}</td>
              <td>
                {#if ["queued", "leased", "running", "retry_wait"].includes(job.state)}
                  <button type="button" onclick={() => cancel(job)}>Cancel</button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  {/if}
</section>
