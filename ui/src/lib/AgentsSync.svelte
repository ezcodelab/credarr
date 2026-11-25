<script>
  import { onMount } from "svelte";
  import { api, ApiError, errorText, timestamp } from "./api.js";
  import Banner from "./Banner.svelte";

  let { onsignout = null } = $props();

  let agents = $state([]);
  let targets = $state([]);
  let jobs = $state([]);
  let sync = $state(null);
  let loading = $state(true);
  let error = $state("");
  let message = $state("");

  let enrollOpen = $state(false);
  let enrollName = $state("");
  let enrollCompose = $state(true);
  let enrollEnv = $state(false);
  let token = $state("");
  let enrollBusy = $state(false);
  let revokeArmed = $state("");
  let agentEditingId = $state("");
  let agentEditName = $state("");
  let agentEditCompose = $state(true);
  let agentEditEnv = $state(false);
  let agentEditBusy = $state(false);

  let targetOpen = $state(false);
  let targetEditingId = $state("");
  let targetDeleteArmed = $state("");
  let targetWorkflow = $state("compose");
  let targetName = $state("");
  let targetAgent = $state("");
  let targetPath = $state("");
  let targetProject = $state("");
  let targetServices = $state("");
  let targetEnvFile = $state("");
  let targetValues = $state("");
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

  function openEnroll() {
    enrollOpen = true;
    token = "";
  }

  function openTarget(target = null) {
    targetOpen = true;
    targetEditingId = target?.id ?? "";
    targetWorkflow = target?.workflow ?? "compose";
    targetName = target?.name ?? "";
    targetAgent = target?.agent_id ?? targetAgent;
    targetPath = target?.stack_path ?? "";
    targetProject = target?.project_name ?? "";
    targetServices = (target?.services ?? []).join(", ");
    targetEnvFile = target?.env_file ?? "";
    targetValues = Object.entries(target?.values ?? {})
      .map(([key, credential]) => `${key}=${credential}`)
      .join("\n");
    if (!targetAgent && agents.length) targetAgent = agents[0].id;
  }

  async function enroll(event) {
    event.preventDefault();
    if (enrollBusy || !enrollName.trim()) return;
    const capabilities = [
      ...(enrollCompose ? ["compose"] : []),
      ...(enrollEnv ? ["env"] : []),
    ];
    if (!capabilities.length) {
      error = "select at least one capability";
      return;
    }
    enrollBusy = true;
    error = "";
    token = "";
    try {
      const answer = await api("/agents/enrollment", {
        method: "POST",
        body: { name: enrollName.trim(), capabilities },
      });
      token = answer?.token ?? "";
      enrollName = "";
      enrollOpen = false;
      message = "Enrollment token created.";
      await load();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout?.();
      else error = errorText(failure);
    } finally {
      enrollBusy = false;
    }
  }

  function valueMap() {
    const values = {};
    for (const line of targetValues.split("\n")) {
      const [key, credential] = line.split("=", 2).map((item) => item.trim());
      if (key && credential) values[key] = credential;
    }
    return values;
  }

  async function addTarget(event) {
    event.preventDefault();
    if (targetBusy) return;
    targetBusy = true;
    error = "";
    try {
      const body = {
        name: targetName.trim(),
        agent_id: targetAgent,
        stack_path: targetPath.trim(),
        project_name: targetProject.trim(),
        services: targetServices
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean),
        workflow: targetWorkflow,
        env_file: targetWorkflow === "env" ? targetEnvFile.trim() : null,
        values: targetWorkflow === "env" ? valueMap() : {},
        enabled: true,
      };
      await api(
        targetEditingId
          ? `/sync/targets/${encodeURIComponent(targetEditingId)}`
          : "/sync/targets",
        { method: targetEditingId ? "PATCH" : "POST", body },
      );
      targetOpen = false;
      targetEditingId = "";
      message = "Target saved.";
      await load();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout?.();
      else error = errorText(failure);
    } finally {
      targetBusy = false;
    }
  }

  async function toggleTarget(target) {
    try {
      await api(`/sync/targets/${encodeURIComponent(target.id)}`, {
        method: "PATCH",
        body: { enabled: !target.enabled },
      });
      await load();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout?.();
      else error = errorText(failure);
    }
  }

  async function testTarget(target) {
    try {
      await api(`/sync/targets/${encodeURIComponent(target.id)}/test`, {
        method: "POST",
      });
      message = "Target test queued.";
      await load();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout?.();
      else error = errorText(failure);
    }
  }

  async function deleteTarget(target) {
    if (targetDeleteArmed !== target.id) {
      targetDeleteArmed = target.id;
      return;
    }
    try {
      await api(`/sync/targets/${encodeURIComponent(target.id)}`, {
        method: "DELETE",
      });
      targetDeleteArmed = "";
      await load();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout?.();
      else error = errorText(failure);
    }
  }

  function editAgent(agent) {
    agentEditingId = agent.id;
    agentEditName = agent.name;
    agentEditCompose = agent.capabilities.includes("compose");
    agentEditEnv = agent.capabilities.includes("env");
  }

  async function saveAgent(event) {
    event.preventDefault();
    if (!agentEditName.trim()) return;
    const current = agents.find((item) => item.id === agentEditingId);
    const capabilities = [
      ...(agentEditCompose ? ["compose"] : []),
      ...(agentEditEnv ? ["env"] : []),
      ...(current?.capabilities ?? []).filter(
        (item) => !["compose", "env"].includes(item),
      ),
    ];
    agentEditBusy = true;
    try {
      await api(`/agents/${encodeURIComponent(agentEditingId)}`, {
        method: "PATCH",
        body: { name: agentEditName.trim(), capabilities },
      });
      agentEditingId = "";
      message = "Agent saved.";
      await load();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout?.();
      else error = errorText(failure);
    } finally {
      agentEditBusy = false;
    }
  }

  async function toggleAgent(agent) {
    try {
      if (agent.status === "disabled" || agent.status === "offline") {
        await api(`/agents/${encodeURIComponent(agent.id)}/enable`, {
          method: "POST",
        });
      } else {
        await api(`/agents/${encodeURIComponent(agent.id)}/disable`, {
          method: "POST",
          body: { reason: "disabled by the operator" },
        });
      }
      await load();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout?.();
      else error = errorText(failure);
    }
  }

  async function testAgent(agent) {
    try {
      const answer = await api(`/agents/${encodeURIComponent(agent.id)}/test`, {
        method: "POST",
      });
      message = `${answer?.jobs?.length ?? 0} target test(s) queued.`;
      await load();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout?.();
      else error = errorText(failure);
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
      <p class="muted">Deliver committed values to Docker.</p>
    </div>
    <button type="button" onclick={load} disabled={loading}>Refresh</button>
  </div>
  {#if error}<Banner tone="danger">{error}</Banner>{/if}
  {#if message}<Banner tone="ok">{message}</Banner>{/if}


  {#if enrollOpen}
    <form class="enroll" onsubmit={enroll}>
      <label class="field">
        Agent name
        <input bind:value={enrollName} placeholder="nas" autocomplete="off" />
      </label>
      <div class="capabilities" role="group" aria-label="Capabilities">
        <label class="check"><input type="checkbox" bind:checked={enrollCompose} /> Restart services</label>
        <label class="check"><input type="checkbox" bind:checked={enrollEnv} /> Write env files</label>
      </div>
      <div class="toolbar">
        <button type="button" onclick={() => (enrollOpen = false)}>Cancel</button>
        <span class="spacer"></span>
        <button class="primary" type="submit" disabled={enrollBusy || !enrollName.trim()}>
          {enrollBusy ? "Creating…" : "Create token"}
        </button>
      </div>
    </form>
  {/if}

  {#if token}
    <div class="token-row">
      <input class="secret" readonly value={token} aria-label="Enrollment token" autocomplete="off" spellcheck="false" />
      <button type="button" onclick={() => (token = "")}>Done</button>
    </div>
  {/if}

  <div class="split">
    <div class="targets">
      <div class="section-head">
        <div>
          <h4>Targets</h4>
          <p class="muted">Where values are delivered.</p>
        </div>
        <button class="primary" type="button" onclick={() => openTarget()}>New target</button>
      </div>

      {#if targetOpen}
        <form class="target-form" onsubmit={addTarget}>
          <div class="workflow-choice" role="group" aria-label="Target type">
            <button
              type="button"
              class:active={targetWorkflow === "compose"}
              aria-pressed={targetWorkflow === "compose"}
              onclick={() => (targetWorkflow = "compose")}
            >
              Restart services
            </button>
            <button
              type="button"
              class:active={targetWorkflow === "env"}
              aria-pressed={targetWorkflow === "env"}
              onclick={() => (targetWorkflow = "env")}
            >
              Write env file
            </button>
          </div>
          <div class="field-grid">
            <label class="field">
              Name
              <input bind:value={targetName} placeholder="homepage" autocomplete="off" />
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
              Stack
              <input bind:value={targetPath} placeholder="/stacks/homepage" autocomplete="off" />
            </label>
            <label class="field">
              Project
              <input bind:value={targetProject} placeholder="homepage" autocomplete="off" />
            </label>
            <label class="field">
              Services
              <input bind:value={targetServices} placeholder="homepage" autocomplete="off" />
            </label>
            {#if targetWorkflow === "env"}
              <label class="field">
                Env file
                <input bind:value={targetEnvFile} placeholder=".env" autocomplete="off" />
              </label>
              <label class="field wide">
                Keys
                <textarea
                  bind:value={targetValues}
                  rows="3"
                  placeholder="HOMEPAGE_VAR_SONARR_API_KEY=sonarr_api_key"
                  spellcheck="false"
                ></textarea>
              </label>
            {/if}
          </div>
          <div class="toolbar">
            <button type="button" onclick={() => (targetOpen = false)}>Cancel</button>
            <span class="spacer"></span>
            <button
              class="primary"
              type="submit"
              disabled={targetBusy || !targetAgent || !targetName.trim() || !targetPath.trim() || !targetProject.trim() || (targetWorkflow === "env" && (!targetEnvFile.trim() || !targetValues.trim()))}
            >
              {targetBusy ? "Saving…" : "Save target"}
            </button>
          </div>
        </form>
      {/if}

      {#if targets.length === 0}
        <p class="muted">No targets.</p>
      {:else}
        <table class="table targets-table">
          <thead><tr><th>Name</th><th>Type</th><th>Stack</th><th>On</th><th></th></tr></thead>
          <tbody>
            {#each targets as target (target.id)}
              <tr>
                <td>
                  <strong>{target.name}</strong>
                  <span class="target-agent muted">
                    {agents.find((item) => item.id === target.agent_id)?.name ?? target.agent_id}
                  </span>
                </td>
                <td>{target.workflow}{target.env_file ? ` · ${target.env_file}` : ""}</td>
                <td>{target.project_name} · {target.stack_path}</td>
                <td>{target.enabled ? "On" : "Off"}</td>
                <td class="row-actions">
                  <button type="button" onclick={() => openTarget(target)}>Edit</button>
                  <button type="button" onclick={() => testTarget(target)}>Test</button>
                  <button type="button" onclick={() => toggleTarget(target)}>
                    {target.enabled ? "Disable" : "Enable"}
                  </button>
                  <button class="danger" type="button" onclick={() => deleteTarget(target)}>
                    {targetDeleteArmed === target.id ? "Confirm" : "Delete"}
                  </button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </div>

    <div class="agents">
      <div class="section-head">
        <div>
          <h4>Agents</h4>
          <p class="muted">Workers that apply them.</p>
        </div>
        <button class="primary" type="button" onclick={openEnroll}>Enroll agent</button>
      </div>
      {#if agents.length === 0}
        <p class="muted">No agents.</p>
      {:else}
        <table class="table">
          <thead><tr><th>Name</th><th>State</th><th>Certificate</th><th></th></tr></thead>
          <tbody>
            {#each agents as agent (agent.id)}
              <tr>
                <td>{agent.name}</td>
                <td>{agent.status}{agent.rootful ? " · rootful" : ""}</td>
                <td>{agent.certificate_expires_at ? timestamp(agent.certificate_expires_at) : "—"}</td>
                <td class="row-actions">
                  {#if agent.status !== "revoked"}
                    <button type="button" onclick={() => editAgent(agent)}>Edit</button>
                    <button type="button" onclick={() => testAgent(agent)}>Test</button>
                    <button type="button" onclick={() => toggleAgent(agent)}>
                      {agent.status === "disabled" ? "Enable" : "Disable"}
                    </button>
                    <button class="danger" type="button" onclick={() => revoke(agent)}>
                      {revokeArmed === agent.id ? "Confirm" : "Revoke"}
                    </button>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
        {#if agentEditingId}
          <form class="enroll" onsubmit={saveAgent}>
            <label class="field">
              Agent name
              <input bind:value={agentEditName} autocomplete="off" />
            </label>
            <div class="capabilities" role="group" aria-label="Capabilities">
              <label class="check"><input type="checkbox" bind:checked={agentEditCompose} /> Restart services</label>
              <label class="check"><input type="checkbox" bind:checked={agentEditEnv} /> Write env files</label>
            </div>
            <div class="toolbar">
              <button type="button" onclick={() => (agentEditingId = "")}>Cancel</button>
              <span class="spacer"></span>
              <button class="primary" type="submit" disabled={agentEditBusy || !agentEditName.trim()}>
                {agentEditBusy ? "Saving…" : "Save agent"}
              </button>
            </div>
          </form>
        {/if}
      {/if}
    </div>
  </div>

  <details class="deliveries">
    <summary>Recent deliveries <span class="muted">{jobs.length}</span></summary>
    {#if jobs.length === 0}
      <p class="muted">No jobs.</p>
    {:else}
      <table class="table">
        <thead><tr><th>Credential</th><th>State</th><th>Attempts</th><th>Result</th><th></th></tr></thead>
        <tbody>
          {#each jobs as job (job.id)}
            <tr>
              <td>{job.kind === "probe" ? "target test" : job.credential}</td>
              <td>{job.state}</td>
              <td class="tabular">{job.attempts}/{job.max_attempts}</td>
              <td>{job.last_error || "—"}</td>
              <td class="row-action">
                {#if ["queued", "leased", "running", "retry_wait"].includes(job.state)}
                  <button type="button" onclick={() => cancel(job)}>Cancel</button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </details>
</section>

<style>
  .enroll,
  .target-form {
    padding: 0.85rem;
    border: 1px solid var(--line);
    border-radius: var(--radius);
    background: var(--panel-2);
    margin: 0.6rem 0 1rem;
  }
  .capabilities {
    display: flex;
    align-items: center;
    gap: 0.9rem;
    flex-wrap: wrap;
    margin-top: 0.65rem;
  }
  .token-row {
    display: flex;
    align-items: center;
    gap: 0.45rem;
    margin: 0.6rem 0 1rem;
  }
  .token-row input {
    flex: 1;
    min-width: 0;
  }
  .split {
    display: grid;
    grid-template-columns: minmax(0, 1fr);
    gap: 1.1rem;
    align-items: start;
  }
  .split h4 {
    margin: 0;
    font-size: 0.88rem;
  }
  .targets,
  .agents {
    min-width: 0;
  }
  .targets > .section-head,
  .agents > .section-head {
    min-height: 2.5rem;
    align-items: center;
    margin-bottom: 0.45rem;
  }
  .targets > .section-head .muted,
  .agents > .section-head .muted {
    margin: 0.1rem 0 0;
    font-size: 0.76rem;
  }
  .field.wide { grid-column: 1 / -1; }
  .workflow-choice {
    display: flex;
    gap: 0.35rem;
    margin-bottom: 0.7rem;
  }
  .workflow-choice button {
    flex: 1;
  }
  .workflow-choice button.active {
    border-color: var(--accent);
    background: color-mix(in srgb, var(--accent) 12%, var(--panel-2));
    color: var(--text);
  }
  .target-agent {
    display: block;
    margin-top: 0.12rem;
    font-size: 0.72rem;
  }
  td.row-actions {
    display: table-cell;
    width: 1%;
    text-align: right;
    white-space: nowrap;
  }
  .row-actions button {
    margin-left: 0.3rem;
  }
  .row-actions .danger {
    color: var(--bad);
  }
  .deliveries {
    margin-top: 1rem;
    border-top: 1px solid var(--line);
    padding-top: 0.75rem;
  }
  .deliveries summary {
    cursor: pointer;
    font-weight: 600;
    font-size: 0.88rem;
  }
  .deliveries summary .muted {
    margin-left: 0.35rem;
    font-weight: 400;
  }
  @media (max-width: 900px) {
    .split {
      grid-template-columns: 1fr;
    }
  }
</style>
