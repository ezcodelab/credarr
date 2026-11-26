<script>
  import { onMount } from "svelte";
  import { api, ApiError, errorText, timestamp } from "./api.js";
  import { agentServerUrl, deliveryConfigured, listenerCopy } from "./agents.js";
  import Banner from "./Banner.svelte";
  import LoadingRows from "./LoadingRows.svelte";

  let { onsignout = null } = $props();

  let agents = $state([]);
  let targets = $state([]);
  let jobs = $state([]);
  let sync = $state(null);
  let plane = $state(null);
  let loading = $state(true);
  let error = $state("");
  let message = $state("");

  let enrollOpen = $state(false);
  let enrollName = $state("");
  let enrollCompose = $state(true);
  let enrollEnv = $state(false);
  let token = $state("");
  let enrolledName = $state("");
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

  const treeConfigured = $derived(deliveryConfigured(sync));
  const agentServer = $derived(agentServerUrl(plane));
  const listener = $derived(listenerCopy(plane));
  const enrollCommand = $derived(
    `credarr-agent --server ${agentServer} \\\n` +
      "  --ca /etc/credarr/agent-ca.crt \\\n" +
      "  --vault-root /srv/credarr-vault \\\n" +
      "  --vault-key /etc/credarr/vault-tree.key \\\n" +
      "  --allowed-root /srv \\\n" +
      "  --state-dir /var/lib/credarr-agent \\\n" +
      `  enroll --name ${enrolledName || "<agent-name>"} ` +
      "--token-file /run/credarr/enroll.token",
  );
  const agentExample = $derived(
    "services:\n" +
      "  credarr-agent:\n" +
      "    image: ghcr.io/ezcodelab/credarr-agent:latest\n" +
      "    restart: unless-stopped\n" +
      "    group_add: [\"999\"]\n" +
      "    command:\n" +
      "      - --server\n" +
      `      - ${agentServer}\n` +
      "      - --ca\n" +
      "      - /agent/agent-ca.crt\n" +
      "      - --vault-root\n" +
      "      - /vault\n" +
      "      - --vault-key\n" +
      "      - /agent/vault-tree.key\n" +
      "      - --allowed-root\n" +
      "      - /stacks\n" +
      "      - --state-dir\n" +
      "      - /agent/state\n" +
      "      - run\n" +
      "    volumes:\n" +
      "      - ./agent:/agent\n" +
      "      - ./vault:/vault:ro\n" +
      "      - /var/run/docker.sock:/var/run/docker.sock\n" +
      "      - /path/to/stacks:/stacks",
  );

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

  function openEnroll() {
    enrollOpen = true;
    token = "";
    enrolledName = "";
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
      enrolledName = enrollName.trim();
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

  {#if plane}
    <div class="listener" class:off={listener.off}>
      <div>
        <strong>{plane.enabled ? "Agent listener on" : "Agent listener off"}</strong>
        <span class="muted">{listener.text}</span>
      </div>
      {#if plane.ca}
        <a href="/api/v1/agents/ca" download="agent-ca.crt">Download CA</a>
      {/if}
    </div>
  {/if}

  {#if sync && !treeConfigured}
    <Banner tone="warn" title="Docker delivery is not configured.">
      Set CREDARR_VAULT_TREE and CREDARR_VAULT_TREE_KEY, then restart the server.
      Auditing and rotation still work without delivery.
    </Banner>
  {/if}

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
    <div class="enroll-followup">
      <p class="muted">
        Save this token to <code>/run/credarr/enroll.token</code> on the agent
        host, download the CA, then run:
      </p>
      <pre><code>{enrollCommand}</code></pre>
    </div>
  {/if}

  {#if loading && agents.length === 0 && targets.length === 0 && jobs.length === 0}
    <LoadingRows label="Reading agents and delivery targets…" rows={4} />
  {:else if error && agents.length === 0 && targets.length === 0 && jobs.length === 0}
    <p class="muted">Agents, targets and recent deliveries are unavailable.</p>
  {:else}
  <div class="split">
    <div class="targets">
      <div class="section-head">
        <div>
          <h4>Targets</h4>
          <p class="muted">Where values are delivered.</p>
        </div>
        <button
          class="primary"
          type="button"
          onclick={() => openTarget()}
          disabled={!treeConfigured}
          title={treeConfigured ? undefined : "Set CREDARR_VAULT_TREE and CREDARR_VAULT_TREE_KEY first"}
        >
          New target
        </button>
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
          <caption class="sr-only">Delivery targets</caption>
          <thead><tr><th>Name</th><th>Type</th><th>Stack</th><th>On</th><th><span class="sr-only">Actions</span></th></tr></thead>
          <tbody>
            {#each targets as target (target.id)}
              <tr>
                <td data-label="Name">
                  <strong>{target.name}</strong>
                  <span class="target-agent muted">
                    {agents.find((item) => item.id === target.agent_id)?.name ?? target.agent_id}
                  </span>
                </td>
                <td data-label="Type">{target.workflow}{target.env_file ? ` · ${target.env_file}` : ""}</td>
                <td data-label="Stack">{target.project_name} · {target.stack_path}</td>
                <td data-label="On">{target.enabled ? "On" : "Off"}</td>
                <td class="row-actions" data-label="Actions">
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
        <div class="agent-empty">
          <p class="muted">
            No agents are enrolled. Create a token, then run the
            credarr-agent image on the Docker host. Auditing and rotation keep
            working without one; only Docker delivery needs an agent.
          </p>
          <details class="agent-setup">
            <summary>How to run the agent</summary>
            <p class="muted">
              The agent pulls jobs over this listener. It needs the CA, the
              shared tree key, and access to the Docker socket.
            </p>
            <pre><code>{agentExample}</code></pre>
          </details>
        </div>
      {:else}
        <table class="table agents-table">
          <caption class="sr-only">Delivery agents</caption>
          <thead><tr><th>Name</th><th>State</th><th>Certificate</th><th><span class="sr-only">Actions</span></th></tr></thead>
          <tbody>
            {#each agents as agent (agent.id)}
              <tr>
                <td data-label="Name">{agent.name}</td>
                <td data-label="State">{agent.status}{agent.rootful ? " · rootful" : ""}</td>
                <td data-label="Certificate">{agent.certificate_expires_at ? timestamp(agent.certificate_expires_at) : "—"}</td>
                <td class="row-actions" data-label="Actions">
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
      <table class="table jobs-table">
        <caption class="sr-only">Recent delivery jobs</caption>
        <thead><tr><th>Credential</th><th>State</th><th>Attempts</th><th>Result</th><th><span class="sr-only">Actions</span></th></tr></thead>
        <tbody>
          {#each jobs as job (job.id)}
            <tr>
              <td data-label="Credential">{job.kind === "probe" ? "target test" : job.credential}</td>
              <td data-label="State">{job.state}</td>
              <td class="tabular" data-label="Attempts">{job.attempts}/{job.max_attempts}</td>
              <td data-label="Result">{job.last_error || "—"}</td>
              <td class="row-action" data-label="Actions">
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
  {/if}
</section>

<style>
  .listener {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.8rem;
    flex-wrap: wrap;
    padding: 0.55rem 0.7rem;
    margin: 0 0 0.9rem;
    border: 1px solid var(--line);
    border-radius: var(--radius);
    background: var(--panel-2);
    font-size: 0.8rem;
  }
  .listener > div {
    display: flex;
    flex-direction: column;
    gap: 0.12rem;
    min-width: 0;
  }
  .listener.off {
    border-color: var(--warn-line);
    background: var(--warn-soft);
  }
  .listener a {
    font-weight: 600;
    white-space: nowrap;
  }
  .enroll-followup {
    margin: 0 0 1rem;
    min-width: 0;
  }
  .enroll-followup p {
    margin: 0 0 0.45rem;
  }
  .enroll-followup pre,
  .agent-setup pre {
    margin: 0;
    padding: 0.65rem;
    overflow-x: auto;
    border: 1px solid var(--line);
    border-radius: var(--radius-sm);
    background: var(--bg-elevated);
    font-size: 0.72rem;
    line-height: 1.45;
  }
  .agent-empty {
    max-width: 62ch;
  }
  .agent-setup {
    margin-top: 0.55rem;
  }
  .agent-setup summary {
    cursor: pointer;
    font-weight: 600;
    font-size: 0.82rem;
  }
  .agent-setup p {
    margin: 0.45rem 0;
  }
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
  @media (min-width: 721px) {
    td.row-actions {
      display: table-cell;
      width: 1%;
      text-align: right;
      white-space: nowrap;
    }
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
