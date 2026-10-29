<script>
  import { onMount } from "svelte";
  import { api, ApiError, errorText } from "./api.js";
  import Banner from "./Banner.svelte";
  import ConfirmDialog from "./ConfirmDialog.svelte";
  import { toast } from "./toast.js";
  import StatusPill from "./StatusPill.svelte";

  // Named notification services: every row has its own name, kind, switch,
  // fields and delivery stats. Secrets are write-only - the API answers
  // "configured" flags, never values, so an empty secret field keeps the
  // stored one and only an explicit clear on the server removes it.
  let { onsignout } = $props();

  const TYPE_LABEL = {
    ntfy: "Ntfy",
    webhook: "Webhook",
    discord: "Discord",
    telegram: "Telegram",
    email: "Email",
  };
  const TELEGRAM_API_BASE = "https://api.telegram.org";
  const typeLabel = (kind) => TYPE_LABEL[kind] ?? kind;

  let services = $state(null);
  let types = $state(["ntfy", "webhook", "discord", "telegram", "email"]);
  let kinds = $state([]);
  let error = $state("");
  let view = $state("list"); // list | form
  let original = $state(null); // the row being edited, or null on create
  let form = $state(blankForm("ntfy"));
  let busy = $state(false);
  let testing = $state("");
  let testingDraft = $state(false);
  let draftTest = $state(null); // { ok, detail }
  let tested = $state(null); // { name, rows }
  let deleteTarget = $state(null);
  let deleting = $state(false);

  // Success is one dull word; the list changing is the rest of the answer.
  // Errors stay inline where the failure happened.

  function blankForm(kind) {
    return {
      name: "",
      kind,
      url: kind === "telegram" ? TELEGRAM_API_BASE : "",
      topic: "",
      token: "",
      secret: "",
      auth_header: "",
      discord_username: "",
      discord_avatar: "",
      discord_here: false,
      smtp_host: "",
      smtp_port: 587,
      smtp_username: "",
      smtp_from: "",
      smtp_to: "",
      smtp_tls: "starttls",
      smtp_auth: "auto",
      enabled_types: [],
    };
  }

  const editing = $derived(original !== null);
  // A stored secret survives an edit untouched when its field stays blank.
  const keptSecret = (flag) => Boolean(editing && original?.[flag]);

  function secretReady(which, flag) {
    const typed = String(form[which] ?? "").trim() !== "";
    return typed || keptSecret(flag);
  }

  function formReady() {
    if (!form.name.trim()) return false;
    if (form.kind === "email") {
      const port = Number(form.smtp_port);
      if (!form.smtp_host.trim() || !form.smtp_from.trim() || !form.smtp_to.trim())
        return false;
      if (!Number.isInteger(port) || port < 1 || port > 65535) return false;
      if (
        form.smtp_auth !== "none" &&
        (!form.smtp_username.trim() || !secretReady("token", "token_configured"))
      ) {
        return false;
      }
      if (
        editing &&
        original?.kind === "email" &&
        original.token_configured &&
        (form.smtp_host.trim() !== (original.smtp_host ?? "") ||
          Number(form.smtp_port) !== Number(original.smtp_port ?? 587)) &&
        !form.token.trim()
      ) {
        return false;
      }
      return true;
    }
    if (!form.url.trim()) return false;
    if (form.kind === "ntfy") {
      if (!form.topic.trim()) return false;
      // The server refuses a URL change that drops the stored token, so the
      // form asks for it up front instead of surfacing the 400.
      if (
        editing &&
        original?.kind === "ntfy" &&
        form.url.trim() !== (original.url ?? "") &&
        original.token_configured &&
        !form.token.trim()
      ) {
        return false;
      }
      return true;
    }
    if (form.kind === "telegram") {
      if (
        editing &&
        original?.kind === "telegram" &&
        form.url.trim() !== (original.url ?? "") &&
        original.token_configured &&
        !form.token.trim()
      ) {
        return false;
      }
      return form.topic.trim() !== "" && secretReady("token", "token_configured");
    }
    if (form.kind === "webhook") {
      if (
        editing &&
        original?.kind === "webhook" &&
        form.url.trim() !== (original.url ?? "")
      ) {
        if (original.auth_header_configured && !form.auth_header.trim()) return false;
        if (original.secret_configured && !form.secret.trim()) return false;
      }
    }
    return true;
  }

  const tokenHelp = $derived(
    editing &&
      original?.kind === "ntfy" &&
      form.url.trim() !== (original.url ?? "") &&
      original.token_configured &&
      !form.token.trim()
      ? "The server URL changed: re-enter the access token."
      : "Required if your ntfy server has access control enabled. Generate a token via your server's admin interface or ntfy token add",
  );

  const emailTokenHelp = $derived(
    editing &&
      original?.kind === "email" &&
      original.token_configured &&
      (form.smtp_host.trim() !== (original.smtp_host ?? "") ||
        Number(form.smtp_port) !== Number(original.smtp_port ?? 587)) &&
      !form.token.trim()
      ? "The SMTP server changed: re-enter the password."
      : "Use an app password if your provider requires one.",
  );

  const webhookSecretHelp = $derived(
    editing &&
      original?.kind === "webhook" &&
      form.url.trim() !== (original.url ?? "") &&
      original.secret_configured &&
      !form.secret.trim()
      ? "The webhook URL changed: re-enter the signing secret."
      : `Sent as X-Credarr-Signature, an HMAC-SHA256 of the body. Optional.${keptSecret("secret_configured") ? " One is stored; leave blank to keep it." : ""}`,
  );

  const webhookAuthHelp = $derived(
    editing &&
      original?.kind === "webhook" &&
      form.url.trim() !== (original.url ?? "") &&
      original.auth_header_configured &&
      !form.auth_header.trim()
      ? "The webhook URL changed: re-enter the authorization header."
      : `Sent as the Authorization header. Optional.${keptSecret("auth_header_configured") ? " One is stored; leave blank to keep it." : ""}`,
  );

  const telegramTokenHelp = $derived(
    editing &&
      original?.kind === "telegram" &&
      form.url.trim() !== (original.url ?? "") &&
      original.token_configured &&
      !form.token.trim()
      ? "The API Base changed: re-enter the bot token."
      : `Create a bot via @BotFather on Telegram to get a token.${keptSecret("token_configured") ? " One is stored; leave blank to keep it." : ""}`,
  );

  // The name box suggests a name per platform, the way Profilarr's does.
  const namePlaceholder = $derived(
    form.kind === "ntfy"
      ? "e.g., Phone Alerts"
      : form.kind === "webhook"
        ? "e.g., Home Assistant"
        : form.kind === "telegram"
          ? "e.g., Personal Bot"
          : form.kind === "email"
            ? "e.g., Email Alerts"
            : "e.g., Main Discord Server",
  );

  function kindsSummary(service) {
    const selected = service.enabled_types ?? [];
    if (!selected.length) return "all kinds";
    return `${selected.length} of ${kinds.length || selected.length} kinds`;
  }

  function statsSummary(service) {
    const stats = service.stats ?? { delivered: 0, failed: 0, pending: 0 };
    const parts = [];
    if (stats.delivered) parts.push(`${stats.delivered} delivered`);
    if (stats.failed) parts.push(`${stats.failed} failed`);
    if (stats.pending) parts.push(`${stats.pending} pending`);
    return parts.join(" · ") || "no deliveries yet";
  }

  async function load() {
    error = "";
    try {
      const answer = await api("/notifications/services", { timeout: 10_000 });
      services = answer.services ?? [];
      if (Array.isArray(answer.types) && answer.types.length) types = answer.types;
      if (Array.isArray(answer.kinds)) kinds = answer.kinds;
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else error = errorText(failure);
    }
  }

  onMount(load);

  function startCreate() {
    error = "";
    tested = null;
    draftTest = null;
    original = null;
    form = blankForm(types[0] ?? "ntfy");
    view = "form";
  }

  function startEdit(service) {
    error = "";
    tested = null;
    draftTest = null;
    original = service;
    form = {
      ...blankForm(service.kind),
      name: service.name,
      url: service.url ?? "",
      topic: service.topic ?? "",
      discord_username: service.discord_username ?? "",
      discord_avatar: service.discord_avatar ?? "",
      discord_here: service.discord_here === true,
      smtp_host: service.smtp_host ?? "",
      smtp_port: service.smtp_port ?? 587,
      smtp_username: service.smtp_username ?? "",
      smtp_from: service.smtp_from ?? "",
      smtp_to: service.smtp_to ?? "",
      smtp_tls: service.smtp_tls ?? "starttls",
      smtp_auth: service.smtp_auth ?? "auto",
      enabled_types: [...(service.enabled_types ?? [])],
    };
    view = "form";
  }

  function changeKind(event) {
    const kind = event.currentTarget.value;
    const name = form.name;
    draftTest = null;
    form = { ...blankForm(kind), name };
  }

  // Secrets ride along only when typed: omitted keeps the stored one, and
  // only an explicit server-side clear removes it. Non-secret blanks are
  // sent as-is for the kind's own fields.
  function body() {
    const out = {
      discord_here: form.discord_here,
      enabled_types: [...form.enabled_types],
    };
    if (!editing) {
      out.name = form.name.trim();
      out.kind = form.kind;
    }
    for (const key of ["url", "topic", "discord_username", "discord_avatar"]) {
      out[key] = String(form[key] ?? "").trim();
    }
    if (form.kind === "email") {
      for (const key of [
        "smtp_host",
        "smtp_username",
        "smtp_from",
        "smtp_to",
        "smtp_tls",
        "smtp_auth",
      ]) {
        out[key] = String(form[key] ?? "").trim();
      }
      out.smtp_port = Number(form.smtp_port);
    }
    for (const key of ["token", "secret", "auth_header"]) {
      if (String(form[key] ?? "").trim() !== "") out[key] = form[key].trim();
    }
    return out;
  }

  async function testDraft() {
    if (busy || testingDraft || !formReady()) return;
    testingDraft = true;
    error = "";
    draftTest = null;
    try {
      const payload = {
        ...body(),
        name: form.name.trim() || "test",
        kind: form.kind,
      };
      const existing = editing
        ? `?existing=${encodeURIComponent(original.name)}`
        : "";
      const answer = await api(`/notifications/services/test${existing}`, {
        method: "POST",
        body: payload,
        timeout: 60_000,
      });
      draftTest = { ok: answer?.ok === true, detail: answer?.detail ?? "" };
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else error = errorText(failure);
    } finally {
      testingDraft = false;
    }
  }

  async function save() {
    if (busy || testingDraft || !formReady()) return;
    busy = true;
    error = "";
    draftTest = null;
    try {
      if (editing) {
        await api(`/notifications/services/${encodeURIComponent(original.name)}`, {
          method: "PATCH",
          body: body(),
          timeout: 10_000,
        });
      } else {
        await api("/notifications/services", {
          method: "POST",
          body: body(),
          timeout: 10_000,
        });
      }
      toast();
      view = "list";
      original = null;
      await load();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else error = errorText(failure);
    } finally {
      busy = false;
    }
  }

  async function toggleEnabled(service) {
    if (busy || testing) return;
    busy = true;
    error = "";
    try {
      await api(`/notifications/services/${encodeURIComponent(service.name)}`, {
        method: "PATCH",
        body: { enabled: service.enabled === false },
        timeout: 10_000,
      });
      toast();
      await load();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else error = errorText(failure);
    } finally {
      busy = false;
    }
  }

  async function remove() {
    if (deleting || !deleteTarget) return;
    deleting = true;
    error = "";
    try {
      await api(`/notifications/services/${encodeURIComponent(deleteTarget.name)}`, {
        method: "DELETE",
        timeout: 10_000,
      });
      toast();
      deleteTarget = null;
      await load();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else error = errorText(failure);
    } finally {
      deleting = false;
    }
  }

  async function test(service) {
    if (testing) return;
    testing = service.name;
    error = "";
    tested = null;
    try {
      // A black-holed sink answers slowly; the call holds the server's
      // delivery lock while it tries, so this waits rather than guessing.
      const answer = await api(
        `/notifications/services/${encodeURIComponent(service.name)}/test`,
        { method: "POST", timeout: 60_000 },
      );
      tested = { name: service.name, rows: answer.deliveries ?? [] };
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else error = errorText(failure);
    } finally {
      testing = "";
    }
  }

  function resultText(delivery) {
    if (delivery.state === "delivered") return "accepted";
    if (delivery.state === "failed")
      return `gave up after ${delivery.attempts} attempts: ${delivery.last_error}`;
    return `not delivered: ${delivery.last_error} (it will keep retrying)`;
  }

  function resultStatus(delivery) {
    if (delivery.state === "delivered") return "match";
    if (delivery.state === "failed") return "error";
    return "unverifiable";
  }

  function toggleKind(kind, event) {
    const selected = new Set(form.enabled_types);
    if (event.currentTarget.checked) selected.add(kind);
    else selected.delete(kind);
    form.enabled_types = [...selected];
  }
</script>

<section class="card section" id="settings-notifications">
  {#if view === "form"}
    <div class="section-head">
      <div>
        <p class="muted">
          <button class="link" type="button" onclick={() => (view = "list")}>
            Notifications
          </button>
          / {editing ? original.name : "New"}
        </p>
        <h3>{editing ? "Edit Notification Service" : "New Notification Service"}</h3>
      </div>
      <div class="toolbar">
        <button
          type="button"
          onclick={() => (view = "list")}
          disabled={busy || testingDraft}
        >
          Cancel
        </button>
        <button
          type="button"
          onclick={testDraft}
          disabled={busy || testingDraft || !formReady()}
        >
          {testingDraft ? "Testing…" : "Test"}
        </button>
        <button
          class="primary"
          type="button"
          onclick={save}
          disabled={busy || testingDraft || !formReady()}
        >
          {busy ? "Saving…" : "Save"}
        </button>
      </div>
    </div>

    {#if draftTest}
      <p class={draftTest.ok ? "muted" : "error"}>
        {draftTest.ok
          ? "Test delivered."
          : `Test failed${draftTest.detail ? `: ${draftTest.detail}` : "."}`}
      </p>
    {/if}

    {#if error}<Banner tone="danger">{error}</Banner>{/if}

    <div class="field-grid align-start notify-top">
      <div>
        <label class="field">
          Service Type
          {#if editing}
            <input value={typeLabel(form.kind)} disabled aria-label="Service Type" />
          {:else}
            <select
              value={form.kind}
              onchange={changeKind}
              disabled={busy}
              aria-label="Service Type"
            >
              {#each types as id (id)}
                <option value={id}>{typeLabel(id)}</option>
              {/each}
            </select>
          {/if}
        </label>
        {#if !editing}
          <p class="field-help">The platform to send notifications to.</p>
        {/if}
      </div>
      <label class="field">
        Service Name
        <input
          bind:value={form.name}
          placeholder={namePlaceholder}
          autocomplete="off"
          spellcheck="false"
          disabled={editing || busy}
          aria-label="Service Name"
        />
        <span class="field-help">
          {editing
            ? "The name cannot be changed; delete and create again to rename."
            : "Letters, digits, spaces and _ - . @"}
        </span>
      </label>
    </div>

    {#if form.kind === "email"}
      <div class="field-grid align-start">
        <label class="field">
          SMTP Host
          <input
            bind:value={form.smtp_host}
            placeholder="smtp.example.com"
            autocomplete="off"
            spellcheck="false"
            aria-label="SMTP Host"
          />
        </label>
        <label class="field">
          Port
          <input
            type="number"
            min="1"
            max="65535"
            bind:value={form.smtp_port}
            aria-label="SMTP Port"
          />
          <span class="field-help">Typically 587 for STARTTLS or 465 for SSL.</span>
        </label>
        <label class="field">
          Username
          <input
            bind:value={form.smtp_username}
            placeholder="credarr@example.com"
            autocomplete="off"
            spellcheck="false"
            aria-label="SMTP Username"
          />
        </label>
        <label class="field">
          Password
          <input
            type="password"
            bind:value={form.token}
            placeholder={keptSecret("token_configured") ? "••••••••••••••••" : "app password"}
            autocomplete="off"
            spellcheck="false"
            aria-label="SMTP Password"
          />
          <span class="field-help">
            {#if keptSecret("token_configured")}One is stored; leave blank to keep it. {/if}
            {emailTokenHelp}
          </span>
        </label>
        <label class="field">
          From
          <input
            bind:value={form.smtp_from}
            placeholder="Credarr <credarr@example.com>"
            autocomplete="off"
            spellcheck="false"
            aria-label="From address"
          />
        </label>
        <label class="field">
          Recipients
          <textarea
            rows="3"
            bind:value={form.smtp_to}
            placeholder="ops@example.com&#10;oncall@example.com"
            spellcheck="false"
            aria-label="Recipients"
          ></textarea>
          <span class="field-help">One address per line.</span>
        </label>
        <label class="field">
          TLS
          <select bind:value={form.smtp_tls} aria-label="SMTP TLS">
            <option value="starttls">STARTTLS</option>
            <option value="ssl">SSL</option>
            <option value="none">None</option>
          </select>
        </label>
        <label class="field">
          Authentication
          <select bind:value={form.smtp_auth} aria-label="SMTP Authentication">
            <option value="auto">Auto</option>
            <option value="none">None</option>
            <option value="plain">PLAIN</option>
            <option value="login">LOGIN</option>
            <option value="crammd5">CRAM-MD5</option>
          </select>
        </label>
      </div>
    {:else if form.kind === "ntfy"}
      <div class="field-grid align-start">
        <label class="field">
          Server URL
          <input
            bind:value={form.url}
            placeholder="https://ntfy.sh"
            autocomplete="off"
            spellcheck="false"
            aria-label="Server URL"
          />
          <span class="field-help">
            The ntfy server URL. Use https://ntfy.sh for the public instance or your self-hosted URL.
          </span>
        </label>
        <label class="field">
          Topic
          <input
            bind:value={form.topic}
            placeholder="credarr"
            autocomplete="off"
            spellcheck="false"
            aria-label="Topic"
          />
        </label>
        <label class="field">
          Access Token
          <input
            type="password"
            bind:value={form.token}
            placeholder={keptSecret("token_configured") ? "••••••••••••••••" : "tk_..."}
            autocomplete="off"
            spellcheck="false"
            aria-label="Access Token"
          />
          <span class="field-help">
            {#if keptSecret("token_configured")}One is stored. {/if}{tokenHelp}
          </span>
        </label>
      </div>
    {:else if form.kind === "discord"}
      <div class="field-grid align-start">
        <label class="field">
          Webhook URL
          <input
            type="password"
            bind:value={form.url}
            placeholder="https://discord.com/api/webhooks/..."
            autocomplete="off"
            spellcheck="false"
            aria-label="Webhook URL"
          />
          <span class="field-help">
            Get this from Server Settings → Integrations → Webhooks in Discord.
          </span>
        </label>
        <label class="field">
          Bot username (optional)
          <input
            bind:value={form.discord_username}
            placeholder="credarr"
            autocomplete="off"
            spellcheck="false"
            aria-label="Bot username"
          />
        </label>
        <label class="field">
          Avatar URL (optional)
          <input
            bind:value={form.discord_avatar}
            placeholder="https://example.com/avatar.png"
            autocomplete="off"
            spellcheck="false"
            aria-label="Avatar URL"
          />
        </label>
        <label class="field">
          Mention everyone
          <span class="setup-check">
            <input
              type="checkbox"
              bind:checked={form.discord_here}
              disabled={busy}
              aria-label="Mention everyone"
            />
          </span>
        </label>
      </div>
    {:else if form.kind === "webhook"}
      <div class="field-grid align-start">
        <label class="field">
          Webhook URL
          <input
            type="password"
            bind:value={form.url}
            placeholder="https://example.com/webhook"
            autocomplete="off"
            spellcheck="false"
            aria-label="Webhook URL"
          />
        </label>
        <label class="field">
          Signing Secret
          <input
            type="password"
            bind:value={form.secret}
            placeholder={keptSecret("secret_configured") ? "••••••••••••••••" : "Bearer your-token"}
            autocomplete="off"
            spellcheck="false"
            aria-label="Signing Secret"
          />
          <span class="field-help">
            {webhookSecretHelp}
          </span>
        </label>
        <label class="field">
          Authorization header
          <input
            type="password"
            bind:value={form.auth_header}
            placeholder={keptSecret("auth_header_configured") ? "••••••••••••••••" : "Bearer ..."}
            autocomplete="off"
            spellcheck="false"
            aria-label="Authorization header"
          />
          <span class="field-help">
            {webhookAuthHelp}
          </span>
        </label>
      </div>
    {:else if form.kind === "telegram"}
      <div class="field-grid align-start">
        <label class="field">
          Bot Token
          <input
            type="password"
            bind:value={form.token}
            placeholder={keptSecret("token_configured") ? "••••••••••••••••" : "123456789:ABCdefGHI..."}
            autocomplete="off"
            spellcheck="false"
            aria-label="Bot Token"
          />
          <span class="field-help">
            {telegramTokenHelp}
          </span>
        </label>
        <label class="field">
          Chat ID
          <input
            bind:value={form.topic}
            placeholder="e.g., 123456789"
            autocomplete="off"
            spellcheck="false"
            aria-label="Chat ID"
          />
          <span class="field-help">
            Your user or group chat ID. Message @userinfobot on Telegram to find yours.
          </span>
        </label>
        <label class="field">
          API Base
          <input
            bind:value={form.url}
            placeholder="https://api.telegram.org"
            autocomplete="off"
            spellcheck="false"
            aria-label="API Base"
          />
          <span class="field-help">Only change this for a self-hosted Bot API server.</span>
        </label>
      </div>
    {/if}

    {#if kinds.length}
      <h4 class="settings-subhead">Notification Types</h4>
      <p class="field-help">
        Leave everything off to send every kind. Test notifications always send.
      </p>
      <div class="setup-check-list">
        {#each kinds as kind (kind)}
          <label class="setup-check">
            <input
              type="checkbox"
              checked={form.enabled_types.includes(kind)}
              onchange={(event) => toggleKind(kind, event)}
              disabled={busy}
              aria-label={`Notify ${kind.replaceAll("_", " ")}`}
            />
            {kind.replaceAll("_", " ")}
          </label>
        {/each}
      </div>
    {/if}
  {:else}
    <div class="section-head">
      <div>
        <h3>Notifications</h3>
        <p class="muted">Manage notification services and delivery settings</p>
      </div>
      <button class="primary" type="button" onclick={startCreate}>Add Service</button>
    </div>

    {#if error}<Banner tone="danger">{error}</Banner>{/if}

    {#if services === null}
      <p class="muted">Loading notification services…</p>
    {:else if services.length === 0}
      <p class="muted">No notification services configured. Click 'Add Service' to get started.</p>
    {:else}
      <table>
        <caption class="sr-only">Notification services</caption>
        <thead>
          <tr><th>Service</th><th>Type</th><th>Status</th><th>Notifications</th><th>Delivery</th><th></th></tr>
        </thead>
        <tbody>
          {#each services as service (service.id)}
            <tr>
              <td><strong>{service.name}</strong></td>
              <td>{typeLabel(service.kind)}</td>
              <td>
                <StatusPill
                  status={service.enabled === false ? "off" : "enabled"}
                  label={service.enabled === false ? "disabled" : "enabled"}
                />
              </td>
              <td><span class="muted">{kindsSummary(service)}</span></td>
              <td><span class="muted">{statsSummary(service)}</span></td>
              <td>
                <div class="row-actions">
                  <button
                    type="button"
                    onclick={() => test(service)}
                    disabled={testing !== ""}
                  >
                    {testing === service.name ? "Testing…" : "Test"}
                  </button>
                  <button type="button" onclick={() => startEdit(service)}>Edit</button>
                  <button
                    type="button"
                    onclick={() => toggleEnabled(service)}
                    disabled={busy || testing !== ""}
                  >
                    {service.enabled === false ? "Enable" : "Disable"}
                  </button>
                  <button
                    class="danger"
                    type="button"
                    onclick={() => (deleteTarget = service)}
                  >
                    Delete
                  </button>
                </div>
              </td>
            </tr>
            {#if tested?.name === service.name}
              <tr class="detail">
                <td colspan="6">
                  <ul class="outcomes">
                    {#each tested.rows as delivery (delivery.sink)}
                      <li>
                        <StatusPill status={resultStatus(delivery)} label={delivery.state} />
                        <span><code>{delivery.sink}</code>: {resultText(delivery)}</span>
                      </li>
                    {/each}
                  </ul>
                </td>
              </tr>
            {/if}
          {/each}
        </tbody>
      </table>
    {/if}
  {/if}
</section>

{#if deleteTarget}
  <ConfirmDialog
    title="Delete Service"
    message={`Delete the notification service "${deleteTarget.name}"? Past deliveries stay in the ledger; this cannot be undone.`}
    confirmText="Delete Service"
    busy={deleting}
    onconfirm={remove}
    oncancel={() => (deleteTarget = "")}
  />
{/if}
