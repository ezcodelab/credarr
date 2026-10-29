<script>
  import { onMount } from "svelte";
  import {
    api,
    ApiError,
    errorText,
    setCsrfToken,
    timestamp,
  } from "../lib/api.js";
  import Banner from "../lib/Banner.svelte";
  import ConfirmDialog from "../lib/ConfirmDialog.svelte";
  import PageHeader from "../lib/PageHeader.svelte";
  import StatusPill from "../lib/StatusPill.svelte";
  import { clearDraft } from "../lib/setup.js";
  import { toast } from "../lib/toast.js";
  import NotificationServices from "../lib/NotificationServices.svelte";
  import Topology from "./Topology.svelte";

  // Sinks are configured here because drift has to reach the operator without
  // a console open. Secrets are write-only end to end: the server never sends
  // one back, so an empty field means "keep what is stored", and removing the
  // sink is how a stored secret goes away.
  let {
    onsignout,
    onrefresh = null,
    onreopen = null,
    onreset = null,
    section = "",
  } = $props();

  let shownSection = $state("");

  let currentPassword = $state("");
  let newPassword = $state("");
  let confirmPassword = $state("");
  let passwordBusy = $state(false);
  let securityError = $state("");
  let securityNotice = $state("");
  let sessions = $state(null);
  let sessionsError = $state("");
  let sessionsBusy = $state(false);
  let revoking = $state(0);
  let revokeAllArmed = $state(false);
  let resetOpen = $state(false);
  let resetBusy = $state(false);
  let resetError = $state("");

  // The interval is persisted and applied to the running scheduler; the
  // console shows minutes because that is how an operator thinks about the
  // gap between drift checks. Auto-rotation has its own due-time audit.
  let auditMinutes = $state("");
  let auditSeconds = $state(3600);
  let auditEnabled = $state(true);
  let auditBusy = $state(false);
  let auditAction = $state("");
  let auditError = $state("");
  let auditRange = $state({ minimum: 1, maximum: 10080 });

  // Automation keys live here now: the first-run wizard no longer asks for
  // one, and the console itself uses the admin session.
  let keys = $state(null);
  let keysBusy = $state(false);
  let keysError = $state("");
  let newKey = $state(null);
  let keyCopied = $state(false);
  let revokingKey = $state(0);
  let revokeKeyId = $state(0);

  // The sidebar's Settings menu scrolls to a section. The effect waits for the
  // anchor to exist before it marks the section as shown.
  $effect(() => {
    if (!section) {
      shownSection = "";
      return;
    }
    if (section === shownSection) return;
    const anchor = document.getElementById(`settings-${section}`);
    if (!anchor) return;
    shownSection = section;
    // The cards were just rendered, so the first pass can land before the
    // browser has laid them out; the next frame scrolls to the settled page.
    requestAnimationFrame(() => anchor.scrollIntoView({ block: "start" }));
  });

  async function loadSessions() {
    sessionsBusy = true;
    sessionsError = "";
    try {
      sessions = (await api("/auth/sessions", { timeout: 10_000 })).sessions;
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        onsignout();
        return;
      }
      sessionsError = errorText(failure);
    } finally {
      sessionsBusy = false;
    }
  }

  onMount(() => {
    // Three independent reads; a slow sessions list must not delay the schedule
    // or the API-key panel.
    Promise.all([loadSessions(), loadKeys(), loadAudit()]);
  });

  async function loadAudit() {
    try {
      const answer = await api("/settings/audit", { timeout: 10_000 });
      auditSeconds = answer.interval_seconds;
      auditMinutes = String(
        Number((answer.interval_seconds / 60).toFixed(2)),
      );
      auditEnabled = answer.enabled !== false;
      auditRange = {
        minimum: Math.round(answer.minimum_seconds / 60),
        maximum: Math.round(answer.maximum_seconds / 60),
      };
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        onsignout();
        return;
      }
      auditError = errorText(failure);
    }
  }

  async function saveAudit(event) {
    event.preventDefault();
    auditError = "";
    const minutes = Number(auditMinutes);
    const seconds = Math.round(minutes * 60);
    if (
      !Number.isFinite(minutes) ||
      seconds < auditRange.minimum * 60 ||
      seconds > auditRange.maximum * 60
    ) {
      auditError = `Enter between ${auditRange.minimum} and ${auditRange.maximum} minutes.`;
      return;
    }
    auditBusy = true;
    auditAction = "save";
    try {
      const answer = await api("/settings/audit", {
        method: "PUT",
        body: { interval_seconds: seconds, enabled: true },
        timeout: 10_000,
      });
      auditSeconds = answer.interval_seconds;
      auditMinutes = String(
        Number((answer.interval_seconds / 60).toFixed(2)),
      );
      auditEnabled = answer.enabled !== false;
      toast();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else auditError = errorText(failure);
    } finally {
      auditBusy = false;
      auditAction = "";
    }
  }

  async function setAuditEnabled(enabled) {
    if (auditBusy) return;
    auditError = "";
    auditBusy = true;
    auditAction = enabled ? "enable" : "disable";
    try {
      const answer = await api("/settings/audit", {
        method: "PUT",
        body: { interval_seconds: auditSeconds, enabled },
        timeout: 10_000,
      });
      auditSeconds = answer.interval_seconds;
      auditMinutes = String(
        Number((answer.interval_seconds / 60).toFixed(2)),
      );
      auditEnabled = answer.enabled !== false;
      toast();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) onsignout();
      else auditError = errorText(failure);
    } finally {
      auditBusy = false;
      auditAction = "";
    }
  }

  function disableAudit() {
    return setAuditEnabled(false);
  }

  async function loadKeys() {
    keysBusy = true;
    keysError = "";
    try {
      const answer = await api("/keys", { timeout: 10_000 });
      keys = Array.isArray(answer) ? answer : [];
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        onsignout();
        return;
      }
      keysError = errorText(failure);
    } finally {
      keysBusy = false;
    }
  }

  async function createKey() {
    if (keysBusy) return;
    keysBusy = true;
    keysError = "";
    keyCopied = false;
    try {
      const answer = await api("/keys", { method: "POST", timeout: 10_000 });
      if (!answer?.key || !answer?.id) {
        throw new Error("the server returned no key");
      }
      newKey = { id: answer.id, key: answer.key };
      await loadKeys();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        onsignout();
        return;
      }
      keysError = errorText(failure);
    } finally {
      keysBusy = false;
    }
  }

  async function copyNewKey() {
    if (!newKey) return;
    try {
      await navigator.clipboard.writeText(newKey.key);
      keyCopied = true;
    } catch {
      keysError = "the browser refused clipboard access; select the key and copy it";
    }
  }

  async function revokeKey(item) {
    if (revokingKey) return;
    revokingKey = item.id;
    keysError = "";
    try {
      await api(`/keys/${encodeURIComponent(item.id)}`, { method: "DELETE" });
      if (newKey?.id === item.id) newKey = null;
      await loadKeys();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        onsignout();
        return;
      }
      keysError = errorText(failure);
    } finally {
      revokingKey = 0;
      revokeKeyId = 0;
    }
  }

  async function changePassword(event) {
    event.preventDefault();
    securityError = "";
    securityNotice = "";
    if (newPassword !== confirmPassword) {
      securityError = "The two new passwords differ.";
      return;
    }
    passwordBusy = true;
    try {
      await api("/auth/password", {
        method: "POST",
        body: { current_password: currentPassword, new_password: newPassword },
      });
      // The server rotated the session; the old CSRF token is now dead.
      const me = await api("/auth/me");
      setCsrfToken(me.csrf);
      currentPassword = newPassword = confirmPassword = "";
      securityNotice = "Password changed. Every other session is signed out.";
      await loadSessions();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        onsignout();
        return;
      }
      securityError = errorText(failure);
    } finally {
      passwordBusy = false;
    }
  }

  async function revokeSession(session) {
    revoking = session.id;
    securityError = "";
    securityNotice = "";
    try {
      await api(`/auth/sessions/${session.id}`, { method: "DELETE" });
      if (session.current) {
        onsignout();
        return;
      }
      securityNotice = "That session is signed out.";
      await loadSessions();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        onsignout();
        return;
      }
      securityError = errorText(failure);
    } finally {
      revoking = 0;
    }
  }

  async function revokeAllSessions() {
    if (!revokeAllArmed) {
      revokeAllArmed = true;
      return;
    }
    revoking = -1;
    securityError = "";
    securityNotice = "";
    try {
      await api("/auth/sessions", { method: "DELETE" });
      // The server revokes this session too and clears the cookie.
      onsignout();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        onsignout();
        return;
      }
      securityError = errorText(failure);
    } finally {
      revoking = 0;
      revokeAllArmed = false;
    }
  }

  async function resetTopology() {
    if (resetBusy) return;
    resetBusy = true;
    resetError = "";
    try {
      // An empty replace is the store's own deletion path: names the new
      // manifest drops lose their working copies too.
      await api("/topology/import", {
        method: "POST",
        body: {
          mode: "replace",
          yaml: "version: 1\ncredentials: {}\n",
          confirm: "replace",
        },
        timeout: 15_000,
      });
      clearDraft();
      resetOpen = false;
      await onreset?.();
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        onsignout();
        return;
      }
      resetError = errorText(failure);
    } finally {
      resetBusy = false;
    }
  }




  // The per-card test button targets its own service; the no-write draft
  // test below is the only one that delivers to every configured sink.



</script>



<PageHeader title="Settings">
  {#snippet actions()}
    <button type="button" onclick={onreopen} disabled={!onreopen}>
      Re-run Setup Wizard
    </button>
    <button type="button" onclick={() => (resetOpen = true)}>
      Reset
    </button>
  {/snippet}
</PageHeader>

{#if resetError}<Banner tone="danger">{resetError}</Banner>{/if}

<section class="card section" id="settings-security">
  <div class="section-head">
    <div>
      <h3>Security</h3>
    </div>
  </div>

  <form onsubmit={changePassword}>
    <h4 class="settings-subhead">Change password</h4>
    <div class="field-grid">
      <label class="field">
        <span>current password</span>
        <input
          type="password"
          autocomplete="current-password"
          bind:value={currentPassword}
          required
        />
      </label>
      <label class="field">
        <span>new password</span>
        <input
          type="password"
          autocomplete="new-password"
          minlength="12"
          bind:value={newPassword}
          required
        />
      </label>
      <label class="field">
        <span>confirm new password</span>
        <input
          type="password"
          autocomplete="new-password"
          minlength="12"
          bind:value={confirmPassword}
          required
        />
      </label>
    </div>
    <p class="field-help">At least 12 characters.</p>
    <div class="toolbar">
      <button
        class="primary"
        type="submit"
        disabled={passwordBusy || !currentPassword || !newPassword || !confirmPassword}
      >
        {passwordBusy ? "Changing…" : "Change password"}
      </button>
    </div>
  </form>
  {#if securityNotice}<Banner tone="ok">{securityNotice}</Banner>{/if}
  {#if securityError}<Banner tone="danger">{securityError}</Banner>{/if}

  <hr class="settings-divider" />

  <div class="section-head">
    <div>
      <h4 class="settings-subhead">Active sessions</h4>
    </div>
    <button
      class="danger"
      type="button"
      onclick={revokeAllSessions}
      disabled={revoking !== 0 || !sessions?.length}
    >
      {revoking === -1
        ? "Signing out…"
        : revokeAllArmed
          ? "Confirm: sign out everywhere"
          : "Revoke all and sign out"}
    </button>
  </div>
  {#if revokeAllArmed}
    <p class="field-help">
      This revokes every browser session, including this one. You will need the
      password to sign back in.
      <button class="link" type="button" onclick={() => (revokeAllArmed = false)}>
        Cancel
      </button>
    </p>
  {/if}
  {#if sessionsError}<Banner tone="danger">{sessionsError}</Banner>{/if}
  {#if sessions === null && sessionsBusy}
    <p class="muted">Loading sessions…</p>
  {:else if sessions?.length}
    <ul class="session-list">
      {#each sessions as session (session.id)}
        <li class="session-row">
          <div class="session-main">
            <div class="session-title">
              <strong>{session.device}</strong>
              {#if session.current}<span class="pill accent">this session</span>{/if}
            </div>
            <div class="session-meta muted">
              <span>Started {timestamp(session.created_at)}</span>
              <span>Last active {timestamp(session.last_seen_at)}</span>
              <span>Expires {timestamp(session.absolute_expires_at)}</span>
            </div>
          </div>
          <button
            class="danger"
            type="button"
            onclick={() => revokeSession(session)}
            disabled={revoking !== 0}
          >
            {revoking === session.id ? "Revoking…" : "Revoke"}
          </button>
        </li>
      {/each}
    </ul>
  {:else}
    <p class="muted">No active browser sessions.</p>
  {/if}
</section>

<section class="card section" id="settings-audit">
  <div class="section-head">
    <div>
      <h3>Audit schedule</h3>
    </div>
    <StatusPill
      status={auditEnabled ? "enabled" : "off"}
      label={auditEnabled ? "enabled" : "off"}
    />
  </div>
  <form onsubmit={saveAudit}>
    <label class="field">
      <span>Minutes between audits</span>
      <input
        type="number"
        min={auditRange.minimum}
        max={auditRange.maximum}
        step="0.5"
        bind:value={auditMinutes}
        required
      />
    </label>
    <p class="field-help">
      {#if auditEnabled}
        Drift checks run on this cadence. Auto-rotation does not wait for it:
        a due credential triggers its own audit first.
      {:else}
        Off. Enable schedule starts timed audits on this cadence. Auto-rotation
        keeps its own due-time audit.
      {/if}
    </p>
    <div class="toolbar">
      {#if auditEnabled}
        <button type="button" onclick={disableAudit} disabled={auditBusy}>
          {auditAction === "disable" ? "Disabling…" : "Disable schedule"}
        </button>
      {/if}
      <span class="spacer"></span>
      <button class="primary" type="submit" disabled={auditBusy || !auditMinutes}>
        {auditAction === "save"
          ? auditEnabled
            ? "Saving…"
            : "Enabling…"
          : auditEnabled
            ? "Save"
            : "Enable schedule"}
      </button>
    </div>
  </form>
  {#if auditError}<Banner tone="danger">{auditError}</Banner>{/if}
</section>

<section class="card section" id="settings-keys">
  <div class="section-head">
    <div>
      <h3>API keys</h3>
    </div>
    <button type="button" onclick={createKey} disabled={keysBusy}>
      {keysBusy && !keys ? "Loading…" : "Create API key"}
    </button>
  </div>
  {#if keysError}<Banner tone="danger">{keysError}</Banner>{/if}
  {#if newKey}
    <div class="setup-key" aria-labelledby="settings-new-key">
      <div class="setup-key-head">
        <h4 id="settings-new-key">Your new API key</h4>
        <span class="pill">one-time display</span>
      </div>
      <p class="muted">
        The server will not show it again. Copy it now; it stays valid until
        revoked.
      </p>
      <div class="setup-key-row">
        <input readonly value={newKey.key} aria-label="New API key" autocomplete="off" spellcheck="false" />
        <button type="button" onclick={copyNewKey}>
          {keyCopied ? "Copied" : "Copy"}
        </button>
        <button type="button" onclick={() => (newKey = null)}>
          Done
        </button>
      </div>
    </div>
  {/if}
  {#if keys === null && keysBusy}
    <p class="muted">Loading keys…</p>
  {:else if keys?.length}
    <ul class="session-list">
      {#each keys as item (item.id)}
        <li class="session-row">
          <div class="session-main">
            <div class="session-title">
              <strong><code>{item.prefix}…</code></strong>
            </div>
            <div class="session-meta muted">
              <span>Created {timestamp(item.created_at)}</span>
              {#if item.last_used_at}
                <span>Last used {timestamp(item.last_used_at)}</span>
              {:else}
                <span>Never used</span>
              {/if}
            </div>
          </div>
          <button
            class="danger"
            type="button"
            onclick={() =>
              revokeKeyId === item.id ? revokeKey(item) : (revokeKeyId = item.id)}
            disabled={revokingKey !== 0}
          >
            {revokingKey === item.id
              ? "Revoking…"
              : revokeKeyId === item.id
                ? "Confirm revoke"
                : "Revoke"}
          </button>
        </li>
      {/each}
    </ul>
  {:else}
    <p class="muted">No API keys.</p>
  {/if}
</section>

{#if resetOpen}
  <ConfirmDialog
    title="Reset everything?"
    message="Replaces the declared topology with an empty manifest. Stored keys for dropped apps are deleted and cannot be recovered here. The admin password and notification services stay."
    confirmText="Reset everything"
    busy={resetBusy}
    onconfirm={resetTopology}
    oncancel={() => (resetOpen = false)}
  />
{/if}

<NotificationServices onsignout={onsignout} />

<div id="settings-topology">
  <Topology onrefresh={onrefresh} onsignout={onsignout} />
</div>
