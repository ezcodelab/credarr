<script>
  import { onMount } from "svelte";
  import { api, ApiError, elapsed, errorText, timestamp } from "../lib/api.js";
  import Banner from "../lib/Banner.svelte";
  import EmptyState from "../lib/EmptyState.svelte";
  import Icon from "../lib/Icon.svelte";
  import PageHeader from "../lib/PageHeader.svelte";
  import StatusPill from "../lib/StatusPill.svelte";
  import { credentialTitle, friendlyReason } from "../lib/names.js";
  import { eventInfo, statusInfo } from "../lib/status.js";

  // Activity is the audit and what changed since. An event is one *change*:
  // the status an audit found differs from the last one recorded. That is why
  // a key that keeps drifting appears once and not every hour. Nothing here
  // edits; Apps is where anything gets fixed.
  let { status, onapps, onsettings, onsignout } = $props();

  const LIMIT = 200;
  let data = $state(null);
  let error = $state("");
  let loading = $state(true);
  let query = $state("");

  const lastAudit = $derived(status?.last_audit ?? null);
  const visibleEvents = $derived(
    (data?.events ?? []).filter((event) => {
      const needle = query.trim().toLowerCase();
      if (!needle) return true;
      const kind = eventInfo(event.kind);
      const haystack =
        `${kind.label} ${event.credential ?? ""} ${credentialTitle(event.credential ?? "")} ${event.sink ?? ""} ${event.detail ?? ""} ${friendlyReason(event.detail ?? "")} ${eventReason(event)} ${event.status ?? ""} ${event.previous_status ?? ""}`.toLowerCase();
      return haystack.includes(needle);
    }),
  );
  const filtering = $derived(query.trim() !== "");

  function eventReason(event) {
    return (
      friendlyReason(event.detail) ||
      (event.status ? statusInfo(event.status).why : "") ||
      "—"
    );
  }

  async function load() {
    loading = true;
    error = "";
    try {
      data = await api(`/events?limit=${LIMIT}`, { timeout: 10_000 });
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 401) {
        onsignout();
        return;
      }
      error = errorText(failure);
    } finally {
      loading = false;
    }
  }

  onMount(load);

  function deliveryText(event, sink) {
    // A silent event is recorded but never notified; saying "queued" would
    // read as a delivery that will move, which it never will.
    if (event.silent === true) return "not notified: recorded only";
    if (event.sink && event.sink !== sink.name)
      return `not sent: test for ${event.sink}`;
    const delivery = event.deliveries.find((row) => row.sink === sink.name);
    if (delivery?.state === "delivered") return `delivered ${timestamp(delivery.delivered_at)}`;
    if (delivery?.state === "failed")
      return `gave up after ${delivery.attempts} attempts: ${delivery.last_error}`;
    if (delivery?.state === "pending" && event.at < sink.updated_at)
      return "not sent: the sink was configured later";
    if (delivery?.state === "pending") return `retrying in ${elapsed(nextIn(delivery))}: ${delivery.last_error}`;
    if (event.at < sink.updated_at) return "not sent: the sink was configured later";
    return "queued";
  }

  function nextIn(delivery) {
    return Math.max(0, (delivery.next_attempt_at ?? 0) - Date.now() / 1000);
  }

  function deliveryCategory(event, sink) {
    if (event.silent === true) return "not sent";
    if (event.sink && event.sink !== sink.name) return "not sent";
    const delivery = event.deliveries.find((row) => row.sink === sink.name);
    if (delivery?.state === "delivered") return "delivered";
    if (delivery?.state === "failed") return "failed";
    if (delivery?.state === "pending" && event.at < sink.updated_at) return "not sent";
    if (delivery?.state === "pending") return "pending";
    if (event.at < sink.updated_at) return "not sent";
    return "queued";
  }

  function deliveryTone(event, sink) {
    const category = deliveryCategory(event, sink);
    if (category === "delivered") return "ok";
    if (category === "failed") return "bad";
    if (category === "pending") return "warn";
    return "none";
  }

  function deliverySummary(event) {
    if (!data?.sinks?.length) return { status: "off", label: "no sink configured" };
    const categories = data.sinks.map((sink) => deliveryCategory(event, sink));
    const delivered = categories.filter((category) => category === "delivered").length;
    const failed = categories.filter((category) => category === "failed").length;
    const waiting = categories.filter(
      (category) => category === "pending" || category === "queued",
    ).length;
    const skipped = categories.filter((category) => category === "not sent").length;
    const parts = [];
    if (delivered) parts.push(`${delivered} delivered`);
    if (waiting) parts.push(`${waiting} pending`);
    if (failed) parts.push(`${failed} failed`);
    if (skipped) parts.push(`${skipped} not sent`);
    const status = failed
      ? "error"
      : waiting || (delivered > 0 && skipped > 0)
        ? "unverifiable"
        : delivered === categories.length
          ? "match"
          : "none";
    return { status, label: parts.join(" · ") };
  }

  function clearFilters() {
    query = "";
  }
</script>

<PageHeader title="Activity">
  {#snippet actions()}
    <button onclick={load} disabled={loading}>
      {loading ? "Loading…" : "Refresh"}
    </button>
  {/snippet}
</PageHeader>

{#if lastAudit}
  <p class="muted">
    Last audit finished {timestamp(lastAudit.finished_at)}.
    {#if !data?.events?.length}
      It set the baseline; only changes appear below.
    {/if}
  </p>
{/if}

{#if error}
  <Banner tone="danger">{error}</Banner>
{/if}

{#if data && data.events.length === 0}
  <EmptyState title="No changes yet" icon="events">
    <p>The first audit sets a baseline; only changes appear here.</p>
    <p class="muted">
      {#if data.sinks.length === 0}
        No notification service is configured, so nothing is delivered.
      {:else}
        Notifying: {data.sinks.map((sink) => sink.name).join(", ")}.
      {/if}
    </p>
    {#snippet actions()}
      <button class="primary" onclick={onsettings}>Add a notification service</button>
      <button onclick={onapps}>Back to Apps</button>
    {/snippet}
  </EmptyState>
{:else if data}
  <div class="table-tools">
    <label class="search">
      <Icon name="search" size={15} />
      <input
        bind:value={query}
        type="search"
        placeholder="Filter activity…"
        aria-label="Filter activity"
      />
    </label>
    {#if filtering}
      <button onclick={clearFilters}>Clear filters</button>
    {/if}
    <span class="count">{visibleEvents.length} of {data.events.length}</span>
  </div>

  {#if visibleEvents.length === 0}
    <div class="empty compact">
      <p>No change matches that filter.</p>
      <button onclick={clearFilters}>Show everything</button>
    </div>
  {:else}
    <table class="events-table">
      <caption class="sr-only">Changes and their delivery state</caption>
      <thead>
        <tr>
          <th>When</th>
          <th>Change</th>
          <th>App</th>
          <th>What happened</th>
          <th>Delivery</th>
        </tr>
      </thead>
      <tbody>
        {#each visibleEvents as event (event.id)}
          {@const kind = eventInfo(event.kind)}
          {@const delivery = deliverySummary(event)}
          <tr>
            <td class="muted time">{timestamp(event.at)}</td>
            <td>
              <span class="event-pills">
                <StatusPill status={kind.status} label={kind.label} />
                {#if event.kind === "rotation_manual"}
                  <StatusPill status="manual" label="manual" />
                {/if}
              </span>
            </td>
            <td>{event.credential ? credentialTitle(event.credential) : "—"}</td>
            <td class="muted">{eventReason(event)}</td>
            <td>
              {#if data.sinks.length === 0}
                <span class="muted">no service configured</span>
              {:else}
                <details class="delivery">
                  <summary>
                    <StatusPill status={delivery.status} label={delivery.label} />
                  </summary>
                  <div class="delivery-detail">
                    {#each data.sinks as sink (sink.name)}
                      <div class="delivery-line" class:delivery-bad={deliveryTone(event, sink) === "bad"}>
                        <code>{sink.name}</code> — {deliveryText(event, sink)}
                      </div>
                    {/each}
                  </div>
                </details>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
{/if}
