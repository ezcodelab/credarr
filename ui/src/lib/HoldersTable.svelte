<script>
  import StatusPill from "./StatusPill.svelte";
  import { serviceById, describeHolder } from "./setupCatalog.js";
  import { statusRank } from "./status.js";

  // The holder rows on the credential's own page. The words are the API's:
  // `managed` is the provenance gate, but the table never says the word —
  // a copy either rotates like the rest or carries its own warning.
  //
  // A reader needs the plain answer first: which app, which row or field.
  // The target is a machine name (`seerr.settings_json[sonarr]`); the row
  // says where the copy lives in that screen's own words instead.
  //
  // `onremove` receives one target or a whole group's targets when the caller
  // allows unlinking; without it the table is read-only. A group with more than
  // one row can still be removed as a unit, but each row is removable too.
  // `oncount` receives one target and the typed number, when the caller can
  // write the declaration; `busy` locks the inputs during that write.
  let { consumers, owner = "This key", onremove = null, oncount = null, busy = false } = $props();

  function targetInfo(target) {
    const match = /^([^.]+)\.([^[]+)(?:\[(.*)\])?$/.exec(String(target ?? ""));
    if (!match) return null;
    const [, service, slot, qualifier = ""] = match;
    return { service, slot, qualifier };
  }

  function holderLocation(item, groupService) {
    return describeHolder(
      {
        service: item.info?.service ?? groupService,
        slot: item.info?.slot ?? "",
        qualifier: item.info?.qualifier ?? "",
      },
      owner,
    );
  }

  // Copies are shown and rotated as one unit per service: a rotation already
  // writes every copy of the key in a single run, so fragmenting one app into
  // a row per target only hides that. Grouping keeps the worst audit verdict
  // of the group, which is the one that needs acting on.
  function groupsOf(consumers) {
    const groups = new Map();
    for (const consumer of consumers) {
      const info = targetInfo(consumer.target);
      const service = info?.service ?? String(consumer.target ?? "");
      if (!groups.has(service)) groups.set(service, { service, items: [] });
      groups.get(service).items.push({ consumer, info });
    }
    return [...groups.values()];
  }

  function worstOf(group) {
    let worst = group.items[0];
    for (const item of group.items) {
      if (statusRank(item.consumer.status) < statusRank(worst.consumer.status)) {
        worst = item;
      }
    }
    return worst;
  }
</script>

{#if consumers.length === 0}
  <p class="muted">No copies declared.</p>
{:else}
  <table>
    <caption class="sr-only">Copies of this credential</caption>
    <thead>
      <tr>
        <th>Copy</th>
        {#if oncount}<th>Copies</th>{/if}
        <th>Last audit</th>
        {#if onremove}<th><span class="sr-only">Actions</span></th>{/if}
      </tr>
    </thead>
    <tbody>
      {#each groupsOf(consumers) as group (group.service)}
        {@const copies = group.items.reduce((sum, item) => sum + (item.consumer.count ?? 1), 0)}
        {@const managed = group.items.every((item) => item.consumer.managed)}
        {@const worst = worstOf(group)}
        <tr>
          <td>
            <span class="row-title">
              {serviceById(group.service)?.label ?? group.service}
            </span>
            {#if !oncount && (copies > 1 || group.items.length > 1)}<span class="muted"> · {copies} copies</span>{/if}
            {#each group.items as item (item.consumer.target)}
              <div class="muted">{holderLocation(item, group.service)}</div>
            {/each}
            {#if !managed}
              <div class="muted">Credarr can't write this copy yet.</div>
            {/if}
          </td>
          {#if oncount}
            <td>
              {#each group.items as item (item.consumer.target)}
                <div class="count-line">
                  <input
                    class="count-input"
                    type="number"
                    min="1"
                    step="1"
                    value={item.consumer.count ?? 1}
                    aria-label={`Number of copies in ${serviceById(group.service)?.label ?? group.service}${item.info?.qualifier ? `: ${item.info.qualifier}` : ""}`}
                    disabled={busy}
                    onchange={async (event) => {
                      const input = event.currentTarget;
                      const saved = await oncount(item.consumer.target, input.value);
                      if (saved !== true) input.value = item.consumer.count ?? 1;
                    }}
                  />
                  {#if onremove}
                    <button
                      class="link"
                      type="button"
                      disabled={busy}
                      onclick={() => onremove([item.consumer.target])}
                    >
                      Remove
                    </button>
                  {/if}
                </div>
              {/each}
            </td>
          {/if}
          <td>
            {#if worst.consumer.status}
              <StatusPill status={worst.consumer.status} />
              {#if worst.consumer.status !== "live" && worst.consumer.detail}
                <div class="status-detail">{worst.consumer.detail}</div>
              {/if}
            {:else}
              <StatusPill status="none" label="not audited yet" />
            {/if}
          </td>
          {#if onremove}
            <td>
              <div class="row-actions">
                {#if group.items.length > 1}
                  <button
                    class="danger"
                    type="button"
                    onclick={() => onremove(group.items.map((item) => item.consumer.target))}
                  >
                    Remove all
                  </button>
                {/if}
              </div>
            </td>
          {/if}
        </tr>
      {/each}
    </tbody>
  </table>
{/if}
