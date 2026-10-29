// The wizard's authoring catalog. It mirrors the target registry and the
// holder/mint capabilities this build actually ships; a test compares it with
// `build_registry().known_targets()` so a new target cannot silently appear
// only in one place.
//
// This is a catalog, not a topology. Selecting a service here only groups the
// credential editor; the manifest still declares credentials, holders and
// `canonical.service`, exactly like a hand-written one.

const SLOT_META = {
  indexers: {
    label: "indexers",
    note: "Indexer rows; written over the Servarr API. Sonarr and Radarr have a measured test route.",
    proof: "API write; exercise where measured",
    mechanism: "",
    writer: true,
  },
  download_clients: {
    label: "download clients",
    note: "Download-client rows; written over the Servarr API. Sonarr and Radarr have a measured test route; no equality readback is exposed.",
    proof: "API write; test where measured",
    mechanism: "",
    writer: true,
  },
  applications: {
    label: "applications",
    note: "Prowlarr application rows; written and exercised over Prowlarr's API.",
    proof: "holder API test",
    mechanism: "",
    writer: true,
  },
  settings_json: {
    label: "settings",
    note: "A row in Seerr's settings; the running process reports it over its own API.",
    proof: "running service",
    mechanism: "process_api",
    writer: true,
  },
  label: {
    label: "labels",
    note: "A Homepage label rendered at deploy time; this build cannot read the deployed copy back.",
    proof: "deploy-time only",
    mechanism: "redeploy",
    writer: false,
  },
  arr_config: {
    label: "Arr instances",
    note: "A copy of this key in a Profilarr Arr instance. Profilarr's API has no update route, so this copy is updated by hand.",
    proof: "manual only",
    mechanism: "",
    writer: false,
  },
  instance: {
    label: "instances",
    note: "qui's instance row; written over qui's API and proven by its connection test.",
    proof: "process connection test",
    mechanism: "",
    writer: true,
  },
};

const SERVARR_LIBRARY = ["sonarr", "radarr", "lidarr", "readarr", "whisparr"];
const SERVARR_LIBRARY_IDS = new Set(SERVARR_LIBRARY);

const SERVICE_DEFS = [
  {
    id: "sonarr",
    label: "Sonarr",
    blurb: "TV library manager.",
    mint: { mechanism: "servarr_command" },
    slots: ["indexers", "download_clients"],
  },
  {
    id: "radarr",
    label: "Radarr",
    blurb: "Film library manager.",
    mint: { mechanism: "servarr_command" },
    slots: ["indexers", "download_clients"],
  },
  {
    id: "prowlarr",
    label: "Prowlarr",
    blurb: "Indexer manager.",
    mint: { mechanism: "servarr_command" },
    slots: ["indexers", "download_clients", "applications"],
  },
  {
    id: "lidarr",
    label: "Lidarr",
    blurb: "Music library manager.",
    mint: { mechanism: "servarr_command" },
    slots: ["indexers", "download_clients"],
  },
  {
    id: "readarr",
    label: "Readarr",
    blurb: "Book library manager.",
    mint: { mechanism: "servarr_command" },
    slots: ["indexers", "download_clients"],
  },
  {
    id: "whisparr",
    label: "Whisparr",
    blurb: "Adult-media library manager.",
    mint: { mechanism: "servarr_command" },
    slots: ["indexers", "download_clients"],
  },
  {
    id: "jellyfin",
    label: "Jellyfin",
    blurb: "No holder target for its own key.",
    mint: { mechanism: "jellyfin_auth_keys" },
    slots: [],
  },
  {
    id: "seerr",
    label: "Seerr",
    blurb: "Holds Sonarr, Radarr and Jellyfin keys; mints its own.",
    mint: { mechanism: "seerr_regenerate" },
    slots: ["settings_json"],
  },
  {
    id: "qbittorrent",
    label: "qBittorrent",
    blurb: "Its API key is held by qui and *arr download clients.",
    mint: { mechanism: "qbittorrent_rotate_api" },
    slots: [],
  },
  {
    id: "homepage",
    label: "Homepage",
    blurb: "Renders labels at deploy time.",
    mint: null,
    slots: ["label"],
    holderOnly: true,
  },
  {
    id: "profilarr",
    label: "Profilarr",
    blurb:
      "Stores Arr instance keys; its API has no update route, so copies are manual.",
    mint: null,
    slots: ["arr_config"],
    holderOnly: true,
  },
  {
    id: "qui",
    label: "qui",
    blurb: "Holds a qBittorrent credential.",
    mint: null,
    slots: ["instance"],
  },
  {
    id: "grafana",
    label: "Grafana",
    blurb: "Service-account tokens; rotation revokes the named token last.",
    mint: { mechanism: "grafana_service_token" },
    slots: [],
    port: 3000,
  },
  {
    id: "arcane",
    label: "Arcane",
    blurb: "API keys; the row is found from the key's prefix.",
    mint: { mechanism: "arcane_api_key" },
    slots: [],
    port: 3552,
  },
  {
    id: "gitea",
    label: "Gitea",
    blurb: "API tokens minted with a password; webhook secrets over the hook API.",
    mint: { mechanism: "gitea_token" },
    slots: [],
    port: 3000,
  },
];

export const SERVICE_CATALOG = SERVICE_DEFS.map((service) => ({
  ...service,
  targets: service.slots.map((slot) => {
    const meta = SLOT_META[slot];
    return {
      key: `${service.id}.${slot}`,
      service: service.id,
      slot,
      ...meta,
      exercised: Boolean(meta.writer && hasConfirmation(service.id, slot)),
      label: `${service.label} ${meta.label}`,
    };
  }),
}));

export const SERVICE_BY_ID = new Map(
  SERVICE_CATALOG.map((service) => [service.id, service]),
);

export const TARGETS = SERVICE_CATALOG.flatMap((service) => service.targets);

export const TARGET_BY_KEY = new Map(TARGETS.map((target) => [target.key, target]));

export function serviceById(id) {
  return SERVICE_BY_ID.get(id) ?? null;
}

export function targetByKey(key) {
  return TARGET_BY_KEY.get(key) ?? null;
}

export function targetKey(service, slot) {
  return `${service}.${slot}`;
}

export function targetString({ service, slot, qualifier = "" }) {
  const row = String(qualifier ?? "").trim();
  return `${service}.${slot}${row ? `[${row}]` : ""}`;
}

// Where a copy lives, in the words of the services' own settings screens:
// Prowlarr manages "Apps", Servarr screens list indexers and download
// clients, Seerr has one settings row per app, qui lists instances, and a
// Homepage label is rendered at deploy time, never read back.
export function describeHolder(holder, ownerLabel) {
  const owner = ownerLabel || "This key";
  const service = serviceById(holder?.service)?.label ?? holder?.service ?? "?";
  const qualifier = String(holder?.qualifier ?? "").trim();
  switch (holder?.slot) {
    case "applications":
      return qualifier
        ? `A copy of ${owner}'s key is in ${service}'s ${qualifier} app.`
        : `A copy of ${owner}'s key is in ${service}'s Apps.`;
    case "indexers":
      return qualifier
        ? `A copy of ${owner}'s key is in ${service}'s ${qualifier} indexer.`
        : `A copy of ${owner}'s key is in each of ${service}'s indexers.`;
    case "download_clients":
      return qualifier
        ? `A copy of ${owner}'s key is in ${service}'s ${qualifier} download client.`
        : `A copy of ${owner}'s key is in each of ${service}'s download clients.`;
    case "settings_json":
      return qualifier
        ? `A copy of ${owner}'s key is in ${service}'s ${qualifier} settings.`
        : `A copy of ${owner}'s key is in ${service}'s settings.`;
    case "label":
      return `A copy of ${owner}'s key is rendered as a Homepage label when you deploy. It is not read back.`;
    case "instance":
      return qualifier
        ? `A copy of ${owner}'s key is in ${service}'s ${qualifier} instance.`
        : `A copy of ${owner}'s key is in a ${service} instance.`;
    case "arr_config":
      return qualifier
        ? `A copy of ${owner}'s key is in ${service}'s ${qualifier} Arr instance. Profilarr has no update API; update this copy by hand.`
        : `A copy of ${owner}'s key is in ${service}'s Arr instances. Profilarr has no update API; update these copies by hand.`;
    default:
      return targetString({
        service: holder?.service ?? "?",
        slot: holder?.slot ?? "?",
        qualifier,
      });
  }
}

export function defaultClass(serviceId) {
  return serviceById(serviceId)?.mint ? "A-unv" : "B";
}

export function defaultMaxAge(serviceId) {
  return serviceById(serviceId)?.mint ? 90 : null;
}

export function defaultNeverRotate(serviceId) {
  return serviceById(serviceId)?.mint ? false : true;
}

export function defaultCredentialName(serviceId) {
  if (serviceId === "qbittorrent") return "qbittorrent_api_key";
  return `${serviceId}_api_key`;
}

export function defaultPort(id) {
  return serviceById(id)?.port ?? (id === "jellyfin" ? 8096 : 8989);
}

// Rotation methods that need fields on the credential. Every other mint in
// this build takes no fields, so the wizard only renders inputs for these.
// `credential: true` marks a field that names another credential in the same
// manifest (never a value). Optional engine overrides (`key_name`,
// `permissions`, `token_name`, `scopes`) stay import-only: the manifest
// preview shows them, the wizard does not edit them, and an edit that leaves
// them alone keeps them.
export const WRITE_MECHANISMS = {
  grafana_service_token: {
    label: "Grafana service-account token",
    about:
      "The service generates the new secret; the old credential is revoked last, so there is always a working key.",
    fields: [
      {
        key: "token_name",
        label: "Token name",
        required: true,
        placeholder: "homelab-homepage",
        help: "The token row Grafana shows. Rotation revokes this name after the replacement works.",
      },
    ],
  },
  arcane_api_key: {
    label: "Arcane API key",
    about:
      "The service generates the new secret; the old credential is revoked last, so there is always a working key.",
    note: "No fields: the key's row is found from its prefix, and its name and grants are copied onto the replacement.",
    fields: [],
  },
  gitea_token: {
    label: "Gitea API token",
    about:
      "The service generates the new secret; the old credential is revoked last, so there is always a working key.",
    fields: [
      {
        key: "username",
        label: "Username",
        required: true,
        placeholder: "admin",
        help: "The user whose tokens are managed. Basic auth mints and deletes them.",
      },
      {
        key: "mint_with",
        label: "Password credential",
        required: true,
        credential: true,
        help: "The stored credential holding this user's password.",
      },
    ],
  },
  gitea_hook_secret: {
    label: "Gitea webhook secret",
    about:
      "The hook is updated in place and pinged; the old secret stops working the moment the new one is written.",
    fields: [
      {
        key: "repo",
        label: "Repository",
        required: true,
        placeholder: "owner/repo",
        help: "owner/repo naming the hook to update.",
      },
      {
        key: "hook_url",
        label: "Hook URL",
        required: true,
        placeholder: "https://deploy/hook",
        help: "The hook endpoint; identifies the hook alongside the repo.",
      },
      {
        key: "mint_with",
        label: "API token credential",
        required: true,
        credential: true,
        help: "A Gitea API token with write:repository.",
      },
    ],
  },
};

// The rotation methods a credential of this owner can use. Most owners have
// exactly one and the wizard shows no picker; Gitea also offers the webhook
// secret and a stored password that never rotates.
export function mechanismOptions(ownerId) {
  if (ownerId === "gitea") return ["gitea_token", "gitea_hook_secret", "stored"];
  const mint = serviceById(ownerId)?.mint;
  return mint ? [mint.mechanism] : [];
}

// The holder targets a person is most likely to mean for this issuer. They are
// suggestions only: every one is a real target from the registry, and every one
// can be removed before import.
function hasConfirmation(service, slot) {
  // Keep this in step with writers.py: a confirmation route is a measured
  // holder test or a running-process read-back, not merely a writer.
  if (slot === "settings_json" || slot === "instance" || slot === "applications") {
    return true;
  }
  return (
    (slot === "indexers" || slot === "download_clients") &&
    (service === "sonarr" || service === "radarr")
  );
}

export function holderSuggestions(ownerId) {
  const owner = serviceById(ownerId);
  const out = [];
  const seen = new Set();
  const add = (service, slot, qualifier, why) => {
    const key = targetKey(service, slot);
    const target = targetByKey(key);
    if (!target) return;
    const identity = `${key}[${qualifier ?? ""}]`;
    if (seen.has(identity)) return;
    seen.add(identity);
    out.push({
      service,
      slot,
      qualifier: qualifier ?? "",
      key,
      label: `${target.label}${qualifier ? ` [${qualifier}]` : ""}`,
      why,
      writer: target.writer,
      exercised: target.writer && hasConfirmation(service, slot),
      proof: target.proof,
    });
  };
  const cap = owner?.label ?? ownerId;

  if (SERVARR_LIBRARY_IDS.has(ownerId)) {
    add("prowlarr", "applications", cap, `Prowlarr's ${cap} application row.`);
    if (ownerId === "sonarr" || ownerId === "radarr") {
      add("seerr", "settings_json", ownerId, `Seerr's ${cap} settings row.`);
    }
    if (["sonarr", "radarr", "lidarr"].includes(ownerId)) {
      add(
        "profilarr",
        "arr_config",
        cap,
        `Profilarr's ${cap} Arr instance; update this copy by hand.`,
      );
    }
  } else if (ownerId === "prowlarr") {
    // Only indexer rows can hold this key: a download-client row
    // authenticates to its download client, never to Prowlarr.
    for (const service of SERVARR_LIBRARY) {
      add(service, "indexers", "", `${cap} indexer rows in ${service} hold this key.`);
    }
  } else if (ownerId === "jellyfin") {
    add("seerr", "settings_json", "jellyfin", "Seerr's Jellyfin settings row.");
  } else if (ownerId === "qbittorrent") {
    for (const service of SERVARR_LIBRARY) {
      // A qBittorrent API key belongs in the apiKey field. The password field
      // is for a username/password download client, not a second copy of this
      // key; suggesting it created a duplicate, unverifiable holder.
      add(service, "download_clients", "qBittorrent:apiKey", `qBittorrent's API key in a ${service} download-client row.`);
    }
    add("qui", "instance", "qBittorrent", "qui's stored qBittorrent credential.");
  }

  add("homepage", "label", "", "A Homepage label; rendered at deploy time, not read back.");
  return out;
}
