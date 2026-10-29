// Credential names are identities in the manifest (`sonarr_api_key`), and the
// engine and the store compare them exactly. Everywhere a person reads one,
// the title is used instead; the slug is still what the YAML and the API carry.
//
// There is no display-name field in the store in v1,
// so the title is derived from the slug. A name that is not the catalog's
// `<service>_api_key` shape falls back to title case.
import { sentenceCase } from "./api.js";
import { serviceById, targetByKey } from "./setupCatalog.js";

const WORDS = { api: "API", id: "ID", url: "URL", ui: "UI" };

export function credentialTitle(name) {
  const slug = String(name ?? "").trim();
  if (!slug) return "Credential";
  if (slug.endsWith("_api_key")) {
    const owner = slug.slice(0, -"_api_key".length);
    const service = serviceById(owner);
    if (service) return `${service.label} API Key`;
    return `${titleCase(owner)} API Key`;
  }
  return titleCase(slug);
}

function titleCase(slug) {
  return String(slug)
    .split(/[_-]+/)
    .filter(Boolean)
    .map((word) => WORDS[word.toLowerCase()] ?? word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

// The inverse, for the one place a title is typed: the wizard's name field and
// the Credentials view. "Sonarr API Key" -> "sonarr_api_key".
export function credentialSlug(title) {
  const text = String(title ?? "").trim().toLowerCase();
  if (!text) return "";
  if (text.endsWith(" api key")) {
    const owner = slugPart(text.slice(0, -" api key".length));
    return owner ? `${owner}_api_key` : "";
  }
  return slugPart(text).slice(0, 64);
}

// One sentence per imported key that will not rotate even though its service
// can mint. The server sends the names and services; the console owns the
// labels and the class-A hint.
export function importWarningLines(warnings) {
  return (warnings ?? [])
    .filter((warning) => warning?.credential)
    .map((warning) => {
      const name = credentialTitle(warning.credential);
      const service = serviceById(warning.service)?.label ?? warning.service;
      return `${name} is marked audit-only, but ${service || "its service"} supports rotation. Set its class to A if it should rotate.`;
    });
}

function slugPart(text) {
  return text.replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}

// Engine sentences name copies by target stub (`sonarr.indexers[Sonarr]`).
// The panel keeps the engine's sentence and swaps only the stub for the
// copy's plain name; anything without a known target passes through untouched.
const TARGET_PREFIX = /^([^.\s:]+)\.([^:[\s]+)(?:\[([^\]]*)\])?\s*:?\s*/;

function targetName(match) {
  const meta = targetByKey(`${match[1]}.${match[2]}`);
  if (!meta) return null;
  return match[3] ? `${meta.label} [${match[3]}]` : meta.label;
}

// A target stub as the copy's plain name, for rows and buttons. Anything
// without a known target comes back as written.
export function copyLabel(target) {
  const text = String(target ?? "");
  const match = TARGET_PREFIX.exec(text);
  if (!match) return text;
  return targetName(match) ?? text;
}

export function friendlyReason(reason) {
  const text = String(reason ?? "");
  const match = TARGET_PREFIX.exec(text);
  if (!match) return sentenceCase(plainEngineText(text));
  const name = targetName(match);
  if (name === null) return sentenceCase(plainEngineText(text));
  return sentenceCase(
    plainEngineText(`${name}: ${text.slice(match[0].length)}`),
  );
}

// Engine field names in operator words. Every engine sentence that reaches
// the screen passes through here, so a dotted write.* token never leaks a
// manifest path into the UI: the planner's words stay, its field paths do
// not. Unknown fields fall back to their words split apart.
const WRITE_FIELD_NAMES = {
  mechanism: "rotation method",
  ui_password: "UI password",
  manual_mint: "manual rotation",
  reconstruct_config: "config rebuild",
  token_name: "token name",
  key_name: "key name",
  permissions: "permissions",
  scopes: "scopes",
  username: "username",
  mint_with: "password credential",
  repo: "repository",
  hook_url: "hook URL",
};

export function plainEngineText(text) {
  return String(text ?? "").replace(
    /write\.([A-Za-z_][A-Za-z0-9_]*)/g,
    (match, field, offset) => {
      const name =
        WRITE_FIELD_NAMES[field] ?? String(field).replace(/_/g, " ");
      if (offset === 0) return name.charAt(0).toUpperCase() + name.slice(1);
      return name;
    },
  );
}

// The login wall names every option at once, so the panel shows its pointer
// instead of the sentence and the credential view never hangs it under one
// field. Split, don't paraphrase: the wall stays verbatim in the ledger.
export function splitLoginWall(reasons) {
  const wall = [];
  const rest = [];
  for (const reason of reasons ?? []) {
    (/web UI login/.test(String(reason ?? "")) ? wall : rest).push(reason);
  }
  return { wall, rest };
}

// A refusal is often several engine facts about one declaration (class B,
// never_rotate, no method). Say the outcome once, then keep only facts the
// operator can act on; the full list stays in the activity ledger.
export function refusalLines(reasons, own = []) {
  const raw = (reasons ?? [])
    .map((reason) => String(reason ?? ""))
    .filter(Boolean);
  const has = (pattern) => raw.some((reason) => pattern.test(reason));
  const classB = has(/\bclass B\b/);
  const neverRotate = has(/\bnever_rotate\b/);
  const noStrategy = has(/no rotation strategy for write\.mechanism/);
  const methodMatch = raw
    .map((reason) =>
      /no rotation strategy for write\.mechanism\s+(?:'([^']*)'|"([^"]*)")/.exec(
        reason,
      ),
    )
    .find(Boolean);
  const method = methodMatch ? methodMatch[1] ?? methodMatch[2] ?? "" : "";
  const lines = [];

  if (classB) {
    lines.push(
      noStrategy
        ? "This key is audit-only and has no usable rotation method."
        : "This key is audit-only.",
    );
  } else {
    if (noStrategy) {
      lines.push(
        method
          ? "The declared rotation method is not supported by this build."
          : "This key has no rotation method.",
      );
    }
    if (neverRotate) lines.push("Rotation is turned off for this key.");
  }

  for (const reason of raw) {
    if (classB && /credential is class B\b/.test(reason)) continue;
    if (neverRotate && /never_rotate\b/.test(reason)) continue;
    if (noStrategy && /no rotation strategy for write\.mechanism/.test(reason)) {
      continue;
    }
    const line = bannerLine(friendlyReason(reason), own);
    if (line && !lines.includes(line)) lines.push(line);
  }
  return lines;
}

// A leading `service:` stripped only when it names one of `own` (the page
// already says whose credential this is; a holder of another service keeps
// its prefix). Stripping starts a new sentence, so it is capitalized.
export function stripServicePrefix(text, own = []) {
  const input = String(text ?? "");
  const match = /^([A-Za-z0-9_-]+):\s+/.exec(input);
  if (!match) return input;
  const known = own.some(
    (name) => String(name ?? "").toLowerCase() === match[1].toLowerCase(),
  );
  if (!known) return input;
  const rest = input.slice(match[0].length);
  return rest.charAt(0).toUpperCase() + rest.slice(1);
}

// One banner line: the service prefix goes when it repeats the page, and a
// trailing "nothing has been changed" goes where the banner title already
// promises nothing started. Run failures keep theirs: a stopped run may be
// partial, so that sentence is load-bearing there.
export function bannerLine(text, own = []) {
  return stripServicePrefix(text, own)
    .replace(/\s*Nothing has been changed\.?\s*$/i, "")
    .trim();
}

// Engine sentences name the write field they refuse (`write.token_name`);
// the credential view hangs each one under the field that can fix it. The
// login-wall sentence is the exception: it names every option at once, so it
// lives at the panel and the pane intro, never under one field.
export function reasonsForField(reasons, fieldKey) {
  const needle = `write.${fieldKey}`;
  return (reasons ?? []).filter((reason) => {
    const text = String(reason ?? "");
    if (!text.includes(needle)) return false;
    return !/web UI login/.test(text);
  });
}
