# Credarr UI system

The console has one visual language. This document is the source of truth for
that language; `UI_IA.md` is the source of truth for the information
architecture. If the code and this document disagree, the code is wrong and the
change must fix one of them in the same commit.

## Direction

**Graphite ledger.** A quiet instrument panel for one operator: keys, copies,
audit evidence and rotation. The screen should feel like a well-kept ledger,
not a marketing dashboard.

- **Character:** quiet, exact, watchful.
- **World:** keys, locks, audit hairlines and night-shift monitoring.
- **Signature:** the key tile with a status dot, and a status word that is
  always visible beside the dot.
- **One accent:** a cool blue marks interaction. Green, amber and red carry
  state. Nothing glows, gradients or competes with content.

Do not copy another product's layout, icons, wording, illustrations or brand
treatments. Borrow the reasoning, then use Credarr's own tokens and components.

## Tokens

All tokens live in `ui/src/app.css` under `:root`. Do not introduce per-page
colours, fonts, radii or spacing values.

| Role | Token | Value |
| --- | --- | --- |
| Page | `--bg` | `#0b0e12` |
| Sidebar / elevated | `--bg-elevated` | `#0f1419` |
| Panel | `--panel` | `#12181e` |
| Raised panel | `--panel-2` | `#182028` |
| Well / inset | `--well` | `#090c0f` |
| Hairline | `--line` | `#222a33` |
| Strong hairline | `--line-strong` | `#333e49` |
| Text | `--text` | `#e6ebf0` |
| Strong text | `--text-strong` | `#f7f9fb` |
| Secondary text | `--dim` | `#9ba6b2` |
| Muted text | `--dim-2` | `#7a8591` |
| Accent | `--accent` | `#7aa7ff` |
| Accent hover | `--accent-hover` | `#9dbdff` |
| Okay | `--ok` | `#5dd39e` |
| Bad | `--bad` | `#ff7a7a` |
| Warning | `--warn` | `#e8b45c` |
| Info | `--info` | `#7fd1e0` |
| Monitor-only | `--monitor` | `#93a1b0` |

Type:

- `--font-sans`: system UI sans. No web-font download.
- `--font-mono`: system monospace for timestamps, URLs and key names.
- `--text-xs` 0.6875rem, `--text-sm` 0.8125rem, `--text-base` 0.875rem,
  `--text-md` 1rem, `--text-lg` 1.375rem, `--text-xl` 1.75rem.
- Headings use weight 600. Body uses 400. Do not use 700–900 for interface
  headings.
- Use `font-variant-numeric: tabular-nums` for times, counts and figures.
- Use `text-wrap: balance` on headings and `text-wrap: pretty` on paragraphs.

Shape:

- `--radius` 12px for panels, `--radius-sm` 8px for controls, `--radius-lg`
  16px for dialogs.
- One-pixel hairlines. Depth comes from surface steps, not shadows. The shadow
  token is reserved for floating layers.

Motion:

- 120–180ms, ease-out. Animate colour, background, border, opacity and
  transform. Never animate layout dimensions.
- Every motion has a `prefers-reduced-motion` fallback.
- Motion explains a state change; it never decorates an entrance.

## Layout

The shell is a 244px sidebar and a fluid main column, capped at 1440px.
Below 960px the sidebar becomes an off-canvas drawer with a sticky mobile bar.

- One `h1` per page, in `PageHeader`.
- One primary action per section. Secondary actions are quiet; destructive
  actions are red and named.
- The page header has one sentence of context. It does not explain the layout.
- Apps is a ledger, not a card wall: one row per app with identity, state,
  copies and an open affordance. The row becomes a stacked card below 960px.
- App detail starts with a summary strip: key tile, state, value state, copies
  and last observation, then a sticky section nav and the working sections.
- Activity starts with a three-part summary (last audit, changes, delivery)
  before the ledger.
- Settings remains a single page with anchored sections; the sidebar's Settings
  submenu is the section index.
- Tables become one card per row below 720px. Column labels survive as inline
  labels, in sentence case.

## Components

Use the existing component before adding another.

| Component | File | Use |
| --- | --- | --- |
| `PageHeader` | `ui/src/lib/PageHeader.svelte` | One `h1`, optional one-sentence description, actions |
| `KeyTile` | `ui/src/lib/KeyTile.svelte` | App identity anchor; decorative status dot |
| `StatusPill` | `ui/src/lib/StatusPill.svelte` | Status word + dot; the word is the accessible signal |
| `Banner` | `ui/src/lib/Banner.svelte` | Page-level state that changes the meaning of the page |
| `EmptyState` | `ui/src/lib/EmptyState.svelte` | Empty state with a next action |
| `Modal` / `ConfirmDialog` | `ui/src/lib/Modal.svelte`, `ConfirmDialog.svelte` | One decision, focus-trapped |
| `Toasts` | `ui/src/lib/Toasts.svelte` | Routine success only |
| `ActivityBar` | `ui/src/lib/ActivityBar.svelte` | One thin line for work in flight |
| `TopologyImport` | `ui/src/lib/TopologyImport.svelte` | Manifest import/export |
| `NotificationServices` | `ui/src/lib/NotificationServices.svelte` | Sink list and form |
| `RotationPanel` | `ui/src/lib/RotationPanel.svelte` | Plan and armed rotation |

Shared CSS classes:

- `.page`, `.page-header`, `.page-actions`
- `.section`, `.section-head`, `.toolbar`, `.field`, `.field-grid`, `.field-help`
- `.card`, `.health-card`, `.key-tile`, `.pill`
- `.apps-ledger`, `.apps-ledger-head`, `.app-card`, `.app-main`, `.app-title`,
  `.app-state`, `.app-copies`, `.app-open`
- `.detail-summary`, `.detail-facts`, `.detail-fact`, `.detail-reason`,
  `.detail-nav`
- `.activity-summary`, `.activity-stat`
- `.empty`, `.banner`, `.toast`, `.overlay`, `.dialog`

## Status and colour

- Use `StatusPill` for every engine state. It renders the engine's word, not a
  softened synonym.
- A dot is a second cue. Never use colour as the only signal.
- Do not use a pill background for ordinary status. Only the exceptional state
  (a page-level alert, a destructive confirmation) gets a filled surface.
- Map tones through `status.js`. Do not invent a new colour in a view.
- If a state has no human word, it does not belong on the screen.

## States

Every screen must design these before the happy path:

- **Empty:** what is missing, why it matters, one next action.
- **Loading:** no spinner under ~300ms; a skeleton keeps the layout stable;
  a progress line for work in flight.
- **Error:** what happened, why if known, the next action. Field errors stay at
  the field; multiple errors get a summary with links.
- **Partial:** say which copy was not compared and why. Never call it a match.
- **Offline / unreachable:** name the server, not a stack trace; offer retry.
- **Permission / auth:** sign out cleanly; do not show the previous session's
  data.
- **Long content:** long key names, URLs and reasons wrap; no horizontal scroll.
- **Success:** one quiet toast for routine saves; no banner per save.

## Accessibility

- WCAG 2.2 AA is the floor: contrast, visible focus, keyboard path, reflow,
  target size, reduced motion, status messages.
- Every action must be reachable by keyboard. Focus returns to the trigger after
  a dialog closes.
- Labels are real labels. Placeholder text is not a label.
- Status is a word plus a dot, not a colour alone.
- Touch targets are 44px on small screens.
- Test at 200% zoom and with a screen reader on the primary path.
- Do not put a secret in a toast, a URL, a log or a screenshot.

## Performance

- Feedback under 100ms; keep flow under 1s; progress and an interrupt for waits
  approaching 10s.
- Do not block the shell on a secondary read. Apps, Activity and Settings load
  their own data; the shell owns `/status` and `/credentials`.
- Use a skeleton only when the layout would otherwise jump. Reserve space.
- Optimistic UI is allowed only when the failure and reconciliation are visible.
- Measure on the target hardware; vendor speed claims are not evidence.

## Adding or changing a screen

1. Read `UI_IA.md`, this document and the nearest view/component. Do not start a
   parallel visual language.
2. Write the one job of the screen and the one primary action. If there are
   three primary actions, rearrange.
3. List the states: empty, loading, error, partial, offline, permission, long
   name, long list.
4. Reuse an existing component or a variant. Add a primitive only when it will be
   used by more than one screen, then add it to the gallery.
5. Use tokens. No per-page colour, font, radius or spacing values.
6. Check 1440, 1024 and 390; check keyboard, focus, reduced motion and 200% zoom.
7. Run `make ui-test`, `make ui-smoke` and `make check`.
8. Capture before/after at the same widths. Run `/design-review`.
9. Update this document and `UI_IA.md` if the pattern or IA changed. Update the
   gallery with the same change.

## Gallery

Run `npm run dev` in `ui/` and open `/?design`. The gallery renders the real
tokens and components; it is development-only and must not be linked from the
product. When you add a primitive, add a row there.

## Review checklist

- One primary action; secondary actions are quiet; destructive actions are red.
- Every state is designed; no dead frames; no plausible-looking zeroes.
- Status is a word plus a dot; colour is never the only signal.
- Labels name things; no label explains the layout.
- No internal API field names, slugs, class or mechanism names in operator copy.
- No new colours, fonts, radii, shadows or spacing outside the tokens.
- Long names, long lists, empty, failure and partial states do not break.
- Keyboard path and visible focus; focus returns after dialogs.
- 1440 / 1024 / 390; no horizontal scroll.
- `make ui-smoke` and `make check` pass.
- The gallery and this document still match the code.

## File map

```
ui/src/app.css                    tokens and shared visual rules
ui/src/App.svelte                shell, nav, global banners, keepalive
ui/src/views/Apps.svelte         Apps ledger, connect form, empty states
ui/src/views/AppDetail.svelte    summary, section nav, connection, history, copies
ui/src/views/Activity.svelte     audit/event ledger
ui/src/views/Settings.svelte     security, schedule, keys, sinks, import/export
ui/src/views/DesignSystem.svelte dev-only gallery (?design)
ui/src/lib/                      shared primitives
ui/tests/smoke.mjs               real browser, real server, fake services
ui/tests/screenshots.mjs         README captures from the real console
```

The rule is simple: **extend this system, never replace it.** A new screen that
cannot be built from these tokens and components is a design decision, and it
must be documented here before it ships.
