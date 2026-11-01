# Credarr UI contract

This is the portable first-pass contract for the Credarr console. It is filled
in place, not copied from another product. `docs/UI_SYSTEM.md` records the
system that carries it.

## Product

Credarr is the credential audit and rotation console for a self-hosted stack.
It joins each credential to the service that issues it, compares every declared
copy, and rotates a key only after proving the plan can run.

## Audience

One operator who knows Sonarr, Prowlarr, Seerr and the rest of the stack, but
not the database schema or the engine's internal field names. They work in
short, high-consequence sessions on a desktop or tablet, sometimes on a phone,
and need the page to stay legible with a queue of work.

## One job

See which app keys are healthy, which copies disagree, and what to rotate next
without leaving the page or translating engine vocabulary.

## Direction

**Character.** Quiet, exact, watchful.
**World.** Keys, locks, an audit ledger, and a night-shift control room; not a
marketing dashboard.
**Moments.** The stack-health strip; one ledger row whose status explains
itself; the rotation summary that says what a run will touch.
**Signature.** The key tile with a status dot, and a status word that is always
visible beside the dot. The Apps ledger is flat and ruled; the selected app's
detail is the one surface that carries the work.

**Principles.**

- One primary action per section; secondary actions stay quiet.
- Status is a word first and a dot second; colour is never the only signal.
- The layout carries the hierarchy; a label does not explain the layout.
- Tokens, components and the gallery are the system; no page-local palette.
- The operator sees the consequence and the next step, not the field path.

## Tokens

The source of truth is [`ui/src/app.css`](../ui/src/app.css). The generic names
the portable audit expects (`--surface`, `--surface-raised`, `--text-muted`,
`--border`, `--radius-md`) are aliases inside that same token block; there is no
second palette or token file.

The gallery is [`ui/src/views/DesignSystem.svelte`](../ui/src/views/DesignSystem.svelte)
at `/?design` under `npm run dev`. It is development-only. No page declares a
new colour, font, radius, shadow or spacing value.

## References

The approved reference set is maintained in the brain's UI notes; the patterns
used here are:

1. **Hex** — a flat icon rail, a searchable list, one inspector, and a selected
   row that is a surface step rather than an accent bar. Do not copy its
   palette, window chrome or system font.
2. **Profilarr** — the three-pane shape, compact metadata rows and a detail
   drawer. Do not copy its light theme or marketing hero.
3. **Arcane** — metric tiles above a resource table, status dots with a label,
   and grouped navigation. Do not copy its near-black palette or progress rings.
4. **OpenBot** — a compact conversation rail with a role and a one-line preview;
   take the rail density, not its empty canvas or avatars.

The reference is a decision about hierarchy and behaviour, never a licence to
copy distinctive layouts, icons, illustrations, wording or brand treatments.

## States

- **Empty.** No topology, no apps, or no matching filter. Say what is missing
  and offer Add app, Resume setup, or Show everything. Never show an empty table
  as a clean audit.
- **Loading.** A skeleton that reserves the final ledger, summary and detail
  layout; no full-page spinner and no plausible zeroes.
- **Error.** Inline where the failure happened; a page-level banner only when it
  changes the meaning of the page. Name the service and the recovery.
- **Partial.** A copy that could not be compared stays `unverifiable` with the
  reason; it is not a match. Manual copies stay neutral and named.
- **Offline / unreachable.** Say the server did not answer, offer retry, and do
  not keep stale values on screen as if they were current.
- **Permission.** A 401 signs out cleanly; it never renders the previous
  session's data. The login wall is not a place to expose the configuration.
- **Long name and long list.** App titles, URLs and engine sentences wrap; the
  ledger stays one column on narrow screens; no horizontal scroll.
- **Focus, hover, selected, disabled.** Visible 2px focus, a quiet surface step
  for hover/selection, and a reason beside every disabled action.

## Accessibility

Target WCAG 2.2 AA. Text and semantic status colours meet the contrast measured
in the design-system review (at least 4.5:1 for normal text); focus is a 2px
accent ring; labels are persistent; status words accompany dots; the keyboard
path follows reading order; dialogs trap focus and return it to the trigger;
reduced motion removes non-essential animation; touch targets are at least
44px at narrow widths. `@axe-core/playwright` runs WCAG A/AA scans in
`make ui-smoke` for setup, empty and populated Apps, Activity, App detail,
Settings, login and the 390px Apps layout; serious or critical violations fail
the smoke. Manual screen-reader and assistive-technology testing are still
unproven.

## Performance

Aim for perceived feedback under 100ms, flow under 1s, and progress with an
interrupt for waits approaching 10s. Do not block the shell on a secondary read;
reserve skeleton space to avoid layout shift; keep the console usable when an
audit job is polling. `make ui-smoke` is the measured browser check; a slow
runner is evidence, not an excuse for a longer wait.

## Acceptance

- `python3 ~/Documents/homelab/brain/bin/ui_system.py audit .` prints
  `ui system: OK`.
- `make check` and `make ui-smoke` pass.
- `/design-review` on the Apps, App detail and Activity screens at 1440, 1024
  and 390 reports 0 blocking findings and at most one quick-win round.
- No horizontal scroll; every state above is visible in the console or named in
  `docs/UI_SYSTEM.md` as unresolved with a reason.
- No page-local palette, font, radius or spacing; the gallery matches the
  shipped components.
