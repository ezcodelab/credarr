# Credarr and the portable UI system

Credarr uses the portable UI contract and schema audit as a structural gate,
not as a copied starter. Its visual language is already defined by
`docs/UI_SYSTEM.md` and the tokens in `ui/src/app.css`; those remain
authoritative.

- **Contract:** `docs/ui-contract.md` — product, audience, one job, direction,
  tokens, references, states, accessibility, performance, acceptance.
- **System:** `docs/UI_SYSTEM.md` — the tokens, components, states and rules.
- **Tokens:** `ui/src/app.css` is the only palette, including the generic audit
  aliases (`--surface`, `--surface-raised`, `--text-muted`, `--border`,
  `--radius-md`). There is no second token file.
- **Gallery:** `ui/src/views/DesignSystem.svelte` is the real Svelte gallery.
  Run `cd ui && npm run dev`, then open `/?design`. It is development-only and
  is not linked from the product.
- **Config:** `ui-system/config.json` points the portable audit at the contract,
  system, real token file and real gallery instead of the starter's static
  copies.
- **Audit:** `ui-system/bin/ui_system.py` is the project-local copy; `init` is a
  one-time harness command, not a runtime dependency.

Run the audit from this repository:

```sh
python3 ui-system/bin/ui_system.py audit .
```

It checks structure and filled-in fields, not visual quality. Then run
`make check`, `make ui-smoke`, and `/design-review` on the screens at 1440, 1024
and 390. A new component or state updates the contract, the system document and
the gallery in the same change. Extend the system; do not add a second visual
language.
