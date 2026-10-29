# Credarr docs

Single maintained reference for operators and contributors. Anything here
that the code contradicts is a bug in this file. The engine
(`src/credarr/`) and the server (`src/credarr_server/`) are authoritative.

Start with `../README.md` (install, first boot, connect an app), then:

| Page | What it is |
| --- | --- |
| `CONCEPTS.md` | Holder map, audit statuses and reason codes, classes, exit codes |
| `ARCHITECTURE.md` | Engine / server / console layout, stores, load-bearing invariants |
| `OPERATING.md` | Audit, rotation, Servarr routes, auto-rotation, notifications, backups, discovery, console map |
| `SERVICES.md` | Mint shapes and per-service coverage with measured versions |
| `API.md` | `/api/v1` reference seed (full contract: the live `/openapi.json`) |
| `LIMITATIONS.md` | Known v1 limits and troubleshooting. Read before exposing or trusting a rotation |
| `TESTING.md` | Test layers, measured coverage, gaps and the rules for new tests |
| `CONTRIBUTING.md` | Toolchain, checks, conventions |
| `ADDING_A_SERVICE.md` | Lifecycle checklist for adding/measuring service support |

The layout follows the two reference projects: Seerr's audience-split
Docusaurus site (`getting-started/`, `using-seerr/`, `troubleshooting`),
and Profilarr's in-repo `docs/` (`ARCHITECTURE.md`, `CONTRIBUTING.md`,
`api/`, per-area deep dives). When a standalone site is built, these pages
map onto its sections without a rewrite; until then this folder is the site.
