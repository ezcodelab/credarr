# Service coverage

Capabilities are measured on disposable containers with synthetic keys. A
`[T]` row is not a claim. Mint shapes:
**reset/replace** (Servarr backup/restore: dead at restart; manual variant:
already dead when the run starts; reconstructed variant: dead at the restart
after restore), **reset/restart** (SABnzbd: set_apikey returns the new key,
mode=restart settles it, old dies at the restart), **rotate** (qBittorrent,
Seerr: the response carries the new key, old dies immediately), **chosen
rotate** (Bazarr: settings-auth-apikey writes a chosen value, old dies
immediately), **reissue** (Jellyfin, Grafana, Arcane, Gitea: replacement
created alongside, predecessor revoked last).

| Service | Own key | Holders | Verified |
| --- | --- | --- | --- |
| Sonarr 4.0.20.3014, Radarr 6.4.4.10685, Prowlarr 2.6.5.5623 | backup/restore or reconstruct | API writes; qBittorrent download-client rows via measured `downloadclient/test` | old 401 / new 200; Forms login measured Sonarr-only |
| Lidarr 3.1.0.4875, Readarr 0.4.19.2811, Whisparr 2.2.0.231 | same backup/restore path | API writes; indexer rows exercised through `indexer/test` on all three pinned builds | mint measured; `indexer/test` 2xx live / non-2xx dead / 2xx restored (2026-10-30) |
| Seerr 3.5.0 | `POST /settings/main/regenerate` (a pinned `API_KEY` env makes it a refused no-op) | `PUT /settings/{service}/{id}`, `POST /settings/jellyfin` | running-process read-back; old key 403s immediately, no restart |
| Jellyfin 12.2.0 | `POST /Auth/Keys`, revoke last, name-scoped stray sweep | Seerr by process read-back | create/propagate/revoke e2e |
| qBittorrent 5.3.0 | `POST /api/v2/app/rotateAPIKey` | Sonarr/Radarr download-client rows | old 403 / new 200 on `/app/version` |
| qui 1.33.0 | n/a (holder) | `PUT /api/instances`, proven by its own connection test; the audit asks the same test and reports `live` | measured, audit readback 2026-10-31 |
| Bazarr 1.6.2 | `settings-auth-apikey` chosen form write; old dies immediately | Sonarr/Radarr keys via `POST /api/system/settings` form; `GET` reports `sonarr.apikey`/`radarr.apikey` from the running process | write 204, process read-back equal, old Bazarr key 401; server auto run `auto_manual` (2026-10-30); a 406/422 value rejection re-chooses the key up to three times (2026-10-31) |
| Grafana 12.1.1 | service-account token (`write.token_name` required) | deploy-time copies are named manual steps | create/revoke-last, Viewer-role 403 refused |
| Arcane 2.17.0 (pinned digest) | scoped key, predecessor found by `keyPrefix` | deploy copies are manual steps | static/bootstrap keys refused before anything is created |
| Gitea 1.27.2 | token via password credential (`write.mint_with` + `write.username`, Basic-only routes), predecessor by `token_last_eight`; webhook secret via `PATCH .../hooks/{id}` found by `write.hook_url` | deploy copies are manual steps | token + hook measured |
| Homepage | holder-only, no key/URL | `homepage.label` (repeatable manual copy, excluded from verdicts) | by design |
| Profilarr ≤ v2.3.1 | n/a | `profilarr.arr_config[<instance>]` manual (API v1 is GET-only; re-check upstream issue #401) | probe-measured 404s |
| Plex, Jackett | none (account-scoped / no API route) | no writer; not offered in the wizard | measured refusal; do not invent a route |
| SABnzbd 5.1.3 | `mode=config&name=set_apikey` then `mode=restart` (reset/restart) | Sonarr/Radarr SABnzbd download-client rows, exercised by `downloadclient/test` | old 403 / new 200; server auto run `auto_succeeded` (2026-10-30) |

Server auto runs (2026-10-31): every wizard mint has one. Sonarr, Radarr,
Prowlarr, Lidarr, Readarr, Whisparr, Jellyfin and qBittorrent record
`auto_succeeded`; Seerr,
Grafana, Arcane and Gitea record `auto_manual` because their only declared copy
is the deploy-time Homepage label, and SABnzbd and Bazarr were proven on
2026-10-30. `docs/ROTATION.md` names the harness per mint.

A service joins this table only with a measured writer or mint; "managed"
means measured for the named version, anything else is monitor-only. New
issuer checklist: where is the key exposed, what actually writes it (a
chosen-value write the service ignores is a measured dead end, not a mint),
what proves the running process uses it.
