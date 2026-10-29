# Service coverage

All measured on disposable containers with synthetic keys. Mint shapes:
**reset/replace** (Servarr backup/restore: dead at restart; manual variant:
already dead when the run starts; reconstructed variant: dead at the restart
after restore), **rotate** (qBittorrent, Seerr: the response carries the new key,
old dies immediately), **reissue** (Jellyfin, Grafana, Arcane, Gitea:
replacement created alongside, predecessor revoked last).

| Service | Own key | Holders | Verified |
| --- | --- | --- | --- |
| Sonarr 4.0.20.3014, Radarr 6.4.4.10685, Prowlarr 2.6.5.5623 | backup/restore or reconstruct | API writes; qBittorrent download-client rows via measured `downloadclient/test` | old 401 / new 200; Forms login measured Sonarr-only |
| Lidarr 3.1.0.4875, Readarr 0.4.19.2811, Whisparr 2.2.0.231 | same backup/restore path | API writes; **indexer rows unproven** (written, never exercised, so the run honestly exits 1) | mint measured; `indexer/test` still `[T]` |
| Seerr 3.5.0 | `POST /settings/main/regenerate` (a pinned `API_KEY` env makes it a refused no-op) | `PUT /settings/{service}/{id}`, `POST /settings/jellyfin` | running-process read-back; old key 403s immediately, no restart |
| Jellyfin 12.2.0 | `POST /Auth/Keys`, revoke last, name-scoped stray sweep | Seerr by process read-back | create/propagate/revoke e2e |
| qBittorrent 5.3.0 | `POST /api/v2/app/rotateAPIKey` | Sonarr/Radarr download-client rows | old 403 / new 200 on `/app/version` |
| qui 1.33.0 | n/a (holder) | `PUT /api/instances`, proven by its own connection test | measured |
| Grafana 12.1.1 | service-account token (`write.token_name` required) | deploy-time copies are named manual steps | create/revoke-last, Viewer-role 403 refused |
| Arcane 2.17.0 (pinned digest) | scoped key, predecessor found by `keyPrefix` | deploy copies are manual steps | static/bootstrap keys refused before anything is created |
| Gitea 1.27.2 | token via password credential (`write.mint_with` + `write.username`, Basic-only routes), predecessor by `token_last_eight`; webhook secret via `PATCH .../hooks/{id}` found by `write.hook_url` | deploy copies are manual steps | token + hook measured |
| Homepage | holder-only, no key/URL | `homepage.label` (repeatable manual copy, excluded from verdicts) | by design |
| Profilarr ≤ v2.3.1 | n/a | `profilarr.arr_config[<instance>]` manual (API v1 is GET-only; re-check upstream issue #401) | probe-measured 404s |
| Plex, Jackett | none (account-scoped / no API route) | monitor-only, class B | do not invent a route |
| Bazarr, SABnzbd | researched routes, **unmeasured** (`POST /api/system/settings`, `mode=set_config`) | none | `[T]` live run required before any claim |

A service joins this table only with a measured writer or mint; "managed"
means measured for the named version, anything else is monitor-only. New
issuer checklist: where is the key exposed, what actually writes it (a
chosen-value write the service ignores is a measured dead end, not a mint),
what proves the running process uses it.
