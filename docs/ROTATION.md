# Rotation coverage and the awesome-arr roadmap

This page answers two questions the setup wizard cannot answer by itself:

1. which service keys this build can rotate unattended, and what proves it;
2. which popular *arr-ecosystem services are next, and which are refusals.

Claim tags follow `docs/SERVICES.md`: `[V]` is measured on the named version,
`[T]` needs a live run before it becomes a claim, and "manual" means no API
write or read-back exists. A service is never added to the wizard as a
monitor-only inscription (decision 21).

## The setup wizard catalog

Every service the wizard offers, with its own-key route, its holder shape, and
whether a **server auto-rotation** run exists. The wizard's `exercised` flag is
pinned to the engine's `holder_for` test path or read-back by
`ui/tests/setup.test.mjs`.

| Service | Own key | Holders | Own key | Auto e2e |
| --- | --- | --- | --- | --- |
| Sonarr 4.0.20.3014 | backup/restore or reconstructed restore | Prowlarr Apps; Seerr settings; Profilarr manual; indexer rows in other *arr apps | `[V]` | `[V]` |
| Radarr 6.4.4.10685 | backup/restore or reconstructed restore | Prowlarr Apps; Seerr settings; Profilarr manual; indexer rows | `[V]` | `[V]` |
| Prowlarr 2.6.5.5623 | backup/restore or reconstructed restore | indexer rows in Sonarr, Radarr, Lidarr, Readarr and Whisparr; Homepage label manual | `[V]` | `[V]` |
| Lidarr 3.1.0.4875 | backup/restore | Prowlarr Apps; Profilarr manual; its own indexer rows are a Prowlarr-key holder, not a Lidarr-key holder | `[V]` | `[V]` |
| Readarr 0.4.19.2811 nightly | backup/restore | Prowlarr Apps; Homepage label manual | `[V]` | `[V]` |
| Whisparr 2.2.0.231 | backup/restore | Prowlarr Apps; Homepage label manual | `[V]` | `[V]` |
| Jellyfin 12.2.0 | `POST /Auth/Keys`, revoke last | Seerr settings, process read-back | `[V]` | `[V]` |
| Seerr 3.5.0 | `POST /settings/main/regenerate` | its own settings rows for Sonarr, Radarr and Jellyfin; Homepage label manual | `[V]` | `[V]` |
| qBittorrent 5.3.0 | `POST /api/v2/app/rotateAPIKey` | Sonarr/Radarr download clients; qui instance test | `[V]` | `[V]` |
| SABnzbd 5.1.3 | `set_apikey` then `mode=restart` | Sonarr/Radarr SABnzbd download-client rows, `downloadclient/test` | `[V]` | `[V]` |
| Bazarr 1.6.2 | `settings-auth-apikey` form write | Sonarr/Radarr keys in its settings, process read-back; Homepage deploy copy is manual | `[V]` | `[V]` |
| Homepage | none | `homepage.label` rendered at deploy time | manual | n/a |
| Profilarr ≤ 2.3.1 | none | `profilarr.arr_config`; API v1 is GET-only | manual | n/a |
| qui 1.33.0 | holder only | `qui.instance`, proven by its connection test | `[V]` | n/a |
| Grafana 12.1.1 | service-account token, revoke last | deploy-time copies are named manual steps | `[V]` | `[V]` |
| Arcane 2.17.0 | scoped key, predecessor by `keyPrefix` | deploy-time copies are named manual steps | `[V]` | `[V]` |
| Gitea 1.27.2 | token via a password rotator; webhook secret over the hook API | deploy-time copies are named manual steps | `[V]` | `[V]` |

`indexer/test` was measured on 2026-10-30 on Lidarr 3.1.0.4875, Readarr
0.4.19.2811 and Whisparr 2.2.0.231: 2xx with the row's live key, non-2xx when
the Torznab upstream rejected it, 2xx after restore.

SABnzbd 5.1.3 was measured on 2026-10-30: `set_apikey` returns the new key,
`mode=restart` settles it, the old key answers 403 and the new key 200 on
`mode=queue`, and Sonarr's SABnzbd download client accepts the new key and
rejects the old one. The server auto run recorded `auto_succeeded`.

Bazarr 1.6.2 was measured on 2026-10-30: `settings-auth-apikey` replaces the
key in the running process with no restart, the old key answers 401 and the new
key 200. The server auto run recorded `auto_manual` because the Homepage copy
is rendered at deploy time; the policy stayed enabled.

Radarr 6.4.4.10685, Lidarr 3.1.0.4875, Readarr 0.4.19.2811 and Whisparr
2.2.0.231 were measured on 2026-10-31 through the real server: the
backup/restore mint rotated each key, Prowlarr's application row was the
holder, and Prowlarr's application test was the audit proof. The old key
answered 401, the new key 200, and the row held the new value
(`tests/live/server_auto_servarr.py`). Prowlarr 2.6.5.5623 was measured the
same way with a Sonarr Torznab indexer row as the holder.

Jellyfin 12.2.0 was measured on 2026-10-31: the reissue created a replacement
key, Seerr's `jellyfin` settings section was written over its API and reported
the value back from the running process, and the predecessor was revoked last.
The server auto run recorded `auto_succeeded`
(`tests/live/server_auto_jellyfin.py`).

Seerr 3.5.0, Grafana 12.1.1, Arcane 2.17.0 and Gitea 1.27.2 were measured on
2026-10-31: each mint rotated its own key with only a deploy-time Homepage copy
declared, so the server run recorded `auto_manual` and left the policy enabled.
The old key was refused and the new one accepted; Gitea's replacement kept the
copied scopes and its password credential was untouched
(`tests/live/server_auto_manual.py`).

qBittorrent 5.3.0 was measured on 2026-10-31 through the real server: the
rotate mint replaced the key, qui's instance row was written over its API, and
qui's own connection test proved the value the holder stores. The old key
answered 403 and the new one 200. The audit learned the same exercise proof, so
a qui-held credential reaches `live` and the auto gate can pass
(`tests/live/server_auto_qbittorrent.py`).

The qBittorrent WebUI password is a separate credential in some external
manifests. It is not in the wizard and no API write is measured for it, so it
stays manual/`[T]` until a disposable measurement proves the write and the
download-client readback.

The wizard no longer offers these targets: Prowlarr's own indexers and
download clients (they do not hold Prowlarr's key), and Lidarr/Readarr/Whisparr
download clients for qBittorrent's API key (those builds expose username and
password only). The engine keeps the generic targets for compatibility; the
wizard's exclusion set is explicit and tested.

## Awesome-arr candidates

| Service | What it holds | Gate 1 answer | Verdict |
| --- | --- | --- | --- |
| Ombi | Sonarr/Radarr keys in its settings | settings API exists, but the write/read-back and old-key death are unmeasured | `[T]`, research |
| Huntarr | Sonarr/Radarr keys in its configuration | no measured write route | `[T]`, research |
| Cleanuparr | Sonarr/Radarr keys in its configuration | no measured write route | `[T]`, research |
| Tautulli | Plex token; its own API key in `config.ini` | Plex token is account-scoped; no own-key write route found yet | `[T]`, likely manual |
| Recyclarr | *arr keys in YAML configuration | no API; a rotation is a config edit and a rerun | manual by design |
| Plex | account-scoped token | no server route creates or revokes the token; a monitor-only inscription is forbidden by decision 21 | refusal `[V]` |
| Jackett | its own API key in `ServerConfig.json`; *arr indexer rows hold it | the config API never touches the API key, so no write path exists | refusal `[V]` |

## Priority order

1. **P0, done:** every wizard `exercised` claim matches the engine; the
   Lidarr/Readarr/Whisparr indexer routes are measured; SABnzbd and Bazarr own
   keys rotate through the server auto path; invalid wizard targets are gone.
2. **P1, done:** every wizard mint has a server auto run. The five Servarr
   apps share one parameterized fixture; Jellyfin, qBittorrent, Seerr, Grafana,
   Arcane and Gitea each have their own harness.
3. **P2:** Ombi, Huntarr and Cleanuparr as settings holders. Each needs the
   same three measurements: where the key is exposed, what writes it, and what
   proves the running process uses it.
4. **Never invent:** Plex, Jackett, Tautulli's Plex token and Recyclarr's
   config-only copies. They are manual or refusals until a real write route is
   measured.


## Out of scope here

The production credential manifest in `../homelab-applications` still uses the
retired path/sqlite schema and does not parse on 1.0. Migrating it is a separate
topology change; this page records product capability, not that deployment's
current declarations.
