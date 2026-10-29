# Adding a service

How new service support is added to Credarr, and what "managed" means. A
service joins `SERVICES.md` only with a measured writer or mint. Source
reading alone never earns it.

## The lifecycle questions

Before any mint, writer, or auto-rotation path is built for an issuer, answer
these for that service. Copy the block per service into the proposal. The
accepted result lands in `SERVICES.md` as the service's row.

```
Service: …
Version pinned: …                    # image digest or reported version
How is a NEW secret created?        chosen / generated / none
How does credarr LEARN it?          response body / config API / restore / impossible
Does learning need a UI session,
a UI password, or an auth change?    yes / no, and name it
What happens to the OLD secret,
and when?                           dead at mint / revocable last / never
Auto-rotation possible under the
standing rules?                     yes / no
If no: allowed fallback             manual paste / reconstruct+restore / deploy-time / upstream ask
Evidence                            docs URL + source pointer + live probe
```

Evidence is tagged where it matters: verified by live measurement, assumed
but not yet measured, or still to verify by live test. Only a live
measurement on a disposable container with synthetic keys moves a claim out
of "to verify".

## Acceptance

**Shipped.** A learn path exists with API-only reads, no UI password by
default, no auth weakening, and a stated old-key death. Or the operator chose
an explicit fallback and the class says so (see `CONCEPTS.md`).

**Monitor-only.** No way to learn the new secret under the standing rules.
The service is recorded as monitor-only or manual, and no writer, UI
field, or auto-rotation support is built for it.

Two rules came from measurement, not theory:

- A chosen-value write that the service ignores is a measured dead end, not
  a mint. It is recorded and not retried.
- `403` is not revocation unless the service's row says so. Only an answered
  `401` proves the old key dead.

## Worked example: Servarr reconstructed restore

The Servarr API constraint is real: after a key change the new key is only
readable from the backup download or the service UI, both behind the UI
login. The rebuilt-config restore avoids the read entirely:

```
Service: sonarr, radarr, prowlarr, lidarr, readarr, whisparr
Version pinned: Sonarr 4.0.20.3014, Radarr 6.4.4.10685,
                Prowlarr 2.6.5.5623, Lidarr 3.1.0.4875,
                Readarr 0.4.19.2811, Whisparr 2.2.0.231
How is a NEW secret created?        chosen by credarr (32 hex)
How does credarr LEARN it?          it chooses the value; the restore upload
                                    installs it; no read-back of config.xml
Does learning need a UI session,
a UI password, or an auth change?   no
What happens to the OLD secret,
and when?                           dead at the restart after the restored
                                    config lands
Auto-rotation possible under the
standing rules?                     yes, when /system/status reports a
                                    non-PostgreSQL databaseType and the critical
                                    host fields are exposed; opt-in
If no: allowed fallback             write.ui_password (same backup/restore mint),
                                    write.manual_mint (no restore write)
Evidence                            live-measured on all six pinned builds:
                                    databaseType=sqlite, plan chose the
                                    reconstructed path, apply exited 0, old key
                                    401 / new key 200, Forms login and URL
                                    base/port preserved. SSL preserved over
                                    HTTPS on Sonarr. PostgreSQL refused with
                                    the key untouched. Holder propagation,
                                    live auto-rotation, and a SIGKILL resume
                                    during restore/restart all converged
                                    without a second mint.
```

## Checklist for a new service

1. Where does the service expose the key? Settings row, database-backed API
   field, encoded blob: read it through the service's API, never a file.
2. What actually writes it? Measure, don't assume. Silent no-op writes are
   the classic trap.
3. What proves the *running process* uses the new value? A process read-back
   on its own API, or a measured test route that exercises the stored value.

See `CONTRIBUTING.md` for the toolchain and `SERVICES.md` for the current
coverage table.
