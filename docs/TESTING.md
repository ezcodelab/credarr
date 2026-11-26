# Testing

What the suite does today, where it is weak, and the rules for new tests.
The numbers here are from the 2026-11-25 tree; re-measure when they move.

## Current shape

| Layer | Tool | Size | Runtime |
| --- | --- | --- | --- |
| Engine + server unit tests | pytest, fake transport, some real HTTP fixtures | 1124 passed, 2 skipped (Python 3.12) | 30 s locally, 79 s on a CI runner, `-n auto` |
| Property tests | hypothesis (inside the above) | 7 | ~1 s |
| Console unit tests | `node --test` | 120 | ~3 s |
| Console end-to-end | Playwright + Chromium + `@axe-core/playwright` against a real server | 237 checks | ~70 s |
| Container black box | pytest `-m integration`, testcontainers | 5 | ~12 s + image start |

`make check` runs the first, second (same invocation) and third layers. The UI
smoke is `make ui-smoke`; the container suite is excluded from the default run
and has its own command below.

## How the eight rules currently stand

| Rule | State | Evidence |
| --- | --- | --- |
| **Avoid mocks** | Mostly fakes already. | `tests/conftest.py` serves real `ThreadingHTTPServer` handlers; `FakeTransport` answers HTTP-shaped calls and exercises the real call path up to the transport seam. `monkeypatch` is used for terminals (`builtins.input`), env vars and a few module seams. |
| **Use Testcontainers for integration** | Was missing. | Added: `tests/integration/test_container.py` boots the built console image, asserts health/console/favicon and first-run setup over HTTP, that a written service survives a restart, and that `/config` and `app.db` are owned by the configured PUID (1234, not the host's). A separate case proves the agent image has the Docker CLI and compose plugin and the console image has neither. |
| **Don't couple to code structure** | Mixed. | White-box imports exist: `_configured_timezone` (`tests/server/test_app.py`), `_image_system`/`_port` (`tests/server/test_discovery.py`), `facade.read_manifest` patched (`tests/test_exit_contract.py`). New tests go through public entry points. |
| **Reproduce a bug in a failing test first** | Practised, not enforced. | Process lessons record it; nothing mechanically checks that a fix arrives with a regression test. |
| **Keep logic out of tests** | Mostly true. | A few tests build plans/statuses inline instead of using a fixture, which duplicates engine logic (`tests/test_exit_contract.py` builds a bare `RotationPlan`). |
| **Mutation and property-based tests** | Was missing. | Added: `tests/test_properties.py` covers parser round-trips, plan ordering and redaction invariants under generated input. |
| **Playwright for real user flows** | Present, one flow file. | `ui/tests/smoke.mjs` drives the built console end to end and runs `@axe-core/playwright` WCAG A/AA scans on setup, empty/populated Apps, Activity, App detail, Settings, login and the 390px Apps layout. Serious or critical violations fail the smoke. Playwright MCP is **not available** in this harness; the committed Playwright + Chromium suite is the substitute and is the rule to follow. |
| **Assert from the user's point of view** | True at the UI layer, less so in Python. | The smoke asserts visible sentences and states; engine tests assert returned objects. Prefer the public API (`create_app`, `facade`, CLI exit codes) over internals when either would catch the bug. |

## Ranked gaps

1. **No container-level proof for the shipped artifact.** A wheel can import
   in a venv and still fail as an image (missing package data, wrong entrypoint,
   `/config` ownership). Kept by the integration suite, do not remove it.
2. **No property tests for the strict parsers.** Manifest/config parsing is
   the "a typo must not skip" boundary; examples cover what someone thought of.
   Covered now by `tests/test_properties.py`.
3. **Structural coupling in older white-box tests.** They are stable and cheap;
   rewriting all of them is not worth the churn. New tests target public
   behaviour, and a white-box test that breaks on a rename should be replaced,
   not repaired, when it is touched anyway.
4. **Bug regressions are not traceable.** Prefer a test name that states the
   behaviour ("a parked candidate is not a resume"), not the ticket id.
5. **Mutation testing is not wired.** `mutmut`/`cosmic-ray` on the engine would
   find unasserted branches in `rotate.py`/`executor.py`. Not adopted: the
   runtime cost is large and the engine's public surface is already pinned by
   exit-code and report tests.

## Commands

```sh
make test                  # engine + server suite (fake service APIs)
make ui-test               # console unit tests
make check                 # lint + Python + console units
make ui-smoke              # build, then drive the console in Chromium
pytest -m integration      # container black box; needs Docker (skips without)
pytest tests/test_properties.py -q   # property tests
pytest -o addopts="" -m "not integration" -q   # explicit counts (the default addopts hide them)
```

## Live holder fixtures

The `tests/live/` scripts are manual, disposable-container harnesses. They are
not part of `make check`, and they never point at the production stack. Run
them from the repository root with the source and live directories on the
path:

```sh
PYTHONPATH="$PWD/src:$PWD/tests/live" .venv/bin/python tests/live/<script>.py
```

Measured additions (2026-10-30 and 2026-10-31):

| Script | Question | Result |
| --- | --- | --- |
| `servarr_indexer_test.py` | Does `indexer/test` exercise the stored key on Lidarr, Readarr and Whisparr? | Lidarr 3.1.0.4875, Readarr 0.4.19.2811, Whisparr 2.2.0.231: 2xx live, non-2xx with a rejected upstream key, 2xx after restore |
| `bazarr_settings.py` | Does Bazarr's form settings API reach the running process, and does its own key change immediately? | Bazarr 1.6.2: write 204, Sonarr/Radarr keys read back from the process, old Bazarr key 401 after `settings-auth-apikey` with no restart |
| `sabnzbd_key.py` | Does SABnzbd's set_apikey/restart sequence settle on the new key, and does Sonarr's SABnzbd row test follow it? | SABnzbd 5.1.3: reset returns a key, restart makes old 403/new 200, `downloadclient/test` accepts new and rejects old |
| `server_auto_sabnzbd.py` | Does the real server auto-rotate a SABnzbd key with a Sonarr holder? | `auto_succeeded`; Sonarr row holds the new key; old 403/new 200 |
| `server_auto_bazarr.py` | Does the real server auto-rotate Bazarr's own key with a deploy-time Homepage copy? | `auto_manual`; old 401/new 200; policy stays enabled |
| `server_auto_servarr.py` | Do Radarr, Lidarr, Readarr and Whisparr auto-rotate with Prowlarr's application row as the holder, and Prowlarr with a Sonarr indexer row? | all five `auto_succeeded`; old 401/new 200; the holder row holds the new key |
| `server_auto_jellyfin.py` | Does the real server auto-rotate Jellyfin's reissued key with Seerr's `jellyfin` section as the holder? | `auto_succeeded`; Seerr reports the new key; old 401/new 200 |
| `agent_flow.py` | Does the real mTLS control plane enroll the shipped agent client, lease a job, verify the shared-tree generation, and deliver a disposable compose service? | `delivered`; one service true; the stack is removed with a unique project name |
| `server_auto_qbittorrent.py` | Does the real server auto-rotate qBittorrent's key with qui's instance test as the holder? | `auto_succeeded`; qui test green; old 403/new 200 |
| `server_auto_manual.py` | Do Seerr, Grafana, Arcane and Gitea mint with only a deploy-time Homepage copy and record `auto_manual`? | all four `auto_manual`; old key refused, new key accepted, policy enabled |

The Torznab stand-in gained music, book and adult caps/items so the three
library managers can validate their own category families; the extra items are
inert for Sonarr and Radarr.

## Continuous integration

`.github/workflows/ci.yml` runs on GitHub Actions; it is the only CI that gates
a merge (the Gitea remote is a read-only mirror). `check`, `container` and
`smoke` are branch-protection contexts: `tests/packaging/test_ci_contract.py`
fails if a required job is renamed, waits on another required job, or is
skipped when the gate fails.

| Job | Runs | When |
| --- | --- | --- |
| `gate` | `make lint`, `make ui-audit`, `make ui-check ui-test` | every run |
| `check` | `scripts/affected-tests` on a PR, the full suite on `main`/nightly | after `gate` |
| `container` | `make image`, then `pytest -m integration` | after `gate`; skipped only for docs/CI/changelog diffs |
| `smoke` | `make ui-smoke` in Chromium | after `gate`; skipped only for docs/CI/tests/changelog diffs |

The gate is seconds and the other three run in parallel, so a pull request
waits for the slowest job, not the sum. The gate is not itself a required
context, so a gate failure fails the required jobs through an explicit guard:
a skipped required check counts as passing.

Tiering: a PR runs the gate, the tests that cover its diff, and an artifact job
only when that job's inputs changed. A push to `main` and the 05:00 schedule run
the full suite, the image and the browser. The auto-merge token's own merge
push does not start a run, so the nightly is what re-tests the merged tree;
`gh workflow run ci.yml --ref main` is the on-demand form. Concurrency cancels a
superseded PR run and lets a `main` push finish.

Measured 2026-11-25 on GitHub-hosted runners, before and after the restructure:

| Measure | Before | After |
| --- | --- | --- |
| PR wall clock, created → green | 222–278 s, median **247 s** (10 runs) | **132 s** full path, **145 s** console-only, **36 s** docs-only |
| queue, created → first job | ~2 s | ~2 s |
| `check` | 110–138 s | 10–90 s (the selection decides) |
| `container` | 55–73 s | 48–51 s |
| `smoke` | 97–162 s | 106–123 s |
| a failing lint | the required checks turned red after the suite finished | **23 s**, all three required checks red |
| Python install | 15 s with pip | 1–2 s with uv from its cache |
| console install | `npm ci` twice in the smoke job (18 s step) | once (11–26 s step, apt for the browser included) |

The critical path is the gate plus the slowest artifact job. The browser smoke
is 70–75 s of checks and sets the floor for any diff that reaches the console,
so it dominates a console pull request.

The browser smoke runs on pull requests; it is no longer manual-only, and it no
longer waits for the Python suite. It is skipped only for paths the built
console and the server cannot observe (`docs/`, `.github/`, `tests/`,
`ui-system/`, the changelog); any other path runs it, so an unlisted change
widens the run instead of skipping it.

Caches are keyed on the file that pins the dependency. The uv cache (29 MB) and
the npm cache hit on every run; the Playwright browser is keyed on
`ui/package-lock.json`, which pins the browser revision. The venv is built per
job with `uv venv --seed`, which keeps `pip` available for the packaging test
that shells out to `python -m pip wheel`. A dependency bump changes the key and
installs once; a restored stale tree is never reused.

The engine suite runs across cores (`-n auto`): 30 s locally against 136 s at
`-n 2`, and the earlier parallel failures were wall-clock assumptions in tests
(now deadline-based). That is also why the suite is not sharded across runners:
two runners at two workers each are slower than one at four.

### Only the tests that cover a change

`scripts/affected-tests` maps a diff to test paths. It is deliberately
conservative: a shared seam (`tests/conftest.py`, `pyproject.toml`, the
transport, the journal, the parser, the target registry) or an unmapped path
selects the **whole** suite. A gap widens the run; it never skips it.

```sh
scripts/affected-tests --base origin/main   # PR: prints paths, "all", or "none"
scripts/affected-tests --range HEAD^..HEAD  # a pushed commit
scripts/affected-tests --all                # force the full suite
pytest -n auto                              # the same suite, across cores
```

`main` runs everything on a push and on the nightly, so a partial run is a
review convenience; the merged tree is fully tested at the next scheduled run.

## Rules for new tests

- Prefer a fake service over a mock: a real HTTP handler, or the injectable
  transport, so the assertion is about behaviour rather than a call signature.
- Assert what the user sees or the API returns: an exit code, a status, a
  rendered sentence, a stored row. Do not assert that a private helper was
  called.
- One behaviour per test, named as the behaviour. If the name needs "and",
  split it.
- Fixtures build state; tests assert. If a test builds a plan or a manifest
  inline, move it to a fixture.
- A bug fix starts with the failing test that states the wrong behaviour, then
  the fix. Keep the test even if the root cause moves.
- New service support is measured, not mocked: see `ADDING_A_SERVICE.md`.
