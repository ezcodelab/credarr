# Testing

What the suite does today, where it is weak, and the rules for new tests.
The numbers here are from the 2026-10-28 tree; re-measure when they move.

## Current shape

| Layer | Tool | Size | Runtime |
| --- | --- | --- | --- |
| Engine + server unit tests | pytest, fake transport, some real HTTP fixtures | 945 passed, 2 skipped | ~3.5 min |
| Property tests | hypothesis (inside the above) | 7 | ~1 s |
| Console unit tests | `node --test` | 104 | ~3 s |
| Console end-to-end | Playwright + Chromium against a real server | 207 checks | ~2 min |
| Container black box | pytest `-m integration`, testcontainers | 4 | ~9 s + image start |

`make check` runs the first, second (same invocation) and third layers. The UI
smoke is `make ui-smoke`; the container suite is excluded from the default run
and has its own command below.

## How the eight rules currently stand

| Rule | State | Evidence |
| --- | --- | --- |
| **Avoid mocks** | Mostly fakes already. | `tests/conftest.py` serves real `ThreadingHTTPServer` handlers; `FakeTransport` answers HTTP-shaped calls and exercises the real call path up to the transport seam. `monkeypatch` is used for terminals (`builtins.input`), env vars and a few module seams. |
| **Use Testcontainers for integration** | Was missing. | Added: `tests/integration/test_container.py` boots the built image, asserts health/console/favicon and first-run setup over HTTP, that a written service survives a restart, and that `/config` and `app.db` are owned by the configured PUID (1234, not the host's). |
| **Don't couple to code structure** | Mixed. | White-box imports exist: `_configured_timezone` (`tests/server/test_app.py`), `_image_system`/`_port` (`tests/server/test_discovery.py`), `facade.read_manifest` patched (`tests/test_exit_contract.py`). New tests go through public entry points. |
| **Reproduce a bug in a failing test first** | Practised, not enforced. | Process lessons record it; nothing mechanically checks that a fix arrives with a regression test. |
| **Keep logic out of tests** | Mostly true. | A few tests build plans/statuses inline instead of using a fixture, which duplicates engine logic (`tests/test_exit_contract.py` builds a bare `RotationPlan`). |
| **Mutation and property-based tests** | Was missing. | Added: `tests/test_properties.py` covers parser round-trips, plan ordering and redaction invariants under generated input. |
| **Playwright for real user flows** | Present, one flow file. | `ui/tests/smoke.mjs` drives the built console end to end. Playwright MCP is **not available** in this harness; the committed Playwright + Chromium suite is the substitute and is the rule to follow. |
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

## Continuous integration

`.gitea/workflows/ci.yaml` runs on Gitea Actions. It does **not** use
`actions/setup-python` or `actions/setup-node`: on this runner those can only
install from the local tool cache, so a version that is not baked into the image
fails with "Version 3.12 was not found in the local cache". CI uses the runner's
`python3` in a venv, and installs Node 24 into `/opt/node24` from nodejs.org
with its published SHA256 checksum. Extracting over an existing `/usr/local`
leaves a mixed npm tree that fails as `Class extends value undefined`.

| Job | Runs | When |
| --- | --- | --- |
| `check` | lint + the full engine/server suite, `-n auto` | push to `main` |
| `pull-request` | lint + only the tests that cover the diff (`scripts/affected-tests`) | pull request |
| `console` | `npm ci` and the console unit tests | push, PR |
| `container` | `make image`, then `pytest -m integration`; prints SKIP without Docker | push, PR |
| `smoke` | `make ui-smoke` in Chromium | manual (`workflow_dispatch`) only |

The browser smoke is manual because it is the one job this runner cannot do
comfortably: 20+ minutes, and the plan preflight outlasts a 90s wait. It is off
the push gate so a red run means a real defect, not a slow machine.

Caches (`pip`, `npm`, the Playwright browser) are declared with
`continue-on-error`, so a runner without a cache server skips them instead of
failing the build. The engine suite runs across cores: 27s locally against 210s
serial, and the earlier parallel failures were wall-clock assumptions in tests
(now deadline-based).

The venv itself is cached, keyed on `pyproject.toml`, and validated with an
import before use. Pip's HTTP cache restored 32 MB and the install still took
8 minutes: the cost is installing, not downloading. A restored venv whose
editable path no longer resolves falls back to a full install.

Measured on this runner for a green push to `main` (2026-10-28), same commit
tree:

| Run | `check` | `console` |
| --- | --- | --- |
| before (serial, cold caches) | ~28 min | ~7 min |
| cold venv cache | 9.3 min | 7.5 min |
| warm venv cache | **2.5 min** | **0.4 min** |

The suite itself is ~2.5 min across cores; everything above that is installing.

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

`main` still runs everything, so a partial run is a review convenience, never the
only gate.

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
