# Contributing

## Toolchain

- Python 3.11+ (`make install` creates `./.venv`), Node 24+ for the console.
- `make test`, `make lint`, `make ui-test`. `make check` runs all three; run it
  before every commit. The other targets are documented in the Makefile; `make
  help` lists them.

## Conventions

- Commit messages use an area prefix: `backend:`, `docs:`, `release:`.
- Smallest correct change. Match existing style and patterns.
- Never commit a real config (`credarr.yaml` is gitignored), a secret, or a
  value-bearing fixture. Synthetic keys only, generated per run.
- A new service needs a live measurement before any "managed" claim. Source
  reading alone never earns it. The lifecycle checklist lives in
  `ADDING_A_SERVICE.md`.
- Keep `docs/` truthful with the code in the same change. The engine and the
  server are authoritative over prose.
- UI changes use `docs/UI_SYSTEM.md` and the dev gallery (`cd ui && npm run dev`,
  then `/?design`). Run `make ui-audit` and keep the contract, system and
  gallery current. A new primitive or pattern updates all three in the same
  change; do not add a second visual language.

## Publishing

GitHub is canonical; Gitea is a read-only pull mirror. `origin` is GitHub and
`gitea` is the read-only mirror. Run `git config core.hooksPath .githooks` once
per clone; the pre-push hook rejects the mirror. `make publish` pushes `main` to
GitHub, and `make release VERSION=x.y.z` builds and pushes the console and agent
images first, then the code and the release tag.

```sh
make publish
make release VERSION=1.2.3
```

The internal working files (agent instructions, decision log, lessons, the live
harness) are not in the repository and never enter it. They are ignored locally
through `.git/info/exclude`, so no tracked file names them. Do not add them back:
they were committed for months before the history was collapsed, and the reason
the history is one commit is that those months cannot be published.

## Merge gate

GitHub is canonical. The gate runs from `main` through `pull_request_target`, so
the workflow comes from the trusted base. The verify job is read-only and checks
the base plus the pull request merge ref. The merge job waits for CI on the
verified head, then merges that exact head. Branch protection requires
`auto-merge / verify` and the PR CI checks. Fork pull requests are supported.

Gitea pulls `main` and tags read-only. It does not accept pull requests and never
pushes back.

A ready pull request with green required checks and an independent review
auto-merges through the GitHub Actions gate. No path is protected; workflow,
Makefile, policy, and deploy-script changes auto-merge after review and
verification. A reviewed, green PR is never left open for the operator.
