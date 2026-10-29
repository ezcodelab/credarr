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

## Publishing

Both remotes hold the same history: one root commit with the product tree.
`make publish` pushes `main` to Gitea and GitHub, and `make release VERSION=x.y.z`
builds and pushes the image first, then the code and the release tag.

```sh
make publish
make release VERSION=1.2.3
```

The internal working files (agent instructions, decision log, lessons, the live
harness) are not in the repository and never enter it. They are ignored locally
through `.git/info/exclude`, so no tracked file names them. Do not add them back:
they were committed for months before the history was collapsed, and the reason
the history is one commit is that those months cannot be published.
