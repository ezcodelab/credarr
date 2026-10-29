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

## Publishing to GitHub

The public repository is a single-commit snapshot, not this history. The
internal working files must never ship in it: they were committed here for
months before they were untracked, so pushing this history would publish them
in old commits. The Gitea-only CI in `.gitea/` stays out for the same reason;
`.github/` is the public twin.

One command for code only:

```sh
make publish                 # snapshot + push main
make publish TAG=v1.0.1      # same, and tag the release
```

One command for code and a new image:

```sh
make release VERSION=1.0.1   # build, push ghcr :1.0.1 and :latest, publish
```

Both need a `github` remote and credentials already working, for example
`docker login ghcr.io` once for the image and a PAT with `repo` and `workflow`
scopes for the push.

What `make snapshot` does, and why it is the mechanism rather than a
convenience:

```sh
git checkout --orphan public-snapshot
git rm -r --cached .            # re-add only what is not ignored locally
git add -A
git rm -r --cached .gitea       # Gitea-only CI
git commit -m "credarr <date>"
```

It then refuses to continue if the snapshot holds any file that `main` does
not track, which is how an internal file would appear. Confirm from the
outside after pushing: a fresh clone must show `git rev-list --count HEAD` of
1, and `gitleaks detect` must be clean. Public `main` is a generated artifact,
so each publish replaces it.
