# credarr builds its own virtualenv, inside the repository.
#
# The venv lives here rather than in a cache directory so that a sibling repo
# can invoke it by an obvious path - homelab-infrastructure's `make drift` calls
# ../credarr/.venv/bin/credarr, and an operator who has cloned credarr anywhere
# should not have to know how this particular machine caches things.

VENV := .venv
BIN  := $(VENV)/bin
PORT ?= 8080

.PHONY: help install test ui-test lint check ci worktree-setup serve ui-dev web ui-smoke wheel image snapshot publish release clean

GHCR := ghcr.io/ezcodelab/credarr

help:  ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-8s\033[0m %s\n", $$1, $$2}'

install: $(BIN)/credarr  ## Create the venv and install credarr into it

$(BIN)/credarr:
	python3 -m venv $(VENV)
	$(BIN)/pip install --quiet --upgrade pip
	$(BIN)/pip install --quiet -e ".[dev]"
	@touch $@

test:  ## Run the test suite
	@if [ ! -x $(BIN)/pytest ]; then $(MAKE) install; fi
	cd . && PYTHONDONTWRITEBYTECODE=1 $(BIN)/pytest -q -p no:cacheprovider

ui-test:  ## Run the console's unit tests (Node only)
	@[ -d ui/node_modules ] || (cd ui && npm ci)
	cd ui && npm test

lint:  ## Lint
	@if [ ! -x $(BIN)/ruff ]; then $(MAKE) install; fi
	$(BIN)/ruff check .

check: lint test ui-test  ## Local release gate: lint, Python tests, UI unit tests

ci: check  ## Alias for check

worktree-setup:  ## OpenCode runs this after creating a workspace: branch + deps
	@if ! git symbolic-ref -q HEAD >/dev/null; then \
		branch="feature/$$(basename "$$PWD" | sed 's/^credarr-//')"; \
		if git show-ref --quiet "refs/heads/$$branch"; then git checkout "$$branch"; \
		else git checkout -b "$$branch"; fi; \
	fi
	$(MAKE) install
	@main=$$(dirname "$$(git rev-parse --git-common-dir)"); \
	if [ -f "$$main/credarr.yaml" ] && [ ! -f credarr.yaml ]; then cp "$$main/credarr.yaml" credarr.yaml; fi
	@[ -d ui/node_modules ] || (cd ui && npm ci)

serve: $(BIN)/credarr  ## Run the BFF in this worktree (PORT=8081 for a second agent)
	@mkdir -p state
	$(BIN)/credarr-server -c credarr.yaml --config-dir state --port $(PORT)

ui-dev:  ## Run the Vite dev server against this worktree's PORT
	@[ -d ui/node_modules ] || (cd ui && npm ci)
	cd ui && CREDARR_API=http://127.0.0.1:$(PORT) npm run dev

web:  ## Build the SPA into the package (Node 24+; first run needs the network)
	cd ui && npm ci
	cd ui && npm run build
	rm -rf src/credarr_server/web
	cp -r ui/dist src/credarr_server/web

ui-smoke: web  ## Drive the built console in a real browser (needs `npx playwright install chromium` once)
	cd ui && npm test
	cd ui && npm run smoke

wheel: web  ## Build the wheel with the console inside (the image's input)
	@if [ ! -x $(BIN)/pip ]; then $(MAKE) install; fi
	# build_py merges into build/lib and never prunes it; a UI rebuild changes
	# the asset names, so a stale tree would ship both bundles.
	rm -rf build
	$(BIN)/pip wheel . -w dist --no-deps

image:  ## Build the one image (needs Docker; the console is built inside it)
	docker build -t credarr:dev .

snapshot:  ## Build the public snapshot branch (one commit, no push)
	@if [ -n "$$(git status --porcelain)" ]; then echo "refusing: commit or stash first"; git status --short; exit 1; fi
	@git branch -D public-snapshot >/dev/null 2>&1 || true
	@git checkout -q --orphan public-snapshot
	@git rm -rq --cached .
	@git add -A
	@git rm -rqf .gitea
	@m=$$(mktemp); t=$$(mktemp); \
	git ls-tree -r --name-only main | sort > $$m; \
	git ls-files | sort > $$t; \
	if comm -13 $$m $$t | grep -q .; then \
		echo "REFUSED: the snapshot carries files main does not track:"; \
		comm -13 $$m $$t; rm -f $$m $$t; \
		git checkout -q main; git branch -D public-snapshot >/dev/null 2>&1 || true; exit 1; \
	fi; rm -f $$m $$t
	@git commit -q -m "credarr $$(date +%F)"
	@echo "snapshot $$(git rev-parse --short HEAD): $$(git ls-files | wc -l | tr -d ' ') files, no .gitea"

publish:  ## Push the code snapshot to GitHub (TAG=v1.2.3 tags it too)
	@if [ "$$(git rev-parse --abbrev-ref HEAD)" != "public-snapshot" ]; then $(MAKE) snapshot; fi
	@git fetch -q github
	@git push --force-with-lease github HEAD:refs/heads/main
	@if [ -n "$(TAG)" ]; then git push --force-with-lease github HEAD:refs/tags/$(TAG); fi
	@git checkout -q main
	@git branch -D public-snapshot >/dev/null 2>&1 || true
	@echo "published to github: main$(if $(TAG), and $(TAG))"

release:  ## Build and push the image, then publish the code (VERSION=x.y.z)
	@if [ -z "$(VERSION)" ]; then echo "usage: make release VERSION=1.2.3"; exit 2; fi
	$(MAKE) image
	docker tag credarr:dev $(GHCR):$(VERSION)
	docker tag credarr:dev $(GHCR):latest
	docker push $(GHCR):$(VERSION)
	docker push $(GHCR):latest
	$(MAKE) publish TAG=v$(VERSION)
	@echo "released $(VERSION): $(GHCR):$(VERSION) and :latest"

clean:  ## Remove build and cache artefacts
	rm -rf .pytest_cache .ruff_cache build dist src/*.egg-info src/credarr_server/web ui/dist ui/test-results
	@find . -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
