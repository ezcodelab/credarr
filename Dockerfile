# syntax=docker/dockerfile:1

# One image, one version, two halves: the console is built where Node lives,
# then the Python wheel - with the console inside it as package data - is built
# and installed where Python lives. The runtime carries neither Node nor a
# source tree, only the installed artifact.

FROM node:24-bookworm-slim AS web
WORKDIR /ui
# The lockfile is the point of `npm ci`: the console the image ships is the one
# the repository pins.
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

FROM python:3.12-slim-bookworm AS wheel
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
# The SPA is package data *before* the wheel is built, so the image ships the
# same artifact `make wheel` produces.
COPY --from=web /ui/dist ./src/credarr_server/web
RUN pip wheel --no-deps --wheel-dir /wheels .

FROM python:3.12-slim-bookworm AS app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CREDARR_CONFIG_DIR=/config \
    HOME=/home/credarr \
    TZ=Etc/UTC

# gosu drops privileges after the entrypoint has aligned the app user with
# PUID/PGID. The image needs no remote-shell client and no Docker socket: the
# app reads local files and asks each service to restart itself over its own
# API. tzdata makes the operator's TZ mean what they expect.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gosu tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 credarr \
    && useradd --uid 1000 --gid 1000 --create-home \
        --shell /usr/sbin/nologin credarr

COPY --from=wheel /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
COPY docker/entrypoint.sh /usr/local/bin/credarr-entrypoint
RUN chmod 0755 /usr/local/bin/credarr-entrypoint

# The app's own state: app.db, credarr.yaml and whatever the operator keeps
# beside them. It must be a local filesystem (DECISIONS decision 8); the app
# refuses a network mount at startup and names the mount in its message.
VOLUME ["/config"]
EXPOSE 8080

# Degraded is unhealthy, on purpose: a process whose audit or delivery loop died
# still answers requests, and every answer is then the past.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/api/v1/health' % os.environ.get('CREDARR_PORT', '8080'), timeout=4)"

ENTRYPOINT ["/usr/local/bin/credarr-entrypoint"]
CMD ["credarr-server", "--config", "/config/credarr.yaml"]
