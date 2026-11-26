"""The BFF: one HTTP surface over the engine, for one admin.

The engine does the work; this module wires it into a process. It builds the
topology store, the audit log and the scheduler over one `app.db` under the
config directory, serves them under `/api/v1`, and keeps the audit loop alive.
Every endpoint calls the same library the command line calls, so the CLI and
the API cannot plan or audit differently; the OpenAPI document is the contract
and `tests/server/test_app.py` pins it.

BFF discipline (DECISIONS standing rule 2): a service secret never reaches a
payload. The only credential a browser sees is the app's own API key, and only
in the response that creates it.
"""

from __future__ import annotations

import argparse
import contextlib
import math
import os
import sqlite3
import ssl
import sys
import threading
import urllib.parse
import zoneinfo
from collections.abc import Awaitable, Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from credarr import __version__, facade, report
from credarr.config import Config, load_config
from credarr.errors import ConfigError, CredctlError, ExitCode
from credarr.instance import DEFAULT_CONFIG_DIR, InstanceLock
from credarr.redact import disable_core_dumps
from credarr.targets import build_registry
from credarr_server import auto_rotation, mounts
from credarr_server.agent_control import AgentControlPlane
from credarr_server.api import mount_api
from credarr_server.api.context import ApiContext
from credarr_server.api.http import _validation_details
from credarr_server.api.services import _seed_services
from credarr_server.audit_jobs import AuditJobs
from credarr_server.audit_log import AuditLog
from credarr_server.auth import AdminAuth
from credarr_server.notifier import DeliveryLoop, Notifier
from credarr_server.scheduler import (
    MAX_AUDIT_INTERVAL_SECONDS,
    MIN_AUDIT_INTERVAL_SECONDS,
    Scheduler,
)
from credarr_server.store import TopologyStore
from credarr_server.sync_store import SyncLoop, SyncStore
from credarr_server.vault import KekUnavailable, VaultError, VaultMaintenanceLoop, VaultTree

# The console binds every interface on purpose: it exists to be reached over
# the LAN, and the container publishes a single port. `--host` narrows it.
DEFAULT_HOST = "0.0.0.0"  # noqa: S104


@dataclass(frozen=True, slots=True)
class ServerSettings:
    """How the process boots: the engine config, the data directory, the socket.

    The command line and the environment fill this in; tests build it directly.
    `config_path` is the same `credarr.yaml` the CLI reads - hosts and paths are
    one deployment's facts, and the app must audit where the CLI audits.
    """

    config_path: Path
    config_dir: Path
    host: str = DEFAULT_HOST
    port: int = 8080
    audit_interval: float = 3600.0
    secure_cookies: bool = False
    # Decision 8: a local filesystem is the assumption SQLite's locks and WAL
    # rest on. This is the documented way to accept a network mount anyway.
    allow_network_config: bool = False
    # Optional, read-only Docker API used by the discovery endpoint. None is
    # the default posture: no socket, no scan.
    docker_url: str | None = None
    # The shared, encrypted delivery tree the agent reads. Off unless the
    # operator mounts one; a target cannot be created without it because there
    # would be no value source an agent could use.
    vault_tree: Path | None = None
    vault_tree_key: Path | None = None
    # The agent control plane. Zero disables the listener; a negative or
    # out-of-range value is a configuration error at parse time.
    agent_port: int = 0
    agent_bind: str | None = None
    # The DNS name or IP an agent will put in its --server URL. It is added to
    # the listener certificate's SAN list; without it a remote agent cannot
    # verify the self-signed listener.
    agent_hostname: str | None = None
    # Extra names agents use to reach the listener, beyond agent_hostname and
    # localhost. A compose service DNS name belongs here.
    agent_sans: tuple[str, ...] = ()
    # Optional CA material. Without these, Credarr creates agent-ca.crt/key in
    # the config directory on first start and signs the listener certificate.
    # With them, Credarr uses that CA and still signs the listener certificate.
    agent_ca_cert: Path | None = None
    agent_ca_key: Path | None = None
    # The zone the console renders timestamps in. It comes from TZ, the same
    # variable the container uses for its clock; an invalid value falls back to
    # UTC rather than letting Intl throw in the browser.
    timezone: str = "UTC"
    # The built SPA, inside the package: `make web` puts it there and the
    # image's node stage does the same (DECISIONS: one image, one version).
    web_dir: Path = field(default_factory=lambda: Path(__file__).parent / "web")

    @property
    def database(self) -> Path:
        """One database: topology, working copies, audit history, admin."""
        return self.config_dir / "app.db"


class AuditLoop:
    """The scheduler thread, and the failure that ends it.

    `Scheduler.serve` deliberately ends when a run cannot be recorded: a loop
    that cannot write to the ledger is a dashboard quietly going stale. The
    caller owns restarting it or surfacing it - here it is surfaced, and
    `/api/v1/health` reports it as degraded.
    """

    def __init__(
        self, scheduler: Scheduler, auto: auto_rotation.AutoRotator | None = None
    ) -> None:
        self.scheduler = scheduler
        self.auto = auto
        self.failure: str | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="credarr-audit", daemon=True)

    @property
    def running(self) -> bool:
        return self._thread.is_alive()

    def set_interval(self, seconds: float) -> None:
        """Apply a cadence change to both the loop and the auto freshness gate."""
        self.scheduler.set_interval(seconds)
        if self.auto is not None:
            self.auto.set_interval(seconds)

    def set_enabled(self, enabled: bool) -> None:
        """Apply the audit-schedule switch without stopping the loop."""
        self.scheduler.set_enabled(enabled)

    def wake(self) -> None:
        self.scheduler.wake()

    def start(self) -> None:
        # Auto reconciles the journal before the first audit can signal it.
        if self.auto is not None:
            self.auto.start()
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self.auto is not None:
            self.auto.stop()
        # An audit in flight can hold the thread past the join; it is a daemon,
        # and the run it is finishing is read-only.
        self._thread.join(timeout=10)

    def _run(self) -> None:
        try:
            self.scheduler.serve(self._stop)
        except Exception as exc:
            self.failure = f"{type(exc).__name__}: {exc}"
            # No audit means no completed-audit signal auto may act on.
            if self.auto is not None:
                self.auto.stop()


def _mount(app: FastAPI) -> None:
    """The `/api/v1` surface. The version is in the path; there is no other."""
    ctx = ApiContext(
        settings=app.state.settings,
        store=app.state.store,
        auth=app.state.auth,
        log=app.state.audit_log,
        audit_jobs=app.state.audit_jobs,
        loop=app.state.loop,
        auto=app.state.auto,
        notifier=app.state.notifier,
        delivery=app.state.delivery,
        config=app.state.config,
        scheduler=app.state.loop.scheduler,
        registry=app.state.loop.scheduler.registry,
        sync=app.state.sync,
        sync_loop=app.state.sync_loop,
        agent_plane=getattr(app.state, "agent_plane", None),
        maintenance=app.state.maintenance,
    )
    app.state.api_context = ctx
    mount_api(app, ctx)


def _check_local_filesystem(settings: ServerSettings, config: Config) -> None:
    """Refuse `/config` or the journal on a network filesystem (decision 8).

    The refusal is the safe direction: the failure it prevents is a rotation
    lock that voids silently, while a wrong refusal is a message and a moved
    directory. `CREDARR_ALLOW_NETWORK_CONFIG=1` is the documented way to read
    the warning and accept the risk.
    """
    # The journal is `<manifest dir>/state/rotation.db`. Checking the journal's
    # own directory, not just the manifest's, is what catches a mount placed
    # exactly at `state/` - the one place the lock would then void.
    for path, what in (
        (settings.config_dir, "the data directory"),
        (facade.journal_for(config).path.parent, "the rotation journal"),
    ):
        mount = mounts.network_mount(path)
        if mount is None:
            continue
        finding = f"{what} {path} is on {mount.fstype} (mounted at {mount.point})"
        if not settings.allow_network_config:
            raise CredctlError(
                f"{finding}: SQLite's locks and WAL need a local filesystem",
                hint="move it to a local disk, or set CREDARR_ALLOW_NETWORK_CONFIG=1 "
                "to accept the documented risk",
            )
        print(
            f"warning: {finding}; SQLite's locks and WAL are not guaranteed there",
            file=sys.stderr,
        )


def _run_once(settings: ServerSettings, *, as_json: bool) -> int:
    """One audit of the app's own store, for cron: the CLI's verdict and code.

    The store is `app.db`, not a manifest file: the console is where the
    topology lives, and a cron run reading a stale YAML would audit a different
    stack from the one the operator edited. Notifications are sent once too, so
    a deployment that only has cron is still a monitor; a delivery problem is a
    warning, never the audit's exit code.
    """
    config = load_config(settings.config_path)
    _check_local_filesystem(settings, config)
    store = TopologyStore(settings.database)
    if not store.load_manifest().credentials:
        # The console refuses to audit an unimported store and says why; a cron
        # run that recorded "0 credentials matched" would be the same lie with
        # no view to correct it.
        print(
            "error: no topology has been imported: nothing was checked",
            file=sys.stderr,
        )
        return ExitCode.CONFIG
    log = AuditLog(settings.database)
    result = Scheduler(store, log, config, interval=settings.audit_interval).once()
    try:
        Notifier(settings.database).tick()
    except (OSError, sqlite3.Error) as exc:
        print(f"warning: the notifications did not run: {exc}", file=sys.stderr)
    if result is None:
        state = log.last_state()
        run = state.last_run if state is not None else None
        detail = run.detail if run is not None and run.detail else "nothing was recorded"
        print(f"the audit did not complete: {detail}", file=sys.stderr)
        if run is not None and run.exit_code is not None:
            return int(run.exit_code)
        return ExitCode.CONFIG
    if as_json:
        report.render_json(result, sys.stdout)
    else:
        report.render_human(result, sys.stdout, colour=None)
    return report.exit_code_for(result)


BOOTSTRAP_CONFIG = """\
# Created by credarr on first boot. The console writes deployment facts and
# keys into /config/app.db; this file only supplies the host name and where a
# CLI manifest would live. Edit it if you deploy the CLI beside the server.
version: 1
default_host: local
manifest: credentials.yaml
hosts:
  local:
    urls: {}
"""

BOOTSTRAP_MANIFEST = """\
# Created by credarr on first boot. The console's topology lives in app.db;
# this file is the empty starting point a CLI run or export can use.
version: 1
credentials: {}
"""


def _write_new_file(path: Path, text: str, *, mode: int) -> bool:
    """Create `path` once, atomically, and never replace an existing file."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ConfigError(
            f"cannot create {path.parent}: {exc.strerror}",
            hint="credarr needs a writable directory for its first-run config",
        ) from None
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError:
        return False
    except OSError as exc:
        raise ConfigError(
            f"cannot create {path}: {exc.strerror}",
            hint="credarr needs to write its first-run config here; make the "
            "directory writable or pass -c/--config at a writable path",
        ) from None
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    return True


def _bootstrap_config(settings: ServerSettings) -> None:
    """Create the minimal config a first-run console needs, once.

    The server audits the store, not a manifest file, so this is the only file
    it cannot start without. The empty manifest is written beside it so a CLI
    run or export has the path the config names; an existing file is never
    replaced, and an existing config is never rewritten (a typo must still be
    an error, not silently repaired).
    """
    path = settings.config_path
    if path.exists():
        return
    if not settings.allow_network_config:
        # Do not create anything on a mount the server is about to refuse.
        for candidate, what in (
            (settings.config_dir, "the data directory"),
            (path.parent, "the config and journal directory"),
        ):
            mount = mounts.network_mount(candidate)
            if mount is None:
                continue
            raise CredctlError(
                f"{what} {candidate} is on {mount.fstype} "
                f"(mounted at {mount.point}): SQLite's locks and WAL need a "
                "local filesystem",
                hint="move it to a local disk, or set CREDARR_ALLOW_NETWORK_CONFIG=1 "
                "to accept the documented risk",
            )
    manifest = path.parent / "credentials.yaml"
    if not manifest.exists():
        _write_new_file(manifest, BOOTSTRAP_MANIFEST, mode=0o600)
    if _write_new_file(path, BOOTSTRAP_CONFIG, mode=0o600):
        print(
            f"bootstrapped a first-run config at {path}; edit it if you need "
            "predeclared service URLs",
            file=sys.stderr,
        )


def create_app(settings: ServerSettings) -> FastAPI:
    """The application, wired over `settings.config_path` and `settings.database`."""
    _bootstrap_config(settings)
    config = load_config(settings.config_path)
    _check_local_filesystem(settings, config)
    tree = None
    if settings.vault_tree is not None:
        tree = VaultTree(
            settings.vault_tree,
            settings.vault_tree_key or settings.config_dir / "vault-tree.key",
        )
        try:
            tree.ensure_key()
        except VaultError as exc:
            raise ConfigError(str(exc), hint=exc.hint) from None
    store = TopologyStore(settings.database, vault_tree=tree)
    _seed_services(store, config, store.load_manifest())
    auth = AdminAuth(settings.database)
    log = AuditLog(settings.database)
    audit_jobs = AuditJobs()
    # One registry for the process: the audit, the topology import and the
    # holder/version answers must agree about what this build knows.
    registry = build_registry()
    journal = facade.journal_for(config)
    persisted_interval = store.audit_interval()
    initial_interval = (
        persisted_interval
        if persisted_interval is not None
        and MIN_AUDIT_INTERVAL_SECONDS
        <= persisted_interval
        <= MAX_AUDIT_INTERVAL_SECONDS
        else settings.audit_interval
    )
    persisted_enabled = store.audit_enabled()
    initial_enabled = True if persisted_enabled is None else persisted_enabled
    auto = auto_rotation.AutoRotator(
        store, config, log, journal, interval=initial_interval
    )
    loop = AuditLoop(
        Scheduler(
            store,
            log,
            config,
            interval=initial_interval,
            enabled=initial_enabled,
            registry=registry,
            on_audit=auto.notify,
            next_due=auto.next_due,
            has_due=auto.has_due,
        ),
        auto,
    )
    # The notifier reads what the audit writes, so it is built after the log and
    # shares the database with it: an event and its delivery state must not be
    # able to disagree across a restart.
    notifier = Notifier(settings.database)
    delivery = DeliveryLoop(notifier)
    sync = SyncStore(settings.database, tree_configured=tree is not None)
    sync_loop = SyncLoop(sync)
    maintenance = VaultMaintenanceLoop(store.vault)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> Iterator[None]:
        loop.start()
        delivery.start()
        sync_loop.start()
        maintenance.start()
        try:
            yield
        finally:
            maintenance.stop()
            sync_loop.stop()
            loop.stop()
            delivery.stop()

    app = FastAPI(title="credarr", version=__version__, lifespan=lifespan)

    @app.exception_handler(RequestValidationError)
    async def validation_error(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Answer a bad request without echoing the rejected value."""
        return JSONResponse(status_code=422, content={"detail": _validation_details(exc)})

    @app.exception_handler(VaultError)
    async def vault_error(_request: Request, exc: VaultError) -> JSONResponse:
        """Expected value-store refusals are a sentence, not a bare 500."""
        return JSONResponse(
            status_code=503 if isinstance(exc, KekUnavailable) else 409,
            content={"detail": exc.render()},
        )

    app.state.settings = settings
    app.state.store = store
    app.state.auth = auth
    app.state.audit_log = log
    app.state.audit_jobs = audit_jobs
    app.state.loop = loop
    app.state.auto = auto
    app.state.notifier = notifier
    app.state.delivery = delivery
    app.state.sync = sync
    app.state.sync_loop = sync_loop
    app.state.maintenance = maintenance
    app.state.config = config

    @app.middleware("http")
    async def no_store(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Nothing under `/api/v1` is cacheable, and nothing may be framed.

        Authenticated payloads behind a shared cache would be replayable to an
        unauthenticated caller, and health answers must not be served stale.
        The framing ban covers the console as well: a live admin session is
        clickjacking-capable, so one policy is applied to every response.
        """
        response = await call_next(request)
        if request.url.path.startswith("/api/v1"):
            response.headers["Cache-Control"] = "no-store"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
        return response

    _mount(app)
    if (settings.web_dir / "index.html").is_file():
        # The console, served at "/" and nowhere else: no client-side routes
        # exist, so there is no history fallback. Mounted *after* the API, so
        # /api/v1 and the framework's docs pages answer first. A deployment
        # without a build is an API-only deployment, not a broken one - hence
        # the check rather than a hard failure.
        app.mount("/", StaticFiles(directory=settings.web_dir, html=True), name="console")
    return app


def _configured_timezone() -> str:
    """The console's display zone, validated once at boot.

    TZ is the operator-facing knob and the same value the container clock uses.
    An invalid or unset value falls back to UTC; the browser must never receive
    a name Intl will reject.
    """
    name = (os.environ.get("TZ") or "UTC").strip()
    try:
        zoneinfo.ZoneInfo(name)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        return "UTC"
    return name


def _positive_seconds(value: str) -> float:
    """Usage, exit 2 - for anything that would spin the loop.

    That is not only zero and negatives: `Event.wait(nan)` returns
    immediately (a non-blocking acquire), so a `nan` interval would audit
    back-to-back while `/health` stayed green.
    """
    seconds = float(value)
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError("the audit interval must be a positive, finite number")
    return seconds


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="credarr-server",
        description="credarr's BFF: the audit loop and the HTTP API.",
    )
    parser.add_argument(
        "-c", "--config", type=Path, default=Path("credarr.yaml"),
        help="engine configuration file (default: credarr.yaml)",
    )
    parser.add_argument(
        "--config-dir", type=Path,
        default=Path(os.environ.get("CREDARR_CONFIG_DIR", DEFAULT_CONFIG_DIR)),
        help="directory holding app.db (default: /config, env CREDARR_CONFIG_DIR)",
    )
    parser.add_argument(
        "--host", default=os.environ.get("CREDARR_HOST", DEFAULT_HOST),
        help="address to bind (env CREDARR_HOST)",
    )
    parser.add_argument(
        "--port", type=int, default=os.environ.get("CREDARR_PORT", "8080"),
        help="port to bind (env CREDARR_PORT)",
    )
    parser.add_argument(
        "--audit-interval", type=_positive_seconds, metavar="SECONDS",
        default=os.environ.get("CREDARR_AUDIT_INTERVAL", "3600"),
        help="seconds between audits (env CREDARR_AUDIT_INTERVAL, default 3600)",
    )
    parser.add_argument(
        "--agent-port", type=int,
        default=int(os.environ.get("CREDARR_AGENT_PORT", "8443")),
        help="mTLS agent listener port; 0 disables it (env CREDARR_AGENT_PORT, "
        "default 8443)",
    )
    parser.add_argument(
        "--agent-bind", default=os.environ.get("CREDARR_AGENT_BIND", DEFAULT_HOST),
        help="address for the mTLS agent listener (env CREDARR_AGENT_BIND)",
    )
    parser.add_argument(
        "--agent-hostname", default=os.environ.get("CREDARR_AGENT_HOSTNAME") or None,
        help="name or IP an agent uses to reach the listener; added to its "
        "certificate SANs (env CREDARR_AGENT_HOSTNAME)",
    )
    parser.add_argument(
        "--agent-san", action="append", default=None,
        help="extra DNS name or IP for the listener certificate SANs; repeatable "
        "(env CREDARR_AGENT_SANS, comma separated)",
    )
    parser.add_argument(
        "--agent-ca-cert", type=Path,
        default=(
            Path(os.environ["CREDARR_AGENT_CA_CERT"])
            if os.environ.get("CREDARR_AGENT_CA_CERT")
            else None
        ),
        help="bring-your-own CA certificate (env CREDARR_AGENT_CA_CERT)",
    )
    parser.add_argument(
        "--agent-ca-key", type=Path,
        default=(
            Path(os.environ["CREDARR_AGENT_CA_KEY"])
            if os.environ.get("CREDARR_AGENT_CA_KEY")
            else None
        ),
        help="bring-your-own CA key; Credarr signs the listener and client certs "
        "(env CREDARR_AGENT_CA_KEY)",
    )
    parser.add_argument(
        "--secure-cookies", action="store_true",
        help="set the Secure cookie flag: use when serving over HTTPS",
    )
    parser.add_argument(
        "--once", action="store_true",
        help="audit the app's store once, print the run and exit (for cron; no HTTP)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="with --once: print the run as JSON, the CLI's document",
    )
    return parser


_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
_SECURE_VALUES = {"1": True, "true": True, "yes": True, "0": False, "false": False, "no": False}


def _is_loopback(host: str) -> bool:
    name = (host or "").strip().lower()
    return name in _LOOPBACK_HOSTS or name.startswith("127.")


def resolve_session_security(
    *,
    flag: bool,
    env_secure: str | None,
    external_url: str | None,
    host: str,
) -> tuple[bool, list[str]]:
    """Decide the session cookie policy, and say what is risky about it.

    Three inputs, in increasing authority: the flag, CREDARR_SECURE_COOKIES, and
    a declared CREDARR_EXTERNAL_URL. The URL is the only way the app can know
    the scheme it is served under; nothing here trusts a request header, because
    X-Forwarded-Proto is client-supplied unless a proxy is declared and this
    build has no way to verify one.

    A contradiction is an error, not a guess: an https URL with secure cookies
    disabled, or an http URL with them enabled, both produce a console that
    cannot stay signed in.
    """
    value = (env_secure or "").strip().lower()
    if value and value not in _SECURE_VALUES:
        raise ValueError("CREDARR_SECURE_COOKIES must be 1 or 0")
    env_off = value in {"0", "false", "no"}
    secure = bool(flag or _SECURE_VALUES.get(value, False))

    url = (external_url or "").strip()
    if url:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            raise ValueError(
                "CREDARR_EXTERNAL_URL must be an http or https URL with a host"
            )
        if parts.scheme == "https":
            if env_off and not flag:
                raise ValueError(
                    "CREDARR_EXTERNAL_URL is https but CREDARR_SECURE_COOKIES=0: "
                    "remove one of the two"
                )
            secure = True
        elif secure:
            raise ValueError(
                "CREDARR_EXTERNAL_URL is http while secure cookies are on: "
                "the browser would drop the session, so set one scheme"
            )

    warnings: list[str] = []
    if not secure and not _is_loopback(host):
        warnings.append(
            f"secure cookies are off and the console binds {host}; if this "
            "instance is reached over HTTPS, set CREDARR_SECURE_COOKIES=1"
        )
    return secure, warnings


def main(argv: Sequence[str] | None = None) -> int:
    # Before config or secrets are read: a crash must not leave a core file with
    # the working copies this process handles.
    disable_core_dumps()
    parser = _parser()
    args = parser.parse_args(argv)
    agent_sans = args.agent_san
    if agent_sans is None:
        agent_sans = [
            item.strip()
            for item in os.environ.get("CREDARR_AGENT_SANS", "").split(",")
            if item.strip()
        ]
    if args.json and not args.once:
        parser.error("--json is only for --once")
    if not 0 <= args.agent_port <= 65535:
        parser.error("--agent-port must be 0 (disabled) or a TCP port")
    if os.environ.get("CREDARR_RESTART_URL"):
        print(
            "error: CREDARR_RESTART_URL is gone; credarr now asks each service "
            "to restart itself over its own API - remove the variable",
            file=sys.stderr,
        )
        return int(ExitCode.CONFIG)
    try:
        secure_cookies, security_warnings = resolve_session_security(
            flag=args.secure_cookies,
            env_secure=os.environ.get("CREDARR_SECURE_COOKIES"),
            external_url=os.environ.get("CREDARR_EXTERNAL_URL"),
            host=args.host,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return int(ExitCode.CONFIG)
    for line in security_warnings:
        print(f"warning: {line}", file=sys.stderr)
    settings = ServerSettings(
        config_path=args.config.resolve(),
        config_dir=args.config_dir,
        host=args.host,
        port=args.port,
        audit_interval=args.audit_interval,
        secure_cookies=secure_cookies,
        allow_network_config=os.environ.get("CREDARR_ALLOW_NETWORK_CONFIG") == "1",
        docker_url=os.environ.get("CREDARR_DOCKER_URL") or None,
        vault_tree=(
            Path(os.environ["CREDARR_VAULT_TREE"])
            if os.environ.get("CREDARR_VAULT_TREE")
            else None
        ),
        vault_tree_key=(
            Path(os.environ["CREDARR_VAULT_TREE_KEY"])
            if os.environ.get("CREDARR_VAULT_TREE_KEY")
            else None
        ),
        agent_port=args.agent_port,
        agent_bind=args.agent_bind,
        agent_hostname=args.agent_hostname,
        agent_sans=tuple(agent_sans),
        agent_ca_cert=args.agent_ca_cert,
        agent_ca_key=args.agent_ca_key,
        timezone=_configured_timezone(),
    )
    try:
        # One server per config directory. The lock is held across the whole
        # process lifetime (or the one-shot command) and released by the kernel
        # if this process dies, so a stale app.lock never blocks a restart.
        with InstanceLock(settings.config_dir):
            if args.once:
                return _run_once(settings, as_json=args.json)
            app = create_app(settings)
            import uvicorn

            plane: AgentControlPlane | None = None
            if settings.agent_port:
                plane = AgentControlPlane(
                    app.state.sync,
                    settings.config_dir,
                    host=settings.agent_bind or settings.host,
                    port=settings.agent_port,
                    hostname=settings.agent_hostname,
                    sans=settings.agent_sans,
                    ca_cert=settings.agent_ca_cert,
                    ca_key=settings.agent_ca_key,
                )
                try:
                    plane.start()
                except (OSError, ssl.SSLError, ValueError) as exc:
                    print(
                        f"warning: the agent listener did not start on "
                        f"{settings.agent_bind or settings.host}:{settings.agent_port}: {exc}",
                        file=sys.stderr,
                    )
                    plane.failure = f"{type(exc).__name__}: {exc}"
                app.state.agent_plane = plane
                app.state.api_context.agent_plane = plane
            try:
                uvicorn.run(app, host=settings.host, port=settings.port)
            except OSError as exc:
                # A bind/serve failure is not the config directory's fault;
                # report it as such instead of the setup handler below.
                print(f"error: the server could not run: {exc}", file=sys.stderr)
                return int(ExitCode.CONFIG)
            finally:
                if plane is not None:
                    plane.stop()
        return 0
    except CredctlError as exc:
        # Same contract as the CLI: a misconfiguration is exit 3 with the
        # engine's own message, not a traceback.
        print(exc.render(), file=sys.stderr)
        return int(exc.exit_code)
    except (OSError, sqlite3.Error) as exc:
        # An unusable data directory - missing, read-only, not a directory, a
        # corrupt database - is configuration too, and the most likely thing an
        # operator gets wrong. The message names the path they passed.
        error = CredctlError(f"{settings.config_dir}: {exc}")
        print(error.render(), file=sys.stderr)
        return int(error.exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
