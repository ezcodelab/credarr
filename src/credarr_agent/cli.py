"""`credarr-agent`: enroll, run, and report."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from credarr.errors import ExitCode
from credarr.redact import disable_core_dumps

from .client import AgentConfig, AgentError, enroll, run

DEFAULT_STATE = "/var/lib/credarr-agent"


def _env(name: str) -> str | None:
    value = os.environ.get(name, "").strip()
    return value or None


def _env_roots(name: str) -> list[str]:
    return [item.strip() for item in os.environ.get(name, "").split(",") if item.strip()]


def _config(args: argparse.Namespace) -> AgentConfig:
    state = Path(args.state_dir)
    roots = tuple(Path(item) for item in (args.allowed_root or ()))
    return AgentConfig(
        server=args.server,
        state_dir=state,
        vault_root=Path(args.vault_root),
        vault_key=Path(args.vault_key),
        allowed_roots=roots,
        ca_path=Path(args.ca),
        cert_path=state / "agent.crt",
        key_path=state / "agent.key",
        poll_seconds=float(args.poll_seconds),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="credarr-agent",
        description="The outbound deploy agent. Docker lives here, not in the BFF.",
    )
    parser.add_argument(
        "-s",
        "--server",
        default=_env("CREDARR_AGENT_SERVER"),
        help="https URL of the BFF (env CREDARR_AGENT_SERVER)",
    )
    parser.add_argument(
        "--state-dir",
        default=_env("CREDARR_AGENT_STATE") or DEFAULT_STATE,
        help="certificate and key directory (default /var/lib/credarr-agent)",
    )
    parser.add_argument(
        "--vault-root",
        default=_env("CREDARR_AGENT_VAULT_ROOT") or "/vault",
        help="mounted shared vault tree (default /vault)",
    )
    parser.add_argument(
        "--vault-key",
        default=_env("CREDARR_AGENT_VAULT_KEY") or "/run/secrets/CREDARR_VAULT_TREE_KEY",
        help="key file beside the tree (default the CREDARR_VAULT_TREE_KEY secret)",
    )
    parser.add_argument(
        "--ca",
        default=_env("CREDARR_AGENT_CA") or "/run/secrets/CREDARR_AGENT_CA",
        help="the BFF agent CA certificate (default the CREDARR_AGENT_CA secret)",
    )
    parser.add_argument(
        "--allowed-root",
        action="append",
        default=None,
        help="a directory a stack path must be under; repeatable "
        "(env CREDARR_AGENT_ALLOWED_ROOT, comma separated)",
    )
    parser.add_argument(
        "--poll-seconds",
        default=_env("CREDARR_AGENT_POLL_SECONDS") or 5.0,
        help="seconds between job leases (env CREDARR_AGENT_POLL_SECONDS)",
    )
    sub = parser.add_subparsers(dest="command", required=False)
    enroll_parser = sub.add_parser("enroll", help="consume a one-time enrollment token")
    enroll_parser.add_argument(
        "--name",
        default=_env("CREDARR_AGENT_ENROLL_NAME"),
        help="agent name (env CREDARR_AGENT_ENROLL_NAME)",
    )
    enroll_parser.add_argument(
        "--token-file",
        default=_env("CREDARR_AGENT_ENROLL_TOKEN_FILE"),
        help="file holding the one-time token (env CREDARR_AGENT_ENROLL_TOKEN_FILE)",
    )
    enroll_parser.add_argument(
        "--capability",
        action="append",
        default=None,
        help="a capability such as compose or compose:/srv/media; repeatable "
        "(env CREDARR_AGENT_CAPABILITY, comma separated)",
    )
    run_parser = sub.add_parser("run", help="pull and deliver jobs until stopped")
    run_parser.add_argument("--once", action="store_true", help="one lease, then exit")
    return parser


def _missing(args: argparse.Namespace) -> list[str]:
    missing = []
    for value, flag, env in (
        (args.server, "--server", "CREDARR_AGENT_SERVER"),
        (args.vault_root, "--vault-root", "CREDARR_AGENT_VAULT_ROOT"),
        (args.vault_key, "--vault-key", "CREDARR_AGENT_VAULT_KEY"),
        (args.ca, "--ca", "CREDARR_AGENT_CA"),
    ):
        if not value:
            missing.append(f"{flag} (or {env})")
    if not args.allowed_root:
        missing.append("--allowed-root (or CREDARR_AGENT_ALLOWED_ROOT)")
    return missing


def main(argv: Sequence[str] | None = None) -> int:
    disable_core_dumps()
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command is None:
        args.command = "run"
    if args.allowed_root is None:
        args.allowed_root = _env_roots("CREDARR_AGENT_ALLOWED_ROOT")
    if getattr(args, "capability", None) is None:
        args.capability = _env_roots("CREDARR_AGENT_CAPABILITY")
    missing = _missing(args)
    if missing:
        print("error: set " + ", ".join(missing), file=sys.stderr)
        return int(ExitCode.CONFIG)
    if args.command == "enroll":
        if not args.name:
            print("error: set --name or CREDARR_AGENT_ENROLL_NAME", file=sys.stderr)
            return int(ExitCode.CONFIG)
        if not args.token_file:
            print(
                "error: set --token-file or CREDARR_AGENT_ENROLL_TOKEN_FILE",
                file=sys.stderr,
            )
            return int(ExitCode.CONFIG)
        if not Path(args.token_file).is_file():
            print(f"error: no token file at {args.token_file}", file=sys.stderr)
            return int(ExitCode.CONFIG)
    try:
        poll_seconds = float(args.poll_seconds)
    except (TypeError, ValueError):
        print("error: --poll-seconds must be a number", file=sys.stderr)
        return int(ExitCode.CONFIG)
    if not 0 < poll_seconds < 3600:
        print("error: --poll-seconds must be between 0 and 3600", file=sys.stderr)
        return int(ExitCode.CONFIG)
    args.poll_seconds = poll_seconds
    try:
        config = _config(args)
        if args.command == "enroll":
            token = Path(args.token_file).read_text(encoding="utf-8").strip()
            if not token:
                print("error: the enrollment token file is empty", file=sys.stderr)
                return int(ExitCode.CONFIG)
            capabilities = tuple(args.capability) or ("compose",)
            enroll(config, token, name=args.name, capabilities=capabilities)
            print(f"enrolled; certificate written to {config.cert_path}", file=sys.stderr)
            return 0
        return run(config, once=bool(getattr(args, "once", False)))
    except (AgentError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return int(ExitCode.CONFIG)


if __name__ == "__main__":
    raise SystemExit(main())
