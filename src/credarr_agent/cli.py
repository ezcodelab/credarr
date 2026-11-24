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

DEFAULT_STATE = Path(os.environ.get("CREDARR_AGENT_STATE", "/var/lib/credarr-agent"))


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
        rootful=bool(args.rootful),
        ack_rootful=bool(args.ack_rootful),
        poll_seconds=float(args.poll_seconds),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="credarr-agent",
        description="The outbound deploy agent. Docker lives here, not in the BFF.",
    )
    parser.add_argument("-s", "--server", required=True, help="https URL of the BFF")
    parser.add_argument("--state-dir", default=str(DEFAULT_STATE))
    parser.add_argument("--vault-root", required=True, help="mounted shared vault tree")
    parser.add_argument("--vault-key", required=True, help="key file beside the tree")
    parser.add_argument("--ca", required=True, help="the BFF agent CA certificate")
    parser.add_argument(
        "--allowed-root", action="append", default=[],
        help="a directory a stack path must be under; repeatable",
    )
    parser.add_argument("--rootful", action="store_true")
    parser.add_argument("--ack-rootful", action="store_true")
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    sub = parser.add_subparsers(dest="command", required=True)
    enroll_parser = sub.add_parser("enroll", help="consume a one-time enrollment token")
    enroll_parser.add_argument("--name", required=True)
    enroll_parser.add_argument("--token-file", required=True)
    enroll_parser.add_argument(
        "--capability", action="append", default=[],
        help="a capability such as compose or compose:/srv/media; repeatable",
    )
    run_parser = sub.add_parser("run", help="pull and deliver jobs until stopped")
    run_parser.add_argument("--once", action="store_true", help="one lease, then exit")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    disable_core_dumps()
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "enroll" and not Path(args.token_file).is_file():
        print(f"error: no token file at {args.token_file}", file=sys.stderr)
        return int(ExitCode.CONFIG)
    if not (0 < float(args.poll_seconds) < 3600):
        print("error: --poll-seconds must be between 0 and 3600", file=sys.stderr)
        return int(ExitCode.CONFIG)
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
        return run(config, once=bool(args.once))
    except (AgentError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return int(ExitCode.CONFIG)


if __name__ == "__main__":
    raise SystemExit(main())
