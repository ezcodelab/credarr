"""`credarr-kek`: inspect, initialize, and rotate the local key-encryption key.

These are offline operations: stop the server first (the instance lock would
refuse a second process anyway for the rotate path). The rotate command rewraps
every data key under a new KEK and keeps the old key in the keyring, so a
database read can still fall back to a value wrapped before the rotation.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from credarr.errors import CredctlError, ExitCode
from credarr.instance import DEFAULT_CONFIG_DIR, InstanceLock
from credarr.redact import disable_core_dumps

from .store import TopologyStore


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="credarr-kek",
        description="Inspect or rotate the KEK that wraps every stored value.",
    )
    parser.add_argument(
        "--config-dir", type=Path,
        default=Path(os.environ.get("CREDARR_CONFIG_DIR", DEFAULT_CONFIG_DIR)),
    )
    parser.add_argument("--json", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="print non-secret key facts")
    sub.add_parser("init", help="create a key only when the store has none")
    sub.add_parser("rotate", help="rewrap every DEK under a new key")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    disable_core_dumps()
    args = _parser().parse_args(argv)
    database = args.config_dir / "app.db"
    try:
        with InstanceLock(args.config_dir):
            store = TopologyStore(database)
            vault = store.vault
            if args.command == "status":
                status = vault.key_status()
                if args.json:
                    print(json.dumps(status, indent=2, sort_keys=True))
                else:
                    print(f"KEK file: {status['path']}")
                    print(f"present: {status['present']}  available: {status['available']}")
                    if status["error"]:
                        print(f"error: {status['error']}")
                    if status["available"]:
                        print(f"active key: {status['active']}")
                        print(
                            f"versions: {status['versions']}  "
                            f"not under active: {status['unwrapped']}"
                        )
                return 0 if status["available"] else int(ExitCode.CONFIG)
            if args.command == "init":
                status = vault.key_status()
                if status["present"]:
                    print("the KEK already exists; nothing was changed", file=sys.stderr)
                    return 0
                # Construction bootstraps only an empty store; reaching here
                # with data means key_status would have reported unavailable.
                if not status["available"]:
                    print(
                        "refusing to create a replacement KEK over stored values; "
                        "restore the original key from the encrypted backup",
                        file=sys.stderr,
                    )
                    return int(ExitCode.CONFIG)
                print(f"created {status['path']}")
                return 0
            active = vault.rotate_kek()
            print(f"rewrapped every value under key {active}")
            return 0
    except CredctlError as exc:
        print(exc.render(), file=sys.stderr)
        return int(exc.exit_code)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return int(ExitCode.CONFIG)


if __name__ == "__main__":
    raise SystemExit(main())
