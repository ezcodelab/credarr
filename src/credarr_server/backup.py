"""Backups: one encrypted file, and the restore that proves it.

The backup carries `app.db` - every working copy, the admin digest, the API-key
hashes and the notification secrets - plus the engine config that says where the
stack lives. That is exactly why it is encrypted, and why there is no plaintext
mode: the posture is that a backup is a secret (DECISIONS decision 3), and a
tool that can write one unencrypted will be used to.

The format is versioned and small: a magic string, a version byte, a salt, a
nonce, then AES-256-GCM over a tar.gz, with the header bound as associated data
and the key derived from the passphrase with scrypt. The KDF parameters are
constants, not fields: a file asking this build to use other ones is a file from
another format, and the version byte says so. The passphrase is read from a file
or typed, never from argv, where it would land in shell history and `ps`.

The rotation journal is deliberately not in the archive. It lives beside the
manifest (`facade.journal_for`), belongs to the stack rather than the app, and
stays where it is across a restore - which is also the safe direction: an
unfinished rotation must keep being recorded.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import io
import json
import os
import shutil
import sqlite3
import sys
import tarfile
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from credarr import __version__
from credarr.errors import CredctlError, ExitCode
from credarr.instance import InstanceLock
from credarr.redact import disable_core_dumps

from .store import connect

MAGIC = b"CREDARR-BACKUP\n"
FORMAT_VERSION = 1
SALT_BYTES = 16
NONCE_BYTES = 12
MIN_PASSPHRASE_LENGTH = 12

# 32 MiB and a few dozen milliseconds per file, which is what a passphrase typed
# once deserves. Pinned in the format: changing these is a new version byte.
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1

DATABASE_NAME = "app.db"
MANIFEST_NAME = "manifest.json"
CONFIG_PREFIX = "config/"

# What a restored database must have to be this app's store. Integrity alone
# proves a SQLite file; these tables prove whose it is. The audit log and the
# admin settings are created on boot if the backup predates them, so demanding
# them would refuse a backup taken from a store the console has not served yet.
REQUIRED_TABLES = frozenset({"credentials", "holders", "working_copies"})


class BackupError(CredctlError):
    """The archive or the data directory cannot be used. Exit 3, like any other
    configuration problem: the operator must change a file or a flag."""


class BackupUsage(BackupError):
    """The command line asks for something this tool does not do."""

    exit_code = ExitCode.USAGE


def encrypt(payload: bytes, passphrase: str) -> bytes:
    """Authenticated encryption with the header bound to the ciphertext."""
    salt = os.urandom(SALT_BYTES)
    header = MAGIC + bytes([FORMAT_VERSION]) + salt
    nonce = os.urandom(NONCE_BYTES)
    sealed = AESGCM(_key(passphrase, salt)).encrypt(nonce, payload, header + nonce)
    return header + nonce + sealed


def decrypt(blob: bytes, passphrase: str) -> bytes:
    """The payload, or a sentence naming what is wrong with the file."""
    head = len(MAGIC) + 1 + SALT_BYTES
    if not blob.startswith(MAGIC):
        raise BackupError("this file is not a credarr backup")
    if len(blob) < head + NONCE_BYTES:
        raise BackupError("this backup is truncated")
    version = blob[len(MAGIC)]
    if version != FORMAT_VERSION:
        raise BackupError(
            f"this backup is format {version}; this build reads {FORMAT_VERSION}",
            hint="restore it with the credarr version that wrote it",
        )
    salt = blob[len(MAGIC) + 1 : head]
    nonce = blob[head : head + NONCE_BYTES]
    try:
        return AESGCM(_key(passphrase, salt)).decrypt(
            nonce, blob[head + NONCE_BYTES :], blob[:head] + nonce
        )
    except InvalidTag:
        raise BackupError(
            "the passphrase is wrong, or the file is damaged"
        ) from None


def _key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=32,
        maxmem=64 * 1024 * 1024,
    )


def write_backup(*, config_path: Path, config_dir: Path, out: Path, passphrase: str) -> None:
    """Snapshot the app and write the encrypted file. Never overwrites one."""
    _require_passphrase(passphrase)
    config_path, config_dir, out = Path(config_path), Path(config_dir), Path(out)
    if not config_path.is_file():
        raise BackupError(
            f"no config at {config_path}",
            hint="--config names the credarr.yaml this app reads",
        )
    database = config_dir / DATABASE_NAME
    if not database.is_file():
        raise BackupError(
            f"no database at {database}",
            hint="--config-dir names the app's data directory; has the server run once?",
        )
    if out.exists():
        raise BackupError(
            f"{out} already exists",
            hint="name each backup with its date; this tool never overwrites one",
        )
    if not out.parent.is_dir():
        raise BackupError(f"no directory at {out.parent}")

    blob = encrypt(_archive(_snapshot(database), config_path), passphrase)
    temporary = out.with_name(out.name + ".tmp")
    try:
        handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(handle, "wb") as file:
            file.write(blob)
            file.flush()
            os.fsync(file.fileno())
        temporary.replace(out)
        _fsync_directory(out.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def restore_backup(
    *,
    path: Path,
    config_dir: Path,
    config_path: Path | None,
    passphrase: str,
) -> list[Path]:
    """Replace the data directory's app.db (and the config) with the archive's.

    Everything is decrypted, unpacked and checked before the first file is
    touched: a wrong passphrase or a damaged archive leaves the target exactly
    as it was. A previous app.db is kept as `app.db.pre-restore`, because the
    operator's mistake most worth surviving is restoring the wrong file.
    """
    _require_passphrase(passphrase)
    path, config_dir = Path(path), Path(config_dir)
    try:
        blob = path.read_bytes()
    except OSError as exc:
        raise BackupError(f"cannot read {path}: {exc.strerror}") from None
    database_bytes, config_name, config_bytes = _unpack(decrypt(blob, passphrase))

    if not config_dir.is_dir():
        raise BackupError(
            f"no directory at {config_dir}",
            hint="create it, or point --config-dir at the app's data directory",
        )
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = config_dir / f"{DATABASE_NAME}{suffix}"
        if sidecar.exists():
            raise BackupError(
                f"{sidecar} is beside {config_dir / DATABASE_NAME}",
                hint="stop the credarr server first; if it crashed, move the "
                "-wal, -shm and -journal files aside and restore again",
            )
    destination_config = Path(config_path) if config_path is not None else config_dir / config_name
    if not destination_config.parent.is_dir():
        raise BackupError(f"no directory at {destination_config.parent}")

    database = config_dir / DATABASE_NAME
    previous = config_dir / "app.db.pre-restore"
    if previous.exists():
        # The file an operator reaches for when the archive they restored turns
        # out to be the wrong one must not be eaten by the next attempt.
        raise BackupError(
            f"{previous} already exists",
            hint="move it aside first; this restore will not overwrite the "
            "database an earlier restore kept",
        )

    old_config = _read_existing(destination_config)
    # Both files are written and fsynced in a private directory before either
    # destination is touched. If publishing the second one fails, the first is
    # rolled back, so a failed restore leaves the app as it was.
    work = Path(tempfile.mkdtemp(prefix=".restore-", dir=config_dir))
    config_work = work
    try:
        if destination_config.parent != config_dir:
            # Path.replace cannot cross filesystems, so the config is staged
            # beside its destination instead of beside the database.
            config_work = Path(
                tempfile.mkdtemp(prefix=".restore-", dir=destination_config.parent)
            )
        staged_database = _stage(work / DATABASE_NAME, database_bytes, database)
        staged_config = _stage(config_work / "config", config_bytes, destination_config)
        config_published = False
        database_published = False
        try:
            _publish(staged_config, destination_config)
            config_published = True
            if database.exists():
                # A hard link keeps the old database in place until the atomic
                # replacement below; there is no window with app.db missing.
                os.link(database, previous)
            _publish(staged_database, database)
            database_published = True
            _fsync_directory(config_dir)
            if destination_config.parent != config_dir:
                _fsync_directory(destination_config.parent)
        except BaseException:
            if database_published:
                if previous.exists():
                    _publish(previous, database)
                else:
                    database.unlink(missing_ok=True)
            if config_published:
                if old_config is None:
                    destination_config.unlink(missing_ok=True)
                else:
                    _write(destination_config, old_config)
            raise
        finally:
            if not database_published and previous.exists() and database.exists():
                # The database was never replaced; the link was only a rollback
                # aid, so do not leave a second copy behind.
                previous.unlink(missing_ok=True)
    finally:
        shutil.rmtree(work, ignore_errors=True)
        if config_work != work:
            shutil.rmtree(config_work, ignore_errors=True)
    return [database, destination_config]


def _snapshot(database: Path) -> bytes:
    """A consistent copy of a live database, WAL included, as bytes.

    SQLite's backup API takes the read lock and folds the WAL in as it copies,
    so a server that is auditing while the backup runs cannot produce a torn
    copy. The copy stays in memory: a backup tool must not leave a plaintext
    database in a temporary directory on the way to encrypting it.
    """
    target = sqlite3.connect(":memory:")
    try:
        with connect(database) as source:
            source.backup(target)
        # The backup keeps the source's WAL header. VACUUM writes a standalone
        # database that `deserialize` can load during validation.
        target.execute("VACUUM")
        return target.serialize()
    except sqlite3.Error as exc:
        raise BackupError(f"cannot snapshot {database}: {exc}") from None
    finally:
        target.close()


def _archive(snapshot: bytes, config_path: Path) -> bytes:
    try:
        config = config_path.read_bytes()
    except OSError as exc:
        raise BackupError(f"cannot read {config_path}: {exc.strerror}") from None
    manifest = {
        "format": FORMAT_VERSION,
        "created_at": time.time(),
        "credarr": __version__,
        "config_name": config_path.name,
    }
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        def add(name: str, data: bytes) -> None:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = int(time.time())
            archive.addfile(info, io.BytesIO(data))

        add(DATABASE_NAME, snapshot)
        add(CONFIG_PREFIX + config_path.name, config)
        add(MANIFEST_NAME, json.dumps(manifest, indent=2).encode())
    return buffer.getvalue()


def _unpack(payload: bytes) -> tuple[bytes, str, bytes]:
    """The archive's three files, validated. Never extracts to a path."""
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:

            def member(entry: str) -> bytes:
                try:
                    handle = archive.extractfile(entry)
                except KeyError:
                    raise BackupError(f"the backup has no {entry}") from None
                if handle is None:
                    raise BackupError(f"the backup's {entry} is not a file")
                return handle.read()

            try:
                manifest = json.loads(member(MANIFEST_NAME))
            except json.JSONDecodeError:
                raise BackupError("the backup's manifest is not JSON") from None
            if not isinstance(manifest, dict) or manifest.get("format") != FORMAT_VERSION:
                raise BackupError("the backup's manifest names a format this build does not read")
            name = manifest.get("config_name")
            if (
                not isinstance(name, str)
                or not name
                or name in (".", "..")
                or Path(name).name != name
            ):
                raise BackupError("the backup names an unusable config file")
            database = member(DATABASE_NAME)
            config = member(CONFIG_PREFIX + name)
    except tarfile.TarError:
        raise BackupError("the backup's contents are not readable") from None

    _check_snapshot(database)
    return database, name, config


def _check_snapshot(data: bytes) -> None:
    """Integrity, and that it is this app's database, before anything is written.

    The bytes are loaded into an in-memory database, so checking a backup never
    creates a plaintext database file in a temporary directory.
    """
    connection = sqlite3.connect(":memory:")
    try:
        connection.deserialize(data)
        connection.row_factory = sqlite3.Row
        result = connection.execute("PRAGMA integrity_check").fetchone()
        tables = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    except sqlite3.Error as exc:
        raise BackupError(f"the database inside this backup is not readable: {exc}") from None
    finally:
        connection.close()
    if result is None or result[0] != "ok":
        raise BackupError("the database inside this backup is damaged")
    missing = REQUIRED_TABLES - tables
    if missing:
        raise BackupError(
            "the backup does not hold a credarr database",
            hint=f"missing tables: {', '.join(sorted(missing))}",
        )


def _read_existing(destination: Path) -> bytes | None:
    """The old contents, kept in memory for rollback. Small config, small cost."""
    if not destination.exists():
        return None
    try:
        return destination.read_bytes()
    except OSError as exc:
        raise BackupError(f"cannot read {destination}: {exc.strerror}") from None


def _stage(path: Path, data: bytes, destination: Path) -> Path:
    """Write and fsync a private staging file, with the destination's mode."""
    mode = 0o600
    if destination.exists():
        mode = destination.stat().st_mode & 0o777
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as file:
        file.write(data)
        file.flush()
        os.fsync(file.fileno())
    return path


def _publish(source: Path, destination: Path) -> None:
    """The one rename that makes a staged file visible."""
    source.replace(destination)


def _write(destination: Path, data: bytes) -> None:
    """Replace one file atomically, keeping the mode it had before."""
    work = Path(tempfile.mkdtemp(prefix=".restore-", dir=destination.parent))
    try:
        _publish(_stage(work / "file", data, destination), destination)
        _fsync_directory(destination.parent)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_passphrase(passphrase: str) -> None:
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise BackupError(
            f"the backup passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters",
            hint="it is the only thing between this file and every stored value",
        )


def _passphrase(path: Path | None, *, confirm: bool) -> str:
    if path is not None:
        passphrase_path = Path(path)
        try:
            info = passphrase_path.stat()
            text = passphrase_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise BackupError(f"cannot read the passphrase file {path}: {exc.strerror}") from None
        if info.st_mode & 0o077:
            raise BackupError(
                f"the passphrase file {path} is readable by other users",
                hint="chmod 600 it; the passphrase is the only key to the backup",
            )
        passphrase = text.removesuffix("\n").removesuffix("\r")
        if "\n" in passphrase or "\r" in passphrase:
            raise BackupError(f"the passphrase file {path} has more than one line")
    else:
        passphrase = getpass.getpass("backup passphrase: ")
        if confirm and getpass.getpass("again: ") != passphrase:
            raise BackupUsage("the two passphrases differ")
    _require_passphrase(passphrase)
    return passphrase


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="credarr-backup",
        description="Write or restore credarr's encrypted backup. The file is a secret.",
        # An abbreviation would accept `--passphrase secret` as the *file* flag
        # and then name the secret in "cannot read ..." - a passphrase in a log.
        allow_abbrev=False,
    )
    parser.add_argument(
        "-c", "--config", type=Path,
        help="engine config: the one to archive, or where a restore writes it "
        "(default: the archived name beside app.db)",
    )
    parser.add_argument(
        "--config-dir", type=Path,
        default=Path(os.environ.get("CREDARR_CONFIG_DIR", "/config")),
        help="the app's data directory (default: /config, env CREDARR_CONFIG_DIR)",
    )
    parser.add_argument(
        "--out", type=Path,
        help="write the encrypted backup here; it must not exist",
    )
    parser.add_argument(
        "--restore", type=Path, metavar="FILE",
        help="restore the backup in FILE into --config-dir (replaces app.db)",
    )
    parser.add_argument(
        "--yes", action="store_true",
        help="confirm the restore",
    )
    parser.add_argument(
        "--passphrase-file", type=Path,
        help="read the passphrase from this file (0600); without it, it is typed "
        "(never on the command line, where it would land in history and ps)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    # Before the passphrase or a database snapshot is read: a crash must not
    # leave either in a core file.
    disable_core_dumps()
    args = _parser().parse_args(argv)
    if (args.out is None) == (args.restore is None):
        _parser().error("give exactly one of --out and --restore")
    try:
        # A missing --yes is a usage error, not a lock attempt; keep it out of
        # the lock so a refused restore leaves the config directory untouched.
        if args.out is None and not args.yes:
            raise BackupUsage(
                "a restore replaces app.db",
                hint="add --yes once the server is stopped",
            )
        # Both directions open app.db. The read-only snapshot is safe against a
        # live writer, but the deployment rule is one process per /config; a
        # second process is refused rather than left to a different lock.
        with InstanceLock(args.config_dir):
            if args.out is not None:
                passphrase = _passphrase(args.passphrase_file, confirm=True)
                write_backup(
                    config_path=args.config or Path("credarr.yaml"),
                    config_dir=args.config_dir,
                    out=args.out,
                    passphrase=passphrase,
                )
                print(f"wrote {args.out}")
                print(
                    "this file is a secret: it holds every stored value "
                    "and secret this app knows"
                )
                return ExitCode.OK
            written = restore_backup(
                path=args.restore,
                config_dir=args.config_dir,
                config_path=args.config,
                passphrase=_passphrase(args.passphrase_file, confirm=False),
            )
            for path in written:
                print(f"restored {path}")
            print("if app.db was there, it is kept as app.db.pre-restore")
            print("start the server again; it audits with the restored store")
            return ExitCode.OK
    except CredctlError as exc:
        print(exc.render(), file=sys.stderr)
        return exc.exit_code
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return ExitCode.CONFIG


if __name__ == "__main__":  # pragma: no cover - the console script is the entry point
    sys.exit(main())
