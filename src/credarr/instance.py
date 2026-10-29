"""One app process per config directory.

SQLite serializes individual writes, but the server's audit loop, notifier,
and in-process audit serialization assume one owner. Two servers on one
`app.db` would not corrupt a row; they would run two loops against the same
state and disagree about which one is current. The lock makes the deployment
boundary explicit and fails before either process opens the database.
"""

from __future__ import annotations

import errno
import fcntl
import os
import time
from pathlib import Path
from types import TracebackType

from credarr.errors import ConfigError

LOCK_NAME = "app.lock"
DEFAULT_CONFIG_DIR = Path("/config")


class InstanceLock:
    """An exclusive, non-blocking `flock` on `<config>/app.lock`.

    The file is left in place after release. A stale PID is harmless: the
    kernel drops the lock when the process exits, and the next owner
    overwrites the text. Deleting the file instead would race a third process
    opening the old inode while the second held the new one.
    """

    def __init__(self, config_dir: Path | str) -> None:
        self.path = Path(config_dir) / LOCK_NAME
        self._fd: int | None = None

    def acquire(self) -> None:
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError as exc:
            hint = (
                "remove the symlink at that path; app.lock must be a regular file"
                if exc.errno == errno.ELOOP
                else "the config directory must exist and be writable"
            )
            raise ConfigError(
                f"cannot open the instance lock {self.path}: {exc.strerror or exc}",
                hint=hint,
            ) from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise ConfigError(
                f"another credarr process holds this config directory: {self.path}",
                hint="one process per /config is required; stop the other server "
                "or one-shot command first",
            ) from None
        except OSError as exc:
            os.close(fd)
            raise ConfigError(
                f"cannot lock {self.path}: {exc.strerror or exc}",
                hint="the config directory must support POSIX advisory locks",
            ) from exc

        self._fd = fd
        try:
            os.fchmod(fd, 0o600)
            os.ftruncate(fd, 0)
            owner = f"pid={os.getpid()} started={time.time():.0f}\n"
            os.write(fd, owner.encode("ascii", "replace"))
            os.fsync(fd)
        except OSError as exc:
            self.release()
            raise ConfigError(
                f"cannot record the instance lock {self.path}: {exc.strerror or exc}",
            ) from exc

    def release(self) -> None:
        fd = self._fd
        self._fd = None
        if fd is None:
            return
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def __enter__(self) -> InstanceLock:
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.release()
