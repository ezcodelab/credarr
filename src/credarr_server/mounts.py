"""Whether the paths the app depends on sit on a filesystem that can hold them.

Decision 8: `/config` must be local. SQLite's WAL needs a shared-memory
`-shm` file and its cross-process exclusion is POSIX advisory locks; neither
survives NFS, and an Unraid user share (`shfs`) is the same class of trap. The
rotation journal lives beside the manifest, so its directory is checked too -
the void this prevents is the journal lock, the one thing between an
interrupted rotation and a second mint.

The check is a mount-table lookup, not a lock probe. Proving locks work needs a
second process, and what a probe would prove on one path it would not prove
under load; what the table can prove is that the filesystem is one of the types
where they are documented not to work. That is the honest limit: an exotic
local FUSE mount that voids locks is not detected, and the README states the
assumption rather than pretending the check is complete.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

# The filesystem types where POSIX advisory locks or WAL's shared memory are
# documented not to hold. `shfs`/`fuse.shfs` is Unraid's user-share layer: a
# local disk in name, a network-like layer in behaviour.
NETWORK_FILESYSTEMS = frozenset(
    {
        "9p",
        "afs",
        "ceph",
        "cifs",
        "fuse.shfs",
        "fuse.sshfs",
        "glusterfs",
        "nfs",
        "nfs4",
        "shfs",
        "smb3",
        "smbfs",
        "sshfs",
    }
)

# proc(5): a mount point's space, tab, newline and backslash are octal escapes.
_ESCAPES = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}


@dataclass(frozen=True, slots=True)
class Mount:
    """One line of the mount table: where it is mounted, and what it is."""

    point: Path
    fstype: str


def _unescape(field: str) -> str:
    return re.sub(r"\\(040|011|012|134)", lambda match: _ESCAPES[match.group(1)], field)


def parse_mounts(text: str) -> list[Mount]:
    """The mount table as `/proc/self/mountinfo` writes it.

    The separator between the optional fields and the filesystem type is
    `" - "`; the mount point is the fifth field, before it.
    """
    table: list[Mount] = []
    for line in text.splitlines():
        before, separator, after = line.partition(" - ")
        fields = before.split()
        types = after.split()
        if not separator or len(fields) < 5 or not types:
            continue
        table.append(Mount(Path(_unescape(fields[4])), types[0]))
    return table


def read_mounts() -> list[Mount] | None:
    """The mount table, or None when this system does not describe one.

    None is "cannot tell", and every caller treats it as no finding: refusing a
    deployment because `/proc` is hidden (a sandbox, a non-Linux host) would be
    a guess dressed as a check.
    """
    try:
        text = Path("/proc/self/mountinfo").read_text(encoding="utf-8")
    except OSError:
        return None
    return parse_mounts(text)


def mount_for(path: Path, table: Sequence[Mount]) -> Mount | None:
    """The mount a path lives on: the longest mount point that contains it."""
    target = path.resolve()
    best: Mount | None = None
    for mount in table:
        if target != mount.point and mount.point not in target.parents:
            continue
        if best is None or len(mount.point.parts) > len(best.point.parts):
            best = mount
    return best


def network_mount(path: Path, table: Sequence[Mount] | None = None) -> Mount | None:
    """The network filesystem at `path`, if that is what the table says.

    `table=None` reads the real one; tests pass a literal. A missing path is
    fine: the nearest existing prefix is resolved and the rest is appended, so
    a journal directory that does not exist yet is judged by its parent.
    """
    mounts = read_mounts() if table is None else table
    if mounts is None:
        return None
    mount = mount_for(path, mounts)
    if mount is not None and mount.fstype in NETWORK_FILESYSTEMS:
        return mount
    return None
