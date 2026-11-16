"""Filesystem primitives shared by the engine and the server."""

from __future__ import annotations

import os
from pathlib import Path


def fsync_directory(path: Path) -> None:
    """Make a rename durable by fsyncing the directory that holds it."""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
