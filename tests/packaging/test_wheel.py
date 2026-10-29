"""The wheel is the image's input: the console and the three scripts.

A wheel that builds but misses `web/` is an API-only image that looks fine in
the build log. The test builds a wheel from a copy of the packaging inputs -
with a stand-in console, since building the real one is Node's job - and reads
it back. It shells out to pip, never Docker.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

from credarr import __version__

ROOT = Path(__file__).resolve().parents[2]


def test_the_wheel_carries_the_console_and_the_three_scripts(tmp_path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    for name in ("pyproject.toml", "README.md", "LICENSE"):
        shutil.copy2(ROOT / name, source / name)
    shutil.copytree(
        ROOT / "src",
        source / "src",
        ignore=shutil.ignore_patterns("__pycache__", "web"),
    )
    web = source / "src" / "credarr_server" / "web"
    (web / "assets").mkdir(parents=True)
    (web / "index.html").write_text("<!doctype html><title>credarr</title>")
    (web / "assets" / "app.js").write_text("console.log('credarr')\n")

    wheels = tmp_path / "wheels"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            ".",
            "--wheel-dir",
            str(wheels),
        ],
        cwd=source,
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "PIP_DISABLE_PIP_VERSION_CHECK": "1"},
    )

    (wheel,) = wheels.glob("*.whl")
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        entry_points = archive.read(
            next(name for name in names if name.endswith("entry_points.txt"))
        ).decode()
        metadata = archive.read(
            next(name for name in names if name.endswith(".dist-info/METADATA"))
        ).decode()

    assert wheel.name == f"credarr-{__version__}-py3-none-any.whl"
    assert f"Version: {__version__}\n" in metadata
    assert "credarr_server/web/index.html" in names
    assert "credarr_server/web/assets/app.js" in names
    assert "credarr_server/backup.py" in names
    assert "credarr_server/mounts.py" in names
    assert "credarr = credarr.cli:main" in entry_points
    assert "credarr-server = credarr_server.app:main" in entry_points
    assert "credarr-backup = credarr_server.backup:main" in entry_points
