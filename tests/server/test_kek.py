"""The KEK command line: status, rewrap, and the refusal to invent a new key."""

from __future__ import annotations

from pathlib import Path

from credarr.redact import Secret
from credarr.targets import build_registry
from credarr_server.kek_cli import main
from credarr_server.store import TopologyStore

REGISTRY = build_registry()
MANIFEST = """version: 1
credentials:
  sonarr_api_key:
    class: B
    never_rotate: true
"""


def _store(tmp_path: Path) -> TopologyStore:
    manifest = tmp_path / "credentials.yaml"
    manifest.write_text(MANIFEST, encoding="utf-8")
    store = TopologyStore(tmp_path / "app.db")
    store.import_manifest(manifest, REGISTRY)
    return store


def test_status_and_rotate_keep_the_value_readable(tmp_path: Path, capsys) -> None:
    store = _store(tmp_path)
    store.set_value("sonarr_api_key", Secret("kek-value-0123456789"))
    assert main(["--config-dir", str(tmp_path), "status"]) == 0
    assert "present: True" in capsys.readouterr().out
    assert main(["--config-dir", str(tmp_path), "rotate"]) == 0
    assert "rewrapped" in capsys.readouterr().out
    reopened = TopologyStore(tmp_path / "app.db")
    assert reopened.get_value("sonarr_api_key").reveal() == "kek-value-0123456789"


def test_a_missing_key_is_not_replaced_over_values(tmp_path: Path, capsys) -> None:
    store = _store(tmp_path)
    store.set_value("sonarr_api_key", Secret("kek-value-0123456789"))
    (tmp_path / "kek.json").unlink()
    assert main(["--config-dir", str(tmp_path), "status"]) != 0
    assert main(["--config-dir", str(tmp_path), "init"]) != 0
    output = capsys.readouterr().err
    assert "refusing" in output
