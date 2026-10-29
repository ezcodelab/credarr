"""Run-once: cron's half of the server, over the app's own store.

The console is where the topology lives, so a scheduled run must audit `app.db`
and not a stale manifest file. These tests pin the contract a cron job binds
to: the CLI's JSON document, the CLI's exit code, a recorded ledger row, and
the notification the run would have sent.
"""

from __future__ import annotations

import json

import pytest

from conftest import SONARR_KEY, server_config
from credarr.redact import Secret
from credarr_server.app import main as server_main
from credarr_server.audit_log import AuditLog
from credarr_server.notifier import Notifier
from credarr_server.store import TopologyStore


def _command(app, tmp_path, *extra: str) -> list[str]:
    return [
        "--once",
        "--config",
        str(server_config(app, tmp_path)),
        "--config-dir",
        str(tmp_path),
        *extra,
    ]


def test_a_clean_cron_run_exits_zero_with_the_cli_document(app, tmp_path, capsys) -> None:
    assert server_main(_command(app, tmp_path, "--json")) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["version"] == 1
    assert [(row["name"], row["status"]) for row in document["credentials"]] == [
        ("sonarr_api_key", "match"),
        ("seerr_api_key", "indirect"),
    ]

    state = AuditLog(tmp_path / "app.db").last_state()
    assert state is not None and state.last_audit is not None


def test_drift_is_exit_one_in_the_cli_words(app, tmp_path, capsys) -> None:
    app.store.set_value("sonarr_api_key", Secret("0" * 32))
    assert server_main(_command(app, tmp_path, "--json")) == 1
    document = json.loads(capsys.readouterr().out)
    assert document["summary"]["status"] == "drift"


def test_the_first_cron_run_is_a_baseline_and_the_change_is_notified(
    app, tmp_path, sink, capsys
) -> None:
    Notifier(tmp_path / "app.db").save_service("webhook", "webhook", url=sink.url)

    assert server_main(_command(app, tmp_path)) == 0
    capsys.readouterr()
    assert sink.requests == [], "a baseline is not a change"

    app.store.set_value("sonarr_api_key", Secret("0" * 32))
    assert server_main(_command(app, tmp_path)) == 1
    capsys.readouterr()

    request = sink.requests[-1]
    assert json.loads(request["body"])["kind"] == "drift"
    assert json.loads(request["body"])["credential"] == "sonarr_api_key"
    assert SONARR_KEY.encode() not in request["body"]
    assert SONARR_KEY not in json.dumps(request["headers"])


def test_an_empty_store_is_not_a_clean_bill_of_health(app, tmp_path, capsys) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    TopologyStore(empty / "app.db")
    assert (
        server_main(
            [
                "--once",
                "--config",
                str(server_config(app, empty)),
                "--config-dir",
                str(empty),
            ]
        )
        == 3
    )
    assert "no topology has been imported" in capsys.readouterr().err


def test_json_without_once_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as refusal:
        server_main(["--json"])
    assert refusal.value.code == 2


def test_a_missing_config_is_exit_three_with_a_sentence(tmp_path, capsys) -> None:
    assert (
        server_main(
            [
                "--once",
                "--config",
                str(tmp_path / "nope.yaml"),
                "--config-dir",
                str(tmp_path),
            ]
        )
        == 3
    )
    assert "cannot read config" in capsys.readouterr().err
