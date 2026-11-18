"""The apps pin travels as an AGit PR, never as a push to protected main.

`make ship` once built and pushed an image and then failed at
`git push origin main` into homelab-applications, leaving the stack on the old
image while the driver reported a failure at the last step. These scans are
cheap and catch the obvious regression.

The merge helper is a heredoc inside the shell script. It is extracted and run
against a fake Gitea here, because the real server answers a successful merge
with an empty body and a JSON-only client crashed on it.
"""

import json
import re
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "deploy-gitea"
TEXT = SCRIPT.read_text(encoding="utf-8")

HEREDOCS = re.findall(r"<<'PY'\n(.*?)\nPY\n", TEXT, re.S)
MERGE_HELPER = next(
    (block for block in HEREDOCS if "merge_when_checks_succeed" in block), None
)
HEAD = "a" * 40


def test_pin_uses_agit_and_not_a_push_to_main():
    assert "refs/for/main" in TEXT
    assert "push origin main" not in TEXT
    assert "reset --hard" not in TEXT


def test_pin_is_checked_against_origin_main():
    # The local file alone is how a stale, unmerged pin commit read as success.
    assert "show origin/main:compose/credarr/compose.yaml" in TEXT


def test_merge_token_is_operator_supplied():
    assert "${GITEA_TOKEN:-}" in TEXT
    # No file, vault or default value may stand in for the operator's token.
    assert "gitea.token" not in TEXT
    assert "GITEA_TOKEN=" not in TEXT.replace("GITEA_TOKEN=$GITEA_TOKEN", "")


class FakeGitea(BaseHTTPRequestHandler):
    state = {}

    def log_message(self, *args):
        pass

    def _send(self, status, body=None):
        data = b"" if body is None else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.state["merge"] = json.loads(self.rfile.read(length))
        if self.headers.get("Authorization") != "token test-token":
            self._send(401, {"message": "auth"})
        else:
            self._send(self.state["merge_status"])

    def do_GET(self):
        self.state["polls"] += 1
        if self.state["get_status"] != 200:
            self._send(self.state["get_status"], {"message": "no"})
        elif self.state["merged_after"] and self.state["polls"] >= self.state["merged_after"]:
            self._send(200, {"merged": True, "state": "closed", "html_url": "http://x/pulls/1"})
        else:
            self._send(200, {"merged": False, "state": "open"})


def run_helper(tmp_path, *, merge_status=200, merged_after=1, get_status=200, timeout=10):
    assert MERGE_HELPER, "merge helper heredoc not found in deploy-gitea"
    FakeGitea.state = {
        "merge_status": merge_status,
        "merged_after": merged_after,
        "get_status": get_status,
        "polls": 0,
        "merge": None,
    }
    server = HTTPServer(("127.0.0.1", 0), FakeGitea)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    helper = tmp_path / "merge_helper.py"
    helper.write_text(MERGE_HELPER, encoding="utf-8")
    api = f"http://127.0.0.1:{server.server_port}/api/v1/repos/admin/x/pulls/1"
    result = subprocess.run(
        [sys.executable, str(helper), api, HEAD, str(timeout)],
        text=True,
        capture_output=True,
        env={"PATH": "/usr/bin:/bin", "GITEA_TOKEN": "test-token"},
        timeout=30,
    )
    server.shutdown()
    return result


def test_empty_200_merge_body_is_success(tmp_path):
    # The real server answers an immediate merge with 200 and no body.
    result = run_helper(tmp_path, merge_status=200, merged_after=1)
    assert result.returncode == 0, result.stderr
    assert "merged" in result.stdout
    assert FakeGitea.state["merge"] == {
        "Do": "merge",
        "merge_when_checks_succeed": True,
        "head_commit_id": HEAD,
    }


def test_empty_201_scheduled_body_polls_until_merged(tmp_path):
    # Checks pending: 201, no body, then the poll sees the merge land.
    result = run_helper(tmp_path, merge_status=201, merged_after=2)
    assert result.returncode == 0, result.stderr
    assert FakeGitea.state["polls"] >= 2


def test_failed_merge_request_reports_the_body(tmp_path):
    result = run_helper(tmp_path, merge_status=405)
    assert result.returncode == 1
    assert "HTTP 405" in result.stderr


def test_rejected_merge_stops_on_the_first_read(tmp_path):
    result = run_helper(tmp_path, get_status=403)
    assert result.returncode == 1
    assert "HTTP 403" in result.stderr


def test_unmerged_pull_request_times_out(tmp_path):
    result = run_helper(tmp_path, merged_after=None, timeout=0)
    assert result.returncode == 1
    assert "not merged after 0s" in result.stderr
