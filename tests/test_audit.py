"""The end-to-end audit, and the gate that matters most:

    the tool must fail on synthetic drift.

A drift checker that has only ever reported "clean" is not evidence of
anything - it may simply never have looked. So the last tests here deliberately
corrupt one copy of one credential and require a non-clean verdict, with the
unmodified fixture passing first as the control.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import PROWLARR_KEY, RADARR_KEY, SONARR_KEY
from credarr.audit import Auditor, Status
from credarr.config import Config, HostConfig
from credarr.errors import ManifestError
from credarr.facade import read_manifest
from credarr.fingerprint import Fingerprinter
from credarr.model import Manifest
from credarr.secrets import StaticSource
from credarr.targets import build_registry

REGISTRY = build_registry()

SEERR_KEY = "seerr-own-key-000000000000000"  # gitleaks:allow

VAULT = {
    "vault_env_secrets": {
        "prowlarr": {"HOMEPAGE_VAR_PROWLARR_API_KEY": PROWLARR_KEY},
        "sonarr": {"HOMEPAGE_VAR_SONARR_API_KEY": SONARR_KEY},
        "seerr": {"SEERR_API_KEY": SEERR_KEY},
    }
}


def _manifest() -> str:
    return """
version: 1
credentials:
  prowlarr_api_key:
    class: A
    max_age_days: 90
    vault:
      backend: ansible-vault
      file: vault.yml
      path: [vault_env_secrets, prowlarr, HOMEPAGE_VAR_PROWLARR_API_KEY]
    consumers:
      - target: sonarr.indexers
        count: 2
      - target: radarr.indexers
        count: 1
      - target: homepage.label
        count: 1
        mechanism: redeploy
"""


def _parse(text: str) -> Manifest:
    return Manifest.parse(
        text, known_targets=REGISTRY.known_targets(), known_backends=("ansible-vault", "sops")
    )


def _audit(
    manifest_text: str,
    *,
    urls: dict[str, str] | None = None,
    only: set[str] | None = None,
):
    host = HostConfig(name="default", urls=urls or {})
    from credarr.config import Config

    config = Config(version=1, default_host="default", hosts={"default": host},
                    manifest=Path("m.yml"))
    auditor = Auditor(
        manifest=_parse(manifest_text),
        config=config,
        secrets=StaticSource(VAULT),
        fingerprinter=Fingerprinter(),
    )
    return auditor.run(only=only)


def _audit_with_broken_transport(message: str, *, urls: dict[str, str] | None = None):
    """An audit whose every transport call fails with `message`."""
    from conftest import FakeTransport
    from credarr.errors import TransportError

    class Broken(FakeTransport):
        def run_python(self, code, *, timeout=None):
            raise TransportError(message)

    host = HostConfig(name="default", urls=urls or {})
    from credarr.config import Config

    config = Config(version=1, default_host="default", hosts={"default": host},
                    manifest=Path("m.yml"))
    auditor = Auditor(
        manifest=_parse(_manifest()), config=config,
        secrets=StaticSource(VAULT), fingerprinter=Fingerprinter(),
    )
    import credarr.audit as audit_module

    original = audit_module.build_transport
    audit_module.build_transport = lambda: Broken()
    try:
        return auditor.run()
    finally:
        audit_module.build_transport = original


# --- the gate ----------------------------------------------------------------


def test_without_a_readback_every_holder_is_unverifiable():
    """Strict API-only: a holder with no readable API copy is not a finding.

    Rotation may hold the value, but this build cannot compare it. The audit
    must say that instead of pretending the value matched.
    """
    result = _audit(_manifest())

    assert result.exit_status is Status.UNVERIFIABLE
    assert all(
        consumer.status is Status.UNVERIFIABLE
        for credential in result.results
        for consumer in credential.consumers
        if consumer.consumer.target.key != "homepage.label"
    )
    assert any(
        "does not expose a readable copy" in consumer.detail
        for credential in result.results
        for consumer in credential.consumers
    )
    assert any(
        consumer.reason == "no_url"
        for credential in result.results
        for consumer in credential.consumers
    )
    assert not result.problems


STALE_KEY = "stale-holder-key-000000000"


LIVE_MANIFEST = """
version: 1
credentials:
  prowlarr_api_key:
    class: A
    max_age_days: 90
    vault:
      backend: ansible-vault
      file: vault.yml
      path: [vault_env_secrets, prowlarr, HOMEPAGE_VAR_PROWLARR_API_KEY]
    consumers:
      - target: sonarr.indexers
        count: 2
  sonarr_api_key:
    class: A
    max_age_days: 90
    vault:
      backend: ansible-vault
      file: vault.yml
      path: [vault_env_secrets, sonarr, HOMEPAGE_VAR_SONARR_API_KEY]
"""


PROCESS_MANIFEST = """
version: 1
credentials:
  sonarr_api_key:
    class: A
    max_age_days: 90
    vault:
      backend: ansible-vault
      file: vault.yml
      path: [vault_env_secrets, sonarr, HOMEPAGE_VAR_SONARR_API_KEY]
    consumers:
      - target: seerr.settings_json[sonarr]
        count: 1
        mechanism: process_api
"""

# The audit needs the holder's own key, not just the holder's URL. This
# declaration supplies it; the no-key test below deliberately omits it.
PROCESS_MANIFEST_WITH_KEY = PROCESS_MANIFEST + """
  seerr_api_key:
    class: B
    never_rotate: true
    canonical:
      service: seerr
    vault:
      backend: ansible-vault
      file: vault.yml
      path: [vault_env_secrets, seerr, SEERR_API_KEY]
"""


class SeerrAPI:
    """The measured Seerr settings route, returning the live API key."""

    def __init__(
        self,
        *,
        value: str = SONARR_KEY,
        auth_key: str = SEERR_KEY,
        echo: str | None = None,
    ) -> None:
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        self.value = value
        self.auth_key = auth_key
        self.echo = echo
        self.requests: list[tuple[str, str]] = []
        api = self

        class Handler(BaseHTTPRequestHandler):
            def _answer(self, status: int, payload: object) -> None:
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                api.requests.append(("GET", self.path))
                if self.headers.get("X-API-Key") != api.auth_key:
                    self._answer(401, {})
                    return
                if api.echo is not None:
                    self._answer(400, {"message": api.echo})
                    return
                if self.path == "/api/v1/settings/sonarr":
                    self._answer(200, [
                        {"apiKey": api.value, "name": "Sonarr"},
                    ])
                    return
                self._answer(404, {})

            def log_message(self, format: str, *args: object) -> None:
                """Silence. A test's output is its assertions."""

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class HolderAPI:
    """The measured holder test route, with its list and single-row GETs."""

    def __init__(
        self, *, reject: bool = False, network: bool = False, rows: int = 2,
        functional: bool = False,
    ) -> None:
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        self.reject = reject
        self.network = network
        self.functional = functional
        self.rows = rows
        self.requests: list[tuple[str, str]] = []
        self.tests = 0
        holder = self

        class Handler(BaseHTTPRequestHandler):
            def _answer(self, status: int, payload: object) -> None:
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                holder.requests.append(("GET", self.path))
                if self.headers.get("X-Api-Key") != SONARR_KEY:
                    self._answer(401, {})
                    return
                path = self.path.split("?", 1)[0]
                if path == "/api/v3/indexer":
                    self._answer(200, [
                        {
                            "id": index,
                            "name": f"Indexer {index}",
                            "fields": [
                                {"name": "apiKey", "value": "********"},
                            ],
                        }
                        for index in range(holder.rows)
                    ])
                    return
                if path.startswith("/api/v3/indexer/"):
                    try:
                        index = int(path.rsplit("/", 1)[1])
                    except ValueError:
                        self._answer(404, {})
                        return
                    self._answer(200, {
                        "id": index,
                        "name": f"Indexer {index}",
                        "fields": [
                            {"name": "apiKey", "value": "********"},
                            {"name": "baseUrl", "value": "http://prowlarr:9696"},
                        ],
                    })
                    return
                self._answer(404, {})

            def do_POST(self) -> None:
                holder.requests.append(("POST", self.path))
                if self.headers.get("X-Api-Key") != SONARR_KEY:
                    self._answer(401, {})
                    return
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                if self.path != "/api/v3/indexer/test":
                    self._answer(404, {})
                    return
                holder.tests += 1
                if holder.functional:
                    self._answer(
                        400,
                        [{
                            "isWarning": False,
                            "errorMessage": (
                                "Unable to connect to indexer: HTTP request "
                                f"failed: [410:Gone] [GET] at [http://holder/api"
                                f"?t=caps&apikey={STALE_KEY}]"
                            ),
                        }],
                    )
                    return
                if holder.network:
                    self._answer(
                        400,
                        [{
                            "isWarning": False,
                            "errorMessage": (
                                "Unable to connect to indexer: connection refused "
                                f"at [http://holder/api?apikey={STALE_KEY}]"
                            ),
                        }],
                    )
                    return
                if holder.reject:
                    # Deliberately echoes both known credentials and an unknown
                    # stale one in a URL: the audit must scrub all three before
                    # either reaches a report or the ledger.
                    self._answer(
                        400,
                        [{
                            "isWarning": False,
                            "errorMessage": (
                                f"invalid credentials {SONARR_KEY} {PROWLARR_KEY} "
                                f"at [http://holder/api?apikey={STALE_KEY}]"
                            ),
                        }],
                    )
                    return
                self._answer(200, {})

            def log_message(self, format: str, *args: object) -> None:
                """Silence. A test's output is its assertions."""

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def test_a_missing_store_uses_the_holders_own_test_as_liveness():
    """No config bind: ask the holder to use its stored value.

    The accepted test is evidence that the holder is live. It is not equality -
    the value was never read - so the credential must not summarize as match.
    """
    holder = HolderAPI()
    try:
        result = _audit(
            LIVE_MANIFEST, urls={"sonarr": holder.url}, only={"prowlarr_api_key"},
        )
    finally:
        holder.close()

    credential = result.results[0]
    assert credential.status is Status.LIVE
    assert credential.consumers[0].status is Status.LIVE
    assert "not read back" in credential.consumers[0].detail
    # The rows were listed and their tests accepted, so the live scope is known
    # even though equality is not: the console can show (and offer) the count.
    assert credential.consumers[0].observed_count == 2
    assert result.exit_status is Status.LIVE
    assert not result.problems
    from credarr.report import exit_code_for

    assert exit_code_for(result) == 0
    assert holder.tests == 2


def test_a_disabled_indexer_is_a_functional_result_not_a_bad_key():
    """Prowlarr authenticates first, then answers 410 for a disabled indexer.

    The copy is still live; the indexer's own state explains why the test could
    not run a query. It must not turn the credential unverifiable, and the
    service's reason must survive with the URL credential scrubbed.
    """
    holder = HolderAPI(functional=True)
    try:
        result = _audit(
            LIVE_MANIFEST, urls={"sonarr": holder.url}, only={"prowlarr_api_key"},
        )
    finally:
        holder.close()

    consumer = result.results[0].consumers[0]
    assert consumer.status is Status.LIVE
    assert "410:Gone" in consumer.detail
    assert "non-credential condition" in consumer.detail
    assert consumer.observed_count == 2
    assert STALE_KEY not in consumer.detail
    assert result.exit_status is Status.LIVE
    assert not result.problems


def test_a_rejected_liveness_test_is_unverifiable_not_drift():
    """A refusal is ambiguous: a stale process and an access layer look the same.

    It is still a real observation, so it must reach the report - but as "not
    compared", not as a finding that would fail CI.
    """
    holder = HolderAPI(reject=True)
    try:
        result = _audit(
            LIVE_MANIFEST, urls={"sonarr": holder.url}, only={"prowlarr_api_key"},
        )
    finally:
        holder.close()

    consumer = result.results[0].consumers[0]
    assert consumer.status is Status.UNVERIFIABLE
    assert "rejected" in consumer.detail
    assert "not proof of drift" in consumer.detail
    assert result.exit_status is Status.UNVERIFIABLE
    assert not result.problems
    assert SONARR_KEY not in consumer.detail
    assert PROWLARR_KEY not in consumer.detail
    assert STALE_KEY not in consumer.detail
    assert "[redacted]" in consumer.detail


def test_an_inconclusive_liveness_test_names_its_reason():
    """A network failure is not a credential verdict, but it is the reason.

    The measured holder test can fail because its stored URL is wrong, not
    because the key is; the report must say that instead of a bare count.
    """
    holder = HolderAPI(network=True)
    try:
        result = _audit(
            LIVE_MANIFEST, urls={"sonarr": holder.url}, only={"prowlarr_api_key"},
        )
    finally:
        holder.close()

    consumer = result.results[0].consumers[0]
    assert consumer.status is Status.UNVERIFIABLE
    assert "Unable to connect" in consumer.detail
    assert STALE_KEY not in consumer.detail
    assert result.exit_status is Status.UNVERIFIABLE
    assert not result.problems


def test_liveness_without_a_service_key_stays_unverifiable():
    """A holder's URL is not enough: the audit needs that holder's own key."""
    holder = HolderAPI()
    try:
        result = _audit(
            _manifest(), urls={"sonarr": holder.url}, only={"prowlarr_api_key"},
        )
    finally:
        holder.close()

    consumer = result.results[0].consumers[0]
    assert consumer.status is Status.UNVERIFIABLE
    assert "not a match" in consumer.detail
    assert result.exit_status is Status.UNVERIFIABLE
    assert holder.requests == []


def test_a_qualified_row_missing_from_the_holders_api_is_not_a_finding():
    """The holder's list is observable, but a filtered list is not proof.

    Without the database, "no row named X" can mean a filtered endpoint or a
    missing copy. It must stay honest and not fail the run.
    """
    holder = HolderAPI()
    manifest = LIVE_MANIFEST.replace(
        "target: sonarr.indexers\n        count: 2",
        "target: sonarr.indexers[Absent row]\n        count: 1",
    )
    try:
        result = _audit(
            manifest, urls={"sonarr": holder.url}, only={"prowlarr_api_key"},
        )
    finally:
        holder.close()

    consumer = result.results[0].consumers[0]
    assert consumer.status is Status.UNVERIFIABLE
    assert "Absent row" in consumer.detail
    assert "not a finding" in consumer.detail
    assert consumer.reason == "row_missing"
    # The name filter is trustworthy even when the copy is not readable: the
    # API listed no row by that name.
    assert consumer.observed_count == 0
    assert not result.problems
    assert result.exit_status is Status.UNVERIFIABLE


def test_an_unqualified_empty_list_is_not_a_finding():
    """A list with no credential field cannot be called a missing copy."""
    holder = HolderAPI(rows=0)
    try:
        result = _audit(
            LIVE_MANIFEST, urls={"sonarr": holder.url}, only={"prowlarr_api_key"},
        )
    finally:
        holder.close()

    consumer = result.results[0].consumers[0]
    assert consumer.status is Status.UNVERIFIABLE
    assert "lists no rows carrying" in consumer.detail
    assert "not a finding" in consumer.detail
    assert consumer.reason == "field_missing"
    # An empty filtered list cannot be counted: list endpoints may omit the
    # field, so `0` would be an invented number rather than an observation.
    assert consumer.observed_count is None
    assert not result.problems
    assert result.exit_status is Status.UNVERIFIABLE


def test_a_qualified_row_with_the_wrong_copy_count_is_not_live():
    """One accepted row is not proof of two declared copies."""
    holder = HolderAPI()
    manifest = LIVE_MANIFEST.replace(
        "target: sonarr.indexers\n        count: 2",
        "target: sonarr.indexers[Indexer 0]\n        count: 2",
    )
    try:
        result = _audit(
            manifest, urls={"sonarr": holder.url}, only={"prowlarr_api_key"},
        )
    finally:
        holder.close()

    consumer = result.results[0].consumers[0]
    assert consumer.status is Status.UNVERIFIABLE
    assert "declared 2 copies" in consumer.detail
    assert "1 row(s)" in consumer.detail
    assert consumer.reason == "count_mismatch"
    # The API listed one row; the console can offer to set the count to it.
    assert consumer.observed_count == 1
    assert result.exit_status is Status.UNVERIFIABLE


def test_a_process_api_holder_is_verified_over_its_live_api():
    """The running process is the evidence, not the file it was loaded from.

    Seerr's settings route returns the in-memory key, so the audit can prove
    equality without over-claiming what the file alone can say.
    """
    api = SeerrAPI()
    try:
        result = _audit(
            PROCESS_MANIFEST_WITH_KEY, urls={"seerr": api.url},
            only={"sonarr_api_key"},
        )
    finally:
        api.close()

    credential = result.results[0]
    consumer = credential.consumers[0]
    assert consumer.status is Status.MATCH
    assert credential.status is Status.MATCH
    assert result.exit_status is Status.MATCH
    assert "running seerr process" in consumer.detail
    assert api.requests == [("GET", "/api/v1/settings/sonarr")]
    assert consumer.observed_count == 1
    assert SONARR_KEY not in consumer.detail
    assert SEERR_KEY not in consumer.detail


def test_a_process_api_holder_does_not_need_the_file_mount():
    """The live API is the evidence, so a backup/restore host is enough.

    This is the same promise the rotation path makes: a URL and the holder's
    own key, with no config directory to read.
    """
    api = SeerrAPI()
    try:
        result = _audit(
            PROCESS_MANIFEST_WITH_KEY, urls={"seerr": api.url}, only={"sonarr_api_key"},
        )
    finally:
        api.close()

    consumer = result.results[0].consumers[0]
    assert consumer.status is Status.MATCH
    assert "running seerr process" in consumer.detail
    assert api.requests == [("GET", "/api/v1/settings/sonarr")]


def test_a_process_api_holder_reports_the_live_count_it_saw():
    """The count is a declaration; the settings API lists the live entries.

    A holder declared as two copies while the process reports one is drift -
    and the payload carries the 1, so a console can propose the count the stack
    actually reports. (The tripwire stays: this is a finding, not a silent
    adoption.)
    """
    api = SeerrAPI()
    manifest = PROCESS_MANIFEST_WITH_KEY.replace("count: 1", "count: 2")
    try:
        result = _audit(
            manifest, urls={"seerr": api.url}, only={"sonarr_api_key"},
        )
    finally:
        api.close()

    consumer = result.results[0].consumers[0]
    assert consumer.status is Status.DRIFT
    assert "reports 1 'sonarr' entry where 2 copies were declared" in consumer.detail
    assert consumer.observed_count == 1
    assert result.exit_status is Status.DRIFT


def test_a_process_api_holder_that_disagrees_is_drift():
    """The live value is authoritative; a mismatch is a finding, not a gap."""
    api = SeerrAPI(value=RADARR_KEY)
    try:
        result = _audit(
            PROCESS_MANIFEST_WITH_KEY, urls={"seerr": api.url},
            only={"sonarr_api_key"},
        )
    finally:
        api.close()

    credential = result.results[0]
    consumer = credential.consumers[0]
    assert consumer.status is Status.DRIFT
    assert result.exit_status is Status.DRIFT
    assert "differ from the saved value" in consumer.detail
    assert consumer.reason == "value_drift"
    assert RADARR_KEY not in consumer.detail
    assert SEERR_KEY not in consumer.detail


def test_a_process_api_holder_without_its_own_key_is_not_a_match():
    """A declared live read that cannot authenticate never falls back to green."""
    api = SeerrAPI()
    try:
        result = _audit(
            PROCESS_MANIFEST, urls={"seerr": api.url},
            only={"sonarr_api_key"},
        )
    finally:
        api.close()

    consumer = result.results[0].consumers[0]
    assert consumer.status is Status.UNVERIFIABLE
    assert "no stored key for seerr" in consumer.detail
    assert "not confirmed" in consumer.detail
    assert consumer.reason == "no_service_key"
    assert api.requests == []


def test_a_process_api_holder_that_rejects_the_key_is_not_a_match():
    """A 401 is a reason, not a file-level match wearing a green pill."""
    api = SeerrAPI(auth_key="different-holder-key")
    try:
        result = _audit(
            PROCESS_MANIFEST_WITH_KEY, urls={"seerr": api.url},
            only={"sonarr_api_key"},
        )
    finally:
        api.close()

    consumer = result.results[0].consumers[0]
    assert consumer.status is Status.UNVERIFIABLE
    assert "did not answer" in consumer.detail
    assert "not confirmed" in consumer.detail


def test_manual_consumers_are_neutral_and_not_claimed_as_verified():
    result = _audit(_manifest())
    indirect = [
        c for r in result.results for c in r.consumers if c.status is Status.INDIRECT
    ]
    assert len(indirect) == 1
    assert str(indirect[0].consumer.target) == "homepage.label"
    assert indirect[0].detail == ""
    assert indirect[0].reason == "manual_copy"


def test_a_manual_only_credential_is_healthy():
    """A knowingly configured manual copy is not an anomaly.

    The audit has nothing to compare, but it must not invent a warning for a
    Homepage label the operator deliberately declared.
    """
    result = _audit("""
version: 1
credentials:
  prowlarr_api_key:
    class: A
    max_age_days: 90
    vault:
      backend: ansible-vault
      file: vault.yml
      path: [vault_env_secrets, prowlarr, HOMEPAGE_VAR_PROWLARR_API_KEY]
    consumers:
      - target: homepage.label
        count: 1
        mechanism: redeploy
""")
    assert result.exit_status is Status.MATCH
    assert result.results[0].status is Status.MATCH
    assert "manual copies only" in result.results[0].detail
    assert "no API read-back" in result.results[0].detail
    assert result.results[0].reason == "manual_only"
    assert result.results[0].consumers[0].status is Status.INDIRECT
    assert result.results[0].consumers[0].detail == ""
    assert result.results[0].consumers[0].reason == "manual_copy"


def test_a_profilarr_arr_copy_is_manual_and_does_not_change_the_verdict():
    """The registered no-writer target reaches the manual branch, not a
    comparison that would claim the copy was checked."""
    result = _audit("""
version: 1
credentials:
  sonarr_api_key:
    class: A
    max_age_days: 90
    vault:
      backend: ansible-vault
      file: vault.yml
      path: [vault_env_secrets, sonarr, HOMEPAGE_VAR_SONARR_API_KEY]
    consumers:
      - target: profilarr.arr_config[Sonarr]
""")
    credential = result.results[0]
    assert result.exit_status is Status.MATCH
    assert credential.status is Status.MATCH
    assert "manual copies only" in credential.detail
    assert credential.consumers[0].status is Status.INDIRECT
    assert credential.consumers[0].detail == ""


def test_unreachable_holder_is_unverifiable_not_a_match():
    """An API-only audit cannot read a holder that is down.

    It must say the copy was not compared, not fail the run as drift and not
    wave it through as a match.
    """
    result = _audit_with_broken_transport(
        "connection refused",
        urls={"sonarr": "http://127.0.0.1:1", "radarr": "http://127.0.0.1:1"},
    )

    assert result.exit_status is Status.UNVERIFIABLE
    assert not result.problems
    assert all(c.observed_count is None for c in result.results[0].consumers)


def test_an_error_that_echoes_the_value_is_scrubbed():
    """An API that echoes what it was given reaches reports and the audit log,
    so the engine scrubs the value before the message leaves the comparison."""
    api = SeerrAPI(echo=SONARR_KEY)
    try:
        result = _audit(
            PROCESS_MANIFEST_WITH_KEY, urls={"seerr": api.url},
            only={"sonarr_api_key"},
        )
    finally:
        api.close()

    details = [c.detail for r in result.results for c in r.consumers]
    assert details
    assert all(SONARR_KEY not in detail for detail in details)
    assert any("[redacted]" in detail for detail in details)


# --- helpers -----------------------------------------------------------------


def test_the_audit_json_carries_the_live_row_count():
    """`--json` is a consumer too: the observed count travels next to the
    declaration (DECISIONS 26), so a script need not parse the sentence."""
    import io

    from credarr.report import render_json

    holder = HolderAPI()
    try:
        result = _audit(
            LIVE_MANIFEST, urls={"sonarr": holder.url}, only={"prowlarr_api_key"},
        )
    finally:
        holder.close()

    out = io.StringIO()
    render_json(result, out)
    (credential,) = json.loads(out.getvalue())["credentials"]
    (consumer,) = credential["consumers"]
    assert consumer["count"] == 2
    assert consumer["observed_count"] == 2


@pytest.mark.parametrize("body,expected", [
    ("class: A", "max_age_days"),
    ("class: A-unv", "max_age_days"),
])
def test_rotatable_classes_must_state_an_age(body, expected):
    with pytest.raises(Exception, match=expected):
        _parse(f"version: 1\ncredentials:\n  x:\n    {body}\n")


def test_unknown_target_is_an_error_not_a_skip():
    """The bug that made this tool silently useless."""
    text = """
version: 1
credentials:
  x:
    class: A
    max_age_days: 90
    vault: {backend: ansible-vault, file: v.yml, path: [a, b]}
    consumers:
      - target: prolarr.applications
"""
    with pytest.raises(Exception, match="unknown target"):
        _parse(text)


def test_class_b_must_declare_its_policy():
    with pytest.raises(Exception, match="never_rotate"):
        _parse("version: 1\ncredentials:\n  x:\n    class: B\n")


def test_unsupported_manifest_version_is_rejected():
    with pytest.raises(Exception, match="not supported"):
        _parse("version: 99\ncredentials: {}\n")


def test_duplicate_keys_are_rejected():
    with pytest.raises(Exception, match="duplicate key"):
        _parse("version: 1\ncredentials:\n  x:\n    class: A\n    class: B\n")


def test_an_unhashable_yaml_key_is_a_manifest_error():
    """A sequence key is legal YAML and unusable as a mapping key. It must name
    the line, not escape as a TypeError from the duplicate check."""
    with pytest.raises(ManifestError, match="must be a scalar"):
        _parse(
            "version: 1\ncredentials:\n  x:\n    canonical:\n"
            "      ? [a, b]\n      : c\n"
        )


@pytest.mark.parametrize("version", ["true", "1.0"])
def test_the_manifest_version_must_be_the_integer_one(version):
    with pytest.raises(ManifestError, match="not supported"):
        _parse(f"version: {version}\ncredentials: {{}}\n")


def test_a_manifest_that_is_not_utf8_is_a_manifest_error(tmp_path: Path):
    manifest = tmp_path / "credentials.yaml"
    manifest.write_bytes(b"version: 1\n# \xff\ncredentials: {}\n")
    with pytest.raises(ManifestError, match="valid UTF-8"):
        read_manifest(manifest, REGISTRY)


def test_a_duplicate_consumer_target_is_rejected():
    with pytest.raises(ManifestError, match="duplicate target"):
        _parse(
            "version: 1\ncredentials:\n  x:\n    class: A\n    max_age_days: 90\n"
            "    consumers:\n"
            "      - target: sonarr.indexers[One]\n"
            "      - target: sonarr.indexers[One]\n"
        )


def test_homepage_labels_may_repeat_across_credentials():
    """Every app can render its own Homepage widget from the same manual target.

    The target is declared-only (no writer), so two credentials naming it do not
    race for one writable copy. It is still rejected twice inside one credential.
    """
    manifest = _parse(
        "version: 1\ncredentials:\n"
        "  sonarr_api_key:\n    class: A\n    max_age_days: 90\n"
        "    consumers:\n      - target: homepage.label\n"
        "  radarr_api_key:\n    class: A\n    max_age_days: 90\n"
        "    consumers:\n      - target: homepage.label\n"
    )
    assert [
        str(consumer.target)
        for credential in manifest.credentials.values()
        for consumer in credential.consumers
    ] == ["homepage.label", "homepage.label"]


def test_two_qualified_rows_in_one_slot_are_distinct_consumers():
    manifest = _parse(
        "version: 1\ncredentials:\n  x:\n    class: A\n    max_age_days: 90\n"
        "    consumers:\n"
        "      - target: sonarr.indexers[One]\n"
        "      - target: sonarr.indexers[Two]\n"
    )
    assert [str(c.target) for c in manifest.credentials["x"].consumers] == [
        "sonarr.indexers[One]",
        "sonarr.indexers[Two]",
    ]


def test_unknown_keys_are_rejected():
    """A typo'd `consumers` removes every holder, and the rotation then mints a
    value it delivers to nobody, so an ignored key has to be an error."""
    with pytest.raises(Exception, match="unknown key 'cosumers'"):
        _parse(
            "version: 1\ncredentials:\n  x:\n    class: A\n    max_age_days: 90\n"
            "    cosumers:\n      - target: sonarr.indexers\n"
        )
    with pytest.raises(Exception, match="unknown key"):
        _parse("version: 1\ncredentials: {}\ncredentials_typo: {}\n")
    with pytest.raises(Exception, match="unknown key"):
        _parse(
            "version: 1\ncredentials:\n  x:\n    class: A\n    max_age_days: 90\n"
            "    vault: {backend: ansible-vault, file: v.yml, path: [a], extra: 1}\n"
        )
    with pytest.raises(Exception, match="unknown key"):
        _parse(
            "version: 1\ncredentials:\n  x:\n    class: A\n    max_age_days: 90\n"
            "    consumers:\n      - target: sonarr.indexers\n        shorage: x\n"
        )


@pytest.mark.parametrize(
    "canonical,expected",
    [
        ("!!set {a, b}", "plain data"),
        ("!!pairs [{a: 1}]", "plain data"),
        ("!!omap [{a: 1}]", "plain data"),
        ("!!binary aGk=", "plain data"),
        ("2026-10-15", "plain data"),
        (".nan", "finite"),
        (".inf", "finite"),
        ("{1: two}", "keys must be strings"),
        ('"a\\x85b"', "NEL"),
        ("9007199254740993", "holds exactly"),
    ],
)
def test_canonical_values_must_be_plain_data(canonical, expected):
    """YAML can express shapes that change on the way back out, or cannot cross
    the store's JSON, and each of these was measured before being rejected."""
    text = (
        "version: 1\ncredentials:\n  x:\n    class: A\n    max_age_days: 90\n"
        f"    canonical: {{note: {canonical}}}\n"
    )
    with pytest.raises(Exception, match=expected):
        _parse(text)


def test_a_recursive_alias_is_rejected():
    with pytest.raises(Exception, match="recursive alias"):
        _parse(
            "version: 1\ncredentials:\n  x:\n    class: A\n    max_age_days: 90\n"
            "    canonical: {note: &a [*a]}\n"
        )


def test_never_rotate_must_be_a_bool():
    """`bool("false")` is True, so a quoted "false" used to invert the flag."""
    with pytest.raises(Exception, match="never_rotate must be true or false"):
        _parse('version: 1\ncredentials:\n  x:\n    class: B\n    never_rotate: "false"\n')


def test_two_credentials_cannot_share_a_vault_entry():
    """Each credential name takes its own rotation lock, so two names for one
    value can double-mint the same service."""
    text = (
        "version: 1\ncredentials:\n"
        "  a_key:\n    class: A\n    max_age_days: 90\n"
        "    vault: {backend: ansible-vault, file: vault.yml, path: [s, key]}\n"
        "  b_key:\n    class: A\n    max_age_days: 90\n"
        "    vault: {backend: ansible-vault, file: ./vault.yml, path: [s, key]}\n"
    )
    with pytest.raises(Exception, match="one vault entry"):
        _parse(text)


def test_two_credentials_may_share_a_vault_file_at_different_paths():
    text = (
        "version: 1\ncredentials:\n"
        "  a_key:\n    class: A\n    max_age_days: 90\n"
        "    vault: {backend: ansible-vault, file: vault.yml, path: [s, a_key]}\n"
        "  b_key:\n    class: A\n    max_age_days: 90\n"
        "    vault: {backend: ansible-vault, file: vault.yml, path: [s, b_key]}\n"
    )
    assert set(_parse(text).credentials) == {"a_key", "b_key"}


def test_a_ref_is_keyed_as_resolved_not_as_written(tmp_path: Path):
    """`vault.yml` and an absolute path to that same file are one entry: the
    secrets layer joins a relative ref to the manifest's directory
    (`secrets.py: _resolve`), so the aliasing check must join it too."""
    manifest = tmp_path / "credentials.yaml"
    absolute = tmp_path / "vault.yml"

    def write(pair: str) -> None:
        manifest.write_text(
            "version: 1\ncredentials:\n"
            "  a_key:\n    class: A\n    max_age_days: 90\n"
            "    vault: {backend: ansible-vault, file: vault.yml, path: [s, key]}\n"
            "  b_key:\n    class: A\n    max_age_days: 90\n"
            f'    vault: {{backend: ansible-vault, file: "{pair}", path: [s, key]}}\n',
            encoding="utf-8",
        )

    write(str(absolute))
    with pytest.raises(Exception, match="one vault entry"):
        read_manifest(manifest, REGISTRY)

    write("sub/../vault.yml")
    with pytest.raises(Exception, match="one vault entry"):
        read_manifest(manifest, REGISTRY)


def test_max_age_days_and_count_stay_inside_a_json_reader():
    """The store binds these into SQLite and the API will carry them through
    JSON; past 2**53 that stops being the same integer (measured: the store
    raised OverflowError at bind time before this bound)."""
    huge = 2**53
    with pytest.raises(Exception, match="max_age_days must be a positive integer"):
        _parse(
            "version: 1\ncredentials:\n  x:\n    class: A\n"
            f"    max_age_days: {huge}\n"
            "    vault: {backend: ansible-vault, file: vault.yml, path: [s, key]}\n"
        )
    with pytest.raises(Exception, match="count must be a positive integer"):
        _parse(
            "version: 1\ncredentials:\n  x:\n    class: B\n    never_rotate: true\n"
            "    consumers:\n      - target: sonarr.indexers\n"
            f"        count: {huge}\n"
        )


@pytest.mark.parametrize(
    "field",
    [
        '    description: "a\\x85b"\n',
        '    vault: {backend: ansible-vault, file: "v\\x85.yml", path: [a]}\n',
        '    vault: {backend: ansible-vault, file: v.yml, path: ["a\\x85b"]}\n',
        '    consumers:\n      - target: "sonarr.indexers[r\\x85]"\n',
        '    consumers:\n      - target: sonarr.indexers\n        mechanism: "m\\x85n"\n',
        '    consumers:\n      - target: sonarr.indexers\n        host: "h\\x85n"\n',
    ],
)
def test_a_nel_anywhere_is_rejected(field):
    """A NEL is the one measured shape that parses and then folds to a space on
    the way back out, so every string the parser reads has to refuse it."""
    text = "version: 1\ncredentials:\n  x:\n    class: A\n    max_age_days: 90\n" + field
    with pytest.raises(Exception, match="NEL"):
        _parse(text)


# --- the report has to be actionable -----------------------------------------


def test_drift_names_the_row_and_field_not_just_a_count():
    """\"1 of 2 differ\" sends the operator back to the service. The report
    has to say which row and which field, or it is not actionable."""
    import io

    from credarr.report import render_human

    api = SeerrAPI(value=RADARR_KEY)
    try:
        result = _audit(
            PROCESS_MANIFEST_WITH_KEY, urls={"seerr": api.url},
            only={"sonarr_api_key"},
        )
    finally:
        api.close()

    buffer = io.StringIO()
    render_human(result, buffer, colour=False)
    output = buffer.getvalue()

    assert "sonarr:apiKey" in output
    assert RADARR_KEY not in output
    assert SONARR_KEY not in output


def test_a_passing_report_prints_no_credential_values():
    """The report is meant to be pasted into a ticket. Only fingerprints."""
    import io

    from credarr.report import render_human

    api = SeerrAPI()
    try:
        result = _audit(
            PROCESS_MANIFEST_WITH_KEY, urls={"seerr": api.url},
            only={"sonarr_api_key"},
        )
    finally:
        api.close()

    buffer = io.StringIO()
    render_human(result, buffer, colour=False)
    output = buffer.getvalue()

    for secret in (SONARR_KEY, SEERR_KEY):
        assert secret not in output


def test_a_manual_consumer_and_a_no_holder_credential_have_distinct_markers():
    """`manual` describes a configured copy; a credential with no holders is
    not a manual copy just because the audit had nothing to compare."""
    import io

    from credarr.report import render_human

    manual = _audit("""
version: 1
credentials:
  prowlarr_api_key:
    class: A
    max_age_days: 90
    vault:
      backend: ansible-vault
      file: vault.yml
      path: [vault_env_secrets, prowlarr, HOMEPAGE_VAR_PROWLARR_API_KEY]
    consumers:
      - target: homepage.label
        count: 1
        mechanism: redeploy
""")
    buffer = io.StringIO()
    render_human(manual, buffer, colour=False)
    assert "manual" in buffer.getvalue()
    assert "n/a" not in buffer.getvalue()

    no_holder = _audit("""
version: 1
credentials:
  prowlarr_api_key:
    class: A
    max_age_days: 90
    vault:
      backend: ansible-vault
      file: vault.yml
      path: [vault_env_secrets, prowlarr, HOMEPAGE_VAR_PROWLARR_API_KEY]
""")
    buffer = io.StringIO()
    render_human(no_holder, buffer, colour=False)
    assert "n/a" in buffer.getvalue()
    assert "manual" not in buffer.getvalue()


def test_json_output_carries_the_offending_rows():
    import io
    import json as _json

    from credarr.report import render_json

    api = SeerrAPI(value=RADARR_KEY)
    try:
        result = _audit(
            PROCESS_MANIFEST_WITH_KEY, urls={"seerr": api.url},
            only={"sonarr_api_key"},
        )
    finally:
        api.close()

    buffer = io.StringIO()
    render_json(result, buffer)
    payload = _json.loads(buffer.getvalue())
    sonarr = next(
        c for c in payload["credentials"] if c["name"] == "sonarr_api_key"
    )
    mismatched = sonarr["consumers"][0]["mismatched"]
    assert mismatched
    assert mismatched[0]["label"] == "sonarr"
    assert mismatched[0]["field"] == "apiKey"
    assert mismatched[0]["fingerprint"] != RADARR_KEY


def test_a_verified_credential_is_not_downgraded_by_an_indirect_consumer():
    """An indirect consumer is rendered from the canonical value, so nothing
    could have drifted. It must not pull a verified value down to `indirect`."""
    manifest = PROCESS_MANIFEST_WITH_KEY.replace(
        "      - target: seerr.settings_json[sonarr]\n"
        "        count: 1\n"
        "        mechanism: process_api",
        "      - target: seerr.settings_json[sonarr]\n"
        "        count: 1\n"
        "        mechanism: process_api\n"
        "      - target: homepage.label\n"
        "        count: 1\n"
        "        mechanism: redeploy",
    )
    api = SeerrAPI()
    try:
        result = _audit(manifest, urls={"seerr": api.url}, only={"sonarr_api_key"})
    finally:
        api.close()

    sonarr = next(
        r for r in result.results if r.credential.name == "sonarr_api_key"
    )
    statuses = {c.status for c in sonarr.consumers}
    assert Status.MATCH in statuses
    assert Status.INDIRECT in statuses
    assert sonarr.status is Status.MATCH


def test_a_manual_copy_does_not_hide_an_unverifiable_holder():
    manifest = PROCESS_MANIFEST_WITH_KEY.replace(
        "      - target: seerr.settings_json[sonarr]\n"
        "        count: 1\n"
        "        mechanism: process_api",
        "      - target: seerr.settings_json[sonarr]\n"
        "        count: 1\n"
        "        mechanism: process_api\n"
        "      - target: homepage.label\n"
        "        count: 1\n"
        "        mechanism: redeploy",
    )
    result = _audit(manifest, only={"sonarr_api_key"})

    sonarr = next(
        r for r in result.results if r.credential.name == "sonarr_api_key"
    )
    assert sonarr.status is Status.UNVERIFIABLE
    assert Status.INDIRECT in {c.status for c in sonarr.consumers}


def test_a_target_with_no_writer_is_manual_not_unverifiable():
    from credarr.model import Consumer, Target
    from credarr.redact import Secret

    config = HostConfig(name="default", urls={})
    auditor = Auditor(
        manifest=_parse(_manifest()),
        config=Config(
            version=1,
            default_host="default",
            hosts={"default": config},
            manifest=Path("m.yml"),
        ),
        secrets=StaticSource(VAULT),
        fingerprinter=Fingerprinter(),
    )
    consumer = Consumer(target=Target(system="acme", slot="secret"))
    result = auditor._evaluate_consumer(consumer, "fp", Secret("not-a-value"))

    assert result.status is Status.INDIRECT
    assert result.detail == ""
    assert result.reason == "manual_copy"


def test_a_credential_without_a_canonical_carries_its_reason():
    result = _audit("""
version: 1
credentials:
  sonarr_api_key:
    class: A
    max_age_days: 90
""")

    (credential,) = result.results
    assert credential.status is Status.UNVERIFIABLE
    assert credential.reason == "no_canonical"


def test_a_missing_canonical_value_carries_its_reason():
    result = _audit("""
version: 1
credentials:
  sonarr_api_key:
    class: A
    max_age_days: 90
    vault:
      backend: ansible-vault
      file: vault.yml
      path: [vault_env_secrets, missing, HOMEPAGE_VAR_SONARR_API_KEY]
""")

    (credential,) = result.results
    assert credential.status is Status.ERROR
    assert credential.reason == "value_missing"


# -- severity ----------------------------------------------------------------


def test_the_severity_map_covers_every_status():
    """A new status that nothing routes is invisible until runtime."""
    from credarr.audit import _SEVERITY, Status

    missing = [s for s in Status if s not in _SEVERITY]
    assert not missing, f"statuses with no severity: {missing}"


def test_live_sits_below_match_and_above_unverifiable():
    """Liveness is a real observation, but it is not a comparison."""
    from credarr.audit import _SEVERITY, Status

    assert _SEVERITY[Status.LIVE] < _SEVERITY[Status.MATCH]
    assert _SEVERITY[Status.LIVE] > _SEVERITY[Status.UNVERIFIABLE]
    assert _SEVERITY[Status.DRIFT] < _SEVERITY[Status.LIVE]


def test_live_never_exits_non_zero_or_summarizes_as_match():
    """A live holder is not equality and must not page anyone."""
    from credarr.audit import AuditResult, CredentialResult, Status
    from credarr.errors import ExitCode
    from credarr.report import exit_code_for

    live = AuditResult(results=[CredentialResult(
        credential=None, status=Status.LIVE
    )])
    assert exit_code_for(live) == ExitCode.OK
    assert live.exit_status is Status.LIVE

    mixed = AuditResult(results=[
        CredentialResult(credential=None, status=Status.MATCH),
        CredentialResult(credential=None, status=Status.LIVE),
    ])
    assert exit_code_for(mixed) == ExitCode.OK
    assert mixed.exit_status is Status.LIVE


def test_absent_is_not_match_but_is_still_exit_zero():
    """An all-unprovisioned run compared nothing, so it must not summarize as
    MATCH. Exit stays 0: declaring a value you have not provisioned yet is not
    drift, and paging for it would teach operators to ignore the audit."""
    from credarr.audit import AuditResult, CredentialResult, Status
    from credarr.errors import ExitCode
    from credarr.report import exit_code_for

    absent = AuditResult(results=[CredentialResult(
        credential=None, status=Status.ABSENT
    )])
    assert absent.exit_status is Status.ABSENT
    assert exit_code_for(absent) == ExitCode.OK

    mixed = AuditResult(results=[
        CredentialResult(credential=None, status=Status.MATCH),
        CredentialResult(credential=None, status=Status.ABSENT),
    ])
    assert mixed.exit_status is Status.ABSENT
    assert exit_code_for(mixed) == ExitCode.OK


def test_absent_never_hides_a_real_finding():
    from credarr.audit import AuditResult, CredentialResult, Status

    drifted = AuditResult(results=[
        CredentialResult(credential=None, status=Status.ABSENT),
        CredentialResult(credential=None, status=Status.DRIFT),
    ])
    assert drifted.exit_status is Status.DRIFT

    unverifiable = AuditResult(results=[
        CredentialResult(credential=None, status=Status.ABSENT),
        CredentialResult(credential=None, status=Status.UNVERIFIABLE),
    ])
    assert unverifiable.exit_status is Status.ABSENT


def test_only_process_api_claims_a_process_readback():
    from credarr.model import Consumer, Target

    def consumer(mechanism: str) -> Consumer:
        return Consumer(target=Target(system="seerr", slot="settings_json"),
                        mechanism=mechanism)

    assert consumer("process_api").process_readback is True
    assert consumer("redeploy").indirect is True
    assert consumer("redeploy").process_readback is False
    assert Consumer(
        target=Target(system="homepage", slot="label")
    ).indirect is True


def test_a_retired_file_mechanism_is_refused():
    with pytest.raises(Exception, match="retired"):
        _parse("""
version: 1
credentials:
  sonarr_api_key:
    class: B
    max_age_days: 90
    consumers:
      - target: seerr.settings_json[sonarr]
        mechanism: file_unverified
""")
