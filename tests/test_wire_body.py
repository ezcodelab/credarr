"""The request body must be a JSON object, not a JSON string.

This is the bug that only a live service found: the call builder embedded the
body pre-encoded, so the generated script re-encoded a *string* and the service
received `"{\"name\": ...}"` instead of `{"name": ...}`. Prowlarr and Sonarr both
answer 400 to that, and a 400 on a rotation write is indistinguishable from a
refusal unless you look at the body.

So the test looks at the body. It executes the generated script against a stub
`urlopen` and asserts on the bytes that would go over the wire.
"""

from __future__ import annotations

import json

import pytest

from credarr import __version__
from credarr.config import HostConfig
from credarr.executor import _servarr_call

HOST = HostConfig(
    name="t",
    urls={"prowlarr": "http://127.0.0.1:9696"},
)


class _CapturingTransport:
    """Runs the generated script for real, against a stub urlopen."""

    def __init__(self) -> None:
        self.sent_body: bytes | None = None
        self.sent_headers: dict[str, str] | None = None
        self.script: str = ""

    name = "capture"

    def run_python(self, code: str, *, timeout: int | None = None) -> str:
        self.script = code
        namespace = _stub(code)
        try:
            exec(code, namespace)
        finally:
            namespace["_restore"]()
        self.sent_body = namespace["_captured"]
        self.sent_headers = namespace["_captured_headers"]
        return "\x00201\x00{}"


def _stub(_code: str) -> dict:
    """A namespace whose `urllib.request.urlopen` records the request body.

    The generated script does `import urllib.request` itself, so the stub has to
    be reachable by that import - patching a copy of the module in a local
    namespace does not survive it.
    """
    import urllib.request

    namespace: dict = {"_captured": None, "_captured_headers": None}

    class _Response:
        status = 201

        def read(self) -> bytes:
            return b"{}"

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def urlopen(request, timeout=None):
        namespace["_captured"] = request.data
        namespace["_captured_headers"] = dict(request.headers)
        return _Response()

    original = urllib.request.urlopen
    urllib.request.urlopen = urlopen
    namespace["_restore"] = lambda: setattr(urllib.request, "urlopen", original)
    return namespace


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ({"name": "SomeCommand"}, {"name": "SomeCommand"}),
        ({"fields": [{"name": "apiKey", "value": "x"}], "id": 3},
         {"fields": [{"name": "apiKey", "value": "x"}], "id": 3}),
        ([{"name": "a"}], [{"name": "a"}]),
    ],
)
def test_the_wire_body_is_the_object_not_a_string_of_it(body, expected):
    transport = _CapturingTransport()
    _servarr_call(HOST, "prowlarr", "POST", "/command", body=body,
                  key="k", transport=transport)

    assert transport.sent_body is not None, "nothing was sent"
    decoded = json.loads(transport.sent_body)
    # The failure mode this guards: json.loads succeeding on a *str*, which
    # looks like a pass until you compare types.
    assert isinstance(decoded, type(expected)), (
        f"sent a JSON {type(decoded).__name__}, expected {type(expected).__name__}"
    )
    assert decoded == expected


def test_outbound_calls_identify_credarr():
    """A deployment can distinguish the client from Python's default UA."""
    transport = _CapturingTransport()
    _servarr_call(HOST, "prowlarr", "GET", "/system/status",
                  key="k", transport=transport)

    assert transport.sent_headers is not None
    assert transport.sent_headers["User-agent"] == f"credarr/{__version__}"


def test_a_body_is_not_sent_when_there_is_none():
    transport = _CapturingTransport()
    _servarr_call(HOST, "prowlarr", "GET", "/system/status",
                  body=None, key="k", transport=transport)

    assert transport.sent_body is None


def test_a_nested_structure_survives_the_round_trip():
    """Unicode and nesting are where an encoding mistake usually shows up."""
    body = {"name": "Rücktracker", "nested": {"a": [1, 2, {"b": None}]}}
    transport = _CapturingTransport()
    _servarr_call(HOST, "prowlarr", "PUT", "/indexer/1", body=body,
                  key="k", transport=transport)

    assert json.loads(transport.sent_body) == body


def test_a_non_finite_float_does_not_break_the_call():
    """`repr()` emits bare `nan`/`inf`, which are names, not literals.

    A service returning one in any field would otherwise abort the request with
    a NameError - the tool would report a transport failure for a body the
    service had actually written.
    """
    body = {"fields": [{"name": "priority", "value": float("nan")}],
            "other": float("inf")}
    transport = _CapturingTransport()
    _servarr_call(HOST, "prowlarr", "PUT", "/indexer/1", body=body,
                  key="k", transport=transport)

    assert transport.sent_body is not None
    decoded = json.loads(transport.sent_body)
    assert decoded["other"] == float("inf")


def test_a_string_that_looks_like_code_stays_a_string():
    """The body is service-supplied. It must not become executable."""
    body = {"name": "x'); __import__('os').system('id'); #"}
    transport = _CapturingTransport()
    _servarr_call(HOST, "prowlarr", "PUT", "/indexer/1", body=body,
                  key="k", transport=transport)

    assert json.loads(transport.sent_body) == body
