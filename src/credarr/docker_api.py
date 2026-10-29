"""The read-only half of the Docker boundary.

Discovery and the Services image observation use one `GET /containers/json`.
There is no inspect call: the container list is enough for names, image IDs and
ports, and it never carries the environment or labels into a response.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from http.client import HTTPException
from typing import Any, Never

TIMEOUT = 5.0
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
CONTAINERS_PATH = "/containers/json?all=0"


class DockerApiError(Exception):
    """The configured Docker endpoint could not answer a read-only scan."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A 3xx is an answer, not an invitation to another host or path."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        _newurl: str,
    ) -> Never:
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), _NoRedirect()
)


def endpoint(raw: str) -> str:
    """Validate the configured endpoint and return its base URL.

    A userinfo in the URL is refused rather than carried into an error message:
    the endpoint is configuration, and configuration must not become a secret
    path. A base path is allowed for proxies mounted under one; the Docker API
    path is appended to it.
    """
    try:
        parts = urllib.parse.urlsplit(raw)
        host = parts.hostname
    except ValueError as exc:
        raise DockerApiError(f"the Docker endpoint is not a valid URL: {exc}") from None
    if parts.scheme not in ("http", "https", "tcp"):
        raise DockerApiError(
            "the Docker endpoint must be http, https or tcp (usually a "
            "socket-proxy address such as http://socket-proxy:2375)"
        )
    if parts.username or parts.password:
        raise DockerApiError("the Docker endpoint must not contain credentials")
    if not host:
        raise DockerApiError("the Docker endpoint has no host")
    try:
        _ = parts.port  # validates the number; the base URL keeps the original form
    except ValueError:
        raise DockerApiError("the Docker endpoint has an invalid port") from None
    scheme = "http" if parts.scheme == "tcp" else parts.scheme
    path = parts.path.rstrip("/")
    return f"{scheme}://{parts.netloc}{path}"


def containers(base: str) -> list[dict]:
    """Read the running-container list, bounded and without following redirects."""
    try:
        request = urllib.request.Request(  # noqa: S310 - endpoint permits only http(s)/tcp
            f"{base}{CONTAINERS_PATH}",
            headers={"Accept": "application/json"},
        )
        with _OPENER.open(request, timeout=TIMEOUT) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise DockerApiError(
            f"the Docker API refused the read (HTTP {exc.code})"
        ) from None
    except (urllib.error.URLError, TimeoutError, OSError, HTTPException, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        raise DockerApiError(f"the Docker API did not answer: {reason}") from None
    if len(body) > MAX_RESPONSE_BYTES:
        raise DockerApiError("the Docker API response is too large to scan")
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise DockerApiError("the Docker API answered with something that is not JSON") from None
    if not isinstance(payload, list):
        raise DockerApiError("the Docker API did not answer with a container list")
    return [row for row in payload if isinstance(row, dict)]
