"""Transport, logging and Servarr-backup helpers shared by every step kind.

The step drivers call these through the executor's bound attributes or directly;
none of them owns rotation state, so they sit below the mixins and the
orchestrator imports them back for compatibility.
"""

from __future__ import annotations

import base64
import io
import json
import re
import sys
import urllib.parse
import zipfile
from collections.abc import Callable, Mapping
from secrets import token_hex
from xml.sax.saxutils import escape as _xml_escape

from credarr import __version__
from credarr.config import HostConfig
from credarr.errors import RotationError, TransportError
from credarr.redact import scrub, scrub_url_credentials
from credarr.transport import Transport
from credarr.writers import Holder, api_version

# How long to wait for a service to answer after a restart. Restarting Prowlarr
# and immediately hammering its API produces a burst of connection refusals that
# looks like a failure and is not.
READINESS_TIMEOUT = 180
READINESS_INTERVAL = 3
# Identify the client at the HTTP boundary. Cloudflare deployments can reject
# Python's default User-Agent with a 1010 WAF response even though the host is
# reachable; a stable product UA is not a credential and makes that distinction
# visible to the deployment's owner.
USER_AGENT = f"credarr/{__version__}"
# Seerr's settings API updates the running process synchronously, but the
# read-back is a separate request and a slow process may not answer at once.
SEERR_READBACK_TIMEOUT = 30
SEERR_READBACK_INTERVAL = 0.5
# A holder write is validated by the *arr app against its upstream, so one
# write can fail for reasons that have nothing to do with the request. Bounded
# attempts with backoff, because giving up immediately turned a rate limit into
# a thirty-minute outage.
WRITE_ATTEMPTS = 4
WRITE_BACKOFF = 5
# Ceiling on the pacing interval. Bounded because an escalating delay that never
# resets would turn a slow rotation into a stalled one.
MAX_WRITE_INTERVAL = 30.0
# A chosen-value mint can be refused because the service rejects the value's
# shape, not the credential. Nothing is written in that case, so choosing
# another value is safe; three attempts cover a validator with a narrow rule
# without turning a real refusal into an endless mint.
MINT_VALUE_ATTEMPTS = 3
# Mints that park the chosen value before mutating the service and revoke the
# canonical key at the mint. After a crash that reached RECORD, the parked or
# canonical value is the only key the service accepts; minting again would
# revoke the key the holders just received.
PENDING_MINTS = frozenset({"reset", "rotate", "sabnzbd_rotate", "bazarr_rotate", "regenerate"})

# Sonarr validates an indexer while saving it, which can involve contacting it.
# Three of ten took over five seconds and some exceeded thirty, so a short
# timeout turns a successful write into an apparent failure - and a rotation
# that reports failure for a write that landed is worse than one that is slow.
API_TIMEOUT = 180
# Ordinary API answers are JSON documents; a service or a proxy that streams
# without end must not be read into memory. Full database backups are the one
# deliberate exception: they go to an unlinked temporary file in the service
# host's process, never through this buffer (see _servarr_backup_config). They
# still have a ceiling, and only config.xml is extracted from the archive.
MAX_JSON_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_BACKUP_BYTES = 1024 * 1024 * 1024
MAX_CONFIG_XML_BYTES = 8 * 1024 * 1024
# Reading config.xml through the service's own backup API is a multi-step
# operation: ask, wait for the Backup command to complete, download the archive,
# extract the one small file, and delete the archive. The backup command and
# file waits alone can consume 300s; the parent budget must also cover the
# download and ZIP extraction, or the child is killed before it can delete the
# archive and report the real cause.
CONFIG_READ_TIMEOUT = 420
# The same, for the restore upload. The file is tiny; the service can still take
# a while to accept it.
CONFIG_RESTORE_TIMEOUT = 180
# The holder's own test is a second call after a successful write, not a save
# validation. A real Radarr indexer test can exceed 30s while it waits on its
# upstream; 25s cut the local subprocess before Radarr could return its own
# result. The transport still bounds a hang, but it must not be shorter than
# the service's own test. Expiry is inconclusive, never a credential verdict.
EXERCISE_TIMEOUT = 90
# Only these texts name the credential (measured on the pinned *arr pair). The
# status is identical to a 500 or a DNS failure, and a 401 from a proxy or
# allowlist in front of a healthy app produces the same words as a stale key -
# which is why a rejection is ambiguous, not drift. A bare "Apikey" is not a
# marker: the measured 429 body embeds `apikey=` in the request URL while saying
# nothing about the credential.
CREDENTIAL_MARKERS = ("invalid credentials", "api key is invalid")

# These are indexer test failures that happen after the credential was accepted.
# Sonarr/Radarr report a disabled upstream Prowlarr indexer as a 400 carrying
# `[410:Gone]`; Prowlarr itself answers 410 only after API-key authentication.
# A "query successful" with no category results is also a content result, not
# a rejected key. Treating either as a credential failure makes a healthy copy
# look unverifiable.
INDEXER_FUNCTIONAL_MARKERS = (
    "no results in the configured categories",
    "[410:gone]",
)



def _names_credential(text: str) -> bool:
    """Whether a failure's own words name the credential (measured shapes)."""
    normalized = " ".join(text.lower().split())
    return any(marker in normalized for marker in CREDENTIAL_MARKERS)


def _indexer_functional_failure(text: str) -> bool:
    """Whether an indexer test failed after the key was accepted."""
    normalized = " ".join(text.lower().split())
    if any(marker in normalized for marker in INDEXER_FUNCTIONAL_MARKERS):
        return True
    # Prowlarr's XML body names the disabled indexer but Sonarr may only retain
    # the status line. Require both facts: a bare "disabled" can be a temporary
    # 429 and must stay inconclusive.
    return "410" in normalized and "indexer is disabled" in normalized

# Slot name -> the API path segment that addresses it.
#
# They are not the same word. The manifest says "indexers" because that is the
# table and the noun an operator uses; the API says /indexer. Guessing the path
# from the slot name produces a 404 for every row - after the key was revoked.
# Verified against the running services rather than inferred: sonarr serves
# /api/v3/indexer and /api/v3/downloadclient, prowlarr serves
# /api/v1/applications, and none of them serve the plural forms.
# Upstream trouble that a retry can fix, as opposed to a request this tool got
# wrong. Both reach us as the same status: Sonarr and Radarr each validate an
# indexer by calling Prowlarr live during the save, so Prowlarr rate-limiting or
# timing out surfaces as a 400 from the app holding the row. The status is
# Prowlarr's problem wearing Sonarr's status code, and the body text is the
# only thing that distinguishes the two.
TRANSIENT_MARKERS = (
    "too many requests", "429", "rate limit", "timed out", "timeout",
    "unable to connect", "connection refused", "server is unavailable",
    "temporarily unavailable", "no route to host", "try again later",
    "service unavailable", "gateway timeout",
)
# A verdict about the indexer itself. Retrying these forever is pointless: the
# indexer has no content in the categories it is configured for.
PERMANENT_MARKERS = (
    "no results in the configured categories", "could not be converted",
    "is required", "is invalid", "not a valid",
)
TRANSIENT_STATUS = {408, 425, 429, 500, 502, 503, 504}


def log_line(message: str) -> None:
    """Progress during a run, on stderr so the report stays machine-readable."""
    print(message, file=sys.stderr)


def classify_refusal(status: int, payload: object) -> tuple[str, str]:
    """`(verdict, reason)` for a non-2xx holder write.

    transient  - upstream is unwell or busy; the same request may succeed later.
    permanent  - this request cannot succeed as sent, and probably never will.
    unknown    - no body to judge by; worth one retry, then surface it.
    """
    if status in TRANSIENT_STATUS:
        return "transient", f"HTTP {status}"
    text = _explain(payload).lower()
    if any(marker in text for marker in PERMANENT_MARKERS):
        return "permanent", _explain(payload)
    if any(marker in text for marker in TRANSIENT_MARKERS):
        return "transient", _explain(payload)
    if not text:
        return "unknown", f"HTTP {status} with no explanation"
    return "permanent", _explain(payload)


def _explain(payload: object) -> str:
    """One line saying why a service refused something, or nothing.

    Both halves matter. Servarr's problem+json puts the generic summary in
    `title` ("Invalid request Validation failed") and the actual cause in
    `errors` ("Unable to connect to indexer: [429:TooManyRequests]"). Returning
    only the title reproduces the uselessness this is meant to remove.
    """
    if isinstance(payload, dict):
        parts: list[str] = []
        for key in ("title", "message", "detail", "errorMessage"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                parts.append(value.strip())
                break
        errors = payload.get("errors")
        if isinstance(errors, dict) and errors:
            for field, messages in errors.items():
                text = (str(messages[0]) if isinstance(messages, list)
                        and messages else str(messages))
                text = text.strip()
                if text and text not in parts:
                    # "--" is Servarr's placeholder field for a whole-resource
                    # validation failure; it names nothing and only adds noise.
                    parts.append(text if field == "--" else f"{field}: {text}")
                break
        if parts:
            return ": ".join(parts)[:400]
    if isinstance(payload, list):
        # The measured Servarr holder test routes answer with a list of problem
        # objects, not problem+json. Their `errorMessage` is the sentence that
        # says whether this was a credential refusal or a network failure.
        for item in payload:
            if not isinstance(item, dict):
                continue
            for key in ("errorMessage", "message", "detail", "title"):
                value = item.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()[:400]
    if isinstance(payload, str) and payload.strip():
        return payload.strip()[:400]
    return ""


_CONFIG_XML_KEY = re.compile(r"<ApiKey>([^<]*)</ApiKey>")

# The fields a stock Servarr writes into config.xml. The tuple is
# (XML element, /config/host JSON key, kind). ApiKey is set separately: the
# whole point of the reconstructed path is to install a key credarr chose.
_CONFIG_XML_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("BindAddress", "bindAddress", "str"),
    ("Port", "port", "int"),
    ("SslPort", "sslPort", "int"),
    ("EnableSsl", "enableSsl", "bool"),
    ("LaunchBrowser", "launchBrowser", "bool"),
    ("AuthenticationMethod", "authenticationMethod", "enum"),
    ("AuthenticationRequired", "authenticationRequired", "enum"),
    ("AllowedHosts", "allowedHosts", "str"),
    ("AnalyticsEnabled", "analyticsEnabled", "bool"),
    ("LogLevel", "logLevel", "str"),
    ("LogSizeLimit", "logSizeLimit", "int"),
    ("ConsoleLogLevel", "consoleLogLevel", "str"),
    ("Branch", "branch", "str"),
    ("SslCertPath", "sslCertPath", "str"),
    ("SslCertPassword", "sslCertPassword", "str"),
    ("UrlBase", "urlBase", "str"),
    ("TrustedNetworks", "trustedNetworks", "str"),
    ("InstanceName", "instanceName", "str"),
    ("UpdateAutomatically", "updateAutomatically", "bool"),
    ("UpdateMechanism", "updateMechanism", "enum"),
    ("UpdateScriptPath", "updateScriptPath", "str"),
    ("ProxyEnabled", "proxyEnabled", "bool"),
    ("ProxyType", "proxyType", "enum"),
    ("ProxyHostname", "proxyHostname", "str"),
    ("ProxyPort", "proxyPort", "int"),
    ("ProxyUsername", "proxyUsername", "str"),
    ("ProxyPassword", "proxyPassword", "str"),
    ("ProxyBypassFilter", "proxyBypassFilter", "str"),
    ("ProxyBypassLocalAddresses", "proxyBypassLocalAddresses", "bool"),
    ("CertificateValidation", "certificateValidation", "enum"),
    ("BackupFolder", "backupFolder", "str"),
    ("BackupInterval", "backupInterval", "int"),
    ("BackupRetention", "backupRetention", "int"),
    ("TrustCgnatIpAddresses", "trustCgnatIpAddresses", "bool"),
)

# A rebuilt config must carry the settings that decide whether the service is
# reachable and whether the UI still authenticates. The API exposes all of these
# on the pinned builds; a missing one is a refusal, not a default.
_CRITICAL_CONFIG_FIELDS = frozenset({
    "bindAddress",
    "port",
    "sslPort",
    "enableSsl",
    "authenticationMethod",
    "authenticationRequired",
    "urlBase",
    "sslCertPath",
    "sslCertPassword",
    "instanceName",
    "updateMechanism",
    "logLevel",
    "branch",
})


def _config_enum(value: object) -> str:
    """API camelCase enum -> the PascalCase config.xml spelling."""
    text = str(value or "")
    if not text:
        return ""
    if text == "disabledForLocalAddresses":
        return "DisabledForLocalAddresses"
    return text[0].upper() + text[1:]


def _config_value(value: object, kind: str) -> str:
    if kind == "bool":
        if isinstance(value, str):
            return "True" if value.lower() in ("true", "1", "yes") else "False"
        return "True" if value else "False"
    if kind == "int":
        try:
            return str(int(value))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return ""
    if kind == "enum":
        return _config_enum(value)
    return "" if value is None else str(value)


def _config_xml_from_host(host_config: Mapping[str, object], *, api_key: str) -> str:
    """Build the config.xml a stock Servarr would have, with a chosen key.

    Every field comes from `GET /config/host`; the user account and password are
    not part of config.xml and are not touched. The critical fields are
    mandatory, because omitting one would reset it on the service's next start
    and could make the UI or the listener unreachable.
    """
    missing = sorted(
        key for key in _CRITICAL_CONFIG_FIELDS
        if host_config.get(key) is None
    )
    if missing:
        raise RotationError(
            "config/host did not expose the fields a rebuilt config.xml needs: "
            + ", ".join(missing),
            hint="the reconstructed config would reset those settings; nothing "
            "has been restored. Use write.ui_password or write.manual_mint.",
        )

    lines = ["<Config>"]
    for element, key, kind in _CONFIG_XML_FIELDS:
        if key not in host_config:
            continue
        value = host_config.get(key)
        if value is None:
            continue
        lines.append(
            f"  <{element}>{_xml_escape(_config_value(value, kind))}</{element}>"
        )
    lines.append(f"  <ApiKey>{_xml_escape(api_key)}</ApiKey>")
    lines.append("</Config>")
    return "\n".join(lines) + "\n"


def _config_xml_api_key(text: str) -> str | None:
    """The ApiKey element's value, from config.xml text or a backup's copy."""
    match = _CONFIG_XML_KEY.search(text)
    return match.group(1) if match and match.group(1) else None


def _replace_config_xml_key(text: str, new_key: str) -> str:
    """Replace exactly one ApiKey, preserving every other config byte."""
    replaced, count = _CONFIG_XML_KEY.subn(
        lambda _match: f"<ApiKey>{new_key}</ApiKey>",
        text,
        count=1,
    )
    if count != 1:
        raise RotationError(
            "config.xml has no ApiKey element to replace",
            hint="the service's backup did not contain the config shape this "
            "build measured. Nothing has been restored.",
        )
    return replaced


def _backup_route_problem(
    service: str, probe: tuple[int, object] | None
) -> str | None:
    """Why the backup download route cannot be used, or None when it can.

    Servarr's backup download is a web route (`/backup/manual/...`), not an API
    route: with the service's UI authentication on it answers 302 to `/login`
    even while `/api/<version>` accepts the key, and the mint cannot read
    config.xml. Measured on Sonarr 4.0.20.3014, Radarr 6.4.4.10685 and Prowlarr
    2.6.5.5623 (2026-10-22): auth off answers 404 for a name that cannot exist,
    auth on answers 302. `probe` is None when the host could not be reached,
    which the caller already reports.
    """
    if probe is None:
        return None
    status, body = probe
    if status == 404:
        return None
    if status in (301, 302, 303, 307, 308):
        return (
            f"{service}: the backup download is behind the service's web UI "
            f"login (HTTP {status}); its API key cannot open that route, so "
            "the backup/restore mint cannot read config.xml. Declare "
            "write.ui_password with the service's UI credential, use "
            "write.manual_mint and supply the key rotated in the service's UI, "
            "or set Authentication to 'Disabled for Local Addresses' for "
            "credarr's address (or None) and retry"
        )
    if status == 200:
        page = "<html" in str(body).lower() or "<!doctype" in str(body).lower()
        return (
            f"{service}: the backup download answered 200 for a name that "
            "cannot exist"
            + (" (a login page)" if page else "")
            + "; a proxy may be answering instead of the service, so the "
            "backup/restore mint cannot read config.xml"
        )
    return (
        f"{service}: the backup download answered HTTP {status}; the "
        "backup/restore mint needs that route to read config.xml"
    )


def _servarr_backup_config(
    host: HostConfig, service: str, *,
    key: str,
    transport: Transport,
    auth_headers: Mapping[str, str] | None = None,
    timeout: int | None = None,
) -> tuple[str, str]:
    """Create a manual backup, read its config.xml, and delete the backup.

    The archive is downloaded and read inside the host's Python process. Only
    the small config.xml crosses the transport; the database copy never has a
    name on disk (it lives in an unlinked temporary file) and the service-side
    backup is deleted before returning. A failure to delete is a failure: the
    archive contains the still-live key, so restoring over it would leave a
    second copy behind for no reason.
    """
    version = api_version(service)
    root = host.url(service).rstrip("/")
    api = f"{root}/api/{version}"
    script = (
        "import base64,json,sys,tempfile,time,urllib.error,urllib.request,zipfile\n"
        f"MAX_CONTROL_BYTES = {MAX_JSON_RESPONSE_BYTES}\n"
        f"MAX_BACKUP_BYTES = {MAX_BACKUP_BYTES}\n"
        f"MAX_CONFIG_XML_BYTES = {MAX_CONFIG_XML_BYTES}\n"
        f"api = {api!r}\n"
        f"root = {root!r}\n"
        f"key = {key!r}\n"
        f"auth_headers = {dict(auth_headers or {})!r}\n"
        "def fail(stage, name=''):\n"
        "    sys.stdout.write(json.dumps({'error': stage, 'backup': name}))\n"
        "    sys.exit(0)\n"
        "def call(url, method='GET', body=None):\n"
        "    data = json.dumps(body).encode() if body is not None else None\n"
        "    request = urllib.request.Request(url, data=data, method=method)\n"
        "    request.add_header('X-Api-Key', key)\n"
        "    if body is not None:\n"
        "        request.add_header('Content-Type', 'application/json')\n"
        "    try:\n"
        "        with urllib.request.urlopen(request, timeout=60) as response:\n"
        "            raw = response.read(MAX_CONTROL_BYTES + 1)\n"
        "            if len(raw) > MAX_CONTROL_BYTES:\n"
        "                return -2, b''\n"
        "            return response.status, raw\n"
        "    except urllib.error.HTTPError as exc:\n"
        "        return exc.code, b''\n"
        "    except Exception:\n"
        "        return -1, b''\n"
        "status, raw = call(api + '/system/backup')\n"
        "if status != 200:\n"
        "    fail('list HTTP ' + str(status))\n"
        "try:\n"
        "    before = {item.get('id') for item in json.loads(raw) "
        "if isinstance(item, dict)}\n"
        "except Exception:\n"
        "    fail('list was not a backup array')\n"
        "status, raw = call(api + '/command', 'POST', {'name': 'Backup'})\n"
        "if status not in (200, 201, 202):\n"
        "    fail('backup command HTTP ' + str(status))\n"
        "command_id = None\n"
        "try:\n"
        "    command = json.loads(raw)\n"
        "    if isinstance(command, dict) and isinstance(command.get('id'), int):\n"
        "        command_id = command['id']\n"
        "except Exception:\n"
        "    pass\n"
        "if command_id is None:\n"
        "    fail('backup command returned no id; refusing to guess when the "
        "archive is ready')\n"
        "deadline = time.time() + 180\n"
        "while time.time() < deadline:\n"
        "    status, raw = call(api + '/command/' + str(command_id))\n"
        "    if status == 200:\n"
        "        try:\n"
        "            command = json.loads(raw)\n"
        "        except Exception:\n"
        "            command = {}\n"
        "        state = str(command.get('status') or '')\n"
        "        if state == 'completed':\n"
        "            break\n"
        "        if state in ('failed', 'aborted', 'cancelled', 'orphaned'):\n"
        "            detail = str(command.get('message') or "
        "command.get('exception') or 'no detail')\n"
        "            fail('the backup command ' + state + ' (' + detail + ')')\n"
        "    time.sleep(1)\n"
        "else:\n"
        "    fail('the backup command did not finish within 180s')\n"
        "deadline = time.time() + 120\n"
        "new = None\n"
        "while time.time() < deadline:\n"
        "    status, raw = call(api + '/system/backup')\n"
        "    if status == 200:\n"
        "        try:\n"
        "            rows = json.loads(raw)\n"
        "        except Exception:\n"
        "            rows = []\n"
        "        for item in rows:\n"
        "            if not isinstance(item, dict):\n"
        "                continue\n"
        "            path = str(item.get('path') or '')\n"
        "            if item.get('id') not in before and "
        "path.startswith('/backup/manual/'):\n"
        "                new = item\n"
        "                break\n"
        "        if new is not None:\n"
        "            break\n"
        "    time.sleep(1)\n"
        "if new is None:\n"
        "    fail('no manual backup appeared within 120s')\n"
        "path = str(new.get('path') or '')\n"
        "name = str(new.get('name') or '')\n"
        "if not path.startswith('/backup/manual/'):\n"
        "    fail('backup path was not a manual backup', name)\n"
        "xml = None\n"
        "stage = None\n"
        "class _NoRedirect(urllib.request.HTTPRedirectHandler):\n"
        "    def redirect_request(self, *args, **kwargs):\n"
        "        return None\n"
        "def open_backup():\n"
        "    for attempt in range(3):\n"
        "        try:\n"
        "            request = urllib.request.Request(root + path, method='GET')\n"
        "            request.add_header('X-Api-Key', key)\n"
        "            for _header, _value in auth_headers.items():\n"
        "                request.add_header(_header, _value)\n"
        "            opener = urllib.request.build_opener(_NoRedirect)\n"
        "            return opener.open(request, timeout=60)\n"
        "        except urllib.error.HTTPError as exc:\n"
        "            if 500 <= exc.code < 600 and attempt < 2:\n"
        "                time.sleep(1)\n"
        "                continue\n"
        "            raise\n"
        "try:\n"
        "    with open_backup() as response:\n"
        "        with tempfile.TemporaryFile() as temp:\n"
        "            total = 0\n"
        "            while True:\n"
        "                chunk = response.read(1024 * 1024)\n"
        "                if not chunk:\n"
        "                    break\n"
        "                total += len(chunk)\n"
        "                if total > MAX_BACKUP_BYTES:\n"
        "                    stage = ('the backup exceeded ' "
        "+ str(MAX_BACKUP_BYTES) + ' bytes')\n"
        "                    break\n"
        "                temp.write(chunk)\n"
        "            if stage is None:\n"
        "                temp.seek(0)\n"
        "                try:\n"
        "                    with zipfile.ZipFile(temp) as archive:\n"
        "                        names = [n for n in archive.namelist() "
        "if n.rsplit('/', 1)[-1].lower() == 'config.xml']\n"
        "                        if not names:\n"
        "                            stage = 'the backup contains no config.xml'\n"
        "                        elif len(names) > 1:\n"
        "                            stage = ('the backup contains ' "
        "+ str(len(names)) + ' config.xml files')\n"
        "                        else:\n"
        "                            with archive.open(names[0]) as member:\n"
        "                                xml = member.read(MAX_CONFIG_XML_BYTES + 1)\n"
        "                            if len(xml) > MAX_CONFIG_XML_BYTES:\n"
        "                                xml = None\n"
        "                                stage = ('config.xml exceeded ' "
        "+ str(MAX_CONFIG_XML_BYTES) + ' bytes')\n"
        "                except Exception:\n"
        "                    stage = 'the downloaded backup was not a readable ZIP'\n"
        "except urllib.error.HTTPError as exc:\n"
        "    if 300 <= exc.code < 400:\n"
        "        stage = ('the backup download redirected to the service "
        "login (HTTP ' + str(exc.code) + ')')\n"
        "    else:\n"
        "        stage = 'the backup download returned HTTP ' + str(exc.code)\n"
        "except Exception:\n"
        "    stage = 'the backup download could not be read'\n"
        "status, _ = call(api + '/system/backup/' + str(new.get('id')), "
        "'DELETE')\n"
        "if status not in (200, 204):\n"
        "    fail('could not delete the temporary backup', name)\n"
        "if stage is not None or xml is None:\n"
        "    fail(stage or 'could not read config.xml from the backup', name)\n"
        "sys.stdout.write(json.dumps({'xml': base64.b64encode(xml).decode(), "
        "'backup': name}))\n"
    )
    out = transport.run_python(script, timeout=timeout or CONFIG_READ_TIMEOUT)
    try:
        payload = json.loads(out)
    except json.JSONDecodeError:
        raise RotationError(
            f"{service}: the backup probe returned no usable result",
            hint="nothing has been restored. Check that the service's backup "
            "API is reachable and authenticates with its stored key.",
        ) from None
    if not isinstance(payload, dict):
        raise RotationError(f"{service}: the backup probe returned no usable result")
    if payload.get("error"):
        error = str(payload.get("error") or "")
        backup = str(payload.get("backup") or "")
        if "redirected to the service login" in error:
            # Measured on Sonarr 4.0.20, Radarr 6.4.4 and Prowlarr 2.6.5: with
            # the service's UI authentication on, the backup download is a web
            # route behind the login even while /api/<version> accepts the key.
            # With a declared UI credential the login was attempted; a redirect
            # here means it did not open the route.
            hint = (
                "the service's backup download is behind its web UI login, and "
                "the API key cannot open that route. "
                + (
                    "The UI login with write.ui_password did not open it; check "
                    "that stored password. "
                    if auth_headers
                    else "If write.ui_password is declared, check its stored "
                    "value; otherwise declare it, use write.manual_mint and "
                    "supply the key rotated in the service's UI. "
                )
                + "Setting the service's Authentication to 'Disabled for Local "
                "Addresses' for credarr's address (or None) also works. Nothing "
                "has been restored."
            )
        elif "delete" in error:
            hint = (
                "the temporary backup could not be deleted and still contains the "
                "current key. Delete it from the service's Backups page before "
                "retrying; nothing has been restored."
            )
        elif "did not finish within" in error or "returned no id" in error:
            hint = (
                "nothing has been restored. The backup command may still be "
                "running and may leave a completed backup on the service; check "
                "its Backups page before retrying."
            )
        else:
            hint = (
                "nothing has been restored. Check the service's backup API "
                "and its stored key."
            )
        raise RotationError(
            f"{service}: could not read config.xml over the backup API "
            f"({error}"
            + (f"; backup {backup!r}" if backup else "")
            + ")",
            hint=hint,
        )
    encoded = payload.get("xml")
    if not isinstance(encoded, str):
        raise RotationError(f"{service}: the backup probe returned no config.xml")
    try:
        xml = base64.b64decode(encoded).decode("utf-8-sig")
    except (ValueError, UnicodeDecodeError):
        raise RotationError(
            f"{service}: the backup's config.xml was not readable UTF-8"
        ) from None
    if len(xml) > 2_000_000:
        raise RotationError(f"{service}: the backup's config.xml is unexpectedly large")
    return xml, str(payload.get("backup") or "")


def _servarr_restore_config(
    host: HostConfig, service: str, *,
    key: str,
    xml: bytes,
    transport: Transport,
    timeout: int | None = None,
) -> tuple[int, object]:
    """Upload one config.xml inside a config-only ZIP.

    The extension matters. The pinned Sonarr build accepts `.xml` at the
    upload route but its backup service has no XML branch in this release: an
    `.xml` upload is treated as a **database** and moved over `sonarr.db`.
    A ZIP containing only `config.xml` is the shape the backup service
    actually understands, and it restores only that file.

    The archive is built here, so no host file is involved. The upload is the
    only mutation; the caller persists the chosen key before calling this.
    """
    version = api_version(service)
    url = f"{host.url(service).rstrip('/')}/api/{version}/system/backup/restore/upload"
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("config.xml", xml)
    boundary = f"----credarr{token_hex(12)}"
    head = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; '
        'filename="credarr-config.zip"\r\n'
        "Content-Type: application/zip\r\n\r\n"
    ).encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    body = head + archive.getvalue() + tail
    script = (
        "import sys,urllib.error,urllib.request\n"
        f"url = {url!r}\n"
        f"key = {key!r}\n"
        f"body = {body!r}\n"
        f"boundary = {boundary!r}\n"
        "class _NoRedirect(urllib.request.HTTPRedirectHandler):\n"
        "    def redirect_request(self, *args, **kwargs):\n"
        "        return None\n"
        "request = urllib.request.Request(url, data=body, method='POST')\n"
        "request.add_header('X-Api-Key', key)\n"
        "request.add_header('Content-Type', "
        "'multipart/form-data; boundary=' + boundary)\n"
        "try:\n"
        "    opener = urllib.request.build_opener(_NoRedirect)\n"
        "    with opener.open(request, timeout=120) as response:\n"
        "        sys.stdout.write('\\x00' + str(response.status))\n"
        "except urllib.error.HTTPError as exc:\n"
        "    sys.stdout.write('\\x00' + str(exc.code))\n"
        "except Exception:\n"
        "    sys.stdout.write('\\x00-1')\n"
    )
    out = transport.run_python(script, timeout=timeout or CONFIG_RESTORE_TIMEOUT)
    parts = out.split("\x00")
    if len(parts) < 2:
        raise RotationError(f"{service}: the restore probe returned no status")
    try:
        status = int(parts[1])
    except ValueError:
        raise RotationError(
            f"{service}: the restore probe returned no usable status"
        ) from None
    if status == -1:
        raise TransportError(
            f"{service}: the config restore could not be reached",
            hint="the restore may or may not have been applied; the pending "
            "value is parked, so re-running re-reads the service state and "
            "resumes from whatever the service actually holds.",
        )
    return status, None


def _servarr_login(
    host: HostConfig, service: str, *,
    username: str,
    password: str,
    transport: Transport,
    timeout: int | None = None,
) -> dict[str, str]:
    """Log in to a Servarr web UI and return the session header.

    Forms auth is a web route, not an API one: `POST /login` with a form body
    answers 302 with the auth cookie on success, and 302 to
    `loginFailed=true` without one on failure. The cookie is sent only to the
    backup download, which is the route the API key cannot open.
    """
    url = f"{host.url(service).rstrip('/')}/login"
    body = urllib.parse.urlencode({"username": username, "password": password})
    script = (
        "import json,sys,urllib.error,urllib.request\n"
        f"url = {url!r}\n"
        f"body = {body!r}\n"
        "class _NoRedirect(urllib.request.HTTPRedirectHandler):\n"
        "    def redirect_request(self, *args, **kwargs):\n"
        "        return None\n"
        "request = urllib.request.Request(url, data=body.encode(), "
        "method='POST')\n"
        "request.add_header('Content-Type', "
        "'application/x-www-form-urlencoded')\n"
        "try:\n"
        "    opener = urllib.request.build_opener(_NoRedirect)\n"
        "    with opener.open(request, timeout=60) as response:\n"
        "        sys.stdout.write(json.dumps({'error': 'the login answered "
        "HTTP ' + str(response.status) + ' instead of a redirect'}))\n"
        "except urllib.error.HTTPError as exc:\n"
        "    location = exc.headers.get('Location') or ''\n"
        "    cookies = exc.headers.get_all('Set-Cookie') or []\n"
        "    pairs = [raw.split(';', 1)[0] for raw in cookies]\n"
        "    pairs = [pair for pair in pairs if '=' in pair]\n"
        "    if 'loginFailed' in location or not pairs:\n"
        "        sys.stdout.write(json.dumps({'error': 'the service refused "
        "the UI login'}))\n"
        "    else:\n"
        "        sys.stdout.write(json.dumps({'cookie': '; '.join(pairs)}))\n"
        "except Exception:\n"
        "    sys.stdout.write(json.dumps({'error': 'the login request could "
        "not be read'}))\n"
    )
    out = transport.run_python(script, timeout=timeout or API_TIMEOUT)
    try:
        payload = json.loads(out)
    except json.JSONDecodeError:
        raise RotationError(
            f"{service}: the UI login returned no usable result",
            hint="check that the service's web UI is reachable; nothing has "
            "been changed.",
        ) from None
    if not isinstance(payload, dict) or payload.get("error"):
        error = (
            str(payload.get("error")) if isinstance(payload, dict)
            else "no usable result"
        )
        raise RotationError(
            f"{service}: the UI login failed ({error})",
            hint="check the stored password named by write.ui_password and "
            "that the service uses Forms or Basic authentication. Nothing has "
            "been changed.",
        )
    cookie = payload.get("cookie")
    if not isinstance(cookie, str) or not cookie:
        raise RotationError(
            f"{service}: the UI login returned no session cookie",
            hint="nothing has been changed.",
        )
    return {"Cookie": cookie}


def _servarr_call(
    host: HostConfig, service: str, method: str, path: str,
    *, body: dict | None = None, key: str | None = None,
    transport: Transport | None = None, auth_header: str = "X-Api-Key",
    auth_transport: str = "header", timeout: int | None = None,
    versioned: bool = True, follow_redirects: bool = True,
    extra_headers: Mapping[str, str] | None = None,
    content_type: str = "application/json",
    query_key_name: str = "ApiKey",
) -> tuple[int, object]:
    """Call a Servarr API, from the host that owns it.

    Routed through the transport rather than made locally, because the config's
    URLs are loopback addresses - they mean "from the machine running the
    service". Making them from the controller would either fail outright or,
    worse, silently reach a different service on the same port.

    `versioned=False` addresses a web route (`/backup/manual/...`), which has no
    `/api/<version>` prefix. `follow_redirects=False` lets a caller see a 302 for
    what it is: Servarr's web routes answer the login redirect when the service's
    UI authentication is on, and following it would turn a capability failure
    into a 200 login page.

    A connection failure is a reportable condition, not a traceback: it is
    exactly what the preflight exists to find. `timeout` bounds the transport
    call itself, so a caller answering a human (the Services view) can cap a
    blackholed host instead of inheriting the deployment's command timeout.
    `content_type` names the body encoding: JSON for the APIs, form encoding
    for Bazarr's settings route.
    """
    version = api_version(service)
    # Jellyfin has no `/api/{version}` prefix - its routes are `/Auth/Keys` -
    # so a versioned prefix would turn a real 404 into the wrong kind of one.
    prefix = "" if version is None or not versioned else f"/api/{version}"
    url = f"{host.url(service).rstrip('/')}{prefix}{path}"
    if not url.startswith(("http://", "https://")):
        raise RotationError(
            f"refusing to call {url!r}: not an http(s) URL",
            hint="the base URL comes from the host config; a non-http scheme "
            "here means the config is wrong",
        )
    # What an error message may quote. Captured before the credential is
    # embedded below, so no failure message has to rely on scrub() to be safe.
    # The probe still carries the key: that is what query auth needs.
    display_url = url
    if key is not None and auth_transport == "query":
        # Done here rather than in the generated script: it is string building the
        # caller can read, and it keeps `__import__` out of the probe.
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{query_key_name}={urllib.parse.quote(str(key))}"

    if follow_redirects:
        # The default path is the plain urlopen the wire-body tests patch;
        # only a caller that must see a redirect builds an opener.
        opener_line = ""
        open_line = (
            f"    with urllib.request.urlopen(request, timeout={API_TIMEOUT}) "
            "as response:\n"
        )
    else:
        opener_line = (
            "class _NoRedirect(urllib.request.HTTPRedirectHandler):\n"
            "    def redirect_request(self, *args, **kwargs):\n"
            "        return None\n"
            "opener = urllib.request.build_opener(_NoRedirect)\n"
        )
        open_line = f"    with opener.open(request, timeout={API_TIMEOUT}) as response:\n"

    if transport is None:
        raise RotationError(
            f"cannot reach {service}: no transport configured",
            hint="the executor must route API calls through the host transport",
        )

    # The key goes in the script's source, not its argv: argv is world-readable
    # through /proc on the host running the probe.
    #
    # `auth_header` is a literal from this module and never manifest input.
    # Servarr reads `X-Api-Key`; Seerr reads `X-API-Key`. HTTP treats header
    # names case-insensitively, but each application compares its own spelling,
    # so the wrong one is a 403 that reads as a refusal rather than a typo.
    script = (
        "import json, sys, urllib.error, urllib.request\n"
        f"method = {method!r}\n"
        f"url = {url!r}\n"
        f"MAX_RESPONSE_BYTES = {MAX_JSON_RESPONSE_BYTES}\n"
        # The body crosses as JSON text and is decoded on the far side: one encode
        # here, one decode there. Embedding the Python object instead would
        # make repr() emit `nan` and `inf` for non-finite floats, which are
        # bare names and would abort the call with a NameError instead of
        # sending what the service actually said.
        f"body = json.loads({json.dumps(body)!r})\n"
        f"key = {key!r}\n"
        f"auth_header = {auth_header!r}\n"
        f"user_agent = {USER_AGENT!r}\n"
        f"extra_headers = {dict(extra_headers or {})!r}\n"
        f"content_type = {content_type!r}\n"
        "if body is None:\n"
        "    data = None\n"
        "elif content_type == 'application/x-www-form-urlencoded':\n"
        "    import urllib.parse\n"
        "    data = urllib.parse.urlencode(body).encode()\n"
        "else:\n"
        "    data = json.dumps(body).encode()\n"
        "request = urllib.request.Request(url, data=data, method=method)\n"
        "request.add_header('Content-Type', content_type)\n"
        "request.add_header('User-Agent', user_agent)\n"
        "if key is not None:\n"
        "    request.add_header(auth_header, key)\n"
        "for _header, _value in extra_headers.items():\n"
        "    request.add_header(_header, _value)\n"
        + opener_line
        + "try:\n"
        + open_line
        + "        raw = response.read(MAX_RESPONSE_BYTES + 1)\n"
        "        if len(raw) > MAX_RESPONSE_BYTES:\n"
        "            sys.stdout.write('\\x00-2\\x00')\n"
        "        else:\n"
        "            sys.stdout.write('\\x00' + str(response.status) + '\\x00' + raw.decode())\n"
        "except urllib.error.HTTPError as exc:\n"
        # The body is the only thing distinguishing 'this service refused' from
        # 'this request was malformed', and a 400 on a rotation write is
        # otherwise indistinguishable from a refusal. Only the diagnostic fields
        # are lifted out: an error response can echo the submitted resource,
        # and that resource carries the credential being propagated.
        "    import json as _json\n"
        "    try:\n"
        "        _b = json.loads(exc.read().decode()[:8192])\n"
        "        if isinstance(_b, dict):\n"
        "            _d = {k: _b[k] for k in "
        "('title', 'errors', 'detail', 'message', 'errorMessage') if k in _b}\n"
        "        elif isinstance(_b, list):\n"
        # The holder test routes answer with a list of problem objects; lifting
        # only `errorMessage` keeps the submitted resource out of the note.
        "            _d = [{'errorMessage': _x['errorMessage']} for _x in _b "
        "if isinstance(_x, dict) and isinstance(_x.get('errorMessage'), str)]\n"
        "        else:\n"
        "            _d = None\n"
        "        _note = _json.dumps(_d)[:600] if _d else ''\n"
        "    except Exception:\n"
        "        _note = ''\n"
        "    sys.stdout.write('\\x00' + str(exc.code) + '\\x00' + _note)\n"
        "except Exception as exc:\n"
        "    sys.stdout.write('\\x00-1\\x00' + type(exc).__name__)\n"
    )
    out = transport.run_python(script, timeout=timeout)
    parts = out.split("\x00")
    if len(parts) < 3:
        raise RotationError(
            f"{service}: the probe returned no usable response",
            hint="a probe that cannot reach the service must say so rather "
            "than look like a refusal",
        )
    status_text, payload = parts[1], parts[2]
    try:
        status = int(status_text)
    except ValueError:
        raise RotationError(f"{service}: unusable status {status_text!r}") from None

    if status == -2:
        raise RotationError(
            f"{service}: the response from {display_url} exceeded "
            f"{MAX_JSON_RESPONSE_BYTES} bytes; refusing to buffer it",
            hint="the route is meant to answer with a small JSON document. "
            "Nothing has been written; check for a proxy or service fault "
            "that is streaming a non-JSON body.",
        )
    if status == -1:
        raise TransportError(
            f"{service} at {display_url} could not be reached: {payload}",
            hint="this is what the preflight is for; nothing has been changed",
        )
    if not payload.strip():
        return status, None
    try:
        return status, json.loads(payload)
    except json.JSONDecodeError:
        return status, payload


def exercise_holder(
    host: HostConfig,
    transport: Transport,
    holder: Holder,
    resource: dict,
    service_key: str,
    *,
    call: Callable[..., tuple[int, object]] = _servarr_call,
    timeout: float = EXERCISE_TIMEOUT,
    secrets: tuple[str | None, ...] = (),
) -> tuple[str, str]:
    """Ask a holder's own test route to use the stored value.

    The resource is the row exactly as the pre-write GET returned it, mask
    intact. Servarr treats the mask as "unchanged" and substitutes the stored
    value, so the test exercises what the running process holds. Shared by the
    rotation executor and the standing audit; both must ask the same question.

    An indexer test can fail after authentication - a disabled Prowlarr indexer
    (410) or an empty category result. That is content state, not a credential
    rejection, so it counts as accepted while retaining the service's words.
    """
    if not holder.test_path:
        return "unsupported", ""
    try:
        status, payload = call(
            host, holder.system, "POST",
            "/" + holder.test_path.lstrip("/"),
            body=resource, key=service_key, transport=transport,
            auth_header=holder.auth_header_name,
            auth_transport=holder.auth_transport,
            timeout=timeout,
        )
    except (TransportError, RotationError) as exc:
        return "inconclusive", scrub_url_credentials(
            scrub(str(exc), service_key, *secrets)
        )
    detail = scrub_url_credentials(
        scrub(_explain(payload), service_key, *secrets)
    )
    if 200 <= status < 300:
        return "accepted", detail
    if _names_credential(detail):
        return "rejected", detail
    if holder.slot == "indexers" and (
        status == 410 or _indexer_functional_failure(detail)
    ):
        # The key reached the upstream and authenticated; the indexer itself is
        # disabled or returned no category results. That is not a credential
        # rejection, so it must not make the copy unverifiable.
        return "accepted", detail
    return "inconclusive", detail or f"HTTP {status}"
