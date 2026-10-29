"""A string that refuses to be printed by accident.

The failure mode this exists to prevent is not hypothetical. A credential value
that reaches a log line, a traceback, a repr() in a debugger, or an f-string
becomes a credential in someone's terminal scrollback, a CI log, or a bug
report. Every one of those is a place the value was supposed to never be.

So the value is only ever reachable through an explicit reveal() call, which is
greppable. Everything else - repr, str, format, f-strings - returns a redaction.
That is the whole design: make the safe path the default and the unsafe path
something you have to go looking for.
"""

from __future__ import annotations

import hmac
import re

# Below this length a value is short enough that removing it would damage
# unrelated text - a one-character value appears in every message. Real
# credentials are far longer (Servarr keys are 32), so the floor costs nothing
# and keeps an accidental short match from destroying the diagnostic it was
# meant to clean.
MIN_SCRUB_LENGTH = 8
REDACTED = "[redacted]"


def scrub(text: str, *values: object) -> str:
    """Remove any credential a service echoed back into its own diagnostic.

    `Secret` stops a value being printed by accident while it is still wrapped.
    It cannot help after `reveal()`: a service that echoes the resource it was
    given - which the Servarr validation errors have done - hands the credential
    straight back to whatever reports the refusal, and from there to an exception
    message, a log line, the journal, or a terminal.

    This is that second boundary. It cleans text that already exists rather than
    preventing it, which is why it is not a substitute for `Secret`.
    """
    for value in values:
        if isinstance(value, Secret):
            value = value.reveal()
        if not isinstance(value, str) or len(value) < MIN_SCRUB_LENGTH:
            continue
        text = text.replace(value, REDACTED)
    return text


_QUERY_CREDENTIAL = re.compile(
    r"(?i)([?&](?:api[_-]?key|apikey|token|access_token|password|secret)=)"
    r"([^&\s\]\"'<>]+)"
)


def scrub_url_credentials(text: str) -> str:
    """Redact credential-shaped query values without knowing the value.

    A holder's connection test can report the URL it tried, including the
    *stored* key. When the holder is stale, that value is not the audit's
    canonical and `scrub` cannot know it. This is the shape-based backstop.

    shortcut: the measured test-route body embeds the stored key in a URL query;
    a future response that puts an unknown stale key in a plain JSON field would
    not be caught. Widen this when that shape is measured.
    """
    return _QUERY_CREDENTIAL.sub(r"\1[redacted]", text)


def disable_core_dumps() -> None:
    """Refuse core dumps for this process.

    The process holds plaintext credentials while comparing them. A core dump
    writes that memory to disk, where it outlives the run and defeats the point
    of an encrypted vault. Best effort: a hard RLIMIT_CORE of zero is what
    actually prevents it, and some environments disallow the call.
    """
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        # Some hardened environments forbid lowering a limit. Failing the whole
        # run over a best-effort hardening step would be worse than the risk.
        return


class Secret:
    """Holds one credential value.

    Only reveal() returns the plaintext. Equality is constant time so comparing
    two secrets cannot leak their common prefix through timing. It is unhashable
    so it cannot end up as a dict key that gets serialised into a report.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError(f"Secret needs a str, got {type(value).__name__}")
        self._value = value

    def reveal(self) -> str:
        """Return the plaintext. Every call site is a deliberate act."""
        return self._value

    def __repr__(self) -> str:
        return f"Secret(***, {len(self._value)} chars)"

    __str__ = __repr__

    def __format__(self, format_spec: str) -> str:
        # Covers f"{secret}", f"{secret!r}" and str.format(). Returning the
        # redaction regardless of spec means no format string can opt back in.
        return f"Secret(***, {len(self._value)} chars)"

    def __bool__(self) -> bool:
        return bool(self._value)

    def __len__(self) -> int:
        return len(self._value)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secret):
            return NotImplemented
        return hmac.compare_digest(self._value.encode(), other._value.encode())

    def __hash__(self) -> int:
        raise TypeError(
            "Secret is deliberately unhashable so a credential cannot become a "
            "dict key and be serialised into a report"
        )

    def __reduce__(self) -> tuple[type[Secret], tuple[str]]:
        # Copy and pickle default to pickling a credential. Refuse, so a secret
        # cannot cross a process boundary inside a multiprocessing queue.
        raise TypeError("Secret cannot be pickled")
