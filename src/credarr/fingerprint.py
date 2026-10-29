"""Compare credential values without revealing or storing them.

A fingerprint has to survive being printed into a terminal, a CI log and a bug
report, because that is where the tool's output ends up. Plain SHA-256 does not
survive that safely for every input: the credentials in a vault are mostly
passwords, and passwords are low entropy. Anyone holding a hash of "hunter2" can
confirm it in microseconds, and a fingerprint that is ever written down becomes
an oracle for guessing the value behind it.

So the fingerprint is an HMAC keyed with a random salt generated per run. That
makes a leaked output useless for guessing - there is no key to guess against -
while still being perfectly good at the only job it has: telling you whether two
values held right now are the same value.

The cost is that fingerprints do not match between runs. Nothing needs them to.
Drift detection compares the vault against live consumers within a single run.
Pinning the salt is supported for operators who want cross-run correlation, and
it is opt-in precisely because it gives up the property above.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets as _secrets

from .redact import Secret

# 12 hex chars is 48 bits. Collisions across a few hundred credentials are not a
# concern, and the short form stays readable in a report. The comparison always
# uses the full digest internally; only display is truncated.
DISPLAY_LENGTH = 12
SALT_BYTES = 32


class Fingerprinter:
    """Produces a short, salted, non-reversible tag for a Secret."""

    __slots__ = ("_pinned", "_salt")

    def __init__(self, salt: bytes | None = None) -> None:
        if salt is None:
            self._salt = _secrets.token_bytes(SALT_BYTES)
            self._pinned = False
        else:
            if len(salt) < 16:
                raise ValueError("fingerprint salt must be at least 16 bytes")
            self._salt = salt
            self._pinned = True

    @property
    def pinned(self) -> bool:
        """True when the salt is stable across runs, and the fingerprints are
        therefore guessable by anyone who has both the salt and a candidate."""
        return self._pinned

    def digest(self, secret: Secret) -> bytes:
        return hmac.new(self._salt, secret.reveal().encode("utf-8"), hashlib.sha256).digest()

    def of(self, secret: Secret) -> str:
        """The display form: a truncated hex tag, safe to print."""
        return self.digest(secret).hex()[:DISPLAY_LENGTH]

    def matches(self, left: Secret, right: Secret) -> bool:
        """Constant-time comparison of two secrets."""
        return hmac.compare_digest(self.digest(left), self.digest(right))

    @classmethod
    def from_config(cls, pinned_salt: str | None) -> Fingerprinter:
        """Build from configuration. `pinned_salt` is hex."""
        if not pinned_salt:
            return cls()
        try:
            salt = bytes.fromhex(pinned_salt)
        except ValueError as exc:
            raise ValueError("fingerprint salt must be hex-encoded") from exc
        return cls(salt)
