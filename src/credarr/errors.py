"""Errors that represent expected, reportable failures.

Anything raised that is not a CredctlError is a bug and should propagate with a
traceback. Everything the tool can legitimately fail at gets a subclass and an
exit code, so the CLI never has to guess and CI never has to parse a string.
"""

from __future__ import annotations


class ExitCode:
    """Exit codes are part of the public interface. Changing one is a breaking
    change for anyone wiring this into CI, so they are named rather than
    scattered as integer literals."""

    OK = 0
    DRIFT = 1
    USAGE = 2
    CONFIG = 3
    UNREACHABLE = 4
    REFUSED = 5


class CredctlError(Exception):
    """Base class for every failure the tool reports on purpose."""

    exit_code: int = ExitCode.CONFIG
    # Only these errors carry one. The executor's failure handler reads it with
    # getattr, so an exception that is not a CredctlError still reports as a
    # failed run rather than raising an AttributeError of its own.
    hint: str | None = None

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.hint = hint

    def render(self) -> str:
        out = f"error: {self}"
        if self.hint:
            out += f"\n{self.hint}"
        return out


class ConfigError(CredctlError):
    """The configuration file is unusable."""

    exit_code = ExitCode.CONFIG


class ManifestError(CredctlError):
    """The credential manifest is unusable.

    Raised for structural problems and for targets that name a system or slot
    that does not exist. An unknown target is an error rather than a skip: a
    typo that silently reports "skip" is a checker that cannot tell the
    difference between "no drift" and "never looked".
    """

    exit_code = ExitCode.CONFIG


class TransportError(CredctlError):
    """A service API could not be reached, or the local call subprocess failed."""

    exit_code = ExitCode.UNREACHABLE


class SecretSourceError(CredctlError):
    """Secrets could not be read from the configured backend."""

    exit_code = ExitCode.CONFIG


class RotationError(CredctlError):
    """A rotation could not be attempted or could not complete.

    Distinct from a plan that refuses to execute: the plan is a deliberate
    refusal, this is a failure partway through. Exit 1 either way, because a
    rotation that started and did not finish leaves consumers inconsistent and
    must not read as success.
    """

    exit_code = ExitCode.DRIFT
