"""Provider-neutral, fail-closed adaptation of the public SecuRedact API.

This module deliberately has no MCP dependency. Provider hooks call the stable
``SecuredactEngine.prepare`` API in-process so an MCP client/model choice cannot
turn a privacy check into an optional action.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from securedact_core import PrepareStatus, RedactionRequest, SecuredactEngine
from securedact_mcp.runtime_lifecycle import RuntimeLoadFailure
from securedact_mcp.server import build_runtime


class EnforcementOutcome(StrEnum):
    ALLOW = "allow"
    SANITIZED = "sanitized"
    REVIEW_REQUIRED = "review_required"
    BLOCKED = "blocked"
    INTERNAL_FAILURE = "internal_failure"


class _Preparer(Protocol):
    def prepare(self, request: RedactionRequest) -> Any: ...


@dataclass(frozen=True)
class EnforcementResult:
    """A safe provider-neutral decision; it never carries raw rejected text."""

    outcome: EnforcementOutcome
    sanitized_text: str | None = None


class PrivacyEnforcer:
    """Translate public SecuRedact results into deterministic hook outcomes.

    Any exception, malformed result, unavailable detector/model, or policy
    failure is ``INTERNAL_FAILURE``. Hook front ends turn that outcome into a
    block on protected lifecycle paths.
    """

    def __init__(self, engine: _Preparer) -> None:
        self._engine = engine

    @classmethod
    def from_environment(cls) -> PrivacyEnforcer:
        """Build the same verified, offline runtime used by the local server.

        Provider hooks run in a fresh process, so constructing the bare core
        engine would omit SecuRedact's managed contextual detector.  This is a
        direct in-process runtime setup, not an MCP call.
        """

        runtime = build_runtime()
        engine = SecuredactEngine(
            runtime.engine,
            configuration_error=runtime.contextual_failure_code,
        )
        if runtime.contextual_failure_code is not None:
            return cls(engine)
        try:
            if runtime.prepare_loader is not None:
                runtime.prepare_loader()
            runtime.engine.startup()
        except RuntimeLoadFailure as exc:
            return cls(SecuredactEngine(runtime.engine, configuration_error=exc.failure_code))
        except Exception:
            return cls(
                SecuredactEngine(runtime.engine, configuration_error="contextual_model_load_failed")
            )
        if not runtime.engine.full_ready():
            return cls(
                SecuredactEngine(
                    runtime.engine,
                    configuration_error=(
                        runtime.engine.readiness_failure_code() or "contextual_model_load_failed"
                    ),
                )
            )
        return cls(engine)

    def inspect_text(self, text: str) -> EnforcementResult:
        if not isinstance(text, str):
            return EnforcementResult(EnforcementOutcome.INTERNAL_FAILURE)
        try:
            result = self._engine.prepare(RedactionRequest(text=text))
        except Exception:
            return EnforcementResult(EnforcementOutcome.INTERNAL_FAILURE)
        if result.status == PrepareStatus.OK:
            sanitized = result.sanitized_text
            if not isinstance(sanitized, str):
                return EnforcementResult(EnforcementOutcome.INTERNAL_FAILURE)
            if sanitized == text:
                return EnforcementResult(EnforcementOutcome.ALLOW)
            return EnforcementResult(EnforcementOutcome.SANITIZED, sanitized)
        if result.status == PrepareStatus.REVIEW_REQUIRED:
            return EnforcementResult(EnforcementOutcome.REVIEW_REQUIRED)
        if result.status == PrepareStatus.BLOCKED:
            return EnforcementResult(EnforcementOutcome.BLOCKED)
        return EnforcementResult(EnforcementOutcome.INTERNAL_FAILURE)

    def inspect_payload(self, payload: object) -> tuple[EnforcementResult, object | None]:
        """Recursively sanitize text-bearing string leaves without changing shape."""

        try:
            return self._inspect_payload(payload)
        except Exception:
            return EnforcementResult(EnforcementOutcome.INTERNAL_FAILURE), None

    def _inspect_payload(self, payload: object) -> tuple[EnforcementResult, object | None]:
        if isinstance(payload, str):
            result = self.inspect_text(payload)
            return (
                result,
                result.sanitized_text
                if result.outcome == EnforcementOutcome.SANITIZED
                else payload,
            )
        if isinstance(payload, Mapping):
            sanitized: dict[object, object] = {}
            changed = False
            for key, value in payload.items():
                if not isinstance(key, str):
                    return EnforcementResult(EnforcementOutcome.INTERNAL_FAILURE), None
                result, replacement = self._inspect_payload(value)
                if result.outcome not in {EnforcementOutcome.ALLOW, EnforcementOutcome.SANITIZED}:
                    return result, None
                sanitized[key] = replacement
                changed = changed or result.outcome == EnforcementOutcome.SANITIZED
            return (
                EnforcementResult(EnforcementOutcome.SANITIZED)
                if changed
                else EnforcementResult(EnforcementOutcome.ALLOW),
                sanitized,
            )
        if isinstance(payload, list):
            sanitized_items: list[object] = []
            changed = False
            for value in payload:
                result, replacement = self._inspect_payload(value)
                if result.outcome not in {EnforcementOutcome.ALLOW, EnforcementOutcome.SANITIZED}:
                    return result, None
                sanitized_items.append(replacement)
                changed = changed or result.outcome == EnforcementOutcome.SANITIZED
            return (
                EnforcementResult(EnforcementOutcome.SANITIZED)
                if changed
                else EnforcementResult(EnforcementOutcome.ALLOW),
                sanitized_items,
            )
        if payload is None or isinstance(payload, bool | int | float):
            return EnforcementResult(EnforcementOutcome.ALLOW), payload
        return EnforcementResult(EnforcementOutcome.INTERNAL_FAILURE), None
