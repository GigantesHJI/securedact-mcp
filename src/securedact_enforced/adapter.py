"""Provider-neutral, fail-closed adaptation of the public SecuRedact API.

This module deliberately has no MCP dependency. Provider hooks call the stable
``SecuredactEngine.prepare`` API in-process so an MCP client/model choice cannot
turn a privacy check into an optional action.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from securedact_core import (
    PolicyLoadError,
    PrepareOutcome,
    PrepareStatus,
    PrivacyAction,
    RedactionRequest,
    SecuredactEngine,
    load_policy_registry_from_environment,
)
from securedact_core.firewall import FirewallDecision, ToolOperation
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
    prepare_outcome: PrepareOutcome | None = None
    entity_types: tuple[str, ...] | None = None


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
        try:
            runtime.engine.policies = load_policy_registry_from_environment(runtime.engine.policies)
        except (PolicyLoadError, OSError, RuntimeError):
            return cls(
                SecuredactEngine(
                    runtime.engine,
                    configuration_error="policy_configuration_invalid",
                )
            )
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
        entity_types = (
            tuple(sorted(result.counts.keys())) if getattr(result, "counts", None) else None
        )
        prepare_outcome = getattr(result, "outcome", None)
        if prepare_outcome is not None:
            try:
                prepare_outcome = PrepareOutcome(prepare_outcome)
            except ValueError:
                return EnforcementResult(EnforcementOutcome.INTERNAL_FAILURE)
        if result.status == PrepareStatus.OK:
            sanitized = result.sanitized_text
            if not isinstance(sanitized, str):
                return EnforcementResult(EnforcementOutcome.INTERNAL_FAILURE)
            if prepare_outcome == PrepareOutcome.ALLOW:
                return (
                    EnforcementResult(
                        EnforcementOutcome.ALLOW,
                        prepare_outcome=prepare_outcome,
                        entity_types=entity_types,
                    )
                    if sanitized == text
                    else EnforcementResult(EnforcementOutcome.INTERNAL_FAILURE)
                )
            if prepare_outcome in {PrepareOutcome.PSEUDONYMIZED, PrepareOutcome.REDACTED}:
                return (
                    EnforcementResult(
                        EnforcementOutcome.SANITIZED,
                        sanitized,
                        prepare_outcome,
                        entity_types=entity_types,
                    )
                    if sanitized != text
                    else EnforcementResult(EnforcementOutcome.INTERNAL_FAILURE)
                )
            # Preserve schema-v1 compatibility for older preparers while the
            # Gemini path requires an explicit signed PrepareOutcome.
            if prepare_outcome is None:
                if sanitized == text:
                    return EnforcementResult(EnforcementOutcome.ALLOW, entity_types=entity_types)
                return EnforcementResult(
                    EnforcementOutcome.SANITIZED, sanitized, entity_types=entity_types
                )
            return EnforcementResult(EnforcementOutcome.INTERNAL_FAILURE)
        if result.status == PrepareStatus.REVIEW_REQUIRED:
            return (
                EnforcementResult(
                    EnforcementOutcome.REVIEW_REQUIRED,
                    prepare_outcome=prepare_outcome,
                    entity_types=entity_types,
                )
                if prepare_outcome in {None, PrepareOutcome.REVIEW_REQUIRED}
                else EnforcementResult(EnforcementOutcome.INTERNAL_FAILURE)
            )
        if result.status == PrepareStatus.BLOCKED:
            return (
                EnforcementResult(
                    EnforcementOutcome.BLOCKED,
                    prepare_outcome=prepare_outcome,
                    entity_types=entity_types,
                )
                if prepare_outcome in {None, PrepareOutcome.BLOCKED}
                else EnforcementResult(EnforcementOutcome.INTERNAL_FAILURE)
            )
        return EnforcementResult(EnforcementOutcome.INTERNAL_FAILURE)

    @staticmethod
    def _aggregate_prepare_outcomes(
        outcomes: list[PrepareOutcome | None], *, changed: bool
    ) -> PrepareOutcome | None:
        if any(outcome is None for outcome in outcomes):
            return None
        if not changed:
            return PrepareOutcome.ALLOW
        if PrepareOutcome.REDACTED in outcomes:
            return PrepareOutcome.REDACTED
        return PrepareOutcome.PSEUDONYMIZED

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
            prepare_outcomes: list[PrepareOutcome | None] = []
            for key, value in payload.items():
                if not isinstance(key, str):
                    return EnforcementResult(EnforcementOutcome.INTERNAL_FAILURE), None
                result, replacement = self._inspect_payload(value)
                if result.outcome not in {EnforcementOutcome.ALLOW, EnforcementOutcome.SANITIZED}:
                    return result, None
                sanitized[key] = replacement
                changed = changed or result.outcome == EnforcementOutcome.SANITIZED
                prepare_outcomes.append(result.prepare_outcome)
            return (
                EnforcementResult(
                    EnforcementOutcome.SANITIZED if changed else EnforcementOutcome.ALLOW,
                    prepare_outcome=self._aggregate_prepare_outcomes(
                        prepare_outcomes, changed=changed
                    ),
                ),
                sanitized,
            )
        if isinstance(payload, list):
            sanitized_items: list[object] = []
            changed = False
            prepare_outcomes = []
            for value in payload:
                result, replacement = self._inspect_payload(value)
                if result.outcome not in {EnforcementOutcome.ALLOW, EnforcementOutcome.SANITIZED}:
                    return result, None
                sanitized_items.append(replacement)
                changed = changed or result.outcome == EnforcementOutcome.SANITIZED
                prepare_outcomes.append(result.prepare_outcome)
            return (
                EnforcementResult(
                    EnforcementOutcome.SANITIZED if changed else EnforcementOutcome.ALLOW,
                    prepare_outcome=self._aggregate_prepare_outcomes(
                        prepare_outcomes, changed=changed
                    ),
                ),
                sanitized_items,
            )
        if payload is None or isinstance(payload, bool | int | float):
            return EnforcementResult(
                EnforcementOutcome.ALLOW, prepare_outcome=PrepareOutcome.ALLOW
            ), payload
        return EnforcementResult(EnforcementOutcome.INTERNAL_FAILURE), None


@dataclass(frozen=True)
class ToolResultInspection:
    """Provider-neutral outcome of inspecting one tool result (FW-020).

    The result is the model-bound payload returned by a tool. ``action`` is the
    safe decision; ``sanitized_result`` carries the structurally-preserved
    sanitized payload when ``action == SANITIZED``; ``reason_code`` explains a
    block/hide decision; ``entities`` are the detected entity-type categories
    (used for metadata-only audit, never raw values).
    """

    action: EnforcementOutcome
    sanitized_result: object | None = None
    reason_code: str | None = None
    entities: tuple[str, ...] | None = None


# An ``inspector`` turns a raw result payload into the daemon-backed enforcement
# outcome without the provider hook knowing the transport details. It returns
# ``(outcome, sanitized_payload, entity_types, reason_code)``.
ToolResultInspector = Callable[
    [object], tuple[EnforcementOutcome, object | None, tuple[str, ...] | None, str | None]
]


def inspect_tool_result(
    inspector: ToolResultInspector,
    *,
    provider: str,
    tool_name: str | None,
    operation: ToolOperation | None,
    result: object,
) -> ToolResultInspection:
    """Centralized, provider-neutral tool-result inspection (FW-020).

    Provider hooks translate their host result schema into a single ``result``
    payload and supply a daemon-backed ``inspector``. The shared layer never
    re-implements content scanning; it reports the outcome, the sanitized
    (structure-preserving) payload, the reason code, and detected entity types.

    A malformed/empty result that cannot be inspected is reported as
    ``INTERNAL_FAILURE`` so the caller fails closed (hide/block) rather than
    leaking raw content.
    """

    try:
        outcome, sanitized, entities, reason_code = inspector(result)
        if not isinstance(outcome, EnforcementOutcome):
            return ToolResultInspection(EnforcementOutcome.INTERNAL_FAILURE)
        if outcome == EnforcementOutcome.ALLOW:
            return ToolResultInspection(EnforcementOutcome.ALLOW, entities=entities)
        if outcome == EnforcementOutcome.SANITIZED:
            return ToolResultInspection(
                EnforcementOutcome.SANITIZED,
                sanitized_result=sanitized,
                entities=entities,
            )
        # BLOCKED / REVIEW_REQUIRED / INTERNAL_FAILURE all mean the raw result
        # must not reach the model; the provider layer hides or replaces it.
        return ToolResultInspection(outcome, reason_code=reason_code, entities=entities)
    except Exception:
        return ToolResultInspection(EnforcementOutcome.INTERNAL_FAILURE)


def firewall_decision_outcome(decision: FirewallDecision) -> EnforcementOutcome:
    """Map a ``FirewallDecision`` onto a provider-neutral enforcement outcome.

    The ``PrivacyAction`` enum is intentionally unchanged; approval and review
    requirements are encoded on the ``FirewallDecision`` and surface here as
    ``REVIEW_REQUIRED`` (a host-deny the user can override), while ``BLOCK``
    becomes an unoverrideable deny.
    """

    if decision.action == PrivacyAction.BLOCK:
        return EnforcementOutcome.BLOCKED
    if decision.requires_approval or decision.action == PrivacyAction.REVIEW:
        return EnforcementOutcome.REVIEW_REQUIRED
    return EnforcementOutcome.ALLOW
