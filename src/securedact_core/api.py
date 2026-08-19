# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import os
import threading
from collections import Counter
from collections.abc import Iterable
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .detectors.base import Detector
from .engine import PrivacyEngine, ReviewRequiredError, SendingBlockedError
from .models import (
    AnalysisResult,
    FindingDecision,
    PrivacyAction,
    RedactionMode,
    ReviewDecision,
)
from .policies import Policy, PolicyRegistry
from .policy_loader import PolicyLoadError, load_policy_registry_from_environment
from .production import build_production_engine
from .restoration import RestorationSessionError, RestorationVault
from .taxonomy import SPECIAL_CATEGORY_TYPES

PUBLIC_SCHEMA_VERSION: Literal["1"] = "1"
DEFAULT_MAX_TEXT_CHARS = 1_000_000


class ResponseMode(StrEnum):
    MINIMAL = "minimal"
    REVIEW = "review"
    DEBUG = "debug"
    RESTORE_CAPABLE = "restore_capable"


class PrepareStatus(StrEnum):
    OK = "ok"
    REVIEW_REQUIRED = "review_required"
    BLOCKED = "blocked"


class PrepareOutcome(StrEnum):
    ALLOW = "allow"
    PSEUDONYMIZED = "pseudonymized"
    REDACTED = "redacted"
    REVIEW_REQUIRED = "review_required"
    BLOCKED = "blocked"


class ReviewOption(StrEnum):
    SEND_PSEUDONYMIZED = "send_pseudonymized"
    EDIT_REPLACEMENTS = "edit_replacements"
    KEEP_SELECTED_VALUES = "keep_selected_values"
    CANCEL = "cancel"


class ErrorCode(StrEnum):
    POLICY_NOT_FOUND = "policy_not_found"
    POLICY_CONFIGURATION_INVALID = "policy_configuration_invalid"
    DETECTOR_UNAVAILABLE = "detector_unavailable"
    POLICY_BLOCKED = "policy_blocked"
    REVIEW_REQUIRED = "human_review_required"
    RESIDUAL_VALIDATION_FAILED = "residual_validation_failed"
    DEBUG_DISABLED = "debug_mode_disabled"
    RESTORATION_SESSION_FAILED = "restoration_session_failed"
    REVIEW_DECISION_INVALID = "review_decision_invalid"
    TRANSFORMATION_FAILED = "transformation_failed"


class SecuredactError(RuntimeError):
    """Base exception for public Securedact API setup failures."""


class SecuredactConfigurationError(SecuredactError):
    """The local engine could not be configured safely."""


class RedactionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str = Field(max_length=DEFAULT_MAX_TEXT_CHARS)
    policy: str = Field(default="strict_external_ai", pattern=r"^[a-z][a-z0-9_]{0,63}$")
    language: Literal["auto", "en", "nl"] = "auto"
    response_mode: ResponseMode = ResponseMode.MINIMAL
    review_decisions: tuple[ReviewDecision, ...] = ()

    @model_validator(mode="after")
    def review_decision_ids_are_unique(self) -> RedactionRequest:
        identifiers = [decision.detection_id for decision in self.review_decisions]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("review decision IDs must be unique")
        return self


class SafeFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str = ""
    start: int = Field(ge=0)
    end: int = Field(gt=0)
    entity_type: str
    action: str
    confidence: float = Field(ge=0.0, le=1.0)
    source: str
    decision: FindingDecision = FindingDecision.REVIEW
    reason_code: str | None = None
    suggested_replacement: str | None = None


class PrepareResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = PUBLIC_SCHEMA_VERSION
    status: PrepareStatus
    outcome: PrepareOutcome | None = None
    policy: str
    policy_version: int | None = None
    policy_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    counts: dict[str, int] = Field(default_factory=dict)
    action_counts: dict[str, int] = Field(default_factory=dict)
    sanitized_text: str | None = None
    reason_codes: list[str] = Field(default_factory=list)
    findings: list[SafeFinding] | None = None
    restoration_session: str | None = None
    review_options: list[ReviewOption] | None = None
    debug_details: list[dict[str, Any]] | None = None

    @model_validator(mode="after")
    def enforce_approved_output_boundary(self) -> PrepareResult:
        if self.status == PrepareStatus.OK and self.sanitized_text is None:
            raise ValueError("approved results require sanitized_text")
        if self.status != PrepareStatus.OK and (
            self.sanitized_text is not None or self.restoration_session is not None
        ):
            raise ValueError("unapproved results cannot contain approved output")
        if self.outcome is not None:
            approved_outcomes = {
                PrepareOutcome.ALLOW,
                PrepareOutcome.PSEUDONYMIZED,
                PrepareOutcome.REDACTED,
            }
            if (self.status == PrepareStatus.OK) != (self.outcome in approved_outcomes):
                raise ValueError("status and provider-neutral outcome are inconsistent")
            if (
                self.status == PrepareStatus.REVIEW_REQUIRED
                and self.outcome != PrepareOutcome.REVIEW_REQUIRED
            ):
                raise ValueError("review status requires a review outcome")
            if self.status == PrepareStatus.BLOCKED and self.outcome != PrepareOutcome.BLOCKED:
                raise ValueError("blocked status requires a blocked outcome")
        return self


class RestorationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str = Field(max_length=DEFAULT_MAX_TEXT_CHARS)
    restoration_session: str = Field(min_length=1, max_length=128)


class RestorationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = PUBLIC_SCHEMA_VERSION
    status: PrepareStatus
    restored_text: str | None = None
    reason_codes: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def enforce_restoration_boundary(self) -> RestorationResult:
        if self.status == PrepareStatus.OK and self.restored_text is None:
            raise ValueError("successful restoration requires restored_text")
        if self.status != PrepareStatus.OK and self.restored_text is not None:
            raise ValueError("failed restoration cannot contain restored text")
        return self


class SecuredactEngine:
    """Stable synchronous API for local, provider-neutral privacy preparation.

    A lock serializes detector inference because injected statistical detectors
    are not assumed to be thread-safe. The restoration vault is independently
    concurrency-safe and is cleared when this object is closed or the process
    exits.
    """

    def __init__(
        self,
        privacy_engine: PrivacyEngine,
        *,
        restoration_vault: RestorationVault | None = None,
        debug_enabled: bool = False,
        configuration_error: str | None = None,
    ) -> None:
        self.privacy_engine = privacy_engine
        self.restoration_vault = restoration_vault or RestorationVault()
        self.debug_enabled = debug_enabled
        self.configuration_error = configuration_error
        self._inference_lock = threading.RLock()

    @classmethod
    def from_environment(cls) -> SecuredactEngine:
        require_contextual = os.getenv("SECUREDACT_REQUIRE_FLAIR", "1") != "0"
        engine = build_production_engine(require_contextual=require_contextual)
        configuration_error: str | None = None
        try:
            engine.policies = load_policy_registry_from_environment(engine.policies)
        except (PolicyLoadError, OSError, RuntimeError):
            configuration_error = ErrorCode.POLICY_CONFIGURATION_INVALID.value
        engine.startup()
        return cls(
            engine,
            debug_enabled=os.getenv("SECUREDACT_ENABLE_DEBUG_RESPONSES") == "1",
            configuration_error=configuration_error,
        )

    @classmethod
    def with_detectors(
        cls,
        deterministic_detectors: Iterable[Detector],
        *,
        contextual_detectors: Iterable[Detector] = (),
        policies: PolicyRegistry | None = None,
        require_contextual: bool = False,
        debug_enabled: bool = False,
    ) -> SecuredactEngine:
        deterministic = list(deterministic_detectors)
        contextual = list(contextual_detectors)
        if not deterministic:
            raise SecuredactConfigurationError("at least one deterministic detector is required")
        if any(detector.contextual for detector in deterministic):
            raise SecuredactConfigurationError("deterministic detector collection is invalid")
        if any(not detector.contextual for detector in contextual):
            raise SecuredactConfigurationError("contextual detector collection is invalid")
        engine = PrivacyEngine(
            [*deterministic, *contextual],
            policies,
            require_contextual=require_contextual,
            required_detector_names=frozenset(detector.name for detector in deterministic),
        )
        engine.startup()
        return cls(engine, debug_enabled=debug_enabled)

    def prepare(self, request: RedactionRequest) -> PrepareResult:
        if self.configuration_error is not None:
            return self._blocked(request, [self.configuration_error])
        try:
            policy = self.privacy_engine.policies.get(request.policy)
        except ValueError:
            return self._blocked(request, [ErrorCode.POLICY_NOT_FOUND.value])
        if request.response_mode == ResponseMode.DEBUG and not self.debug_enabled:
            return self._blocked(
                request,
                [ErrorCode.DEBUG_DISABLED.value],
                policy=policy,
            )

        with self._inference_lock:
            analysis = self.privacy_engine.analyze(
                request.text,
                request.policy,
                language=request.language,
            )
            counts = self._counts(analysis)
            action_counts = self._action_counts(analysis, policy)
            if not analysis.engine_ready or any(
                warning.endswith("detector unavailable") for warning in analysis.warnings
            ):
                return self._blocked(
                    request,
                    [
                        self.privacy_engine.readiness_failure_code()
                        or ErrorCode.DETECTOR_UNAVAILABLE.value
                    ],
                    policy=policy,
                    counts=counts,
                    action_counts=action_counts,
                )
            if analysis.blocked:
                return self._blocked(
                    request,
                    [ErrorCode.POLICY_BLOCKED.value],
                    policy=policy,
                    counts=counts,
                    action_counts=action_counts,
                )
            if analysis.requires_review and not request.review_decisions:
                return self._review_required(
                    request,
                    policy,
                    analysis,
                    counts,
                    action_counts,
                )
            try:
                redaction = self.privacy_engine.redact(
                    request.text,
                    request.policy,
                    analysis=analysis,
                    decisions=list(request.review_decisions),
                )
            except ReviewRequiredError:
                return self._review_required(
                    request,
                    policy,
                    analysis,
                    counts,
                    action_counts,
                )
            except SendingBlockedError:
                return self._blocked(
                    request,
                    [ErrorCode.POLICY_BLOCKED.value],
                    policy=policy,
                    counts=counts,
                    action_counts=action_counts,
                )
            except ValueError:
                return self._blocked(
                    request,
                    [
                        (
                            ErrorCode.REVIEW_DECISION_INVALID
                            if request.review_decisions
                            else ErrorCode.TRANSFORMATION_FAILED
                        ).value
                    ],
                    policy=policy,
                    counts=counts,
                    action_counts=action_counts,
                )

            residual = self.privacy_engine.scan_residual(
                request.text,
                redaction,
                analysis,
                request.policy,
            )
            if not residual.safe_to_send:
                return self._blocked(
                    request,
                    [ErrorCode.RESIDUAL_VALIDATION_FAILED.value],
                    policy=policy,
                    counts=counts,
                    action_counts=action_counts,
                )
            restoration_session: str | None = None
            if request.response_mode == ResponseMode.RESTORE_CAPABLE and redaction.mapping:
                try:
                    restoration_session = self.restoration_vault.store(redaction.mapping)
                except RestorationSessionError as exc:
                    return self._blocked(
                        request,
                        [exc.code.value],
                        policy=policy,
                        counts=counts,
                        action_counts=action_counts,
                    )
            transformed = redaction.sanitized_text != request.text
            outcome = (
                PrepareOutcome.ALLOW
                if not transformed
                else PrepareOutcome.REDACTED
                if policy.replacement_mode == RedactionMode.REMOVE
                else PrepareOutcome.PSEUDONYMIZED
            )
            return PrepareResult(
                status=PrepareStatus.OK,
                outcome=outcome,
                policy=policy.name,
                policy_version=policy.schema_version,
                policy_digest=policy.digest,
                counts=counts,
                action_counts=action_counts,
                sanitized_text=redaction.sanitized_text,
                reason_codes=self._approved_reason_codes(
                    analysis,
                    outcome,
                    review_resolved=bool(request.review_decisions),
                ),
                findings=(
                    self._safe_findings(analysis, policy)
                    if request.response_mode in {ResponseMode.REVIEW, ResponseMode.DEBUG}
                    else None
                ),
                restoration_session=restoration_session,
                debug_details=(
                    self._debug_details(analysis)
                    if request.response_mode == ResponseMode.DEBUG
                    else None
                ),
            )

    def restore(self, request: RestorationRequest) -> RestorationResult:
        try:
            mapping = self.restoration_vault.consume(request.restoration_session)
        except RestorationSessionError as exc:
            return RestorationResult(
                status=PrepareStatus.BLOCKED,
                reason_codes=[exc.code.value],
            )
        with self._inference_lock:
            restored = self.privacy_engine.restore(request.text, mapping)
        mapping.clear()
        return RestorationResult(status=PrepareStatus.OK, restored_text=restored)

    def close(self) -> None:
        self.restoration_vault.clear()

    @staticmethod
    def _counts(analysis: AnalysisResult) -> dict[str, int]:
        counts = Counter(item.entity_type.value for item in analysis.entities)
        for assertion in analysis.assertions:
            if counts[assertion.category.value] == 0:
                counts[assertion.category.value] += 1
        return dict(sorted(counts.items()))

    @staticmethod
    def _action_counts(analysis: AnalysisResult, policy: Policy) -> dict[str, int]:
        controlled_evidence = {
            (span.start, span.end, assertion.category)
            for assertion in analysis.assertions
            for span in assertion.evidence_spans
        }
        counts = Counter(
            (item.decision or FindingDecision.REVIEW).value
            for item in analysis.entities
            if not (
                item.entity_type in SPECIAL_CATEGORY_TYPES
                and (item.start, item.end, item.entity_type) in controlled_evidence
            )
        )
        for assertion in analysis.assertions:
            decision = (
                FindingDecision.BLOCK
                if assertion.action == PrivacyAction.BLOCK
                else FindingDecision.REVIEW
                if assertion.requires_review or assertion.action == PrivacyAction.REVIEW
                else (
                    FindingDecision.REDACT
                    if policy.replacement_mode == RedactionMode.REMOVE
                    else FindingDecision.PSEUDONYMIZE
                )
                if assertion.action == PrivacyAction.REDACT
                else FindingDecision.ALLOW
            )
            counts[decision.value] += 1
        return dict(sorted(counts.items()))

    @staticmethod
    def _safe_findings(analysis: AnalysisResult, policy: Policy) -> list[SafeFinding]:
        counters: Counter[str] = Counter()
        known_values: dict[tuple[str, str], str] = {}
        findings: list[SafeFinding] = []
        controlled_evidence = {
            (span.start, span.end, assertion.category)
            for assertion in analysis.assertions
            for span in assertion.evidence_spans
        }
        for item in analysis.entities:
            if (
                item.entity_type in SPECIAL_CATEGORY_TYPES
                and (item.start, item.end, item.entity_type) in controlled_evidence
            ):
                continue
            suggested: str | None = None
            decision = item.decision or FindingDecision.REVIEW
            if decision in {FindingDecision.PSEUDONYMIZE, FindingDecision.REVIEW}:
                value_key = (item.entity_type.value, item.text)
                suggested = known_values.get(value_key)
                if suggested is None:
                    counters[item.entity_type.value] += 1
                    suggested = (
                        f"[{item.entity_type.value.upper()}_{counters[item.entity_type.value]}]"
                    )
                    known_values[value_key] = suggested
            elif decision == FindingDecision.REDACT:
                suggested = "[REDACTED]"
            findings.append(
                SafeFinding(
                    finding_id=item.id,
                    start=item.start,
                    end=item.end,
                    entity_type=item.entity_type.value,
                    action=(item.action.value if item.action is not None else "review"),
                    confidence=item.confidence,
                    source=item.source.value,
                    decision=decision,
                    reason_code=item.rationale_code,
                    suggested_replacement=suggested,
                )
            )
        for assertion in analysis.assertions:
            decision = (
                FindingDecision.BLOCK
                if assertion.action == PrivacyAction.BLOCK
                else FindingDecision.REVIEW
                if assertion.requires_review or assertion.action == PrivacyAction.REVIEW
                else (
                    FindingDecision.REDACT
                    if policy.replacement_mode == RedactionMode.REMOVE
                    else FindingDecision.PSEUDONYMIZE
                )
                if assertion.action == PrivacyAction.REDACT
                else FindingDecision.ALLOW
            )
            suggested = None
            if decision in {FindingDecision.PSEUDONYMIZE, FindingDecision.REVIEW}:
                counters[assertion.category.value] += 1
                suggested = (
                    f"[{assertion.category.value.upper()}_{counters[assertion.category.value]}]"
                )
            elif decision == FindingDecision.REDACT:
                suggested = "[REDACTED]"
            findings.append(
                SafeFinding(
                    finding_id=assertion.id,
                    start=assertion.full_span_start,
                    end=assertion.full_span_end,
                    entity_type=assertion.category.value,
                    action=assertion.action.value,
                    confidence=assertion.confidence,
                    source=assertion.detector,
                    decision=decision,
                    reason_code=assertion.rationale_code,
                    suggested_replacement=suggested,
                )
            )
        return findings

    @staticmethod
    def _review_reason_codes(analysis: AnalysisResult) -> list[str]:
        codes = {ErrorCode.REVIEW_REQUIRED.value}
        codes.update(
            item.rationale_code
            for item in analysis.entities
            if item.requires_review and item.rationale_code is not None
        )
        codes.update(
            assertion.rationale_code
            for assertion in analysis.assertions
            if assertion.requires_review
        )
        return sorted(codes, key=lambda code: (code != ErrorCode.REVIEW_REQUIRED.value, code))

    @staticmethod
    def _approved_reason_codes(
        analysis: AnalysisResult,
        outcome: PrepareOutcome,
        *,
        review_resolved: bool,
    ) -> list[str]:
        codes = {
            item.rationale_code
            for item in analysis.entities
            if item.rationale_code
            in {"generic_geographic_reference", "multiple_detector_agreement"}
        }
        if review_resolved:
            codes.add("review_resolved")
        elif outcome == PrepareOutcome.PSEUDONYMIZED:
            codes.add("automatic_pseudonymization")
        elif outcome == PrepareOutcome.REDACTED:
            codes.add("automatic_redaction")
        return sorted(codes)

    @staticmethod
    def _debug_details(analysis: AnalysisResult) -> list[dict[str, Any]]:
        details = [
            {
                "category": item.entity_type.value,
                "source": item.source.value,
                "confidence": item.confidence,
                "decision": (item.decision or FindingDecision.REVIEW).value,
                "decision_reason": item.rationale_code,
                "supporting_sources": sorted(source.value for source in item.supporting_sources),
                "conflicting_categories": sorted(
                    entity_type.value for entity_type in item.conflicting_entity_types
                ),
            }
            for item in analysis.entities
        ]
        details.extend(
            {
                "category": assertion.category.value,
                "source": assertion.detector,
                "confidence": assertion.confidence,
                "decision": (
                    FindingDecision.BLOCK.value
                    if assertion.action == PrivacyAction.BLOCK
                    else FindingDecision.REVIEW.value
                    if assertion.requires_review or assertion.action == PrivacyAction.REVIEW
                    else FindingDecision.PSEUDONYMIZE.value
                    if assertion.action == PrivacyAction.REDACT
                    else FindingDecision.ALLOW.value
                ),
                "decision_reason": assertion.rationale_code,
                "supporting_sources": [assertion.detector],
                "conflicting_categories": [],
            }
            for assertion in analysis.assertions
        )
        return details

    @classmethod
    def _review_required(
        cls,
        request: RedactionRequest,
        policy: Policy,
        analysis: AnalysisResult,
        counts: dict[str, int],
        action_counts: dict[str, int],
    ) -> PrepareResult:
        return PrepareResult(
            status=PrepareStatus.REVIEW_REQUIRED,
            outcome=PrepareOutcome.REVIEW_REQUIRED,
            policy=policy.name,
            policy_version=policy.schema_version,
            policy_digest=policy.digest,
            counts=counts,
            action_counts=action_counts,
            reason_codes=cls._review_reason_codes(analysis),
            findings=(
                cls._safe_findings(analysis, policy)
                if request.response_mode in {ResponseMode.REVIEW, ResponseMode.DEBUG}
                else None
            ),
            review_options=list(ReviewOption),
            debug_details=(
                cls._debug_details(analysis)
                if request.response_mode == ResponseMode.DEBUG
                else None
            ),
        )

    @staticmethod
    def _blocked(
        request: RedactionRequest,
        reason_codes: list[str],
        *,
        policy: Policy | None = None,
        counts: dict[str, int] | None = None,
        action_counts: dict[str, int] | None = None,
        status: PrepareStatus = PrepareStatus.BLOCKED,
    ) -> PrepareResult:
        return PrepareResult(
            status=status,
            outcome=(
                PrepareOutcome.REVIEW_REQUIRED
                if status == PrepareStatus.REVIEW_REQUIRED
                else PrepareOutcome.BLOCKED
            ),
            policy=request.policy,
            policy_version=policy.schema_version if policy is not None else None,
            policy_digest=policy.digest if policy is not None else None,
            counts=counts or {},
            action_counts=action_counts or {},
            reason_codes=reason_codes,
            review_options=(
                list(ReviewOption) if status == PrepareStatus.REVIEW_REQUIRED else None
            ),
        )
