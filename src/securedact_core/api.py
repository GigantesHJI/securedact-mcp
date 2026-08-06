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
from .models import AnalysisResult
from .policies import Policy, PolicyRegistry
from .policy_loader import LocalPolicyLoader, PolicyLoadError
from .production import build_production_engine
from .restoration import RestorationSessionError, RestorationVault

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


class ErrorCode(StrEnum):
    POLICY_NOT_FOUND = "policy_not_found"
    POLICY_CONFIGURATION_INVALID = "policy_configuration_invalid"
    DETECTOR_UNAVAILABLE = "detector_unavailable"
    POLICY_BLOCKED = "policy_blocked"
    REVIEW_REQUIRED = "human_review_required"
    RESIDUAL_VALIDATION_FAILED = "residual_validation_failed"
    DEBUG_DISABLED = "debug_mode_disabled"
    RESTORATION_SESSION_FAILED = "restoration_session_failed"


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


class SafeFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    start: int = Field(ge=0)
    end: int = Field(gt=0)
    entity_type: str
    action: str
    confidence: float = Field(ge=0.0, le=1.0)
    source: str
    reason_code: str | None = None


class PrepareResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1"] = PUBLIC_SCHEMA_VERSION
    status: PrepareStatus
    policy: str
    policy_version: int | None = None
    policy_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    counts: dict[str, int] = Field(default_factory=dict)
    sanitized_text: str | None = None
    reason_codes: list[str] = Field(default_factory=list)
    findings: list[SafeFinding] | None = None
    restoration_session: str | None = None
    debug_details: list[dict[str, Any]] | None = None

    @model_validator(mode="after")
    def enforce_approved_output_boundary(self) -> PrepareResult:
        if self.status == PrepareStatus.OK and self.sanitized_text is None:
            raise ValueError("approved results require sanitized_text")
        if self.status != PrepareStatus.OK and (
            self.sanitized_text is not None or self.restoration_session is not None
        ):
            raise ValueError("unapproved results cannot contain approved output")
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
            engine.policies = LocalPolicyLoader.from_environment().load(engine.policies)
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
                )
            if analysis.blocked:
                return self._blocked(
                    request,
                    [ErrorCode.POLICY_BLOCKED.value],
                    policy=policy,
                    counts=counts,
                )
            if analysis.requires_review:
                return PrepareResult(
                    status=PrepareStatus.REVIEW_REQUIRED,
                    policy=policy.name,
                    policy_version=policy.schema_version,
                    policy_digest=policy.digest,
                    counts=counts,
                    reason_codes=[ErrorCode.REVIEW_REQUIRED.value],
                    findings=(
                        self._safe_findings(analysis)
                        if request.response_mode in {ResponseMode.REVIEW, ResponseMode.DEBUG}
                        else None
                    ),
                    debug_details=(
                        self._debug_details(analysis)
                        if request.response_mode == ResponseMode.DEBUG
                        else None
                    ),
                )
            try:
                redaction = self.privacy_engine.redact(
                    request.text,
                    request.policy,
                    analysis=analysis,
                )
            except ReviewRequiredError:
                return self._blocked(
                    request,
                    [ErrorCode.REVIEW_REQUIRED.value],
                    policy=policy,
                    counts=counts,
                    status=PrepareStatus.REVIEW_REQUIRED,
                )
            except SendingBlockedError:
                return self._blocked(
                    request,
                    [ErrorCode.POLICY_BLOCKED.value],
                    policy=policy,
                    counts=counts,
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
                    )
            return PrepareResult(
                status=PrepareStatus.OK,
                policy=policy.name,
                policy_version=policy.schema_version,
                policy_digest=policy.digest,
                counts=counts,
                sanitized_text=redaction.sanitized_text,
                findings=(
                    self._safe_findings(analysis)
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
    def _safe_findings(analysis: AnalysisResult) -> list[SafeFinding]:
        return [
            SafeFinding(
                start=item.start,
                end=item.end,
                entity_type=item.entity_type.value,
                action=(item.action.value if item.action is not None else "review"),
                confidence=item.confidence,
                source=item.source.value,
                reason_code=item.rationale_code,
            )
            for item in analysis.entities
        ]

    @staticmethod
    def _debug_details(analysis: AnalysisResult) -> list[dict[str, Any]]:
        return [item.model_dump(mode="json") for item in analysis.entities]

    @staticmethod
    def _blocked(
        request: RedactionRequest,
        reason_codes: list[str],
        *,
        policy: Policy | None = None,
        counts: dict[str, int] | None = None,
        status: PrepareStatus = PrepareStatus.BLOCKED,
    ) -> PrepareResult:
        return PrepareResult(
            status=status,
            policy=request.policy,
            policy_version=policy.schema_version if policy is not None else None,
            policy_digest=policy.digest if policy is not None else None,
            counts=counts or {},
            reason_codes=reason_codes,
        )
