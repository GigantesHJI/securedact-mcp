from __future__ import annotations

import re
import threading
from collections import Counter
from collections.abc import Iterable
from urllib.parse import unquote

from .detectors.base import Detector
from .detectors.contextual_detector import ContextualPrivacyDetector
from .detectors.regex_detector import RegexDetector
from .merge import merge_detections
from .model_management import ModelManager
from .models import (
    AnalysisResult,
    Detection,
    DetectionSource,
    EntityType,
    IndirectDisclosureRisk,
    PartialMatch,
    PrivacyAction,
    RedactionResult,
    ResidualScanResult,
    ReviewAction,
    ReviewDecision,
    SanitizationAudit,
    SensitiveAssertion,
)
from .policies import Policy, PolicyRegistry
from .redaction import redact_text, restore_text
from .taxonomy import CATEGORY_DEFINITIONS, CRITICAL_TYPES, SPECIAL_CATEGORY_TYPES, mask_preview

VALID_PLACEHOLDER = re.compile(r"^\[(?:REDACTED|[A-Z][A-Z0-9_]*_\d+)\]$")
PLACEHOLDER_IN_TEXT = re.compile(r"\[(?:REDACTED|[A-Z][A-Z0-9_]*_\d+)\]")
BRACKETED_VALUE = re.compile(r"\[[^\[\]\r\n]{1,100}\]")


class PrivacyEngine:
    def __init__(
        self,
        detectors: Iterable[Detector] | None = None,
        policies: PolicyRegistry | None = None,
        *,
        require_contextual: bool = False,
        model_manager: ModelManager | None = None,
    ) -> None:
        self.detectors: list[Detector] = (
            list(detectors)
            if detectors is not None
            else [RegexDetector(), ContextualPrivacyDetector()]
        )
        self.policies = policies or PolicyRegistry()
        self.require_contextual = require_contextual
        self.model_manager = model_manager
        self._startup_warnings: list[str] = []
        self._startup_failure_codes: dict[str, str] = {}
        self._detector_lock = threading.RLock()

    def startup(self) -> None:
        self._startup_warnings.clear()
        self._startup_failure_codes.clear()
        for detector in list(self.detectors):
            loader = getattr(detector, "load", None)
            if loader is None:
                continue
            try:
                loader()
            except Exception:
                self._startup_warnings.append(f"{detector.name} detector unavailable")
                safe_code = getattr(detector, "failure_code", None)
                self._startup_failure_codes[detector.name] = (
                    str(safe_code)
                    if safe_code
                    else (
                        "contextual_detector_startup_failed"
                        if detector.contextual
                        else "detector_startup_failed"
                    )
                )

    def analyze(
        self,
        text: str,
        policy_name: str = "default",
        category_actions: dict[EntityType, PrivacyAction] | None = None,
        *,
        advanced_unsafe_mode: bool = False,
        confirmed_allow_categories: set[EntityType] | None = None,
    ) -> AnalysisResult:
        policy, actions, policy_exceptions = self.policies.resolve_actions(
            policy_name,
            category_actions,
            advanced_unsafe_mode=advanced_unsafe_mode,
            confirmed_allow_categories=confirmed_allow_categories,
        )
        candidates: list[Detection] = []
        assertions: list[SensitiveAssertion] = []
        warnings = list(self._startup_warnings)
        warnings.extend(policy_exceptions)
        detectors = list(self.detectors)
        statistical_detectors = [detector for detector in detectors if detector.contextual]
        contextual_configured = bool(statistical_detectors)
        contextual_ready = not self.require_contextual

        if self.require_contextual:
            explicit_states = [
                bool(detector.ready)
                for detector in statistical_detectors
                if hasattr(detector, "ready")
            ]
            if explicit_states and not all(explicit_states):
                detectors = [detector for detector in detectors if not detector.contextual]
                warnings.append("contextual detector is unavailable")

        for detector in detectors:
            try:
                detected = detector.detect(text)
                assertion_detector = getattr(detector, "detect_assertions", None)
                if assertion_detector is not None:
                    assertions.extend(assertion_detector(text))
                if detector.contextual:
                    contextual_ready = True
            except Exception:
                warning = f"{detector.name} detector unavailable"
                if warning not in warnings:
                    warnings.append(warning)
                continue
            candidates.extend(detected)

        if self.require_contextual and not contextual_configured:
            warnings.append("contextual detector is not configured")
            contextual_ready = False

        merged = merge_detections(candidates)
        assertion_evidence = {
            (span.start, span.end, assertion.category)
            for assertion in assertions
            for span in assertion.evidence_spans
        }
        accepted: list[Detection] = []
        for entity in merged:
            if entity.entity_type not in policy.enabled_entity_types:
                continue
            if entity.confidence < policy.minimum_confidence:
                continue
            action = actions[entity.entity_type]
            controlled_by_assertion = (
                entity.entity_type in SPECIAL_CATEGORY_TYPES
                and (entity.start, entity.end, entity.entity_type) in assertion_evidence
            )
            needs_review = (action == PrivacyAction.REVIEW and not controlled_by_assertion) or (
                action == PrivacyAction.REDACT
                and (
                    entity.entity_type in policy.always_review_types
                    or (
                        entity.source in policy.review_sources
                        and (
                            policy.review_all_contextual
                            or entity.confidence < policy.auto_accept_confidence
                        )
                    )
                )
            )
            definition = CATEGORY_DEFINITIONS[entity.entity_type]
            accepted.append(
                entity.model_copy(
                    update={
                        "requires_review": needs_review,
                        "context": self._context(text, entity.start, entity.end),
                        "action": action,
                        "severity": definition.severity,
                        "masked_preview": mask_preview(entity.text),
                    }
                )
            )

        configured_assertions: list[SensitiveAssertion] = []
        for assertion in assertions:
            action = actions[assertion.category]
            requires_review = action == PrivacyAction.REVIEW
            if (
                policy.contextual_residual_scan
                and assertion.indirect_disclosure_risk == IndirectDisclosureRisk.HIGH
            ):
                requires_review = True
                if action == PrivacyAction.REDACT:
                    action = PrivacyAction.REVIEW
            configured_assertions.append(
                assertion.model_copy(
                    update={
                        "action": action,
                        "requires_review": requires_review,
                    }
                )
            )

        blocked = any(entity.action == PrivacyAction.BLOCK for entity in accepted) or any(
            assertion.action == PrivacyAction.BLOCK for assertion in configured_assertions
        )
        return AnalysisResult(
            entities=accepted,
            assertions=configured_assertions,
            requires_review=(
                any(entity.requires_review for entity in accepted)
                or any(assertion.requires_review for assertion in configured_assertions)
            ),
            blocked=blocked,
            engine_ready=contextual_ready,
            warnings=warnings,
        )

    def replace_contextual_detector(self, detector: Detector | None) -> None:
        with self._detector_lock:
            self.detectors = [item for item in self.detectors if not item.contextual]
            if detector is not None:
                self.detectors.append(detector)

    def contextual_ready(self) -> bool:
        contextual = [detector for detector in self.detectors if detector.contextual]
        if not self.require_contextual:
            return True
        if not contextual:
            return False
        return all(bool(getattr(detector, "ready", True)) for detector in contextual)

    def contextual_failure_code(self) -> str | None:
        if not self.require_contextual or self.contextual_ready():
            return None
        contextual = [detector for detector in self.detectors if detector.contextual]
        if not contextual:
            return "contextual_model_not_configured"
        for detector in contextual:
            safe_code = getattr(detector, "failure_code", None)
            if safe_code:
                return str(safe_code)
            startup_code = self._startup_failure_codes.get(detector.name)
            if startup_code:
                return startup_code
        return "contextual_model_not_ready"

    def redact(
        self,
        text: str,
        policy_name: str = "default",
        decisions: list[ReviewDecision] | None = None,
        *,
        analysis: AnalysisResult | None = None,
        category_actions: dict[EntityType, PrivacyAction] | None = None,
        advanced_unsafe_mode: bool = False,
        confirmed_allow_categories: set[EntityType] | None = None,
        audit_mode: bool = False,
    ) -> RedactionResult:
        policy, actions, _ = self.policies.resolve_actions(
            policy_name,
            category_actions,
            advanced_unsafe_mode=advanced_unsafe_mode,
            confirmed_allow_categories=confirmed_allow_categories,
        )
        result = analysis or self.analyze(
            text,
            policy_name,
            category_actions,
            advanced_unsafe_mode=advanced_unsafe_mode,
            confirmed_allow_categories=confirmed_allow_categories,
        )
        entities = self._redaction_entities(
            text,
            result,
            decisions or [],
            policy,
            actions,
            audit_mode=audit_mode,
        )
        return redact_text(text, merge_detections(entities), policy.replacement_mode)

    def _redaction_entities(
        self,
        text: str,
        analysis: AnalysisResult,
        decisions: list[ReviewDecision],
        policy: Policy,
        actions: dict[EntityType, PrivacyAction],
        *,
        audit_mode: bool,
    ) -> list[Detection]:
        by_id = {decision.detection_id: decision for decision in decisions}
        controlled_evidence = {
            (span.start, span.end, assertion.category)
            for assertion in analysis.assertions
            for span in assertion.evidence_spans
        }
        output: list[Detection] = []
        unresolved: list[Detection] = []

        for entity in analysis.entities:
            action = actions[entity.entity_type]
            decision = by_id.get(entity.id)
            if action == PrivacyAction.BLOCK and not audit_mode:
                raise SendingBlockedError("The active policy blocks this content")
            if action == PrivacyAction.ALLOW:
                continue
            if decision is not None:
                if decision.action == ReviewAction.BLOCK:
                    raise SendingBlockedError("Sending was blocked during privacy review")
                if decision.action in {ReviewAction.IGNORE, ReviewAction.ALLOW_ONCE}:
                    continue
                if decision.action == ReviewAction.CHANGE_TYPE:
                    output.append(
                        entity.model_copy(
                            update={
                                "entity_type": decision.entity_type,
                                "requires_review": False,
                            }
                        )
                    )
                    continue
                output.append(entity.model_copy(update={"requires_review": False}))
                continue
            if (
                entity.entity_type in SPECIAL_CATEGORY_TYPES
                and (entity.start, entity.end, entity.entity_type) in controlled_evidence
            ):
                continue
            if entity.requires_review and not audit_mode:
                unresolved.append(entity)
                continue
            output.append(entity.model_copy(update={"requires_review": False}))

        people_by_id = {
            entity.id: entity
            for entity in analysis.entities
            if entity.entity_type == EntityType.PERSON
        }
        for assertion in analysis.assertions:
            action = actions[assertion.category]
            decision = by_id.get(assertion.id)
            if action == PrivacyAction.BLOCK and not audit_mode:
                raise SendingBlockedError("The active policy blocks this assertion")
            if action == PrivacyAction.ALLOW:
                continue
            if decision is not None and decision.action == ReviewAction.BLOCK:
                raise SendingBlockedError("Sending was blocked during privacy review")
            if decision is not None and decision.action in {
                ReviewAction.IGNORE,
                ReviewAction.ALLOW_ONCE,
            }:
                continue
            if assertion.requires_review and decision is None and not audit_mode:
                unresolved.append(self._assertion_detection(text, assertion))
                continue

            scope = decision.action if decision is not None else ReviewAction.REDACT_ASSERTION
            if scope == ReviewAction.REDACT_ATTRIBUTE:
                output.extend(self._evidence_detections(text, assertion))
            elif scope == ReviewAction.REDACT_PERSON_AND_ATTRIBUTE:
                output.extend(self._evidence_detections(text, assertion))
                output.extend(
                    people_by_id[subject_id]
                    for subject_id in assertion.subject_entity_ids
                    if subject_id in people_by_id
                )
            elif scope == ReviewAction.REDACT_SENTENCE:
                output.append(self._assertion_detection(text, assertion, sentence=True))
            else:
                output.append(self._assertion_detection(text, assertion))

        if unresolved and policy.block_on_unreviewed:
            raise ReviewRequiredError(unresolved)
        return output

    @staticmethod
    def _evidence_detections(
        text: str,
        assertion: SensitiveAssertion,
    ) -> list[Detection]:
        return [
            Detection(
                start=span.start,
                end=span.end,
                text=text[span.start : span.end],
                entity_type=assertion.category,
                confidence=assertion.confidence,
                source=DetectionSource.CONTEXTUAL,
                rule="assertion_evidence",
                precedence=95,
            )
            for span in assertion.evidence_spans
        ]

    @staticmethod
    def _assertion_detection(
        text: str,
        assertion: SensitiveAssertion,
        *,
        sentence: bool = False,
    ) -> Detection:
        start = assertion.sentence_start if sentence else assertion.full_span_start
        end = assertion.sentence_end if sentence else assertion.full_span_end
        return Detection(
            start=start,
            end=end,
            text=text[start:end],
            entity_type=assertion.category,
            confidence=assertion.confidence,
            source=DetectionSource.CONTEXTUAL,
            rule="full_sentence" if sentence else "full_sensitive_assertion",
            precedence=110,
            rationale_code=assertion.rationale_code,
        )

    def scan_residual(
        self,
        original_text: str,
        redaction: RedactionResult,
        analysis: AnalysisResult,
        policy_name: str,
        category_actions: dict[EntityType, PrivacyAction] | None = None,
        *,
        advanced_unsafe_mode: bool = False,
        confirmed_allow_categories: set[EntityType] | None = None,
    ) -> ResidualScanResult:
        policy, actions, _ = self.policies.resolve_actions(
            policy_name,
            category_actions,
            advanced_unsafe_mode=advanced_unsafe_mode,
            confirmed_allow_categories=confirmed_allow_categories,
        )
        sanitized = redaction.sanitized_text
        placeholder_stripped = PLACEHOLDER_IN_TEXT.sub(
            lambda match: " " * len(match.group(0)),
            sanitized,
        )
        partial: list[PartialMatch] = []
        for entity in redaction.entities:
            if self._retained_normalized(entity.text, placeholder_stripped):
                partial.append(
                    PartialMatch(
                        entity_type=entity.entity_type,
                        reason="normalized_source_value_remains",
                    )
                )
            prefix_match = re.match(r"[A-Z]{2,16}(?:-[A-Z]{2,8})?[-_]", entity.text, re.IGNORECASE)
            if prefix_match and prefix_match.group(0).casefold() in placeholder_stripped.casefold():
                partial.append(
                    PartialMatch(
                        entity_type=entity.entity_type,
                        reason="identifier_prefix_remains",
                    )
                )

        residual: list[Detection] = []
        # Typed placeholders are intentionally structured and may resemble
        # configured prefixes or labelled values. Hide only valid generated
        # placeholders from re-detection; malformed bracketed output remains
        # visible to the detector and the explicit malformed-output check.
        residual_input = placeholder_stripped
        for detector in self.detectors:
            if detector.name != "regex":
                continue
            try:
                findings = detector.detect(residual_input)
            except Exception:
                return ResidualScanResult(
                    safe_to_send=False,
                    critical_residual_count=1,
                    partial_match_findings=[
                        PartialMatch(
                            entity_type=EntityType.UNKNOWN_SENSITIVE,
                            reason="residual_detector_failed",
                        )
                    ],
                )
            for finding in findings:
                action = actions[finding.entity_type]
                if action != PrivacyAction.ALLOW:
                    residual.append(finding)

        malformed = [
            value
            for value in BRACKETED_VALUE.findall(sanitized)
            if not VALID_PLACEHOLDER.fullmatch(value)
        ]
        indirect: list[str] = []
        if policy.contextual_residual_scan:
            for assertion in analysis.assertions:
                if assertion.action == PrivacyAction.ALLOW:
                    continue
                if assertion.indirect_disclosure_risk != IndirectDisclosureRisk.HIGH:
                    continue
                if any(
                    pattern.search(sanitized)
                    for pattern in (
                        re.compile(r"attends?\s+(?:a\s+)?mosque", re.IGNORECASE),
                        re.compile(r"\bunion dues\b", re.IGNORECASE),
                        re.compile(r"\bchemotherapy session\b", re.IGNORECASE),
                        re.compile(r"\bfingerprint template\b", re.IGNORECASE),
                        re.compile(r"\b(?:her wife|his husband)\b", re.IGNORECASE),
                    )
                ):
                    indirect.append(assertion.id)

        critical_count = sum(
            1
            for finding in residual
            if finding.entity_type in CRITICAL_TYPES
            or actions[finding.entity_type] in {PrivacyAction.BLOCK, PrivacyAction.REDACT}
        )
        safe = not residual and not partial and not malformed and not indirect
        return ResidualScanResult(
            safe_to_send=safe,
            residual_findings=residual,
            partial_match_findings=partial,
            critical_residual_count=critical_count,
            malformed_placeholders=malformed,
            possible_indirect_disclosures=indirect,
        )

    def audit(
        self,
        text: str,
        policy_name: str = "gdpr_strict",
        category_actions: dict[EntityType, PrivacyAction] | None = None,
        *,
        confirmed_allow_categories: set[EntityType] | None = None,
        advanced_unsafe_mode: bool = False,
    ) -> SanitizationAudit:
        _, actions, _ = self.policies.resolve_actions(
            policy_name,
            category_actions,
            advanced_unsafe_mode=advanced_unsafe_mode,
            confirmed_allow_categories=confirmed_allow_categories,
        )
        analysis = self.analyze(
            text,
            policy_name,
            category_actions,
            advanced_unsafe_mode=advanced_unsafe_mode,
            confirmed_allow_categories=confirmed_allow_categories,
        )
        redaction = self.redact(
            text,
            policy_name,
            analysis=analysis,
            category_actions=category_actions,
            advanced_unsafe_mode=advanced_unsafe_mode,
            confirmed_allow_categories=confirmed_allow_categories,
            audit_mode=True,
        )
        residual = self.scan_residual(
            text,
            redaction,
            analysis,
            policy_name,
            category_actions,
            advanced_unsafe_mode=advanced_unsafe_mode,
            confirmed_allow_categories=confirmed_allow_categories,
        )
        return SanitizationAudit(
            profile=policy_name,
            original_findings=analysis.entities,
            assertions=analysis.assertions,
            applied_replacements=redaction.entity_counts,
            sanitized_text=redaction.sanitized_text,
            residual_scan=residual,
            coverage_by_category=dict(
                Counter(item.entity_type.value for item in analysis.entities)
            ),
            explicitly_allowed_categories=sorted(
                (
                    entity_type
                    for entity_type, action in actions.items()
                    if action == PrivacyAction.ALLOW
                ),
                key=lambda item: item.value,
            ),
            provider_invoked=False,
        )

    @staticmethod
    def apply_review_decisions(
        entities: list[Detection],
        decisions: list[ReviewDecision],
    ) -> list[Detection]:
        """Compatibility helper for consumers that review only entity findings."""

        by_id = {decision.detection_id: decision for decision in decisions}
        output: list[Detection] = []
        for entity in entities:
            decision = by_id.get(entity.id)
            if decision is None:
                output.append(entity)
                continue
            if decision.action == ReviewAction.BLOCK:
                raise SendingBlockedError("Sending was blocked during privacy review")
            if decision.action in {ReviewAction.IGNORE, ReviewAction.ALLOW_ONCE}:
                continue
            if decision.action == ReviewAction.CHANGE_TYPE:
                output.append(
                    entity.model_copy(
                        update={
                            "entity_type": decision.entity_type,
                            "requires_review": False,
                        }
                    )
                )
                continue
            output.append(entity.model_copy(update={"requires_review": False}))
        return output

    @staticmethod
    def restore(text: str, mapping: dict[str, str]) -> str:
        return restore_text(text, mapping)

    @staticmethod
    def _retained_normalized(source: str, sanitized: str) -> bool:
        variants = {
            source,
            source.casefold(),
            re.sub(r"\s+", " ", source).strip(),
            re.sub(r"[\s._:/-]+", "", source).casefold(),
            unquote(source),
        }
        targets = {
            sanitized,
            sanitized.casefold(),
            re.sub(r"\s+", " ", sanitized).strip(),
            re.sub(r"[\s._:/-]+", "", sanitized).casefold(),
            unquote(sanitized),
        }
        return any(
            variant and len(variant) >= 3 and variant in target
            for variant in variants
            for target in targets
        )

    @staticmethod
    def _context(text: str, start: int, end: int, radius: int = 36) -> str:
        left = max(0, start - radius)
        right = min(len(text), end + radius)
        prefix = "…" if left else ""
        suffix = "…" if right < len(text) else ""
        return f"{prefix}{text[left:start]}⟦{text[start:end]}⟧{text[end:right]}{suffix}"


class PrivacyError(RuntimeError):
    pass


class ReviewRequiredError(PrivacyError):
    def __init__(self, entities: list[Detection]) -> None:
        super().__init__("Privacy review is required before sending")
        self.entities = entities


class SendingBlockedError(PrivacyError):
    pass
