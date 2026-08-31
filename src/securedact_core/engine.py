from __future__ import annotations

import re
import threading
from collections import Counter
from collections.abc import Iterable
from urllib.parse import unquote

from .detectors.base import Detector
from .detectors.contextual_detector import ContextualPrivacyDetector
from .detectors.regex_detector import RegexDetector
from .merge import merge_detections, merge_detections_with_evidence
from .model_management import ModelManager
from .models import (
    AnalysisResult,
    Detection,
    DetectionSource,
    EntityType,
    FindingDecision,
    IndirectDisclosureRisk,
    PartialMatch,
    PrivacyAction,
    RedactionMode,
    RedactionResult,
    ResidualScanResult,
    ReviewAction,
    ReviewDecision,
    SanitizationAudit,
    SensitiveAssertion,
)
from .normalization import normalize_for_detection
from .policies import Policy, PolicyRegistry
from .redaction import redact_text, restore_text
from .taxonomy import CATEGORY_DEFINITIONS, CRITICAL_TYPES, SPECIAL_CATEGORY_TYPES, mask_preview

VALID_PLACEHOLDER = re.compile(r"^\[(?:REDACTED|[A-Z][A-Z0-9_]*_\d+)\]$")
PLACEHOLDER_IN_TEXT = re.compile(r"\[(?:REDACTED|[A-Z][A-Z0-9_]*_\d+)\]")
BRACKETED_VALUE = re.compile(r"\[[^\[\]\r\n]{1,100}\]")
_GEOGRAPHIC_TYPES = frozenset({EntityType.LOCATION, EntityType.COUNTRY})
_DIRECT_PERSONAL_TYPES = frozenset(
    {
        EntityType.EMAIL,
        EntityType.PHONE,
        EntityType.ADDRESS,
        EntityType.STREET_ADDRESS,
        EntityType.HOUSE_NUMBER,
        EntityType.POSTCODE,
        EntityType.DATE_OF_BIRTH,
        EntityType.BSN,
        EntityType.PASSPORT_NUMBER,
        EntityType.DRIVING_LICENCE_NUMBER,
        EntityType.NATIONAL_ID,
        EntityType.CUSTOMER_NUMBER,
        EntityType.EMPLOYEE_ID,
        EntityType.PAYROLL_NUMBER,
        EntityType.PATIENT_NUMBER,
        EntityType.MEDICAL_RECORD_NUMBER,
        EntityType.IBAN,
        EntityType.SSN,
        EntityType.FAX,
        EntityType.ACCOUNT_NUMBER,
        EntityType.HEALTH_PLAN_BENEFICIARY,
        EntityType.VEHICLE_IDENTIFIER,
        EntityType.US_ZIP,
    }
)
_PERSONAL_RELATION = re.compile(
    r"\b(?:emails?|emailed|calls?|called|works?\s+with|repl(?:y|ies|ied)\s+to|"
    r"lives?\s+(?:at|in)|resides?\s+(?:at|in)|contact(?:ed|s)?|belongs?\s+to)\b",
    re.IGNORECASE,
)


class PrivacyEngine:
    def __init__(
        self,
        detectors: Iterable[Detector] | None = None,
        policies: PolicyRegistry | None = None,
        *,
        require_contextual: bool = False,
        model_manager: ModelManager | None = None,
        required_detector_names: frozenset[str] = frozenset(),
    ) -> None:
        self.detectors: list[Detector] = (
            list(detectors)
            if detectors is not None
            else [RegexDetector(), ContextualPrivacyDetector()]
        )
        self.policies = policies or PolicyRegistry()
        self.require_contextual = require_contextual
        self.model_manager = model_manager
        self.required_detector_names = required_detector_names
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
        language: str = "auto",
        advanced_unsafe_mode: bool = False,
        confirmed_allow_categories: set[EntityType] | None = None,
    ) -> AnalysisResult:
        if language not in {"auto", "en", "nl"}:
            raise ValueError("Unsupported analysis language")
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

        seen_special: set[EntityType] = set()
        for detector in detectors:
            try:
                context_aware = getattr(detector, "detect_with_context", None)
                if context_aware is not None:
                    detected = context_aware(
                        text, {"special_categories": seen_special, "language": language}
                    )
                else:
                    language_detector = getattr(detector, "detect_for_language", None)
                    detected = (
                        language_detector(text, language)
                        if detector.contextual and language_detector is not None
                        else detector.detect(text)
                    )
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
            seen_special |= {
                entity.entity_type
                for entity in detected
                if entity.entity_type in SPECIAL_CATEGORY_TYPES
            }

        if self.require_contextual and not contextual_configured:
            warnings.append("contextual detector is not configured")
            contextual_ready = False

        merged = merge_detections_with_evidence(candidates)
        assertion_evidence = {
            (span.start, span.end, assertion.category)
            for assertion in assertions
            for span in assertion.evidence_spans
        }
        accepted: list[Detection] = []
        for entity in merged:
            if entity.entity_type not in policy.enabled_entity_types:
                continue
            below_detection_threshold = entity.confidence < policy.threshold_for(entity.entity_type)
            if (
                below_detection_threshold
                and entity.entity_type not in policy.low_confidence_review_types
                and not entity.conflicting_entity_types
            ):
                continue
            action = actions[entity.entity_type]
            generic_geography = self._is_generic_geographic_reference(text, entity, merged)
            controlled_by_assertion = (
                entity.entity_type in SPECIAL_CATEGORY_TYPES
                and (entity.start, entity.end, entity.entity_type) in assertion_evidence
            )
            decision, reason_code = self._decide_finding(
                text,
                entity,
                merged,
                policy,
                action,
                generic_geography=generic_geography,
                below_detection_threshold=below_detection_threshold,
            )
            effective_action = {
                FindingDecision.ALLOW: PrivacyAction.ALLOW,
                FindingDecision.PSEUDONYMIZE: PrivacyAction.REDACT,
                FindingDecision.REDACT: PrivacyAction.REDACT,
                FindingDecision.REVIEW: PrivacyAction.REVIEW,
                FindingDecision.BLOCK: PrivacyAction.BLOCK,
            }[decision]
            needs_review = decision == FindingDecision.REVIEW and not controlled_by_assertion
            definition = CATEGORY_DEFINITIONS[entity.entity_type]
            accepted.append(
                entity.model_copy(
                    update={
                        "requires_review": needs_review,
                        "context": self._context(text, entity.start, entity.end),
                        "action": effective_action,
                        "decision": decision,
                        "severity": definition.severity,
                        "masked_preview": mask_preview(entity.text),
                        "rationale_code": reason_code,
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
                        "rationale_code": (
                            "sensitive_category_requires_review"
                            if requires_review
                            else assertion.rationale_code
                        ),
                    }
                )
            )

        blocked = any(entity.action == PrivacyAction.BLOCK for entity in accepted) or any(
            assertion.action == PrivacyAction.BLOCK for assertion in configured_assertions
        )
        deterministic_ready = self.deterministic_detectors_ready()
        if not deterministic_ready:
            warnings.append("required deterministic detector stack is incomplete")
        return AnalysisResult(
            entities=accepted,
            assertions=configured_assertions,
            requires_review=(
                any(entity.requires_review for entity in accepted)
                or any(assertion.requires_review for assertion in configured_assertions)
            ),
            blocked=blocked,
            engine_ready=contextual_ready and deterministic_ready,
            warnings=warnings,
        )

    def _decide_finding(
        self,
        text: str,
        entity: Detection,
        entities: list[Detection],
        policy: Policy,
        policy_action: PrivacyAction,
        *,
        generic_geography: bool,
        below_detection_threshold: bool,
    ) -> tuple[FindingDecision, str]:
        if generic_geography:
            return FindingDecision.ALLOW, "generic_geographic_reference"
        if policy_action == PrivacyAction.BLOCK:
            return FindingDecision.BLOCK, "policy_blocked"
        if policy_action == PrivacyAction.ALLOW:
            return FindingDecision.ALLOW, "policy_allowed"
        if entity.entity_type in SPECIAL_CATEGORY_TYPES:
            return FindingDecision.REVIEW, "sensitive_category_requires_review"
        if below_detection_threshold:
            return FindingDecision.REVIEW, "ambiguous_detection"

        rule = policy.automatic_pseudonymization_rules.get(entity.entity_type)
        source_threshold = rule.source_thresholds.get(entity.source) if rule is not None else None
        threshold_met = source_threshold is not None and entity.confidence >= source_threshold
        contextual_review_forced = entity.entity_type in policy.always_review_types or (
            entity.source in policy.review_sources and policy.review_all_contextual
        )
        personal_context = (
            self._has_personal_context(text, entity, entities)
            if rule is not None and rule.require_personal_context
            else True
        )
        structured_certainty = (
            rule is not None
            and entity.source in {DetectionSource.REGEX, DetectionSource.LABEL}
            and threshold_met
        )
        conflict_requires_review = (
            bool(entity.conflicting_entity_types) and not structured_certainty
        )

        if (
            rule is not None
            and threshold_met
            and personal_context
            and not contextual_review_forced
            and not conflict_requires_review
        ):
            if not policy.automatic_pseudonymization:
                return FindingDecision.REVIEW, "automatic_pseudonymization_disabled"
            if len(entity.supporting_sources) > 1:
                reason = "multiple_detector_agreement"
            elif structured_certainty:
                reason = "high_confidence_structured_pii"
            else:
                reason = "high_confidence_contextual_pii"
            decision = (
                FindingDecision.REDACT
                if policy.replacement_mode == RedactionMode.REMOVE
                else FindingDecision.PSEUDONYMIZE
            )
            return decision, reason
        if entity.entity_type == EntityType.LOCATION and self._has_personal_location_context(
            text, entity, entities
        ):
            return FindingDecision.REVIEW, "personal_location_context"
        return FindingDecision.REVIEW, "ambiguous_detection"

    @classmethod
    def _has_personal_context(
        cls,
        text: str,
        entity: Detection,
        entities: list[Detection],
    ) -> bool:
        if entity.source == DetectionSource.LABEL:
            return True
        sentence_start, sentence_end = cls._sentence_span(text, entity.start, entity.end)
        sentence = text[sentence_start:sentence_end]
        sentence_entities = [
            item for item in entities if item.start < sentence_end and item.end > sentence_start
        ]
        if entity.entity_type == EntityType.LOCATION:
            return cls._has_precise_personal_location_context(text, entity, entities)
        if any(item.entity_type in _DIRECT_PERSONAL_TYPES for item in sentence_entities):
            return True
        people = [item for item in sentence_entities if item.entity_type == EntityType.PERSON]
        return len({item.text.casefold() for item in people}) >= 2 and bool(
            _PERSONAL_RELATION.search(sentence)
        )

    @classmethod
    def _has_personal_location_context(
        cls,
        text: str,
        entity: Detection,
        entities: list[Detection],
    ) -> bool:
        sentence_start, sentence_end = cls._sentence_span(text, entity.start, entity.end)
        sentence_entities = [
            item for item in entities if item.start < sentence_end and item.end > sentence_start
        ]
        has_person = any(item.entity_type == EntityType.PERSON for item in sentence_entities)
        return has_person and bool(_PERSONAL_RELATION.search(text[sentence_start:sentence_end]))

    @classmethod
    def _has_precise_personal_location_context(
        cls,
        text: str,
        entity: Detection,
        entities: list[Detection],
    ) -> bool:
        sentence_start, sentence_end = cls._sentence_span(text, entity.start, entity.end)
        sentence_entities = [
            item for item in entities if item.start < sentence_end and item.end > sentence_start
        ]
        has_personal_relation = cls._has_personal_location_context(text, entity, entities)
        has_precise_address = any(
            item.entity_type
            in {
                EntityType.ADDRESS,
                EntityType.STREET_ADDRESS,
                EntityType.HOUSE_NUMBER,
                EntityType.POSTCODE,
            }
            for item in sentence_entities
        )
        return has_personal_relation and has_precise_address

    @staticmethod
    def _sentence_span(text: str, start: int, end: int) -> tuple[int, int]:
        left_boundaries = [text.rfind(boundary, 0, start) for boundary in ".?!\n"]
        sentence_start = max(left_boundaries) + 1
        right_boundaries = [
            position for boundary in ".?!\n" if (position := text.find(boundary, end)) >= 0
        ]
        sentence_end = min(right_boundaries) if right_boundaries else len(text)
        return sentence_start, sentence_end

    @staticmethod
    def _is_generic_geographic_reference(
        text: str, entity: Detection, entities: list[Detection]
    ) -> bool:
        """Whether a country/place is public geography rather than personal location.

        Detection deliberately retains LOCATION/GPE findings.  This policy-stage
        rule only permits an otherwise review-only geographic mention when no
        person is associated with it in the same sentence.  Precise addresses,
        postcodes and street data use their own entity types and are never
        affected by this rule.
        """

        if entity.entity_type not in _GEOGRAPHIC_TYPES:
            return False
        sentence_start, sentence_end = PrivacyEngine._sentence_span(text, entity.start, entity.end)
        return not any(
            item.entity_type == EntityType.PERSON
            and item.start < sentence_end
            and item.end > sentence_start
            for item in entities
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

    def deterministic_detectors_ready(self) -> bool:
        if not self.required_detector_names:
            return True
        configured = {detector.name for detector in self.detectors if not detector.contextual}
        return self.required_detector_names.issubset(configured)

    def full_ready(self) -> bool:
        return self.deterministic_detectors_ready() and self.contextual_ready()

    def readiness_failure_code(self) -> str | None:
        if not self.deterministic_detectors_ready():
            return "privacy_detector_stack_incomplete"
        return self.contextual_failure_code()

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
            # Analysis may refine a policy default using surrounding context
            # (for example, public geography versus a person's location).
            # Redaction must honor that effective decision rather than
            # recomputing the unrefined type-level default.
            action = entity.action or actions[entity.entity_type]
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
                if decision.action == ReviewAction.REPLACE:
                    output.append(
                        entity.model_copy(
                            update={
                                "requires_review": False,
                                "replacement": decision.replacement,
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
            if decision is not None and decision.action == ReviewAction.REPLACE:
                output.append(
                    self._assertion_detection(text, assertion).model_copy(
                        update={"replacement": decision.replacement}
                    )
                )
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
        normalized_residual_targets = self._normalized_variants(placeholder_stripped)
        partial: list[PartialMatch] = []
        for entity in redaction.entities:
            if self._retained_normalized(entity.text, normalized_residual_targets):
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
            if detector.contextual:
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

        residual = merge_detections(residual)

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
    def _retained_normalized(source: str, targets: set[str]) -> bool:
        variants = PrivacyEngine._normalized_variants(source)
        return any(
            variant and len(variant) >= 3 and variant in target
            for variant in variants
            for target in targets
        )

    @staticmethod
    def _normalized_variants(value: str) -> set[str]:
        normalized = normalize_for_detection(value, casefold=True).text
        return {
            value,
            value.casefold(),
            normalized,
            re.sub(r"\s+", " ", value).strip(),
            re.sub(r"[\s._:/-]+", "", value).casefold(),
            re.sub(r"[\s._:/-]+", "", normalized),
            unquote(value),
        }

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
