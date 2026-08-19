from __future__ import annotations

from dataclasses import dataclass

from .models import Detection, DetectionSource, EntityType

SOURCE_PRIORITY = {
    DetectionSource.LABEL: 0,
    DetectionSource.REGEX: 1,
    DetectionSource.CREDENTIALS: 1,
    DetectionSource.CONTEXTUAL: 2,
    DetectionSource.FLAIR: 3,
}

TYPE_PRIORITY = {
    EntityType.ADDRESS: 100,
    EntityType.SPECIAL_CATEGORY_CONTEXT: 100,
    EntityType.SENSITIVE_URL_PARAMETER: 130,
    EntityType.INTERNAL_URL: 130,
    EntityType.PRIVATE_KEY: 95,
    EntityType.API_TOKEN: 90,
    EntityType.ACCESS_TOKEN: 90,
    EntityType.SESSION_TOKEN: 90,
    EntityType.PASSPORT_NUMBER: 85,
    EntityType.DRIVING_LICENCE_NUMBER: 85,
    EntityType.CUSTOMER_NUMBER: 85,
    EntityType.CASE_NUMBER: 85,
    EntityType.EMPLOYEE_ID: 85,
    EntityType.PAYROLL_NUMBER: 85,
    EntityType.PATIENT_NUMBER: 85,
    EntityType.MEDICAL_RECORD_NUMBER: 85,
    EntityType.POLICY_NUMBER: 85,
    EntityType.INVOICE_NUMBER: 85,
    EntityType.CREDIT_CARD_NUMBER: 85,
    EntityType.DATE_OF_BIRTH: 80,
    EntityType.APPOINTMENT: 80,
}


@dataclass(frozen=True)
class MergeDecision:
    start: int
    end: int
    entity_type: str
    detector: str
    confidence: float
    precedence: int
    decision: str


def overlaps(left: Detection, right: Detection) -> bool:
    return left.start < right.end and right.start < left.end


def _rank(item: Detection) -> tuple[int, int, int, int, float, int, str, str, str]:
    # Policy-selected assertion/sentence replacement is an explicit privacy
    # decision, not a statistical guess. It must cover nested deterministic
    # findings when the policy calls for the entire assertion to be removed.
    policy_scope = (
        0
        if item.rule in {"full_sensitive_assertion", "full_sentence"}
        else 1
        if item.entity_type in {EntityType.SENSITIVE_URL_PARAMETER, EntityType.INTERNAL_URL}
        else 2
    )
    return (
        policy_scope,
        SOURCE_PRIORITY[item.source],
        -max(item.precedence, TYPE_PRIORITY.get(item.entity_type, 0)),
        -item.length,
        -item.confidence,
        item.start,
        item.entity_type.value,
        item.source.value,
        item.rule or "",
    )


def merge_detections(detections: list[Detection]) -> list[Detection]:
    """Return complete, non-overlapping spans using explicit source/type precedence."""

    ranked = sorted(
        detections,
        key=_rank,
    )
    selected: list[Detection] = []
    for candidate in ranked:
        if any(overlaps(candidate, existing) for existing in selected):
            continue
        selected.append(candidate)
    return sorted(selected, key=lambda item: (item.start, item.end))


def merge_detections_with_evidence(detections: list[Detection]) -> list[Detection]:
    """Use the normal merge result and attach non-sensitive agreement/conflict evidence."""

    selected = merge_detections(detections)
    enriched: list[Detection] = []
    for winner in selected:
        supporting = {
            item.source
            for item in detections
            if item.start == winner.start
            and item.end == winner.end
            and item.entity_type == winner.entity_type
        }
        conflicts = {
            item.entity_type
            for item in detections
            if overlaps(winner, item) and item.entity_type != winner.entity_type
        }
        enriched.append(
            winner.model_copy(
                update={
                    "supporting_sources": frozenset(supporting or {winner.source}),
                    "conflicting_entity_types": frozenset(conflicts),
                }
            )
        )
    return enriched


def debug_merge_detections(
    detections: list[Detection],
) -> tuple[list[Detection], list[MergeDecision]]:
    """Return safe-to-display merge metadata for development tooling.

    Callers may add raw ``Detection.text`` only in an explicitly local development
    view. This function intentionally excludes it from the reusable decision record.
    """

    ranked = sorted(
        detections,
        key=_rank,
    )
    selected: list[Detection] = []
    decisions: list[MergeDecision] = []
    for candidate in ranked:
        accepted = not any(overlaps(candidate, existing) for existing in selected)
        if accepted:
            selected.append(candidate)
        decisions.append(
            MergeDecision(
                start=candidate.start,
                end=candidate.end,
                entity_type=candidate.entity_type.value,
                detector=candidate.rule or candidate.source.value,
                confidence=candidate.confidence,
                precedence=max(
                    candidate.precedence,
                    TYPE_PRIORITY.get(candidate.entity_type, 0),
                ),
                decision="selected" if accepted else "discarded_overlap",
            )
        )
    return sorted(selected, key=lambda item: (item.start, item.end)), decisions
