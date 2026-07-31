from __future__ import annotations

import pytest

from securedact_core import PrivacyEngine
from securedact_core.engine import ReviewRequiredError, SendingBlockedError
from securedact_core.models import (
    Detection,
    DetectionSource,
    EntityType,
    ReviewAction,
    ReviewDecision,
)


class ContextDetector:
    name = "test_context"
    contextual = True

    def detect(self, text: str) -> list[Detection]:
        value = "Ada Lovelace"
        start = text.index(value)
        return [
            Detection(
                start=start,
                end=start + len(value),
                text=value,
                entity_type=EntityType.PERSON,
                confidence=0.70,
                source=DetectionSource.FLAIR,
            )
        ]


class BrokenContextDetector:
    name = "broken_context"
    contextual = True

    def detect(self, _text: str) -> list[Detection]:
        raise RuntimeError("the raw text must never appear in an error")


class CertainContextDetector(ContextDetector):
    def detect(self, text: str) -> list[Detection]:
        return [item.model_copy(update={"confidence": 1.0}) for item in super().detect(text)]


def test_uncertain_contextual_entity_requires_review() -> None:
    engine = PrivacyEngine([ContextDetector()], require_contextual=True)
    text = "Hello Ada Lovelace"
    analysis = engine.analyze(text)
    assert analysis.requires_review
    with pytest.raises(ReviewRequiredError):
        engine.redact(text, analysis=analysis)
    decision = ReviewDecision(detection_id=analysis.entities[0].id, action=ReviewAction.ACCEPT)
    assert (
        engine.redact(text, decisions=[decision], analysis=analysis).sanitized_text
        == "Hello [PERSON_1]"
    )


def test_user_can_ignore_change_type_or_block() -> None:
    engine = PrivacyEngine([ContextDetector()])
    text = "Hello Ada Lovelace"
    analysis = engine.analyze(text)
    entity = analysis.entities[0]
    ignored = ReviewDecision(detection_id=entity.id, action=ReviewAction.IGNORE)
    assert engine.redact(text, decisions=[ignored], analysis=analysis).sanitized_text == text
    changed = ReviewDecision(
        detection_id=entity.id, action=ReviewAction.CHANGE_TYPE, entity_type=EntityType.ORGANIZATION
    )
    assert (
        "[ORGANIZATION_1]"
        in engine.redact(text, decisions=[changed], analysis=analysis).sanitized_text
    )
    blocked = ReviewDecision(detection_id=entity.id, action=ReviewAction.BLOCK)
    with pytest.raises(SendingBlockedError):
        engine.redact(text, decisions=[blocked], analysis=analysis)


def test_required_contextual_detector_fails_closed() -> None:
    result = PrivacyEngine([BrokenContextDetector()], require_contextual=True).analyze(
        "private input"
    )
    assert not result.engine_ready
    assert result.warnings == ["broken_context detector unavailable"]


def test_gdpr_strict_reviews_even_high_confidence_contextual_detection() -> None:
    engine = PrivacyEngine([CertainContextDetector()])
    result = engine.analyze("Hello Ada Lovelace", "gdpr_strict")
    assert result.entities[0].requires_review
