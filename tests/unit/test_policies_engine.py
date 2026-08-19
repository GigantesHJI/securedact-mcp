from __future__ import annotations

import pytest

from securedact_core import PrepareStatus, PrivacyEngine, RedactionRequest, SecuredactEngine
from securedact_core.detectors import RegexDetector
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


class GeographyAndPersonDetector:
    """Deterministic stand-in for contextual PERSON/LOCATION labels."""

    name = "test_geography"
    contextual = True
    ready = True

    _values = (
        ("Sophie de Vries", EntityType.PERSON),
        ("Sophie", EntityType.PERSON),
        ("France", EntityType.LOCATION),
        ("Europe", EntityType.LOCATION),
        ("Zwolle", EntityType.LOCATION),
    )

    def detect(self, text: str) -> list[Detection]:
        findings: list[Detection] = []
        for value, entity_type in self._values:
            start = text.find(value)
            if start >= 0:
                findings.append(
                    Detection(
                        start=start,
                        end=start + len(value),
                        text=value,
                        entity_type=entity_type,
                        confidence=0.99,
                        source=DetectionSource.FLAIR,
                        rationale_code="contextual_entity",
                    )
                )
        return findings


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


@pytest.mark.parametrize(
    "text",
    (
        "Where is France?",
        "What is the capital of France?",
        "France is in Europe.",
        "Zwolle is in the Netherlands.",
        "I want to travel to France.",
    ),
)
@pytest.mark.parametrize("policy", ("default", "strict_external_ai", "gdpr_strict"))
def test_generic_geography_is_not_personal_location_data(text: str, policy: str) -> None:
    engine = PrivacyEngine([GeographyAndPersonDetector()])
    analysis = engine.analyze(text, policy)
    locations = [item for item in analysis.entities if item.entity_type == EntityType.LOCATION]

    assert locations
    assert all(item.action.value == "allow" for item in locations)
    assert all(item.rationale_code == "generic_geographic_reference" for item in locations)
    assert not analysis.requires_review
    result = SecuredactEngine(engine).prepare(RedactionRequest(text=text, policy=policy))
    assert result.status == PrepareStatus.OK
    assert result.sanitized_text == text


@pytest.mark.parametrize(
    "text",
    (
        "Sophie lives in France.",
        "Sophie de Vries lives in Zwolle.",
    ),
)
@pytest.mark.parametrize("policy", ("default", "strict_external_ai", "gdpr_strict"))
def test_person_associated_location_remains_reviewable(text: str, policy: str) -> None:
    analysis = PrivacyEngine([GeographyAndPersonDetector()]).analyze(text, policy)
    location = next(item for item in analysis.entities if item.entity_type == EntityType.LOCATION)

    assert location.action.value == "review"
    assert location.requires_review
    assert analysis.requires_review


def test_full_address_remains_protected_even_with_person_location_context() -> None:
    text = "Sophie de Vries lives at Kerkstraat 24, 8011 AB Zwolle."
    analysis = PrivacyEngine([RegexDetector(), GeographyAndPersonDetector()]).analyze(
        text, "strict_external_ai"
    )

    assert any(item.entity_type == EntityType.ADDRESS for item in analysis.entities)
    assert all(
        item.action.value != "allow"
        for item in analysis.entities
        if item.entity_type in {EntityType.ADDRESS, EntityType.POSTCODE, EntityType.STREET_ADDRESS}
    )


def test_postcode_remains_protected_without_person_context() -> None:
    analysis = PrivacyEngine([RegexDetector()]).analyze("8011 AB", "strict_external_ai")
    postcode = next(item for item in analysis.entities if item.entity_type == EntityType.POSTCODE)

    assert postcode.action.value != "allow"
