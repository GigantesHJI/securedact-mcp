from __future__ import annotations

import pytest

from securedact_core.detectors import ContextualPrivacyDetector, RegexDetector
from securedact_core.merge import merge_detections
from securedact_core.models import Detection, DetectionSource, EntityType


@pytest.mark.parametrize(
    "text",
    [
        "May is followed by June in this calendar.",
        "Mei volgt op april in de kalender.",
    ],
)
def test_month_words_are_not_misclassified_as_people_or_dates(text: str) -> None:
    detections = RegexDetector().detect(text) + ContextualPrivacyDetector().detect(text)
    assert not {
        EntityType.PERSON,
        EntityType.DATE_OF_BIRTH,
        EntityType.DATE,
    }.intersection(item.entity_type for item in detections)


@pytest.mark.parametrize(
    "name",
    [
        "Anne-Marie de Vries",
        "A. de Vries",
        "van der Jolijn van der Leek-Jorlink",
        "Élodie van Oosten",
        "O\u2019Connor",
        "D'Angelo",
    ],
)
def test_self_identified_accented_hyphenated_and_apostrophe_names(name: str) -> None:
    text = f"Mijn naam is {name}."
    people = [
        item
        for item in ContextualPrivacyDetector().detect(text)
        if item.entity_type == EntityType.PERSON
    ]
    assert any(item.text == name and text[item.start : item.end] == name for item in people)


@pytest.mark.parametrize("possessive", ["Gabriel Fernandez's", "Gabriel Fernandez\u2019s"])
def test_contextual_person_span_excludes_possessive_suffix(possessive: str) -> None:
    text = f"{possessive} sexual activity is recorded."

    people = [
        item
        for item in ContextualPrivacyDetector().detect(text)
        if item.entity_type == EntityType.PERSON
    ]

    assert [item.text for item in people] == ["Gabriel Fernandez"]


def test_non_latin_finding_preserves_python_unicode_offsets() -> None:
    text = "Contact 李雷 today."
    start = text.index("李雷")
    finding = Detection(
        start=start,
        end=start + len("李雷"),
        text="李雷",
        entity_type=EntityType.PERSON,
        confidence=0.99,
        source=DetectionSource.FLAIR,
        rule="synthetic_contextual_test",
    )

    assert merge_detections([finding]) == [finding]
    assert text[finding.start : finding.end] == "李雷"


def test_capitalized_email_is_detected_without_case_normalizing_offsets() -> None:
    text = "Contact Alex.Mixed@Example.Test today."
    emails = [item for item in RegexDetector().detect(text) if item.entity_type == EntityType.EMAIL]

    assert len(emails) == 1
    assert emails[0].text == "Alex.Mixed@Example.Test"
    assert text[emails[0].start : emails[0].end] == emails[0].text


def test_common_noun_is_not_promoted_to_an_organization() -> None:
    text = "Orange chairs fill the quiet hall."
    detections = RegexDetector().detect(text) + ContextualPrivacyDetector().detect(text)

    assert all(item.entity_type != EntityType.ORGANIZATION for item in detections)


def test_compound_dutch_location_preserves_unicode_offsets() -> None:
    text = "Reis morgen naar Bergen op Zoom."
    location_text = "Bergen op Zoom"
    start = text.index(location_text)
    finding = Detection(
        start=start,
        end=start + len(location_text),
        text=location_text,
        entity_type=EntityType.LOCATION,
        confidence=0.97,
        source=DetectionSource.FLAIR,
        rule="synthetic_contextual_test",
    )

    assert merge_detections([finding]) == [finding]
    assert text[finding.start : finding.end] == location_text


def test_fullwidth_email_is_detected_but_preserves_source_boundaries() -> None:
    text = "alex\uff20example.test"
    detections = RegexDetector().detect(text)

    finding = next(item for item in detections if item.entity_type == EntityType.EMAIL)

    assert finding.text == text
    assert (finding.start, finding.end) == (0, len(text))
