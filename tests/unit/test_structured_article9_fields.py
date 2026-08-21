"""Structured Article-9 field extraction — production tests.

These tests cover the *general* structural mechanism (``Label: Value``,
``Label = Value``, ``Label - Value`` and ``Label:<newline>Value``) for the
SecuRedact contextual detector. They use independent synthetic fixtures and do
not import any benchmark phrase, value, or record.
"""

from __future__ import annotations

import pytest

from securedact_core.detectors import ContextualPrivacyDetector
from securedact_core.models import EntityType


@pytest.fixture(scope="module")
def detector() -> ContextualPrivacyDetector:
    return ContextualPrivacyDetector()


# --------------------------------------------------------------------------- #
# English structured fields
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("text", "category", "value"),
    [
        ("Religion: Taoist", EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF, "Taoist"),
        ("Ethnicity = Caribbean-Dutch", EntityType.RACIAL_OR_ETHNIC_ORIGIN, "Caribbean-Dutch"),
        (
            "Political opinion - Socialist Party",
            EntityType.POLITICAL_OPINION,
            "Socialist Party",
        ),
        ("Genetic data: pathogenic variant", EntityType.GENETIC_DATA, "pathogenic variant"),
        ("Health condition: eczema", EntityType.HEALTH_DATA, "eczema"),
        ("Sex life: polyamory", EntityType.SEX_LIFE, "polyamory"),
        ("Sexual orientation: asexual", EntityType.SEXUAL_ORIENTATION, "asexual"),
        ("Trade union: CNV", EntityType.TRADE_UNION_MEMBERSHIP, "CNV"),
    ],
)
def test_en_label_value_variants(detector, text, category, value) -> None:
    detections = [d for d in detector.detect(text) if d.entity_type == category]
    assert any(d.text == value for d in detections), f"expected {value!r} in {text!r}"
    match = next(d for d in detections if d.text == value)
    assert text[match.start : match.end] == value
    # The bare category label must never be emitted as the value.
    assert not any(d.text.casefold() == "religion" for d in detections)


def test_en_empty_field_emits_nothing(detector) -> None:
    detections = detector.detect("Religion:")
    assert not any(
        d.entity_type == EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF for d in detections
    )


def test_en_adjacent_article9_and_normal_fields(detector) -> None:
    text = "Religion: Taoist\nNationality: French\nHealth condition: eczema\nOccupation: Engineer"
    detections = detector.detect(text)
    by_type = {d.entity_type: d.text for d in detections}
    assert by_type.get(EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF) == "Taoist"
    assert by_type.get(EntityType.HEALTH_DATA) == "eczema"
    # Non-Article-9 form fields must not be swallowed into Article-9 spans.
    assert EntityType.RACIAL_OR_ETHNIC_ORIGIN not in by_type
    # Ensure the health value stops at its own field boundary.
    health = next(d for d in detections if d.entity_type == EntityType.HEALTH_DATA)
    assert text[health.start : health.end] == "eczema"


def test_en_two_article9_fields(detector) -> None:
    text = "Religion: Taoist\nPolitical opinion: Socialist Party"
    detections = detector.detect(text)
    values = {d.entity_type: d.text for d in detections}
    assert values[EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF] == "Taoist"
    assert values[EntityType.POLITICAL_OPINION] == "Socialist Party"


def test_en_offsets_are_exact(detector) -> None:
    text = "Recorded ethnicity: Caribbean-Dutch"
    detection = next(
        d for d in detector.detect(text) if d.entity_type == EntityType.RACIAL_OR_ETHNIC_ORIGIN
    )
    assert detection.text == "Caribbean-Dutch"
    assert text[detection.start : detection.end] == "Caribbean-Dutch"


def test_en_value_on_next_line(detector) -> None:
    text = "Religion:\nTaoist"
    detection = next(
        d
        for d in detector.detect(text)
        if d.entity_type == EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF
    )
    assert detection.text == "Taoist"


def test_en_next_line_not_consumed(detector) -> None:
    text = "Religion: Taoist\nNationality: French"
    detection = next(
        d
        for d in detector.detect(text)
        if d.entity_type == EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF
    )
    # The value must stop before the next field and must not absorb the newline.
    assert detection.text == "Taoist"
    assert "\n" not in detection.text


def test_en_trailing_punctuation_trimmed(detector) -> None:
    text = "Religion: Taoist!!!"
    detection = next(
        d
        for d in detector.detect(text)
        if d.entity_type == EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF
    )
    assert detection.text == "Taoist"


def test_en_end_of_document_value(detector) -> None:
    text = "A note about the religion field follows in the appendix."
    # Free-text prose mentioning the category word with no field label and no
    # linked subject is not a sensitive finding.
    detections = detector.detect(text)
    assert not any(
        d.entity_type == EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF for d in detections
    )


def test_en_form_field_without_separator_no_value(detector) -> None:
    # "Religion Taoist" (no separator) is not a structured field.
    text = "The religion Taoist community meets on Sundays."
    detections = detector.detect(text)
    assert not any(
        d.entity_type == EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF for d in detections
    )


# --------------------------------------------------------------------------- #
# Dutch structured fields
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("text", "category", "value"),
    [
        ("Religie: boeddhist", EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF, "boeddhist"),
        (
            "Etniciteit = Surinaams-Nederlands",
            EntityType.RACIAL_OR_ETHNIC_ORIGIN,
            "Surinaams-Nederlands",
        ),
        (
            "Politieke voorkeur - Socialistische Partij",
            EntityType.POLITICAL_OPINION,
            "Socialistische Partij",
        ),
        ("Gezondheidsgegevens: eczeem", EntityType.HEALTH_DATA, "eczeem"),
        ("Vakbond: FNV", EntityType.TRADE_UNION_MEMBERSHIP, "FNV"),
        ("Seksuele geaardheid: aseksueel", EntityType.SEXUAL_ORIENTATION, "aseksueel"),
    ],
)
def test_nl_label_value_variants(detector, text, category, value) -> None:
    detections = [d for d in detector.detect(text) if d.entity_type == category]
    assert any(d.text == value for d in detections), f"expected {value!r} in {text!r}"
    match = next(d for d in detections if d.text == value)
    assert text[match.start : match.end] == value


def test_nl_empty_field_emits_nothing(detector) -> None:
    detections = detector.detect("Religie:")
    assert not any(
        d.entity_type == EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF for d in detections
    )


def test_nl_adjacent_article9_and_normal_fields(detector) -> None:
    text = (
        "Religie: boeddhist\nNationaliteit: Frans\nGezondheidsgegevens: eczeem\nBeroep: Ingenieur"
    )
    detections = detector.detect(text)
    by_type = {d.entity_type: d.text for d in detections}
    assert by_type.get(EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF) == "boeddhist"
    assert by_type.get(EntityType.HEALTH_DATA) == "eczeem"
    assert EntityType.RACIAL_OR_ETHNIC_ORIGIN not in by_type


def test_nl_two_article9_fields(detector) -> None:
    text = "Religie: boeddhist\nPolitieke voorkeur: Socialistische Partij"
    detections = detector.detect(text)
    values = {d.entity_type: d.text for d in detections}
    assert values[EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF] == "boeddhist"
    assert values[EntityType.POLITICAL_OPINION] == "Socialistische Partij"


# --------------------------------------------------------------------------- #
# Controls — category words in ordinary prose / unrelated fields
# --------------------------------------------------------------------------- #
def test_category_word_in_prose_is_not_a_finding(detector) -> None:
    text = "This form contains a religion field for optional completion."
    detections = detector.detect(text)
    assert not any(
        d.entity_type == EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF for d in detections
    )


def test_unrelated_non_article9_field_not_detected(detector) -> None:
    text = "Nationality: French\nOccupation: Engineer"
    detections = detector.detect(text)
    # Neither nationality nor occupation is an Article-9 category.
    assert not any(
        d.entity_type
        in {
            EntityType.RACIAL_OR_ETHNIC_ORIGIN,
            EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF,
            EntityType.POLITICAL_OPINION,
            EntityType.TRADE_UNION_MEMBERSHIP,
            EntityType.HEALTH_DATA,
            EntityType.SEX_LIFE,
            EntityType.SEXUAL_ORIENTATION,
            EntityType.GENETIC_DATA,
        }
        for d in detections
    )


def test_bare_category_label_alone_is_not_a_finding(detector) -> None:
    # A schema that merely mentions the category word is not a disclosure.
    text = "The policy discusses the religion field."
    detections = detector.detect(text)
    assert not any(
        d.entity_type == EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF for d in detections
    )


# --------------------------------------------------------------------------- #
# Regression — free-text value detections still work
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("text", "category"),
    [
        ("Emma is Muslim.", EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF),
        ("Jan is katholiek.", EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF),
        ("John identifies as bisexual.", EntityType.SEXUAL_ORIENTATION),
        ("Emma has type 2 diabetes.", EntityType.HEALTH_DATA),
        ("Robert is a member of the Example Workers Union.", EntityType.TRADE_UNION_MEMBERSHIP),
        ("Emma is lid van een vakbond.", EntityType.TRADE_UNION_MEMBERSHIP),
        ("Emma has a BRCA2 pathogenic variant.", EntityType.GENETIC_DATA),
    ],
)
def test_freetext_value_detections_preserved(detector, text, category) -> None:
    detections = detector.detect(text)
    assert any(d.entity_type == category for d in detections)


def test_structured_field_produces_record_subject_assertion(detector) -> None:
    assertions = detector.detect_assertions("Religion: Taoist")
    assert any(
        a.category == EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF
        and a.subject_entity_ids == ["record-subject"]
        for a in assertions
    )


# --------------------------------------------------------------------------- #
# Regression — value span must not over-capture following form fields / prose
# --------------------------------------------------------------------------- #
def test_en_value_not_swallowed_by_following_field(detector) -> None:
    text = "Recorded ethnicity: Turkish-Dutch\nCase: open"
    detection = next(
        d for d in detector.detect(text) if d.entity_type == EntityType.RACIAL_OR_ETHNIC_ORIGIN
    )
    assert detection.text == "Turkish-Dutch"
    assert "\n" not in detection.text
    assert "Case" not in detection.text


def test_en_value_not_swallowed_by_bullet_continuation(detector) -> None:
    text = "Noted ethnicity: Romanian\n- Accommodation arranged"
    detection = next(
        d for d in detector.detect(text) if d.entity_type == EntityType.RACIAL_OR_ETHNIC_ORIGIN
    )
    assert detection.text == "Romanian"
    assert "Accommodation" not in detection.text


def test_en_value_stops_at_sentence_terminator(detector) -> None:
    text = "Noted ethnicity: Romanian. Plan follow-up in 4 weeks."
    detection = next(
        d for d in detector.detect(text) if d.entity_type == EntityType.RACIAL_OR_ETHNIC_ORIGIN
    )
    assert detection.text == "Romanian"


def test_nl_value_not_swallowed_by_following_field(detector) -> None:
    text = "Vastgelegd etniciteit: Roemeense\nZaak: open"
    detection = next(
        d for d in detector.detect(text) if d.entity_type == EntityType.RACIAL_OR_ETHNIC_ORIGIN
    )
    assert detection.text == "Roemeense"
    assert "Zaak" not in detection.text


def test_hyphenated_value_keeps_internal_hyphen(detector) -> None:
    text = "Ethnicity: Caribbean-Dutch"
    detection = next(
        d for d in detector.detect(text) if d.entity_type == EntityType.RACIAL_OR_ETHNIC_ORIGIN
    )
    assert detection.text == "Caribbean-Dutch"
