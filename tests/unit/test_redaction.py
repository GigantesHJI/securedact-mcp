from securedact_core.models import Detection, DetectionSource, EntityType, RedactionMode
from securedact_core.redaction import redact_text, restore_text


def make_detection(text: str, source: str, kind: EntityType) -> Detection:
    start = source.index(text)
    return Detection(
        start=start,
        end=start + len(text),
        text=text,
        entity_type=kind,
        confidence=1,
        source=DetectionSource.REGEX,
    )


def test_typed_tokens_are_stable_for_repeated_values_and_restorable() -> None:
    text = "Ada emailed Ada"
    entities = [
        Detection(
            start=0,
            end=3,
            text="Ada",
            entity_type=EntityType.PERSON,
            confidence=1,
            source=DetectionSource.FLAIR,
        ),
        Detection(
            start=12,
            end=15,
            text="Ada",
            entity_type=EntityType.PERSON,
            confidence=1,
            source=DetectionSource.FLAIR,
        ),
    ]
    result = redact_text(text, entities)
    assert result.sanitized_text == "[PERSON_1] emailed [PERSON_1]"
    assert result.mapping == {"[PERSON_1]": "Ada"}
    assert restore_text(result.sanitized_text, result.mapping) == text


def test_remove_mode_never_creates_a_restoration_mapping() -> None:
    text = "mail me at ada@example.test"
    entity = make_detection("ada@example.test", text, EntityType.EMAIL)
    result = redact_text(text, [entity], RedactionMode.REMOVE)
    assert result.sanitized_text == "mail me at [REDACTED]"
    assert result.mapping == {}


def test_redaction_rejects_stale_offsets() -> None:
    entity = Detection(
        start=0,
        end=3,
        text="Ada",
        entity_type=EntityType.PERSON,
        confidence=1,
        source=DetectionSource.FLAIR,
    )
    try:
        redact_text("Eve", [entity])
    except ValueError as exc:
        assert "offsets" in str(exc)
    else:
        raise AssertionError("stale offsets must be rejected")


def test_restore_leaves_unknown_placeholders_unchanged() -> None:
    assert (
        restore_text(
            "Known [PERSON_1], unknown [EMAIL_9]",
            {"[PERSON_1]": "Ada"},
        )
        == "Known Ada, unknown [EMAIL_9]"
    )


def test_restore_is_single_pass_and_never_recurses_through_mapping_values() -> None:
    assert (
        restore_text(
            "[PERSON_1]",
            {
                "[PERSON_1]": "[EMAIL_1]",
                "[EMAIL_1]": "private@example.test",
            },
        )
        == "[EMAIL_1]"
    )
