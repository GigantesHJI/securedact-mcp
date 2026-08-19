import pytest

from securedact_core.models import Detection, DetectionSource, EntityType, RedactionMode
from securedact_core.redaction import _resolve_person_aliases, redact_text, restore_text


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


def test_custom_pseudonyms_preserve_category_and_cannot_collapse_identities() -> None:
    text = "Ada met Grace"
    ada = make_detection("Ada", text, EntityType.PERSON).model_copy(
        update={"replacement": "[PERSON_7]"}
    )
    grace = make_detection("Grace", text, EntityType.PERSON).model_copy(
        update={"replacement": "[PERSON_7]"}
    )

    with pytest.raises(ValueError, match="Different source entities"):
        redact_text(text, [ada, grace])

    with pytest.raises(ValueError, match="preserve the entity category"):
        redact_text(
            text,
            [ada.model_copy(update={"replacement": "[EMAIL_7]"})],
        )


def test_person_resolution_diagnostics_are_opaque_and_request_local() -> None:
    text = "Sophie de Vries met Sophie."
    entities = [
        make_detection("Sophie de Vries", text, EntityType.PERSON),
        Detection(
            start=text.rindex("Sophie"),
            end=text.rindex("Sophie") + len("Sophie"),
            text="Sophie",
            entity_type=EntityType.PERSON,
            confidence=1,
            source=DetectionSource.FLAIR,
        ),
    ]

    first = _resolve_person_aliases(entities)
    second = _resolve_person_aliases(entities)

    assert first.group_by_index == {0: "person-group-1", 1: "person-group-1"}
    assert first.group_count == 1
    assert first.aliases_merged == 1
    assert first.ambiguous_mentions == 0
    assert first == second
    assert "Sophie" not in repr(first)


def test_person_resolution_handles_case_differences_without_fuzzy_matching() -> None:
    text = "Sophie de Vries met SOPHIE and Sophy."
    entities = [
        make_detection("Sophie de Vries", text, EntityType.PERSON),
        make_detection("SOPHIE", text, EntityType.PERSON),
        make_detection("Sophy", text, EntityType.PERSON),
    ]

    result = redact_text(text, entities)

    assert result.sanitized_text == "[PERSON_1] met [PERSON_1] and [PERSON_2]."


def test_ambiguous_first_name_gets_a_distinct_unresolved_group() -> None:
    text = "Sophie de Vries met Sophie Jansen. Sophie sent the report."
    entities = [
        make_detection("Sophie de Vries", text, EntityType.PERSON),
        make_detection("Sophie Jansen", text, EntityType.PERSON),
        Detection(
            start=text.rindex("Sophie"),
            end=text.rindex("Sophie") + len("Sophie"),
            text="Sophie",
            entity_type=EntityType.PERSON,
            confidence=1,
            source=DetectionSource.FLAIR,
        ),
    ]

    resolution = _resolve_person_aliases(entities)
    result = redact_text(text, entities)

    assert resolution.group_count == 3
    assert resolution.aliases_merged == 0
    assert resolution.ambiguous_mentions == 1
    assert result.sanitized_text == ("[PERSON_1] met [PERSON_2]. [PERSON_3] sent the report.")


def test_unique_and_ambiguous_surname_resolution_is_conservative() -> None:
    unique_text = "Mark Jansen signed the report. Jansen sent it."
    unique_entities = [
        make_detection("Mark Jansen", unique_text, EntityType.PERSON),
        Detection(
            start=unique_text.rindex("Jansen"),
            end=unique_text.rindex("Jansen") + len("Jansen"),
            text="Jansen",
            entity_type=EntityType.PERSON,
            confidence=1,
            source=DetectionSource.FLAIR,
        ),
    ]
    assert redact_text(unique_text, unique_entities).sanitized_text == (
        "[PERSON_1] signed the report. [PERSON_1] sent it."
    )

    ambiguous_text = "Mark Jansen met Sophie Jansen. Jansen sent the report."
    ambiguous_entities = [
        make_detection("Mark Jansen", ambiguous_text, EntityType.PERSON),
        make_detection("Sophie Jansen", ambiguous_text, EntityType.PERSON),
        Detection(
            start=ambiguous_text.rindex("Jansen"),
            end=ambiguous_text.rindex("Jansen") + len("Jansen"),
            text="Jansen",
            entity_type=EntityType.PERSON,
            confidence=1,
            source=DetectionSource.FLAIR,
        ),
    ]
    assert redact_text(ambiguous_text, ambiguous_entities).sanitized_text == (
        "[PERSON_1] met [PERSON_2]. [PERSON_3] sent the report."
    )
