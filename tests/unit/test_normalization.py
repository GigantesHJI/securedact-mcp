from __future__ import annotations

import pytest

from securedact_core.normalization import (
    normalize_for_detection,
    requires_detection_normalization,
)


@pytest.mark.parametrize(
    ("source", "normalized"),
    [
        ("\uff26\uff55\uff4c\uff4c\uff57\uff49\uff44\uff54\uff48", "Fullwidth"),
        ("Jo\u200bhn", "John"),
        ("O\u2019Neil\u2014Smith", "O'Neil-Smith"),
        ("line\r\n   wrap", "line wrap"),
        ("caf\u0065\u0301", "café"),
        ("user&#64;example.test", "user@example.test"),
        ("user%40example%2Etest", "user@example.test"),
        ("%C3%A9@example.test", "é@example.test"),
    ],
)
def test_normalizes_supported_detector_views(source: str, normalized: str) -> None:
    view = normalize_for_detection(source)

    assert view.text == normalized
    assert view.original_text(0, len(view.text)) == source


def test_maps_inner_normalized_span_over_removed_zero_width_character() -> None:
    source = "prefix Jo\u200bhn suffix"
    view = normalize_for_detection(source)
    start = view.text.index("John")

    source_start, source_end = view.original_span(start, start + len("John"))

    assert source[source_start:source_end] == "Jo\u200bhn"


def test_casefold_expansion_preserves_the_original_character_span() -> None:
    source = "Straße"
    view = normalize_for_detection(source, casefold=True)
    start = view.text.index("ss")

    assert view.text == "strasse"
    assert view.original_text(start, start + 2) == "ß"


@pytest.mark.parametrize("start,end", [(-1, 1), (0, 0), (0, 2)])
def test_rejects_invalid_normalized_spans(start: int, end: int) -> None:
    view = normalize_for_detection("x")

    with pytest.raises(ValueError, match="normalized span is invalid"):
        view.original_span(start, end)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("ordinary ASCII text with one space", False),
        ("ordinary.email@example.test", False),
        ("two  spaces", True),
        ("line\nwrap", True),
        ("user%40example.test", True),
        ("Jo\u200bhn", True),
        ("O\u2019Neil", True),
    ],
)
def test_reports_when_offset_normalization_is_required(text: str, expected: bool) -> None:
    assert requires_detection_normalization(text) is expected
