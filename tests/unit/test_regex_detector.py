from __future__ import annotations

import pytest

from securedact_core.detectors import RegexDetector
from securedact_core.models import EntityType


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("ada@example.test", EntityType.EMAIL),
        ("+31 6 12345678", EntityType.PHONE),
        ("NL91 ABNA 0417 1643 00", EntityType.IBAN),
        ("4111 1111 1111 1111", EntityType.CREDIT_CARD),
        ("192.168.12.4", EntityType.IPV4),
        ("2001:db8::8a2e:370:7334", EntityType.IPV6),
        ("https://securedact.example/path?q=yes", EntityType.URL),
        ("123456782", EntityType.BSN),
        ("1012 JS", EntityType.POSTCODE),
    ],
)
def test_detects_valid_deterministic_identifiers(value: str, expected: EntityType) -> None:
    detections = RegexDetector().detect(f"before {value} after")
    assert any(item.entity_type == expected and item.text == value for item in detections)


@pytest.mark.parametrize(
    ("value", "forbidden"),
    [
        ("NL91 ABNA 0417 1643 01", EntityType.IBAN),
        ("4111 1111 1111 1112", EntityType.CREDIT_CARD),
        ("999.168.1.1", EntityType.IPV4),
        ("123456789", EntityType.BSN),
        ("0000 AA", EntityType.POSTCODE),
    ],
)
def test_rejects_invalid_or_failed_checksum_values(value: str, forbidden: EntityType) -> None:
    assert not any(item.entity_type == forbidden for item in RegexDetector().detect(value))


def test_offsets_point_to_the_exact_original_text() -> None:
    text = "Reach me through hello@example.test tomorrow."
    detection = RegexDetector().detect(text)[0]
    assert text[detection.start : detection.end] == detection.text


@pytest.mark.parametrize(
    ("value", "expected", "entity_type"),
    [
        ("user\u200b@example.test", "user\u200b@example.test", EntityType.EMAIL),
        ("user%40example%2Etest", "user%40example%2Etest", EntityType.EMAIL),
        ("user&#64;example.test", "user&#64;example.test", EntityType.EMAIL),
        (
            "\uff2e\uff2c\uff19\uff11\u3000\uff21\uff22\uff2e\uff21\u3000"
            "\uff10\uff14\uff11\uff17\u3000\uff11\uff16\uff14\uff13\u3000\uff10\uff10",
            "\uff2e\uff2c\uff19\uff11\u3000\uff21\uff22\uff2e\uff21\u3000"
            "\uff10\uff14\uff11\uff17\u3000\uff11\uff16\uff14\uff13\u3000\uff10\uff10",
            EntityType.IBAN,
        ),
    ],
)
def test_normalized_detection_maps_back_to_exact_source_offsets(
    value: str,
    expected: str,
    entity_type: EntityType,
) -> None:
    text = f"before {value} after"

    detection = next(item for item in RegexDetector().detect(text) if item.entity_type == entity_type)

    assert detection.text == expected
    assert text[detection.start : detection.end] == expected
