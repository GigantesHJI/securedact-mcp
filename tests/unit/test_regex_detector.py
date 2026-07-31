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
