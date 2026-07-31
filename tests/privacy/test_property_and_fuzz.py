from __future__ import annotations

import ipaddress
import random
import string
from itertools import pairwise

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from securedact_core import (
    Detection,
    DetectionSource,
    EntityType,
    PrivacyConfiguration,
    PrivacyEngine,
)
from securedact_core.detectors import RegexDetector
from securedact_core.detectors.regex_detector import bsn_valid, iban_valid, luhn_valid
from securedact_core.merge import merge_detections
from securedact_core.redaction import redact_text, restore_text


def _nl_iban(account: str) -> str:
    body = f"ABNA{account}"
    rearranged = f"{body}NL00"
    numeric = "".join(str(ord(char) - 55) if char.isalpha() else char for char in rearranged)
    check = 98 - (int(numeric) % 97)
    return f"NL{check:02d}{body}"


def _luhn_card(prefix: str) -> str:
    for digit in string.digits:
        candidate = prefix + digit
        if luhn_valid(candidate):
            return candidate
    raise AssertionError("No Luhn digit found")


def _bsn(first_eight: int) -> str | None:
    prefix = f"{first_eight:08d}"
    weighted = sum(int(char) * weight for char, weight in zip(prefix, range(9, 1, -1), strict=True))
    final = weighted % 11
    if final > 9:
        return None
    candidate = prefix + str(final)
    return candidate if bsn_valid(candidate) else None


@given(st.integers(min_value=0, max_value=9_999_999_999))
@settings(max_examples=40, deadline=None)
def test_validated_iban_is_fully_redacted(account_number: int) -> None:
    iban = _nl_iban(f"{account_number:010d}")
    assert iban_valid(iban)
    text = f"IBAN: {iban}"
    audit = PrivacyEngine([RegexDetector()]).audit(text)
    assert iban not in audit.sanitized_text
    assert "[IBAN_1]" in audit.sanitized_text
    assert audit.residual_scan.safe_to_send


@given(st.integers(min_value=0, max_value=99_999_999_999_999))
@settings(max_examples=40, deadline=None)
def test_luhn_valid_card_is_never_partially_replaced(body: int) -> None:
    card = _luhn_card(f"4{body:014d}")
    text = f"Credit card: {card}"
    audit = PrivacyEngine([RegexDetector()]).audit(text)
    assert card not in audit.sanitized_text
    assert audit.sanitized_text.endswith("[CREDIT_CARD_NUMBER_1]")
    assert audit.residual_scan.safe_to_send


@given(
    st.integers(min_value=10_000_000, max_value=99_999_999)
    .map(_bsn)
    .filter(lambda value: value is not None)
)
@settings(max_examples=35, deadline=None)
def test_valid_bsn_is_redacted_and_invalid_checksum_is_not_accepted(
    bsn: str | None,
) -> None:
    assert bsn is not None
    detector = RegexDetector()
    valid = detector.detect(f"BSN: {bsn}")
    assert any(item.entity_type == EntityType.BSN and item.text == bsn for item in valid)
    replacement = bsn[:-1] + str((int(bsn[-1]) + 1) % 10)
    if not bsn_valid(replacement):
        bare = detector.detect(replacement)
        assert not any(item.entity_type == EntityType.BSN for item in bare)


@given(st.ip_addresses(v=4), st.ip_addresses(v=6), st.binary(min_size=6, max_size=6))
@settings(max_examples=35, deadline=None)
def test_supported_network_identifiers_are_complete(
    ipv4: ipaddress.IPv4Address,
    ipv6: ipaddress.IPv6Address,
    mac_bytes: bytes,
) -> None:
    mac = ":".join(f"{value:02X}" for value in mac_bytes)
    text = f"IPv4: {ipv4}\nIPv6: {ipv6.compressed}\nMAC address: {mac}"
    audit = PrivacyEngine([RegexDetector()]).audit(text)
    assert str(ipv4) not in audit.sanitized_text
    assert ipv6.compressed not in audit.sanitized_text
    assert mac not in audit.sanitized_text
    assert audit.residual_scan.safe_to_send


@given(
    st.text(alphabet=string.ascii_letters + " ", min_size=0, max_size=30),
    st.text(alphabet=string.ascii_letters + " ", min_size=0, max_size=30),
)
@settings(max_examples=50, deadline=None)
def test_redaction_preserves_text_outside_selected_span(prefix: str, suffix: str) -> None:
    value = "CUST-771199"
    text = prefix + "|" + value + "|" + suffix
    start = len(prefix) + 1
    detection = Detection(
        start=start,
        end=start + len(value),
        text=value,
        entity_type=EntityType.CUSTOMER_NUMBER,
        confidence=1.0,
        source=DetectionSource.REGEX,
    )
    result = redact_text(text, [detection])
    assert result.sanitized_text == prefix + "|[CUSTOMER_NUMBER_1]|" + suffix


def test_repeated_values_map_consistently_and_sessions_are_isolated() -> None:
    engine = PrivacyEngine([RegexDetector()])
    first = engine.audit(
        "Customer number: CUST-771199; repeated CUST-771199",
        "gdpr_strict",
    )
    assert first.sanitized_text.count("[CUSTOMER_NUMBER_1]") == 2
    second = engine.redact("Customer number: CUST-882200", "gdpr_strict")
    assert "[CUSTOMER_NUMBER_1]" in second.sanitized_text
    assert "CUST-771199" not in second.mapping.values()
    first_redaction = engine.redact(
        "Customer number: CUST-771199; repeated CUST-771199",
        "gdpr_strict",
    )
    assert restore_text("[UNKNOWN_9]", first_redaction.mapping) == "[UNKNOWN_9]"


def test_seeded_fuzz_inputs_do_not_crash_or_create_overlapping_output() -> None:
    generator = random.Random(0x5EC0DA7)
    alphabet = string.ascii_letters + string.digits + string.punctuation + " \t\n\u00e9\u2014\u200b"
    detector = RegexDetector()
    for _ in range(250):
        text = "".join(generator.choice(alphabet) for _ in range(generator.randrange(0, 400)))
        findings = detector.detect(text)
        merged = merge_detections(findings)
        assert all(left.end <= right.start for left, right in pairwise(merged))
        result = redact_text(text, merged)
        result.sanitized_text.encode("utf-8")


@pytest.mark.parametrize(
    ("text", "forbidden"),
    [
        ("API token: sk-test-123456", ("sk-test-123456",)),
        ("api-token = sk-test-abcdef", ("sk-test-abcdef",)),
        ("API TOKEN:\nsk-test-112233", ("sk-test-112233",)),
        ('"api_token":"sk-test-778899"', ("sk-test-778899",)),
        ("**API token**: `sk-test-445566`", ("sk-test-445566",)),
        ("API token:\u200bsk-test-223344", ("sk-test-223344",)),
        ("API token: SK-TEST-AABBCC", ("SK-TEST-AABBCC",)),
        ("API token: sk\u2014test\u2014ocr123", ("sk\u2014test\u2014ocr123",)),
        ("API token: s k - t e s t - 1 2 3", ("s k - t e s t - 1 2 3",)),
        ("sk-test-before123 (API token)", ("sk-test-before123",)),
        (
            "API token: sk-test-first1; API key: sk-test-second2",
            ("sk-test-first1", "sk-test-second2"),
        ),
        ("[API token: sk-test-bracket3]", ("sk-test-bracket3",)),
        ("API\t token: sk-test-tabbed4", ("sk-test-tabbed4",)),
    ],
)
def test_deterministic_secret_mutations_are_blocked_and_fully_sanitized(
    text: str,
    forbidden: tuple[str, ...],
) -> None:
    engine = PrivacyEngine([RegexDetector()])
    analysis = engine.analyze(text, "gdpr_strict")
    assert any(item.entity_type == EntityType.API_TOKEN for item in analysis.entities)
    assert analysis.blocked
    audit = engine.audit(text, "gdpr_strict")
    for value in forbidden:
        assert value not in audit.sanitized_text
    assert audit.residual_scan.safe_to_send


def test_url_encoded_sensitive_query_is_replaced_as_one_span() -> None:
    value = (
        "https://public.example.test/chat?"
        "token=%73%6B%2Dtest%2Dencoded5&email=url.synthetic%40example.test"
    )
    audit = PrivacyEngine([RegexDetector()]).audit(f"redirect={value}", "gdpr_strict")
    assert value not in audit.sanitized_text
    assert "[SENSITIVE_URL_PARAMETER_1]" in audit.sanitized_text
    assert audit.residual_scan.safe_to_send


@given(
    st.text(min_size=1, max_size=30).filter(
        lambda value: value not in {"redact", "review", "allow", "block"}
    )
)
@settings(max_examples=40, deadline=None)
def test_malformed_category_actions_never_become_allow(action: str) -> None:
    with pytest.raises(ValidationError):
        PrivacyConfiguration.model_validate(
            {
                "active_profile": "gdpr_strict",
                "category_actions": {"api_token": action},
            }
        )
