from __future__ import annotations

import pytest

from securedact_core.detectors import ContextualPrivacyDetector, RegexDetector
from securedact_core.models import EntityType


@pytest.mark.parametrize(
    ("labelled", "value", "expected"),
    [
        ("Passport number", "NX4R7P21", EntityType.PASSPORT_NUMBER),
        ("Driving licence number", "DV-NL-882177", EntityType.DRIVING_LICENCE_NUMBER),
        ("Customer number", "CUST-882911", EntityType.CUSTOMER_NUMBER),
        ("Case number", "CASE-NL-7731", EntityType.CASE_NUMBER),
        ("BIC", "ABNANL2A", EntityType.BIC_SWIFT),
        ("Account reference", "ACC-771882", EntityType.BANK_ACCOUNT_REFERENCE),
        ("Payment reference", "RF18539007547034", EntityType.PAYMENT_REFERENCE),
        ("Expiry", "12/30", EntityType.CARD_EXPIRY),
        ("CVV", "123", EntityType.CARD_SECURITY_CODE),
        ("Invoice number", "INV-2026-819", EntityType.INVOICE_NUMBER),
        ("Employee ID", "EMP-884291", EntityType.EMPLOYEE_ID),
        ("Payroll number", "PAYROLL-7718", EntityType.PAYROLL_NUMBER),
        ("Patient number", "PAT-77921", EntityType.PATIENT_NUMBER),
        ("Medical record number", "MRN-882190", EntityType.MEDICAL_RECORD_NUMBER),
        ("Policy number", "POL-NL-88217731", EntityType.POLICY_NUMBER),
        ("MAC address", "AA:BB:CC:DD:EE:FF", EntityType.MAC_ADDRESS),
        ("Device identifier", "DEV-99882", EntityType.DEVICE_IDENTIFIER),
        ("Session token", "session-test-88aa7711", EntityType.SESSION_TOKEN),
        ("API token", "sk-test-123456", EntityType.API_TOKEN),
    ],
)
def test_labelled_structured_values_use_complete_typed_spans(
    labelled: str,
    value: str,
    expected: EntityType,
) -> None:
    text = f"{labelled}: {value}"
    detections = RegexDetector().detect(text)
    matches = [item for item in detections if item.entity_type == expected]
    assert matches
    assert any(item.text == value and text[item.start : item.end] == value for item in matches)


def test_prefixed_identifiers_outrank_phone_fragments() -> None:
    values = {
        "DV-NL-882177": EntityType.DRIVING_LICENCE_NUMBER,
        "CUST-882911": EntityType.CUSTOMER_NUMBER,
        "CASE-NL-7731": EntityType.CASE_NUMBER,
        "MRN-882190": EntityType.MEDICAL_RECORD_NUMBER,
    }
    detector = RegexDetector()
    for value, expected in values.items():
        detections = detector.detect(value)
        assert any(item.entity_type == expected and item.text == value for item in detections)
        assert not any(item.entity_type == EntityType.PHONE for item in detections)


def test_date_time_expiry_and_postcode_are_not_confused() -> None:
    detector = RegexDetector()
    assert not any(item.entity_type == EntityType.POSTCODE for item in detector.detect("2026"))
    assert {item.entity_type for item in detector.detect("09:30")} == {EntityType.TIME}
    assert not any(item.entity_type == EntityType.CARD_EXPIRY for item in detector.detect("12/30"))
    assert any(
        item.entity_type == EntityType.CARD_EXPIRY for item in detector.detect("Card expiry: 12/30")
    )
    assert {item.entity_type for item in detector.detect("1015 CJ")} == {EntityType.POSTCODE}


def test_complete_address_outranks_nested_components() -> None:
    text = "Keizersgracht 123, 1015 CJ Amsterdam, Netherlands"
    matches = [
        item for item in RegexDetector().detect(text) if item.entity_type == EntityType.ADDRESS
    ]
    assert any(item.text == text for item in matches)


def test_sensitive_and_internal_urls_are_whole_url_findings() -> None:
    detector = RegexDetector()
    sensitive = "https://example.test/case?email=emma%40example.test&token=abc"
    internal = "http://case.internal/portal/CASE-NL-7731"
    assert any(
        item.entity_type == EntityType.SENSITIVE_URL_PARAMETER and item.text == sensitive
        for item in detector.detect(sensitive)
    )
    assert any(
        item.entity_type == EntityType.INTERNAL_URL and item.text == internal
        for item in detector.detect(internal)
    )


@pytest.mark.parametrize(
    ("text", "category"),
    [
        ("Emma identifies as Dutch-Moroccan.", EntityType.RACIAL_OR_ETHNIC_ORIGIN),
        ("John supports the Green Party.", EntityType.POLITICAL_OPINION),
        ("Anna is Muslim.", EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF),
        ("Robert is a member of the Example Workers Union.", EntityType.TRADE_UNION_MEMBERSHIP),
        ("Emma has a BRCA1 pathogenic variant.", EntityType.GENETIC_DATA),
        ("Emma has type 2 diabetes.", EntityType.HEALTH_DATA),
        ("John identifies as bisexual.", EntityType.SEXUAL_ORIENTATION),
        ("Jan is katholiek.", EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF),
        ("Sofia heeft diabetes type 2.", EntityType.HEALTH_DATA),
        ("Emma is lid van een vakbond.", EntityType.TRADE_UNION_MEMBERSHIP),
    ],
)
def test_person_linked_special_category_assertions(
    text: str,
    category: EntityType,
) -> None:
    detector = ContextualPrivacyDetector()
    assertions = detector.detect_assertions(text)
    assert any(item.category == category and item.subject_entity_ids for item in assertions)


@pytest.mark.parametrize(
    "text",
    [
        "The article discusses Christianity.",
        "The election result was announced.",
        "A union published a report.",
        "The hospital treats diabetes.",
        "Facial recognition is debated in parliament.",
        "The program includes a genetics lecture.",
        "The film includes a bisexual character.",
    ],
)
def test_general_discussion_is_not_person_specific_special_category_data(
    text: str,
) -> None:
    assert ContextualPrivacyDetector().detect_assertions(text) == []


def test_negation_is_preserved_on_assertion() -> None:
    assertion = ContextualPrivacyDetector().detect_assertions(
        "Emma is not a member of the Example Workers Union."
    )[0]
    assert assertion.category == EntityType.TRADE_UNION_MEMBERSHIP
    assert assertion.negated


def test_biometric_field_uses_identifier_value_instead_of_natural_language_label() -> None:
    text = "Face-recognition embedding: FACE-77A91B."
    detector = ContextualPrivacyDetector()

    biometric_detections = [
        item for item in detector.detect(text) if item.entity_type == EntityType.BIOMETRIC_DATA
    ]
    assertion = detector.detect_assertions(text)[0]

    assert [item.text for item in biometric_detections] == ["FACE-77A91B"]
    assert [span.text for span in assertion.evidence_spans] == ["FACE-77A91B"]


@pytest.mark.parametrize(
    ("text", "person", "evidence"),
    [
        ("Emma%20Stone has BRCA1.", "Emma%20Stone", "BRCA1"),
        ("Emma\u200b Stone has BRCA1.", "Emma\u200b Stone", "BRCA1"),
        ("Emma Stone has\nBRCA1.", "Emma Stone", "BRCA1"),
        (
            "\uff25\uff4d\uff4d\uff41 \uff33\uff54\uff4f\uff4e\uff45 has "
            "\uff22\uff32\uff23\uff21\uff11.",
            "\uff25\uff4d\uff4d\uff41 \uff33\uff54\uff4f\uff4e\uff45",
            "\uff22\uff32\uff23\uff21\uff11",
        ),
    ],
)
def test_normalized_assertions_preserve_original_person_and_evidence_offsets(
    text: str,
    person: str,
    evidence: str,
) -> None:
    detector = ContextualPrivacyDetector()
    detections = detector.detect(text)
    assertion = detector.detect_assertions(text)[0]

    assert any(item.entity_type == EntityType.PERSON and item.text == person for item in detections)
    assert assertion.evidence_spans[0].text == evidence
    assert text[assertion.evidence_spans[0].start : assertion.evidence_spans[0].end] == evidence
