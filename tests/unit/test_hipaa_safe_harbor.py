from __future__ import annotations

import json
from pathlib import Path

import pytest

from securedact_core.detectors import RegexDetector
from securedact_core.engine import PrivacyEngine
from securedact_core.hipaa import (
    HIPAA_CATEGORY_METADATA,
    HipaaSafeHarborStatus,
    run_hipaa_safe_harbor,
)
from securedact_core.models import EntityType

CORPUS_PATH = (
    Path(__file__).parent.parent.parent / "benchmarks" / "hipaa" / "hipaa_safe_harbor.json"
)
GDPR_CORPUS_DIR = Path(__file__).parent.parent.parent / "benchmarks" / "corpora"


@pytest.fixture()
def regex_detector() -> RegexDetector:
    return RegexDetector()


@pytest.fixture()
def engine() -> PrivacyEngine:
    return PrivacyEngine(detectors=[RegexDetector()])


def _types(text: str) -> set[str]:
    return {item.entity_type.value for item in RegexDetector().detect(text)}


# --- Deterministic detector unit checks ------------------------------------------------


@pytest.mark.parametrize(
    ("text", "entity"),
    [
        ("SSN: 123-45-6789", EntityType.SSN),
        ("Social Security Number: 789 65 4321", EntityType.SSN),
        ("Fax: +1 415-555-8890", EntityType.FAX),
        ("Account No: ACC-773102884", EntityType.ACCOUNT_NUMBER),
        ("Member ID: MBR-448821039", EntityType.HEALTH_PLAN_BENEFICIARY),
        ("VIN: 1M8GDM9AXKP042788", EntityType.VEHICLE_IDENTIFIER),
        ("License plate: 8KGD204", EntityType.VEHICLE_IDENTIFIER),
        ("Device identifier: DEV-55120983", EntityType.DEVICE_IDENTIFIER),
        ("ZIP code: 90210-1234", EntityType.US_ZIP),
        ("Springfield, IL 62704, USA", EntityType.US_ZIP),
        ("62704, IL", EntityType.US_ZIP),
    ],
)
def test_hipaa_identifiers_detected(text: str, entity: EntityType) -> None:
    assert any(item.entity_type == entity for item in RegexDetector().detect(text))


@pytest.mark.parametrize(
    "text",
    [
        "SSN 000-12-3456 is invalid",
        "SSN 666-12-3456 is unassigned",
        "SSN 123-00-4567 has bad group",
        "SSN 123-45-0000 has bad serial",
    ],
)
def test_ssn_invalid_areas_rejected(text: str) -> None:
    assert not any(item.entity_type == EntityType.SSN for item in RegexDetector().detect(text))


def test_vin_check_digit_validated() -> None:
    # 1M8GDM9AXKP042788 carries a valid ISO 3779 check digit (X).
    assert any(
        item.entity_type == EntityType.VEHICLE_IDENTIFIER
        for item in RegexDetector().detect("VIN: 1M8GDM9AXKP042788")
    )
    # 17-char string with an excluded letter (Q) must not be treated as a VIN.
    assert not any(
        item.entity_type == EntityType.VEHICLE_IDENTIFIER
        for item in RegexDetector().detect("token 1Z8GDM9AXKP04278Q here")
    )


@pytest.mark.parametrize(
    "text",
    [
        "The reference number 987654321 is random",  # 9-digit, no separators
        "The quantity 48217 was ordered",  # 5-digit bare
        "The code 12345 appears in the log",  # 5-digit bare
        "Dutch BSN 123456782 and postcode 1015 CJ",  # EU, not US
        "storage age is 45 days",  # age under 89
    ],
)
def test_hard_negatives_not_flagged(text: str) -> None:
    detections = RegexDetector().detect(text)
    assert not any(item.entity_type == EntityType.SSN for item in detections)
    assert not any(item.entity_type == EntityType.US_ZIP for item in detections)
    assert not any(item.entity_type == EntityType.VEHICLE_IDENTIFIER for item in detections)
    assert not any(item.entity_type == EntityType.AGE for item in detections)


def test_eu_identifiers_still_detected_alongside_hipaa() -> None:
    text = "BSN 123456782, postcode 1015 CJ, IBAN NL91 ABNA 0417 1643 00, SSN 123-45-6789"
    types = _types(text)
    assert "bsn" in types
    assert "postcode" in types
    assert "iban" in types
    assert "ssn" in types  # US SSN coexists; EU BSN not misclassified as SSN


# --- Age over 89 ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "present"),
    [
        ("The 92-year-old patient recovered", True),
        ("aged 105 at last visit", True),
        ("age of 90 years", True),
        ("age 45 and age 9 weeks are not individuals over 89", False),
    ],
)
def test_age_over_89_detection(text: str, present: bool) -> None:
    found = any(item.entity_type == EntityType.AGE for item in RegexDetector().detect(text))
    assert found is present


# --- 18-category matrix ----------------------------------------------------------------


def test_eighteen_categories_present() -> None:
    letters = [meta.letter for meta in HIPAA_CATEGORY_METADATA]
    assert letters == [chr(c) for c in range(ord("A"), ord("R") + 1)]


def test_baseline_matrix_counts() -> None:
    full = sum(1 for m in HIPAA_CATEGORY_METADATA if m.status == HipaaSafeHarborStatus.FULL)
    partial = sum(1 for m in HIPAA_CATEGORY_METADATA if m.status == HipaaSafeHarborStatus.PARTIAL)
    unsupported = sum(
        1
        for m in HIPAA_CATEGORY_METADATA
        if m.status == HipaaSafeHarborStatus.UNSUPPORTED_REQUIRES_REVIEW
    )
    not_covered = sum(
        1 for m in HIPAA_CATEGORY_METADATA if m.status == HipaaSafeHarborStatus.NOT_COVERED
    )
    # FULL: D,E,F,G,M,N,O ; PARTIAL: A,B,C,H,I,J,K,L,P,R ; UNSUPPORTED: Q
    # (H was downgraded from FULL to PARTIAL: only standard MRN labels/prefixes are
    # detected; synonyms like 'Record number'/'Chart ID' and separator-less forms are missed.)
    assert full == 7
    assert partial == 10
    assert unsupported == 1
    assert not_covered == 0
    assert full + partial + unsupported + not_covered == 18


def test_category_q_is_unsupported() -> None:
    q = next(m for m in HIPAA_CATEGORY_METADATA if m.letter == "Q")
    assert q.status == HipaaSafeHarborStatus.UNSUPPORTED_REQUIRES_REVIEW


# --- Structured HIPAA result + residual scan --------------------------------------------


def test_structured_result_counts_and_residual(engine: PrivacyEngine) -> None:
    result = run_hipaa_safe_harbor(engine, "SSN: 123-45-6789 and phone +1 415-555-2671")
    assert result.categories_evaluated == 18
    assert result.categories_supported == 17
    assert result.categories_unsupported == 1
    assert result.identifiers_detected >= 2
    assert result.identifiers_redacted >= 2
    # The supported identifiers were redacted, so residual must be empty.
    assert result.residual_identifiers_detected == 0
    g = next(c for c in result.categories if c.letter == "G")
    assert g.detected >= 1
    assert g.redacted >= 1
    assert g.residual == 0


def test_image_limitation_surfaced(engine: PrivacyEngine) -> None:
    result = run_hipaa_safe_harbor(
        engine, "Attached full-face photograph of the patient and a scanned license image."
    )
    assert result.residual_identifiers_detected == 0
    assert any("Q" in w for w in result.unsupported_category_warnings)
    assert "compliance" not in result.disclaimer.lower() or "NOT" in result.disclaimer


def test_result_never_claims_compliance(engine: PrivacyEngine) -> None:
    result = run_hipaa_safe_harbor(engine, "SSN: 123-45-6789")
    text = (result.disclaimer + result.actual_knowledge_note).lower()
    assert "certif" in text or "does not" in text
    # Explicit forbidden claim language must not appear.
    assert "hipaa compliant" not in text


# --- Corpus ----------------------------------------------------------------------------


def _load_corpus() -> list[dict]:
    with CORPUS_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)["samples"]


@pytest.mark.parametrize("sample", _load_corpus(), ids=lambda s: s["id"])
def test_corpus_sample(sample: dict) -> None:
    types = _types(sample["text"])
    for expected in sample.get("expect_present", []):
        assert expected in types, f"{sample['id']}: expected {expected} in {types}"
    for absent in sample.get("expect_absent", []):
        assert absent not in types, f"{sample['id']}: {absent} should be absent in {types}"


def test_corpus_file_is_separate_from_gdpr() -> None:
    """The HIPAA corpus must stay outside the frozen GDPR corpus directory.

    ``securedact_eval.quality.load_evaluation_corpus`` globs ``benchmarks/corpora/*.json``
    and validates every file against the GDPR ``CorpusFile`` schema, and
    ``manifest.json`` pins that directory's contents. A HIPAA corpus placed there breaks
    the quality/release-gate evaluation with ``corpus_schema_invalid``.
    """

    assert CORPUS_PATH.exists()
    assert CORPUS_PATH.parent != GDPR_CORPUS_DIR
    assert not (GDPR_CORPUS_DIR / "hipaa_safe_harbor.json").exists()
    manifest = json.loads((GDPR_CORPUS_DIR / "manifest.json").read_text(encoding="utf-8"))
    on_disk = {path.name for path in GDPR_CORPUS_DIR.glob("*.json")} - {"manifest.json"}
    assert on_disk == set(manifest["files"])
