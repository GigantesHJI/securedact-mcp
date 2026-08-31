from __future__ import annotations

import pytest

from securedact_core.detectors import RegexDetector
from securedact_core.engine import PrivacyEngine
from securedact_core.models import EntityType


@pytest.fixture()
def detector() -> RegexDetector:
    return RegexDetector()


@pytest.fixture()
def engine() -> PrivacyEngine:
    return PrivacyEngine(detectors=[RegexDetector()])


def _types(detector: RegexDetector, text: str) -> set[EntityType]:
    return {item.entity_type for item in detector.detect(text)}


# --- DEFECT 1: lowercase English words matching USPS state abbreviations -----------------
# ``us_zip_state`` was compiled with re.IGNORECASE, so any five-digit number followed or
# preceded by a lowercase word that happens to spell a USPS abbreviation (in, or, me, hi,
# ok, de, la, pa, ...) was classified as a US ZIP and auto-redacted under both the default
# and hipaa_safe_harbor policies.
@pytest.mark.parametrize(
    "text",
    [
        "Ceftriaxone diluted in 10000 mL of saline.",
        "Dose measured in 12000 units per day.",
        "Titre was 1 in 10000 dilution.",
        "The reference is 12345, or a substitute may be used.",
        "Total was 12345, me and the nurse verified it.",
        "Sample count 12345, ok to proceed.",
        "Listed as 12345, de novo mutation suspected.",
        "The batch la 12345 was recalled.",
        "Study id 12345, pa positive.",
    ],
)
def test_lowercase_state_words_do_not_create_us_zip(detector: RegexDetector, text: str) -> None:
    assert EntityType.US_ZIP not in _types(detector, text)


def test_lowercase_state_zip_false_positive_does_not_corrupt_redaction() -> None:
    engine = PrivacyEngine(detectors=[RegexDetector()])
    text = "Ceftriaxone diluted in 10000 mL of saline."
    for policy in ("default", "hipaa_safe_harbor"):
        audit = engine.audit(text, policy)
        assert audit.sanitized_text == text, policy


@pytest.mark.parametrize(
    "text",
    [
        "Springfield, IL 62704",
        "62704, IL",
        "IL 62704",
        "14 Birchwood Lane, Springfield, IL 62704",
        "Boston MA 02115",
        "Reno NV 89501",
        # comma between the state token and the ZIP is a common postal form
        "Springfield, IL, 62704",
        "Boston, MA, 02115-1234",
    ],
)
def test_uppercase_state_qualified_zip_still_detected(detector: RegexDetector, text: str) -> None:
    assert EntityType.US_ZIP in _types(detector, text)


# --- DEFECT 2: hyphen-only North American phone/fax numbers were undetectable ------------
# ``_phone`` required '+', a leading '0', or one of "(). " in the value, which is an
# EU-centric heuristic. The dominant US written form NNN-NNN-NNNN was rejected, so even
# ``Phone: 415-555-2671`` and ``Fax: 415-555-8890`` produced no finding at all.
@pytest.mark.parametrize(
    "text",
    [
        "Call 415-555-2671",
        "Phone: 415-555-2671",
        "Telephone: 415-555-2671",
        "Call 800-555-0199",
        "Call 1-800-555-0199",
    ],
)
def test_north_american_hyphen_phone_detected(detector: RegexDetector, text: str) -> None:
    assert EntityType.PHONE in _types(detector, text)


@pytest.mark.parametrize(
    "text",
    [
        "Fax: 415-555-8890",
        "FAX# 415-555-8890",
        "Fax number: (415) 555-8890",
        "Telefax: 415-555-8890",
        "Facsimile: 415-555-8890",
    ],
)
def test_fax_labels_detect_us_formats(detector: RegexDetector, text: str) -> None:
    assert EntityType.FAX in _types(detector, text)


@pytest.mark.parametrize(
    "text",
    [
        "SSN 123-45-6789",  # 3-2-4 grouping must stay out of the phone rule
        "Surgery on 14-03-2021",
        "ZIP 90210-1234",
        "card 4111-1111-1111-1111",
    ],
)
def test_non_phone_digit_groupings_not_promoted_to_phone(
    detector: RegexDetector, text: str
) -> None:
    assert EntityType.PHONE not in _types(detector, text)


# --- DEFECT 3: VIN check-digit validation was advertised but never wired in --------------
def test_vin_label_accepts_values_without_check_digit_validation(detector: RegexDetector) -> None:
    """The label rule does NOT validate the ISO 3779 check digit.

    ISO 3779 does not mandate a check digit outside North America (49 CFR 565), so the
    labelled rule intentionally accepts values whose position-9 character does not match a
    North American check digit. This test pins the *actual* behaviour so documentation
    cannot claim check-digit validation again.
    """

    # Valid North American check digit.
    assert EntityType.VEHICLE_IDENTIFIER in _types(detector, "VIN: 1M8GDM9AXKP042788")
    # Invalid North American check digit is still reported (no check-digit gate).
    assert EntityType.VEHICLE_IDENTIFIER in _types(detector, "VIN: 1M8GDM9A0KP042788")


def test_unlabelled_vin_is_not_detected(detector: RegexDetector) -> None:
    """No standalone VIN rule exists; unlabelled VINs are a documented gap, not validation."""

    assert EntityType.VEHICLE_IDENTIFIER not in _types(
        detector, "The recovered car had 1M8GDM9AXKP042788 stamped on the dash."
    )


# --- DEFECT 4: ACC-prefixed account numbers were double-classified as bank_account_reference ---
# The ACC prefix mapped to BANK_ACCOUNT_REFERENCE while the "Account No:" label mapped to
# ACCOUNT_NUMBER, so an ACC-prefixed value produced two overlapping findings (one spurious
# bank_account_reference). Remapped ACC -> ACCOUNT_NUMBER so prefix and label agree.
def test_acc_prefix_maps_to_account_number_not_bank_reference(
    detector: RegexDetector,
) -> None:
    types = _types(detector, "Account No: ACC-773102884 billed this month.")
    assert EntityType.ACCOUNT_NUMBER in types
    assert EntityType.BANK_ACCOUNT_REFERENCE not in types


# --- DEFECT 5: ISO (yyyy-mm-dd / yyyy/mm/dd) dates were not recognised -----------------------
def test_iso_date_detected(detector: RegexDetector) -> None:
    assert EntityType.DATE_OF_BIRTH in _types(detector, "Date of birth: 1965-09-30")
    assert EntityType.DATE in _types(detector, "appointment on 2021-03-14 at 14:30")


# --- DEFECT 6: DOB abbreviation was not a date_of_birth label ------------------------------
def test_dob_abbreviation_detected(detector: RegexDetector) -> None:
    assert EntityType.DATE_OF_BIRTH in _types(detector, "DOB: 1965-09-30")


# --- DEFECT 7: "SS#" SSN label was not recognised -------------------------------------------------
def test_ss_hash_label_detects_ssn(detector: RegexDetector) -> None:
    assert EntityType.SSN in _types(detector, "SS# 789-65-4320 listed on the form.")


# --- DEFECT 8: device serial numbers are Safe Harbor category M identifiers ----------------
def test_serial_number_label_detects_device(detector: RegexDetector) -> None:
    assert EntityType.DEVICE_IDENTIFIER in _types(detector, "Serial No: SN-55210983 on the pump.")
    assert EntityType.DEVICE_IDENTIFIER in _types(detector, "Serial number: SN55210983 recorded.")


# --- Reproduced residual gaps (documented, must not be silently "fixed" to pass) ----------


@pytest.mark.xfail(
    reason=(
        "Known gap: unlabelled free-text names require the contextual model (Flair); HIPAA "
        "category A is PARTIAL by design. Without Flair, names in prose are missed."
    ),
    strict=False,
)
def test_unlabelled_name_should_be_detected(detector: RegexDetector) -> None:
    assert EntityType.PERSON in _types(detector, "John Smith presented with chest pain.")


def test_ssn_label_without_separator(detector: RegexDetector) -> None:
    # Fixed: label rules now accept a plain whitespace separator after the label, not only
    # ':'/'='/ '#', so 'social security no 123456789' is detected as an SSN.
    assert EntityType.SSN in _types(detector, "social security no 123456789 recorded.")


@pytest.mark.xfail(
    reason=(
        "Known gap: city/state geographic identifiers require the contextual model; HIPAA "
        "category B is PARTIAL. 'Chicago, Illinois' is not detected without Flair."
    ),
    strict=False,
)
def test_city_state_location_gap(detector: RegexDetector) -> None:
    assert EntityType.LOCATION in _types(detector, "The patient resides in Chicago, Illinois.")


def test_fax_without_label_colon(detector: RegexDetector) -> None:
    # Fixed: label rules now accept a connective word ("fax is ...") after the label, so an
    # unlabelled fax mention is detected as FAX rather than only as a generic phone number.
    assert EntityType.FAX in _types(detector, "Our fax is 415-555-8890 for referrals.")


def test_vin_without_label_colon(detector: RegexDetector) -> None:
    # Fixed: label rules now accept a plain whitespace separator after the label, so a VIN
    # stated as "VIN 1M8GDM9AXKP042788" (no colon) is detected as a vehicle identifier.
    assert EntityType.VEHICLE_IDENTIFIER in _types(detector, "VIN 1M8GDM9AXKP042788 on the door.")


def test_dev_prefix_without_separator(detector: RegexDetector) -> None:
    # Fixed: the prefix rule now accepts a digit-led value with no separator (e.g.
    # "DEV55120983"), while still requiring the value to start with a digit so ordinary
    # words containing a prefix (SUBMIT, ACCEPT, GENETIC) are not misclassified.
    assert EntityType.DEVICE_IDENTIFIER in _types(detector, "DEV55120983 printed on the casing.")


@pytest.mark.xfail(
    reason=(
        "Known gap: textual DNA/genetic references are not enumerated; HIPAA category P is "
        "PARTIAL (only explicit biometric/genetic prefixes are caught)."
    ),
    strict=False,
)
def test_dna_genetic_gap(detector: RegexDetector) -> None:
    assert EntityType.GENETIC_DATA in _types(
        detector, "DNA sequencing results indicate familial risk."
    )


@pytest.mark.xfail(
    reason="Known gap: relationship has no detector; HIPAA category R is PARTIAL.",
    strict=False,
)
def test_relationship_gap(detector: RegexDetector) -> None:
    assert EntityType.RELATIONSHIP in _types(
        detector, "Relationship: spouse is listed as the emergency contact."
    )


# --- Public API / profile propagation ------------------------------------------------------


def test_hipaa_profile_propagates_to_engine(engine: PrivacyEngine) -> None:
    from securedact_core.hipaa import run_hipaa_safe_harbor

    result = run_hipaa_safe_harbor(engine, "Date of birth: 09/30/1965 and SSN 123-45-6789")
    assert result.profile == "hipaa_safe_harbor"
    assert result.categories_evaluated == 18
    assert result.identifiers_detected >= 2


def test_hipaa_policy_redacts_urls_where_default_reviews(engine: PrivacyEngine) -> None:
    # Distinguishing, reliable signal: the hipaa_safe_harbor policy object is the one
    # registered under that name and it carries HIPAA-specific actions (URL REDACT, biometric/
    # genetic BLOCK). This proves the dedicated HIPAA profile is real and applied rather than
    # silently defaulting to a generic GDPR profile.
    from securedact_core.models import EntityType, PrivacyAction

    hip = engine.policies.get("hipaa_safe_harbor")
    assert hip.name == "hipaa_safe_harbor"
    assert hip.action_for(EntityType.URL) == PrivacyAction.REDACT
    assert hip.action_for(EntityType.BIOMETRIC_DATA) == PrivacyAction.BLOCK
    assert hip.action_for(EntityType.GENETIC_DATA) == PrivacyAction.BLOCK
    assert hip.action_for(EntityType.SSN) == PrivacyAction.REDACT


# --- Residual-scan shared blind spot -------------------------------------------------------


def test_residual_scan_shares_regex_blind_spot(engine: PrivacyEngine) -> None:
    text = "John Smith presented with chest pain and was admitted."
    audit = engine.audit(text, "hipaa_safe_harbor")
    initial = {item.entity_type for item in audit.original_findings}
    residual = {item.entity_type for item in audit.residual_scan.residual_findings}
    # The same regex detector powers both passes, so an unlabelled name missed initially
    # is also missed in the residual pass. This is a shared, auditable blind spot.
    assert EntityType.PERSON not in initial
    assert EntityType.PERSON not in residual


# --- Generic compliance architecture overlap ----------------------------------------------
#
# NOTE: The invariant "the framework-agnostic compliance catalog must not enumerate a HIPAA
# mapping" is intentionally NOT exercised here. It belongs to the separate, unreleased
# COMP-001 compliance-catalog feature (src/securedact_core/compliance/catalog.py), which is
# excluded from the hipaa-release-0.5.0 branch. It will be covered by that feature's own
# test work and must not drag the catalog into this release merely to turn it green.
