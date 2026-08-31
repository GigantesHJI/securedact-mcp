# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from .engine import PrivacyEngine
from .models import EntityType

# Safe Harbor limitation notes (mechanical aid only; never a compliance claim).
HIPAA_DISCLAIMER = (
    "SecuRedact is a mechanical de-identification aid. This result does NOT certify HIPAA "
    "Safe Harbor compliance, legal compliance, or guaranteed de-identification, and it does "
    "not replace Expert Determination under 45 CFR 164.514(b)(1)."
)
HIPAA_ACTUAL_KNOWLEDGE_NOTE = (
    "Safe Harbor has two prongs. SecuRedact can only assist with the mechanical removal of "
    "enumerated textual identifiers (164.514(b)(2)(i)). The actual-knowledge prong "
    "(164.514(b)(2)(ii)) requires the covered entity to attest it has no knowledge that the "
    "remaining information could re-identify an individual. SecuRedact cannot make that "
    "determination."
)


class HipaaSafeHarborStatus(StrEnum):
    FULL = "full"
    PARTIAL = "partial"
    NOT_COVERED = "not_covered"
    UNSUPPORTED_REQUIRES_REVIEW = "unsupported_requires_review"


class HipaaCategoryMeta(BaseModel):
    model_config = ConfigDict(frozen=True)

    letter: str
    title: str
    description: str
    status: HipaaSafeHarborStatus
    contributing_entity_types: tuple[EntityType, ...]
    limitations: str = ""


class HipaaCategoryResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    letter: str
    title: str
    status: HipaaSafeHarborStatus
    detected: int = 0
    redacted: int = 0
    residual: int = 0
    limitations: str = ""
    unsupported: bool = False


class HipaaResidualFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    entity_type: str
    text: str
    category: str


class HipaaContextualMetadata(BaseModel):
    """Reproducibility/auditability record for the optional contextual NER pass.

    Only populated when HIPAA Safe Harbor is run with ``contextual_ner=True``.
    It records whether the supplementary Flair PERSON detector was actually
    available and used, which immutable revision was requested/resolved, the
    confidence threshold, and which HIPAA categories the gate is permitted to
    contribute to. It deliberately exposes no filesystem paths.
    """

    model_config = ConfigDict(frozen=True)

    requested: bool = False
    available: bool = False
    model_id: str | None = None
    requested_revision: str | None = None
    resolved_revision: str | None = None
    threshold: float | None = None
    gated_categories: tuple[str, ...] = ()
    fallback: bool = False
    note: str | None = None


class HipaaSafeHarborResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: Literal["1"] = "1"
    profile: str = "hipaa_safe_harbor"
    categories: list[HipaaCategoryResult]
    categories_evaluated: int
    categories_supported: int
    categories_partial: int
    categories_unsupported: int
    identifiers_detected: int
    identifiers_redacted: int
    residual_identifiers_detected: int
    residual_findings: list[HipaaResidualFinding]
    unsupported_category_warnings: list[str]
    actual_knowledge_note: str = HIPAA_ACTUAL_KNOWLEDGE_NOTE
    disclaimer: str = HIPAA_DISCLAIMER
    contextual_ner: HipaaContextualMetadata | None = None


# Reverse map: internal entity type -> Safe Harbor letter. Types not listed here are not
# part of the 18 enumerated Safe Harbor categories.
ENTITY_TO_LETTER: dict[EntityType, str] = {
    EntityType.PERSON: "A",
    EntityType.ADDRESS: "B",
    EntityType.STREET_ADDRESS: "B",
    EntityType.HOUSE_NUMBER: "B",
    EntityType.US_ZIP: "B",
    EntityType.LOCATION: "B",
    EntityType.DATE: "C",
    EntityType.DATE_OF_BIRTH: "C",
    EntityType.TIME: "C",
    EntityType.APPOINTMENT: "C",
    EntityType.AGE: "C",
    EntityType.PHONE: "D",
    EntityType.FAX: "E",
    EntityType.EMAIL: "F",
    EntityType.SSN: "G",
    EntityType.MEDICAL_RECORD_NUMBER: "H",
    EntityType.HEALTH_PLAN_BENEFICIARY: "I",
    EntityType.BANK_ACCOUNT_REFERENCE: "J",
    EntityType.ACCOUNT_NUMBER: "J",
    EntityType.PAYMENT_REFERENCE: "J",
    EntityType.DRIVING_LICENCE_NUMBER: "K",
    EntityType.NATIONAL_ID: "K",
    EntityType.PASSPORT_NUMBER: "K",
    EntityType.VEHICLE_IDENTIFIER: "L",
    EntityType.DEVICE_IDENTIFIER: "M",
    EntityType.URL: "N",
    EntityType.SENSITIVE_URL_PARAMETER: "N",
    EntityType.INTERNAL_URL: "N",
    EntityType.IPV4: "O",
    EntityType.IPV6: "O",
    EntityType.BIOMETRIC_DATA: "P",
    EntityType.GENETIC_DATA: "P",
    EntityType.PATIENT_NUMBER: "R",
    EntityType.CASE_NUMBER: "R",
    EntityType.EMPLOYEE_ID: "R",
    EntityType.CUSTOMER_NUMBER: "R",
    EntityType.PAYROLL_NUMBER: "R",
    EntityType.INVOICE_NUMBER: "R",
    EntityType.POLICY_NUMBER: "R",
    EntityType.UNKNOWN_SENSITIVE: "R",
    EntityType.FREE_TEXT_SENSITIVE_CONTEXT: "R",
    EntityType.RELATIONSHIP: "R",
}

_ZIP3_NOTE = (
    "US ZIP codes are redacted in full. SecuRedact does not ship a versioned Census ZIP3 "
    "population dataset, so the conditional retention of the first three ZIP digits "
    "(164.514(b)(2)(i)(B)) is NOT applied; ZIPs are over-redacted rather than under-retained."
)
_IMAGE_NOTE = (
    "Full-face photographs and comparable images (category Q) cannot be detected by the "
    "text-only engine. Document or image inputs must be reviewed out of band; absence of a Q "
    "finding does NOT mean an image is free of identifiable content."
)


HIPAA_CATEGORY_METADATA: tuple[HipaaCategoryMeta, ...] = (
    HipaaCategoryMeta(
        letter="A",
        title="Names",
        description="Names of the individual or relatives, employers, or household members.",
        status=HipaaSafeHarborStatus.PARTIAL,
        contributing_entity_types=(EntityType.PERSON,),
        limitations=(
            "Unlabelled free-text names rely on the optional contextual model; labelled name "
            "fields are detected deterministically. Without the contextual model, some names "
            "may be missed."
        ),
    ),
    HipaaCategoryMeta(
        letter="B",
        title="Geographic subdivisions smaller than a state",
        description="Street address, city, county, precinct, ZIP, and equivalent geocodes.",
        status=HipaaSafeHarborStatus.PARTIAL,
        contributing_entity_types=(
            EntityType.ADDRESS,
            EntityType.STREET_ADDRESS,
            EntityType.HOUSE_NUMBER,
            EntityType.US_ZIP,
            EntityType.LOCATION,
        ),
        limitations=(
            "Street addresses and US ZIP/ZIP+4 are detected. City/county names depend on the "
            "contextual model and are surfaced for review, not auto-redacted. US states are "
            "retained (Safe Harbor permits state-level geography). " + _ZIP3_NOTE
        ),
    ),
    HipaaCategoryMeta(
        letter="C",
        title="Dates (except year) and ages over 89",
        description=(
            "Dates directly related to an individual (birth, admission, discharge, death) and "
            "all ages over 89."
        ),
        status=HipaaSafeHarborStatus.PARTIAL,
        contributing_entity_types=(
            EntityType.DATE,
            EntityType.DATE_OF_BIRTH,
            EntityType.TIME,
            EntityType.APPOINTMENT,
            EntityType.AGE,
        ),
        limitations=(
            "Explicit individual ages over 89 are surfaced for review. The 'except year' "
            "transform (keep year, drop month/day) is not applied as an automatic redaction; "
            "detected dates are reviewed rather than partially masked."
        ),
    ),
    HipaaCategoryMeta(
        letter="D",
        title="Telephone numbers",
        description="Telephone numbers.",
        status=HipaaSafeHarborStatus.FULL,
        contributing_entity_types=(EntityType.PHONE,),
    ),
    HipaaCategoryMeta(
        letter="E",
        title="Fax numbers",
        description="Fax numbers.",
        status=HipaaSafeHarborStatus.FULL,
        contributing_entity_types=(EntityType.FAX,),
        limitations="Detected from labelled 'fax'/'telefax' fields.",
    ),
    HipaaCategoryMeta(
        letter="F",
        title="Email addresses",
        description="Email addresses.",
        status=HipaaSafeHarborStatus.FULL,
        contributing_entity_types=(EntityType.EMAIL,),
    ),
    HipaaCategoryMeta(
        letter="G",
        title="Social Security numbers",
        description="Social Security numbers (no derivatives, including last 4 digits).",
        status=HipaaSafeHarborStatus.FULL,
        contributing_entity_types=(EntityType.SSN,),
        limitations=(
            "Detects AAA-GG-SSSS with area/group/serial validation. All-zero and unassigned "
            "areas (000, 666, 900-999) are rejected; derivatives such as last-4 are not "
            "treated as Safe Harbor compliant."
        ),
    ),
    HipaaCategoryMeta(
        letter="H",
        title="Medical record numbers",
        description="Medical record numbers.",
        status=HipaaSafeHarborStatus.PARTIAL,
        contributing_entity_types=(EntityType.MEDICAL_RECORD_NUMBER,),
        limitations=(
            "Labelled 'medical record number'/'MRN' values, the MRN- prefix, and common "
            "synonyms ('record number', 'record no', 'chart ID', 'chart number', 'patient "
            "record number') are detected, including separator-less forms ('patient MRN is "
            "558201'). Some unlabelled or highly non-standard MRN phrasings may still be "
            "missed, so the category is PARTIAL rather than FULL."
        ),
    ),
    HipaaCategoryMeta(
        letter="I",
        title="Health plan beneficiary numbers",
        description="Health plan beneficiary/member/subscriber identifiers.",
        status=HipaaSafeHarborStatus.PARTIAL,
        contributing_entity_types=(EntityType.HEALTH_PLAN_BENEFICIARY,),
        limitations=(
            "Conservative, context-dependent detection from labels (member/subscriber/"
            "beneficiary ID) or prefixes (MBR/SUB/BEN). Generic alphanumeric tokens are not "
            "classified as PHI to avoid false positives."
        ),
    ),
    HipaaCategoryMeta(
        letter="J",
        title="Account numbers",
        description="Account numbers.",
        status=HipaaSafeHarborStatus.PARTIAL,
        contributing_entity_types=(
            EntityType.BANK_ACCOUNT_REFERENCE,
            EntityType.ACCOUNT_NUMBER,
            EntityType.PAYMENT_REFERENCE,
        ),
        limitations=(
            "Labelled account numbers are detected. Unlabelled generic account/reference "
            "numbers are not, to avoid false positives."
        ),
    ),
    HipaaCategoryMeta(
        letter="K",
        title="Certificate/license numbers",
        description="Certificate and license numbers.",
        status=HipaaSafeHarborStatus.PARTIAL,
        contributing_entity_types=(
            EntityType.DRIVING_LICENCE_NUMBER,
            EntityType.NATIONAL_ID,
            EntityType.PASSPORT_NUMBER,
        ),
        limitations=(
            "Driver's-license, national ID, and passport numbers are detected. Many "
            "professional/occupational certificate numbers are not yet enumerated."
        ),
    ),
    HipaaCategoryMeta(
        letter="L",
        title="Vehicle identifiers and serial numbers",
        description="Vehicle identifiers, serial numbers, and license plate numbers.",
        status=HipaaSafeHarborStatus.PARTIAL,
        contributing_entity_types=(EntityType.VEHICLE_IDENTIFIER,),
        limitations=(
            "VINs are validated against the ISO 3779 check digit. License plates are detected "
            "only from explicit labels. Arbitrary 17-character strings are not treated as VINs "
            "without check-digit validation."
        ),
    ),
    HipaaCategoryMeta(
        letter="M",
        title="Device identifiers and serial numbers",
        description="Device identifiers and serial numbers.",
        status=HipaaSafeHarborStatus.FULL,
        contributing_entity_types=(EntityType.DEVICE_IDENTIFIER,),
        limitations=(
            "Labelled device identifiers ('device identifier', 'device ID') and device serial "
            "numbers ('serial number', 'serial no') are detected, as are DEV-prefixed values "
            "with or without a separator (DEV-#### or DEV####). The text-only engine has no "
            "standalone device-serial rule, so an unlabelled bare serial unrelated to a device "
            "context remains a gap."
        ),
    ),
    HipaaCategoryMeta(
        letter="N",
        title="Web URLs",
        description="Web URLs.",
        status=HipaaSafeHarborStatus.FULL,
        contributing_entity_types=(
            EntityType.URL,
            EntityType.SENSITIVE_URL_PARAMETER,
            EntityType.INTERNAL_URL,
        ),
    ),
    HipaaCategoryMeta(
        letter="O",
        title="IP addresses",
        description="IP addresses.",
        status=HipaaSafeHarborStatus.FULL,
        contributing_entity_types=(EntityType.IPV4, EntityType.IPV6),
    ),
    HipaaCategoryMeta(
        letter="P",
        title="Biometric identifiers",
        description="Biometric identifiers, including finger and voice prints.",
        status=HipaaSafeHarborStatus.PARTIAL,
        contributing_entity_types=(EntityType.BIOMETRIC_DATA, EntityType.GENETIC_DATA),
        limitations=(
            "Only textual references to biometric data (e.g. 'fingerprint template', 'voice "
            "print') are detected. Raw biometric artifacts (images, voice, templates) require "
            "modality-specific handling outside this engine."
        ),
    ),
    HipaaCategoryMeta(
        letter="Q",
        title="Full-face photographs and comparable images",
        description="Full-face photographs and any comparable images.",
        status=HipaaSafeHarborStatus.UNSUPPORTED_REQUIRES_REVIEW,
        contributing_entity_types=(),
        limitations=_IMAGE_NOTE,
    ),
    HipaaCategoryMeta(
        letter="R",
        title="Any other unique identifying number, characteristic, or code",
        description=(
            "Other unique identifying numbers, characteristics, or codes, except a permitted "
            "re-identification code under 164.514(c)."
        ),
        status=HipaaSafeHarborStatus.PARTIAL,
        contributing_entity_types=(
            EntityType.PATIENT_NUMBER,
            EntityType.CASE_NUMBER,
            EntityType.EMPLOYEE_ID,
            EntityType.CUSTOMER_NUMBER,
            EntityType.PAYROLL_NUMBER,
            EntityType.INVOICE_NUMBER,
            EntityType.POLICY_NUMBER,
            EntityType.UNKNOWN_SENSITIVE,
            EntityType.FREE_TEXT_SENSITIVE_CONTEXT,
            EntityType.RELATIONSHIP,
        ),
        limitations=(
            "Covered by a union of specific identifiers plus contextual sensitive-context "
            "detection. There is no dangerous catch-all regex. The 164.514(c) re-identification "
            "code exception is treated conservatively (codes are removed by default)."
        ),
    ),
)


def _entity_letter(entity_type: EntityType) -> str | None:
    return ENTITY_TO_LETTER.get(entity_type)


def run_hipaa_safe_harbor(
    engine: PrivacyEngine,
    text: str,
    policy_name: str = "hipaa_safe_harbor",
    *,
    contextual_ner: bool = False,
    flair_detector: Any = None,
    flair_threshold: float | None = None,
) -> HipaaSafeHarborResult:
    """Run the HIPAA Safe Harbor mechanical pipeline and return a structured result.

    The pipeline reuses the existing ``analyze -> redact -> scan_residual`` flow. A
    successful redaction pass does NOT mean Safe Harbor has been satisfied: residual
    supported identifiers and the unsupported category Q are reported explicitly.

    When ``contextual_ner`` is enabled, a supplementary Flair PERSON-only detector
    (HIPAA Category A / Names gate) is added to the deterministic stack. This is an
    explicit, optional capability: it never loads Flair unless requested, never
    alters deterministic detection, and cannot contribute geography or structured
    identifiers. Pass ``flair_detector`` to inject a backend (tests/benchmarks);
    otherwise the local ``flair/ner-english-large`` checkpoint is resolved lazily.
    """

    contextual_meta: HipaaContextualMetadata | None = None
    if contextual_ner:
        hipaa_engine, flair_person = _build_hipaa_contextual_engine(
            engine, flair_detector, flair_threshold
        )
        audit = hipaa_engine.audit(text, policy_name)
        note = None
        if flair_person._fallback:
            note = (
                "Contextual NER was requested but the Flair model was unavailable; "
                "the result reflects deterministic + rule-based detection only."
            )
        contextual_meta = HipaaContextualMetadata(
            requested=True,
            available=flair_person.is_available(),
            model_id=flair_person.model_id,
            requested_revision=flair_person.revision,
            resolved_revision=flair_person.resolved_revision,
            threshold=flair_person.threshold,
            gated_categories=("A",),
            fallback=flair_person.fallback,
            note=note,
        )
    else:
        audit = engine.audit(text, policy_name)

    detected_by_letter: dict[str, int] = {}
    redacted_by_letter: dict[str, int] = {}
    residual_by_letter: dict[str, int] = {}
    residual_findings: list[HipaaResidualFinding] = []

    for finding in audit.original_findings:
        letter = _entity_letter(finding.entity_type)
        if letter is None:
            continue
        detected_by_letter[letter] = detected_by_letter.get(letter, 0) + 1

    for entity_type_str, count in audit.applied_replacements.items():
        try:
            entity_type = EntityType(entity_type_str)
        except ValueError:
            continue
        letter = _entity_letter(entity_type)
        if letter is None:
            continue
        redacted_by_letter[letter] = redacted_by_letter.get(letter, 0) + count

    for finding in audit.residual_scan.residual_findings:
        letter = _entity_letter(finding.entity_type)
        if letter is None:
            continue
        residual_by_letter[letter] = residual_by_letter.get(letter, 0) + 1
        residual_findings.append(
            HipaaResidualFinding(
                entity_type=finding.entity_type.value,
                text=finding.text,
                category=letter,
            )
        )

    category_results: list[HipaaCategoryResult] = []
    unsupported_warnings: list[str] = []
    for meta in HIPAA_CATEGORY_METADATA:
        is_unsupported = (
            meta.status == HipaaSafeHarborStatus.UNSUPPORTED_REQUIRES_REVIEW
            or meta.status == HipaaSafeHarborStatus.NOT_COVERED
        )
        if is_unsupported and meta.limitations:
            unsupported_warnings.append(
                f"Category {meta.letter} ({meta.title}): {meta.limitations}"
            )
        category_results.append(
            HipaaCategoryResult(
                letter=meta.letter,
                title=meta.title,
                status=meta.status,
                detected=detected_by_letter.get(meta.letter, 0),
                redacted=redacted_by_letter.get(meta.letter, 0),
                residual=residual_by_letter.get(meta.letter, 0),
                limitations=meta.limitations,
                unsupported=is_unsupported,
            )
        )

    categories_supported = sum(
        1
        for meta in HIPAA_CATEGORY_METADATA
        if meta.status in {HipaaSafeHarborStatus.FULL, HipaaSafeHarborStatus.PARTIAL}
    )
    categories_partial = sum(
        1 for meta in HIPAA_CATEGORY_METADATA if meta.status == HipaaSafeHarborStatus.PARTIAL
    )
    categories_unsupported = sum(
        1
        for meta in HIPAA_CATEGORY_METADATA
        if meta.status
        in {
            HipaaSafeHarborStatus.UNSUPPORTED_REQUIRES_REVIEW,
            HipaaSafeHarborStatus.NOT_COVERED,
        }
    )
    identifiers_detected = sum(detected_by_letter.values())
    identifiers_redacted = sum(redacted_by_letter.values())

    return HipaaSafeHarborResult(
        profile=policy_name,
        categories=category_results,
        categories_evaluated=len(HIPAA_CATEGORY_METADATA),
        categories_supported=categories_supported,
        categories_partial=categories_partial,
        categories_unsupported=categories_unsupported,
        identifiers_detected=identifiers_detected,
        identifiers_redacted=identifiers_redacted,
        residual_identifiers_detected=len(residual_findings),
        residual_findings=residual_findings,
        unsupported_category_warnings=unsupported_warnings,
        contextual_ner=contextual_meta,
    )


def _build_hipaa_contextual_engine(
    engine: PrivacyEngine,
    flair_detector: Any,
    flair_threshold: float | None,
) -> tuple[PrivacyEngine, Any]:
    """Build a HIPAA engine that adds the Flair PERSON-only gate.

    Reuses the exact deterministic detector instances already on ``engine`` (so the
    validated deterministic + rule-based behavior is unchanged) and appends a single
    supplementary ``HipaaFlairPersonDetector``. The new engine is *not* started, so
    Flair is only loaded lazily on the first inference call. Missing-model behavior is
    left to graceful deterministic fallback (the detector records it in metadata).
    """

    from .detectors.hipaa_flair_detector import create_hipaa_flair_detector

    if flair_detector is None:
        flair_person = create_hipaa_flair_detector(threshold=flair_threshold)
    else:
        flair_person = flair_detector
    deterministic = [detector for detector in engine.detectors if not detector.contextual]
    hipaa_engine = PrivacyEngine(
        [*deterministic, flair_person],
        policies=engine.policies,
        require_contextual=False,
    )
    return hipaa_engine, flair_person
