from __future__ import annotations

import re
from enum import StrEnum
from hashlib import sha256

from pydantic import BaseModel, ConfigDict, Field, model_validator


class EntityType(StrEnum):
    PERSON = "person"
    ORGANIZATION = "organization"
    ORGANISATION = "organization"
    LOCATION = "location"
    ADDRESS = "address"
    STREET_ADDRESS = "street_address"
    HOUSE_NUMBER = "house_number"
    COUNTRY = "country"

    DATE = "date"
    DATE_OF_BIRTH = "date_of_birth"
    TIME = "time"
    APPOINTMENT = "appointment"

    EMAIL = "email"
    PHONE = "phone"

    BSN = "bsn"
    PASSPORT_NUMBER = "passport_number"
    DRIVING_LICENCE_NUMBER = "driving_licence_number"
    NATIONAL_ID = "national_id"

    CUSTOMER_NUMBER = "customer_number"
    CASE_NUMBER = "case_number"
    EMPLOYEE_ID = "employee_id"
    PAYROLL_NUMBER = "payroll_number"
    PATIENT_NUMBER = "patient_number"
    MEDICAL_RECORD_NUMBER = "medical_record_number"
    POLICY_NUMBER = "policy_number"
    INVOICE_NUMBER = "invoice_number"

    IBAN = "iban"
    BIC_SWIFT = "bic_swift"
    BANK_ACCOUNT_REFERENCE = "bank_account_reference"
    PAYMENT_REFERENCE = "payment_reference"
    CREDIT_CARD_NUMBER = "credit_card_number"
    CREDIT_CARD = "credit_card_number"
    CARD_EXPIRY = "card_expiry"
    CARD_SECURITY_CODE = "card_security_code"

    MEDICAL_CONDITION = "medical_condition"
    MEDICATION = "medication"
    DOSAGE = "dosage"
    HEALTH_INSURER = "health_insurer"
    MEDICAL_INFORMATION = "medical_information"
    MEDICAL = "medical_information"

    DEPARTMENT = "department"
    PROJECT_NAME = "project_name"
    CONFIDENTIAL_BUSINESS_INFORMATION = "confidential_business_information"

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    MAC_ADDRESS = "mac_address"
    DEVICE_IDENTIFIER = "device_identifier"
    SESSION_TOKEN = "session_token"
    API_TOKEN = "api_token"
    ACCESS_TOKEN = "access_token"
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"
    UNKNOWN_SECRET = "unknown_secret"
    URL = "url"
    SENSITIVE_URL_PARAMETER = "sensitive_url_parameter"
    INTERNAL_URL = "internal_url"

    POSTCODE = "postcode"
    RELATIONSHIP = "relationship"
    FREE_TEXT_SENSITIVE_CONTEXT = "free_text_sensitive_context"
    UNKNOWN_SENSITIVE = "unknown_sensitive"

    RACIAL_OR_ETHNIC_ORIGIN = "racial_or_ethnic_origin"
    POLITICAL_OPINION = "political_opinion"
    RELIGIOUS_OR_PHILOSOPHICAL_BELIEF = "religious_or_philosophical_belief"
    TRADE_UNION_MEMBERSHIP = "trade_union_membership"
    GENETIC_DATA = "genetic_data"
    BIOMETRIC_DATA = "biometric_data"
    HEALTH_DATA = "health_data"
    SEX_LIFE = "sex_life"
    SEXUAL_ORIENTATION = "sexual_orientation"
    SPECIAL_CATEGORY_CONTEXT = "special_category_context"


class DetectionSource(StrEnum):
    LABEL = "label"
    REGEX = "regex"
    CREDENTIALS = "credentials"
    CONTEXTUAL = "contextual"
    FLAIR = "flair"
    ML_ARTICLE9 = "ml_article9"


class PrivacyAction(StrEnum):
    REDACT = "redact"
    REVIEW = "review"
    ALLOW = "allow"
    BLOCK = "block"


class FindingDecision(StrEnum):
    """Provider-neutral disposition selected for one finding."""

    ALLOW = "allow"
    PSEUDONYMIZE = "pseudonymize"
    REDACT = "redact"
    REVIEW = "review"
    BLOCK = "block"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RedactionMode(StrEnum):
    TYPED_TOKENS = "typed_tokens"
    REMOVE = "remove"


class ReviewAction(StrEnum):
    ACCEPT = "accept"
    IGNORE = "ignore"
    CHANGE_TYPE = "change_type"
    BLOCK = "block"
    REDACT_ATTRIBUTE = "redact_attribute"
    REDACT_PERSON_AND_ATTRIBUTE = "redact_person_and_attribute"
    REDACT_ASSERTION = "redact_assertion"
    REDACT_SENTENCE = "redact_sentence"
    ALLOW_ONCE = "allow_once"
    REPLACE = "replace"


class Detection(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str = ""
    start: int = Field(ge=0)
    end: int = Field(gt=0)
    text: str
    entity_type: EntityType
    confidence: float = Field(ge=0.0, le=1.0)
    source: DetectionSource
    rule: str | None = None
    requires_review: bool = False
    context: str = ""
    action: PrivacyAction | None = None
    severity: Severity | None = None
    masked_preview: str = ""
    rationale_code: str | None = None
    precedence: int = 0
    decision: FindingDecision | None = None
    supporting_sources: frozenset[DetectionSource] = frozenset()
    conflicting_entity_types: frozenset[EntityType] = frozenset()
    replacement: str | None = None

    @model_validator(mode="after")
    def validate_span(self) -> Detection:
        if self.end <= self.start:
            raise ValueError("end must be greater than start")
        if not self.id:
            seed = f"{self.start}:{self.end}:{self.entity_type}:{self.source}:{self.text}"
            object.__setattr__(self, "id", sha256(seed.encode("utf-8")).hexdigest()[:16])
        if not self.supporting_sources:
            object.__setattr__(self, "supporting_sources", frozenset({self.source}))
        if self.replacement is not None and not re.fullmatch(
            r"\[[A-Z][A-Z0-9_]*_\d+\]", self.replacement
        ):
            raise ValueError("replacement must be a typed pseudonym token")
        return self

    @property
    def length(self) -> int:
        return self.end - self.start


class ReviewDecision(BaseModel):
    detection_id: str = Field(min_length=1, max_length=64)
    action: ReviewAction
    entity_type: EntityType | None = None
    replacement: str | None = None

    @model_validator(mode="after")
    def type_required_for_change(self) -> ReviewDecision:
        if self.action == ReviewAction.CHANGE_TYPE and self.entity_type is None:
            raise ValueError("entity_type is required when changing type")
        if self.action == ReviewAction.REPLACE:
            if self.replacement is None or not re.fullmatch(
                r"\[[A-Z][A-Z0-9_]*_\d+\]", self.replacement
            ):
                raise ValueError("a typed pseudonym token is required when replacing")
        elif self.replacement is not None:
            raise ValueError("replacement is only valid for replace decisions")
        return self


class TextSpan(BaseModel):
    model_config = ConfigDict(frozen=True)

    start: int = Field(ge=0)
    end: int = Field(gt=0)
    text: str

    @model_validator(mode="after")
    def validate_span(self) -> TextSpan:
        if self.end <= self.start:
            raise ValueError("end must be greater than start")
        return self


class IndirectDisclosureRisk(StrEnum):
    SAFE = "safe"
    POSSIBLE = "possible_indirect_disclosure"
    HIGH = "high_indirect_disclosure"


class SensitiveAssertion(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str = ""
    subject_entity_ids: list[str] = Field(default_factory=list)
    category: EntityType
    full_span_start: int = Field(ge=0)
    full_span_end: int = Field(gt=0)
    sentence_start: int = Field(ge=0)
    sentence_end: int = Field(gt=0)
    evidence_spans: list[TextSpan] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    detector: str
    requires_review: bool = True
    rationale_code: str
    negated: bool = False
    action: PrivacyAction = PrivacyAction.REVIEW
    indirect_disclosure_risk: IndirectDisclosureRisk = IndirectDisclosureRisk.POSSIBLE

    @model_validator(mode="after")
    def validate_assertion(self) -> SensitiveAssertion:
        if self.full_span_end <= self.full_span_start:
            raise ValueError("full assertion span is invalid")
        if self.sentence_end <= self.sentence_start:
            raise ValueError("sentence span is invalid")
        if not self.id:
            seed = f"{self.full_span_start}:{self.full_span_end}:{self.category}:{self.detector}"
            object.__setattr__(self, "id", sha256(seed.encode("utf-8")).hexdigest()[:16])
        return self


class AnalysisResult(BaseModel):
    entities: list[Detection]
    assertions: list[SensitiveAssertion] = Field(default_factory=list)
    requires_review: bool
    blocked: bool = False
    engine_ready: bool = True
    warnings: list[str] = Field(default_factory=list)


class RedactionResult(BaseModel):
    sanitized_text: str
    mapping: dict[str, str]
    entities: list[Detection]
    entity_counts: dict[str, int]


class PartialMatch(BaseModel):
    entity_type: EntityType
    reason: str
    start: int | None = None
    end: int | None = None


class ResidualScanResult(BaseModel):
    safe_to_send: bool
    residual_findings: list[Detection] = Field(default_factory=list)
    partial_match_findings: list[PartialMatch] = Field(default_factory=list)
    critical_residual_count: int = 0
    malformed_placeholders: list[str] = Field(default_factory=list)
    possible_indirect_disclosures: list[str] = Field(default_factory=list)


class SanitizationAudit(BaseModel):
    profile: str
    original_findings: list[Detection]
    assertions: list[SensitiveAssertion] = Field(default_factory=list)
    applied_replacements: dict[str, int]
    sanitized_text: str
    residual_scan: ResidualScanResult
    coverage_by_category: dict[str, int]
    explicitly_allowed_categories: list[EntityType] = Field(default_factory=list)
    provider_invoked: bool = False


class PrivacyReport(BaseModel):
    policy: str
    entity_counts: dict[str, int]
    reviewed_count: int = 0
    ignored_count: int = 0
    replacement_mode: RedactionMode
    sanitized: bool
    detected_categories: dict[str, int] = Field(default_factory=dict)
    redacted_categories: dict[str, int] = Field(default_factory=dict)
    review_required_categories: dict[str, int] = Field(default_factory=dict)
    blocked_categories: dict[str, int] = Field(default_factory=dict)
    allowed_categories: dict[str, int] = Field(default_factory=dict)
    possible_residual_risk: bool = False
    residual_scan: ResidualScanResult | None = None
    special_category_assertion_count: int = 0
    policy_exceptions: list[str] = Field(default_factory=list)
