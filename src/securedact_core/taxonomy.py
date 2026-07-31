from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from .models import EntityType, PrivacyAction, Severity


class CategoryGroup(StrEnum):
    IDENTITY = "Identity"
    CONTACT = "Contact"
    LOCATION = "Location"
    DATES = "Dates and appointments"
    GOVERNMENT = "Government identifiers"
    FINANCIAL = "Financial"
    MEDICAL = "Medical"
    BUSINESS = "Employment and business"
    TECHNICAL = "Technical identifiers"
    CREDENTIALS = "Credentials and secrets"
    RELATIONSHIPS = "Relationships and context"
    SPECIAL_CATEGORY = "GDPR special-category data"
    UNKNOWN = "Unknown sensitive information"


class EntityDefinition(BaseModel):
    model_config = ConfigDict(frozen=True)

    entity_type: EntityType
    display_name: str
    description: str
    group: CategoryGroup
    default_action: PrivacyAction
    severity: Severity
    deterministic_detection: bool
    contextual_detection: bool
    review_recommended: bool


def _definition(
    entity_type: EntityType,
    display_name: str,
    group: CategoryGroup,
    default_action: PrivacyAction,
    severity: Severity = Severity.HIGH,
    *,
    deterministic: bool = False,
    contextual: bool = False,
    review: bool = False,
    description: str | None = None,
) -> EntityDefinition:
    return EntityDefinition(
        entity_type=entity_type,
        display_name=display_name,
        description=description or f"Protect detected {display_name.lower()}.",
        group=group,
        default_action=default_action,
        severity=severity,
        deterministic_detection=deterministic,
        contextual_detection=contextual,
        review_recommended=review,
    )


_D = PrivacyAction.REDACT
_R = PrivacyAction.REVIEW
_B = PrivacyAction.BLOCK

CATEGORY_DEFINITIONS: dict[EntityType, EntityDefinition] = {
    EntityType.PERSON: _definition(
        EntityType.PERSON, "Names", CategoryGroup.IDENTITY, _D, contextual=True
    ),
    EntityType.ORGANIZATION: _definition(
        EntityType.ORGANIZATION,
        "Organisations",
        CategoryGroup.IDENTITY,
        _R,
        contextual=True,
        review=True,
    ),
    EntityType.EMAIL: _definition(
        EntityType.EMAIL, "Email addresses", CategoryGroup.CONTACT, _D, deterministic=True
    ),
    EntityType.PHONE: _definition(
        EntityType.PHONE, "Telephone numbers", CategoryGroup.CONTACT, _D, deterministic=True
    ),
    EntityType.LOCATION: _definition(
        EntityType.LOCATION, "Locations", CategoryGroup.LOCATION, _R, contextual=True, review=True
    ),
    EntityType.ADDRESS: _definition(
        EntityType.ADDRESS,
        "Complete addresses",
        CategoryGroup.LOCATION,
        _D,
        deterministic=True,
        contextual=True,
    ),
    EntityType.STREET_ADDRESS: _definition(
        EntityType.STREET_ADDRESS,
        "Street addresses",
        CategoryGroup.LOCATION,
        _D,
        deterministic=True,
    ),
    EntityType.HOUSE_NUMBER: _definition(
        EntityType.HOUSE_NUMBER, "House numbers", CategoryGroup.LOCATION, _D, deterministic=True
    ),
    EntityType.POSTCODE: _definition(
        EntityType.POSTCODE, "Postcodes", CategoryGroup.LOCATION, _D, deterministic=True
    ),
    EntityType.COUNTRY: _definition(
        EntityType.COUNTRY, "Countries", CategoryGroup.LOCATION, _R, contextual=True, review=True
    ),
    EntityType.DATE: _definition(
        EntityType.DATE, "General dates", CategoryGroup.DATES, _R, contextual=True, review=True
    ),
    EntityType.DATE_OF_BIRTH: _definition(
        EntityType.DATE_OF_BIRTH,
        "Dates of birth",
        CategoryGroup.DATES,
        _D,
        deterministic=True,
        contextual=True,
    ),
    EntityType.TIME: _definition(
        EntityType.TIME,
        "Times",
        CategoryGroup.DATES,
        _R,
        Severity.MEDIUM,
        deterministic=True,
        review=True,
    ),
    EntityType.APPOINTMENT: _definition(
        EntityType.APPOINTMENT,
        "Appointments",
        CategoryGroup.DATES,
        _R,
        contextual=True,
        review=True,
    ),
    EntityType.BSN: _definition(
        EntityType.BSN,
        "Dutch BSNs",
        CategoryGroup.GOVERNMENT,
        _D,
        Severity.CRITICAL,
        deterministic=True,
    ),
    EntityType.PASSPORT_NUMBER: _definition(
        EntityType.PASSPORT_NUMBER,
        "Passport numbers",
        CategoryGroup.GOVERNMENT,
        _D,
        Severity.CRITICAL,
        deterministic=True,
    ),
    EntityType.DRIVING_LICENCE_NUMBER: _definition(
        EntityType.DRIVING_LICENCE_NUMBER,
        "Driving-licence numbers",
        CategoryGroup.GOVERNMENT,
        _D,
        Severity.CRITICAL,
        deterministic=True,
    ),
    EntityType.NATIONAL_ID: _definition(
        EntityType.NATIONAL_ID,
        "National identifiers",
        CategoryGroup.GOVERNMENT,
        _D,
        Severity.CRITICAL,
        deterministic=True,
    ),
    EntityType.CUSTOMER_NUMBER: _definition(
        EntityType.CUSTOMER_NUMBER,
        "Customer numbers",
        CategoryGroup.IDENTITY,
        _D,
        deterministic=True,
    ),
    EntityType.CASE_NUMBER: _definition(
        EntityType.CASE_NUMBER, "Case numbers", CategoryGroup.BUSINESS, _D, deterministic=True
    ),
    EntityType.EMPLOYEE_ID: _definition(
        EntityType.EMPLOYEE_ID, "Employee IDs", CategoryGroup.BUSINESS, _D, deterministic=True
    ),
    EntityType.PAYROLL_NUMBER: _definition(
        EntityType.PAYROLL_NUMBER, "Payroll numbers", CategoryGroup.BUSINESS, _D, deterministic=True
    ),
    EntityType.PATIENT_NUMBER: _definition(
        EntityType.PATIENT_NUMBER,
        "Patient numbers",
        CategoryGroup.MEDICAL,
        _D,
        Severity.CRITICAL,
        deterministic=True,
    ),
    EntityType.MEDICAL_RECORD_NUMBER: _definition(
        EntityType.MEDICAL_RECORD_NUMBER,
        "Medical-record numbers",
        CategoryGroup.MEDICAL,
        _D,
        Severity.CRITICAL,
        deterministic=True,
    ),
    EntityType.POLICY_NUMBER: _definition(
        EntityType.POLICY_NUMBER, "Policy numbers", CategoryGroup.FINANCIAL, _D, deterministic=True
    ),
    EntityType.INVOICE_NUMBER: _definition(
        EntityType.INVOICE_NUMBER,
        "Invoice numbers",
        CategoryGroup.FINANCIAL,
        _D,
        deterministic=True,
    ),
    EntityType.IBAN: _definition(
        EntityType.IBAN, "IBANs", CategoryGroup.FINANCIAL, _D, Severity.CRITICAL, deterministic=True
    ),
    EntityType.BIC_SWIFT: _definition(
        EntityType.BIC_SWIFT, "BIC/SWIFT codes", CategoryGroup.FINANCIAL, _D, deterministic=True
    ),
    EntityType.BANK_ACCOUNT_REFERENCE: _definition(
        EntityType.BANK_ACCOUNT_REFERENCE,
        "Bank-account references",
        CategoryGroup.FINANCIAL,
        _D,
        deterministic=True,
    ),
    EntityType.PAYMENT_REFERENCE: _definition(
        EntityType.PAYMENT_REFERENCE,
        "Payment references",
        CategoryGroup.FINANCIAL,
        _D,
        deterministic=True,
    ),
    EntityType.CREDIT_CARD_NUMBER: _definition(
        EntityType.CREDIT_CARD_NUMBER,
        "Credit-card numbers",
        CategoryGroup.FINANCIAL,
        _D,
        Severity.CRITICAL,
        deterministic=True,
    ),
    EntityType.CARD_EXPIRY: _definition(
        EntityType.CARD_EXPIRY, "Card expiry dates", CategoryGroup.FINANCIAL, _D, deterministic=True
    ),
    EntityType.CARD_SECURITY_CODE: _definition(
        EntityType.CARD_SECURITY_CODE,
        "Card security codes",
        CategoryGroup.FINANCIAL,
        _B,
        Severity.CRITICAL,
        deterministic=True,
    ),
    EntityType.MEDICAL_CONDITION: _definition(
        EntityType.MEDICAL_CONDITION,
        "Medical conditions",
        CategoryGroup.MEDICAL,
        _R,
        contextual=True,
        review=True,
    ),
    EntityType.MEDICATION: _definition(
        EntityType.MEDICATION, "Medication", CategoryGroup.MEDICAL, _R, contextual=True, review=True
    ),
    EntityType.DOSAGE: _definition(
        EntityType.DOSAGE, "Dosage", CategoryGroup.MEDICAL, _R, contextual=True, review=True
    ),
    EntityType.HEALTH_INSURER: _definition(
        EntityType.HEALTH_INSURER,
        "Health insurers",
        CategoryGroup.MEDICAL,
        _R,
        deterministic=True,
        contextual=True,
        review=True,
    ),
    EntityType.MEDICAL_INFORMATION: _definition(
        EntityType.MEDICAL_INFORMATION,
        "Medical information",
        CategoryGroup.MEDICAL,
        _R,
        contextual=True,
        review=True,
    ),
    EntityType.DEPARTMENT: _definition(
        EntityType.DEPARTMENT,
        "Internal departments",
        CategoryGroup.BUSINESS,
        _R,
        contextual=True,
        review=True,
    ),
    EntityType.PROJECT_NAME: _definition(
        EntityType.PROJECT_NAME,
        "Confidential project names",
        CategoryGroup.BUSINESS,
        _R,
        contextual=True,
        review=True,
    ),
    EntityType.CONFIDENTIAL_BUSINESS_INFORMATION: _definition(
        EntityType.CONFIDENTIAL_BUSINESS_INFORMATION,
        "Confidential business information",
        CategoryGroup.BUSINESS,
        _R,
        contextual=True,
        review=True,
    ),
    EntityType.IPV4: _definition(
        EntityType.IPV4, "IPv4 addresses", CategoryGroup.TECHNICAL, _D, deterministic=True
    ),
    EntityType.IPV6: _definition(
        EntityType.IPV6, "IPv6 addresses", CategoryGroup.TECHNICAL, _D, deterministic=True
    ),
    EntityType.MAC_ADDRESS: _definition(
        EntityType.MAC_ADDRESS, "MAC addresses", CategoryGroup.TECHNICAL, _D, deterministic=True
    ),
    EntityType.DEVICE_IDENTIFIER: _definition(
        EntityType.DEVICE_IDENTIFIER,
        "Device identifiers",
        CategoryGroup.TECHNICAL,
        _D,
        deterministic=True,
    ),
    EntityType.URL: _definition(
        EntityType.URL,
        "Public URLs",
        CategoryGroup.TECHNICAL,
        _R,
        Severity.MEDIUM,
        deterministic=True,
        review=True,
    ),
    EntityType.SENSITIVE_URL_PARAMETER: _definition(
        EntityType.SENSITIVE_URL_PARAMETER,
        "URLs with sensitive parameters",
        CategoryGroup.TECHNICAL,
        _D,
        Severity.CRITICAL,
        deterministic=True,
    ),
    EntityType.INTERNAL_URL: _definition(
        EntityType.INTERNAL_URL, "Internal URLs", CategoryGroup.BUSINESS, _D, deterministic=True
    ),
    EntityType.SESSION_TOKEN: _definition(
        EntityType.SESSION_TOKEN,
        "Session tokens",
        CategoryGroup.CREDENTIALS,
        _B,
        Severity.CRITICAL,
        deterministic=True,
    ),
    EntityType.API_TOKEN: _definition(
        EntityType.API_TOKEN,
        "API tokens",
        CategoryGroup.CREDENTIALS,
        _B,
        Severity.CRITICAL,
        deterministic=True,
    ),
    EntityType.ACCESS_TOKEN: _definition(
        EntityType.ACCESS_TOKEN,
        "Access tokens",
        CategoryGroup.CREDENTIALS,
        _B,
        Severity.CRITICAL,
        deterministic=True,
    ),
    EntityType.PASSWORD: _definition(
        EntityType.PASSWORD,
        "Passwords",
        CategoryGroup.CREDENTIALS,
        _B,
        Severity.CRITICAL,
        deterministic=True,
    ),
    EntityType.PRIVATE_KEY: _definition(
        EntityType.PRIVATE_KEY,
        "Private keys",
        CategoryGroup.CREDENTIALS,
        _B,
        Severity.CRITICAL,
        deterministic=True,
    ),
    EntityType.UNKNOWN_SECRET: _definition(
        EntityType.UNKNOWN_SECRET,
        "Unknown secret-like values",
        CategoryGroup.CREDENTIALS,
        _B,
        Severity.CRITICAL,
        deterministic=True,
    ),
    EntityType.RELATIONSHIP: _definition(
        EntityType.RELATIONSHIP,
        "Relationships",
        CategoryGroup.RELATIONSHIPS,
        _R,
        contextual=True,
        review=True,
    ),
    EntityType.FREE_TEXT_SENSITIVE_CONTEXT: _definition(
        EntityType.FREE_TEXT_SENSITIVE_CONTEXT,
        "Sensitive free-text context",
        CategoryGroup.RELATIONSHIPS,
        _R,
        contextual=True,
        review=True,
    ),
    EntityType.UNKNOWN_SENSITIVE: _definition(
        EntityType.UNKNOWN_SENSITIVE,
        "Unknown sensitive information",
        CategoryGroup.UNKNOWN,
        _R,
        contextual=True,
        review=True,
    ),
    EntityType.RACIAL_OR_ETHNIC_ORIGIN: _definition(
        EntityType.RACIAL_OR_ETHNIC_ORIGIN,
        "Racial or ethnic origin",
        CategoryGroup.SPECIAL_CATEGORY,
        _R,
        contextual=True,
        review=True,
    ),
    EntityType.POLITICAL_OPINION: _definition(
        EntityType.POLITICAL_OPINION,
        "Political opinions",
        CategoryGroup.SPECIAL_CATEGORY,
        _R,
        contextual=True,
        review=True,
    ),
    EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF: _definition(
        EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF,
        "Religious or philosophical beliefs",
        CategoryGroup.SPECIAL_CATEGORY,
        _R,
        contextual=True,
        review=True,
    ),
    EntityType.TRADE_UNION_MEMBERSHIP: _definition(
        EntityType.TRADE_UNION_MEMBERSHIP,
        "Trade union membership",
        CategoryGroup.SPECIAL_CATEGORY,
        _R,
        contextual=True,
        deterministic=True,
        review=True,
    ),
    EntityType.GENETIC_DATA: _definition(
        EntityType.GENETIC_DATA,
        "Genetic data",
        CategoryGroup.SPECIAL_CATEGORY,
        _B,
        Severity.CRITICAL,
        contextual=True,
        deterministic=True,
    ),
    EntityType.BIOMETRIC_DATA: _definition(
        EntityType.BIOMETRIC_DATA,
        "Biometric data",
        CategoryGroup.SPECIAL_CATEGORY,
        _B,
        Severity.CRITICAL,
        contextual=True,
        deterministic=True,
    ),
    EntityType.HEALTH_DATA: _definition(
        EntityType.HEALTH_DATA,
        "Health data",
        CategoryGroup.SPECIAL_CATEGORY,
        _R,
        contextual=True,
        review=True,
    ),
    EntityType.SEX_LIFE: _definition(
        EntityType.SEX_LIFE,
        "Sex life",
        CategoryGroup.SPECIAL_CATEGORY,
        _R,
        contextual=True,
        review=True,
    ),
    EntityType.SEXUAL_ORIENTATION: _definition(
        EntityType.SEXUAL_ORIENTATION,
        "Sexual orientation",
        CategoryGroup.SPECIAL_CATEGORY,
        _R,
        contextual=True,
        review=True,
    ),
    EntityType.SPECIAL_CATEGORY_CONTEXT: _definition(
        EntityType.SPECIAL_CATEGORY_CONTEXT,
        "Special-category context",
        CategoryGroup.SPECIAL_CATEGORY,
        _R,
        contextual=True,
        review=True,
    ),
}


if set(CATEGORY_DEFINITIONS) != set(EntityType):
    missing = set(EntityType) - set(CATEGORY_DEFINITIONS)
    extra = set(CATEGORY_DEFINITIONS) - set(EntityType)
    raise RuntimeError(f"Entity taxonomy metadata mismatch: missing={missing}, extra={extra}")


SPECIAL_CATEGORY_TYPES = frozenset(
    {
        EntityType.RACIAL_OR_ETHNIC_ORIGIN,
        EntityType.POLITICAL_OPINION,
        EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF,
        EntityType.TRADE_UNION_MEMBERSHIP,
        EntityType.GENETIC_DATA,
        EntityType.BIOMETRIC_DATA,
        EntityType.HEALTH_DATA,
        EntityType.SEX_LIFE,
        EntityType.SEXUAL_ORIENTATION,
        EntityType.SPECIAL_CATEGORY_CONTEXT,
    }
)

CRITICAL_TYPES = frozenset(
    entity_type
    for entity_type, definition in CATEGORY_DEFINITIONS.items()
    if definition.severity == Severity.CRITICAL
)


def category_metadata() -> list[EntityDefinition]:
    return sorted(
        CATEGORY_DEFINITIONS.values(),
        key=lambda item: (item.group.value, item.display_name),
    )


def mask_preview(value: str) -> str:
    value = value.strip()
    if not value:
        return "••••"
    if len(value) <= 4:
        return "•" * len(value)
    return f"{value[:1]}{'•' * min(10, len(value) - 2)}{value[-1:]}"
