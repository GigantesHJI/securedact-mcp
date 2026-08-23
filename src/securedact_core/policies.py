from __future__ import annotations

import builtins
import json
from hashlib import sha256
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .firewall import FirewallPolicy
from .models import DetectionSource, EntityType, PrivacyAction, RedactionMode
from .taxonomy import (
    CATEGORY_DEFINITIONS,
    CRITICAL_TYPES,
    SPECIAL_CATEGORY_TYPES,
    CategoryGroup,
)

PROFILE_SCHEMA_VERSION = 1
ALL_ENTITY_TYPES = frozenset(EntityType)


class AutomaticPseudonymizationRule(BaseModel):
    """Conservative, source-specific evidence required for automatic transformation.

    Detector confidence values are not assumed to share one calibration scale. A
    policy therefore opts categories and detector sources in independently.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_thresholds: dict[DetectionSource, float]
    require_personal_context: bool = False

    @field_validator("source_thresholds")
    @classmethod
    def validate_source_thresholds(
        cls,
        value: dict[DetectionSource, float],
    ) -> dict[DetectionSource, float]:
        if not value or any(threshold < 0.0 or threshold > 1.0 for threshold in value.values()):
            raise ValueError("automatic pseudonymization thresholds must be between zero and one")
        return value


def _automatic_pseudonymization_rules() -> dict[EntityType, AutomaticPseudonymizationRule]:
    regex_and_label = AutomaticPseudonymizationRule(
        source_thresholds={
            DetectionSource.REGEX: 0.99,
            DetectionSource.LABEL: 0.99,
        }
    )
    validated_regex_and_label = AutomaticPseudonymizationRule(
        source_thresholds={
            DetectionSource.REGEX: 1.0,
            DetectionSource.LABEL: 0.99,
        }
    )
    rules = {
        entity_type: regex_and_label
        for entity_type in {
            EntityType.EMAIL,
            EntityType.PHONE,
            EntityType.ADDRESS,
            EntityType.STREET_ADDRESS,
            EntityType.HOUSE_NUMBER,
            EntityType.POSTCODE,
            EntityType.DATE_OF_BIRTH,
            EntityType.PASSPORT_NUMBER,
            EntityType.DRIVING_LICENCE_NUMBER,
            EntityType.NATIONAL_ID,
            EntityType.CUSTOMER_NUMBER,
            EntityType.CASE_NUMBER,
            EntityType.EMPLOYEE_ID,
            EntityType.PAYROLL_NUMBER,
            EntityType.PATIENT_NUMBER,
            EntityType.MEDICAL_RECORD_NUMBER,
            EntityType.POLICY_NUMBER,
            EntityType.INVOICE_NUMBER,
            EntityType.BIC_SWIFT,
            EntityType.BANK_ACCOUNT_REFERENCE,
            EntityType.PAYMENT_REFERENCE,
            EntityType.CARD_EXPIRY,
            EntityType.IPV4,
            EntityType.IPV6,
            EntityType.MAC_ADDRESS,
            EntityType.DEVICE_IDENTIFIER,
            EntityType.SENSITIVE_URL_PARAMETER,
            EntityType.INTERNAL_URL,
        }
    }
    for entity_type in {
        EntityType.BSN,
        EntityType.IBAN,
        EntityType.CREDIT_CARD_NUMBER,
    }:
        rules[entity_type] = validated_regex_and_label
    rules[EntityType.PERSON] = AutomaticPseudonymizationRule(
        source_thresholds={
            DetectionSource.LABEL: 0.95,
            DetectionSource.CONTEXTUAL: 0.98,
            DetectionSource.FLAIR: 0.98,
        },
        require_personal_context=True,
    )
    rules[EntityType.LOCATION] = AutomaticPseudonymizationRule(
        source_thresholds={
            DetectionSource.CONTEXTUAL: 0.99,
            DetectionSource.FLAIR: 0.99,
        },
        require_personal_context=True,
    )
    return rules


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = PROFILE_SCHEMA_VERSION
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    display_name: str | None = None
    description: str = Field(min_length=1, max_length=500)
    category_actions: dict[EntityType, PrivacyAction] = Field(default_factory=dict)
    enabled_entity_types: frozenset[EntityType] = ALL_ENTITY_TYPES
    minimum_confidence: float = Field(default=0.30, ge=0.0, le=1.0)
    thresholds: dict[EntityType, float] = Field(default_factory=dict)
    auto_accept_confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    always_review_types: frozenset[EntityType] = frozenset()
    review_sources: frozenset[DetectionSource] = frozenset(
        {DetectionSource.FLAIR, DetectionSource.CONTEXTUAL}
    )
    review_all_contextual: bool = False
    automatic_pseudonymization_rules: dict[EntityType, AutomaticPseudonymizationRule] = Field(
        default_factory=_automatic_pseudonymization_rules
    )
    automatic_pseudonymization: bool = True
    low_confidence_review_types: frozenset[EntityType] = CRITICAL_TYPES | SPECIAL_CATEGORY_TYPES
    replacement_mode: RedactionMode = RedactionMode.TYPED_TOKENS
    block_on_unreviewed: bool = True
    block_entity_types: frozenset[EntityType] = frozenset()
    contextual_residual_scan: bool = False
    residual_validation_enabled: bool = True
    residual_on_failure: Literal["block"] = "block"
    default_response_mode: Literal["minimal", "review", "restore_capable"] = "minimal"
    expose_raw_values: bool = False
    expose_mapping: bool = False
    firewall: FirewallPolicy | None = None
    built_in: bool = True

    @field_validator("thresholds")
    @classmethod
    def validate_thresholds(
        cls,
        value: dict[EntityType, float],
    ) -> dict[EntityType, float]:
        if any(threshold < 0.0 or threshold > 1.0 for threshold in value.values()):
            raise ValueError("policy thresholds must be between zero and one")
        return value

    def action_for(self, entity_type: EntityType) -> PrivacyAction:
        if entity_type in self.block_entity_types:
            return PrivacyAction.BLOCK
        if entity_type not in self.enabled_entity_types:
            # Legacy disabled categories are explicit allowances. No built-in profile
            # uses this compatibility route.
            return PrivacyAction.ALLOW
        return self.category_actions.get(
            entity_type,
            CATEGORY_DEFINITIONS[entity_type].default_action,
        )

    def threshold_for(self, entity_type: EntityType) -> float:
        return self.thresholds.get(entity_type, self.minimum_confidence)

    @property
    def digest(self) -> str:
        payload = json.dumps(
            self.model_dump(mode="json"),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        return sha256(payload.encode("utf-8")).hexdigest()


def _secure_defaults() -> dict[EntityType, PrivacyAction]:
    return {
        entity_type: definition.default_action
        for entity_type, definition in CATEGORY_DEFINITIONS.items()
    }


def _profile_actions(
    protected_groups: set[CategoryGroup],
    *,
    strict_special: bool = False,
) -> dict[EntityType, PrivacyAction]:
    actions = _secure_defaults()
    for entity_type, definition in CATEGORY_DEFINITIONS.items():
        if definition.group not in protected_groups and entity_type not in CRITICAL_TYPES:
            # Built-ins never silently allow a sensitive category. Categories outside
            # the profile's focus remain reviewable.
            actions[entity_type] = PrivacyAction.REVIEW
    if strict_special:
        for entity_type in SPECIAL_CATEGORY_TYPES:
            actions[entity_type] = (
                PrivacyAction.BLOCK
                if entity_type in {EntityType.GENETIC_DATA, EntityType.BIOMETRIC_DATA}
                else PrivacyAction.REDACT
            )
    return actions


DEFAULT_POLICY = Policy(
    name="default",
    display_name="Personal Data",
    description="Automatic local protection with review for contextual findings.",
    category_actions=_secure_defaults(),
)


def _strict_external_actions() -> dict[EntityType, PrivacyAction]:
    actions = _secure_defaults()
    for entity_type, definition in CATEGORY_DEFINITIONS.items():
        if definition.group in {CategoryGroup.CREDENTIALS, CategoryGroup.SPECIAL_CATEGORY}:
            actions[entity_type] = PrivacyAction.BLOCK
    actions[EntityType.ORGANIZATION] = PrivacyAction.REVIEW
    return actions


STRICT_EXTERNAL_AI_POLICY = Policy(
    name="strict_external_ai",
    display_name="Strict External AI",
    description="Blocks credentials and special-category data; redacts or reviews other findings.",
    category_actions=_strict_external_actions(),
    minimum_confidence=0.15,
    thresholds={
        EntityType.PERSON: 0.85,
        EntityType.ORGANIZATION: 0.92,
    },
    review_all_contextual=False,
    contextual_residual_scan=True,
)

GDPR_STRICT_POLICY = Policy(
    name="gdpr_strict",
    display_name="GDPR Strict",
    description="Broad protection with review of contextual and special-category assertions.",
    category_actions=_secure_defaults(),
    minimum_confidence=0.15,
    auto_accept_confidence=1.0,
    review_all_contextual=True,
    contextual_residual_scan=True,
)

GDPR_POLICY = GDPR_STRICT_POLICY.model_copy(
    update={
        "name": "gdpr",
        "display_name": "GDPR-related Detection",
        "description": (
            "Broad detection policy for categories relevant to GDPR; not a compliance certification."
        ),
    }
)

IDENTIFIERS_ONLY_POLICY = Policy(
    name="identifiers_only",
    display_name="Identifiers Only",
    description="Redacts direct identifiers while keeping all other sensitive findings reviewable.",
    category_actions=_profile_actions(
        {
            CategoryGroup.IDENTITY,
            CategoryGroup.CONTACT,
            CategoryGroup.LOCATION,
            CategoryGroup.DATES,
            CategoryGroup.GOVERNMENT,
            CategoryGroup.FINANCIAL,
            CategoryGroup.TECHNICAL,
        }
    ),
)

REVIEW_ALL_CONTEXTUAL_POLICY = Policy(
    name="review_all_contextual",
    display_name="Review All Contextual",
    description="Requires local review for every contextual or statistical finding.",
    category_actions=_secure_defaults(),
    review_all_contextual=True,
    auto_accept_confidence=1.0,
    contextual_residual_scan=True,
)

PERSONAL_DATA_POLICY = Policy(
    name="personal_data",
    display_name="Personal Data",
    description="Protects direct and indirect personal identifiers.",
    category_actions=_profile_actions(
        {
            CategoryGroup.IDENTITY,
            CategoryGroup.CONTACT,
            CategoryGroup.LOCATION,
            CategoryGroup.DATES,
            CategoryGroup.GOVERNMENT,
            CategoryGroup.RELATIONSHIPS,
            CategoryGroup.TECHNICAL,
        }
    ),
)

FINANCIAL_DATA_POLICY = Policy(
    name="financial_data",
    display_name="Financial Data",
    description="Protects payment, banking, insurance, and invoice information.",
    category_actions=_profile_actions({CategoryGroup.FINANCIAL}),
)

MEDICAL_DATA_POLICY = Policy(
    name="medical_data",
    display_name="Medical Data",
    description="Protects health information, treatments, appointments, and patient identifiers.",
    category_actions=_profile_actions({CategoryGroup.MEDICAL, CategoryGroup.SPECIAL_CATEGORY}),
    review_all_contextual=True,
)

CREDENTIALS_POLICY = Policy(
    name="credentials_and_secrets",
    display_name="Credentials and Secrets",
    description="Blocks credentials, tokens, secrets, and sensitive technical identifiers.",
    category_actions=_profile_actions({CategoryGroup.CREDENTIALS, CategoryGroup.TECHNICAL}),
)

BUSINESS_POLICY = Policy(
    name="business_confidential",
    display_name="Business Confidential",
    description="Protects internal projects, departments, records, and URLs.",
    category_actions=_profile_actions({CategoryGroup.BUSINESS}),
)

SPECIAL_CATEGORY_STRICT_POLICY = Policy(
    name="special_category_strict",
    display_name="Special Category Strict",
    description="Redacts complete special-category assertions and blocks genetic or biometric data.",
    category_actions=_profile_actions(
        {CategoryGroup.SPECIAL_CATEGORY},
        strict_special=True,
    ),
    minimum_confidence=0.15,
    auto_accept_confidence=1.0,
    review_all_contextual=True,
    contextual_residual_scan=True,
)

CUSTOM_POLICY = Policy(
    name="custom",
    display_name="Custom",
    description="A locally stored profile initialized from GDPR Strict.",
    category_actions=GDPR_STRICT_POLICY.category_actions,
    minimum_confidence=GDPR_STRICT_POLICY.minimum_confidence,
    auto_accept_confidence=GDPR_STRICT_POLICY.auto_accept_confidence,
    review_all_contextual=True,
    contextual_residual_scan=True,
    built_in=False,
)


BUILT_IN_POLICIES = (
    DEFAULT_POLICY,
    STRICT_EXTERNAL_AI_POLICY,
    GDPR_POLICY,
    GDPR_STRICT_POLICY,
    IDENTIFIERS_ONLY_POLICY,
    REVIEW_ALL_CONTEXTUAL_POLICY,
    PERSONAL_DATA_POLICY,
    FINANCIAL_DATA_POLICY,
    MEDICAL_DATA_POLICY,
    CREDENTIALS_POLICY,
    BUSINESS_POLICY,
    SPECIAL_CATEGORY_STRICT_POLICY,
    CUSTOM_POLICY,
)


class PolicyRegistry:
    def __init__(self, policies: list[Policy] | None = None) -> None:
        defaults = policies or list(BUILT_IN_POLICIES)
        names = [policy.name for policy in defaults]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate privacy policy names are not allowed")
        self._policies = {policy.name: policy for policy in defaults}

    def get(self, name: str) -> Policy:
        try:
            return self._policies[name]
        except KeyError as exc:
            raise ValueError(f"Unknown privacy policy: {name}") from exc

    def list(self) -> list[Policy]:
        return [self._policies[name] for name in sorted(self._policies)]

    def register(self, policy: Policy) -> None:
        if policy.name in self._policies:
            raise ValueError(f"Duplicate privacy policy name: {policy.name}")
        self._policies[policy.name] = policy

    def with_automatic_pseudonymization(self, enabled: bool) -> PolicyRegistry:
        """Return an isolated registry with one effective automatic-transformation setting."""

        return PolicyRegistry(
            [
                policy.model_copy(update={"automatic_pseudonymization": enabled})
                for policy in self._policies.values()
            ]
        )

    def resolve_actions(
        self,
        name: str,
        overrides: dict[EntityType, PrivacyAction] | None = None,
        *,
        advanced_unsafe_mode: bool = False,
        confirmed_allow_categories: set[EntityType] | None = None,
    ) -> tuple[Policy, dict[EntityType, PrivacyAction], builtins.list[str]]:
        policy = self.get(name)
        actions = {entity_type: policy.action_for(entity_type) for entity_type in EntityType}
        exceptions: list[str] = []
        confirmed = confirmed_allow_categories or set()
        for entity_type, action in (overrides or {}).items():
            if action == PrivacyAction.ALLOW and entity_type in CRITICAL_TYPES:
                if not advanced_unsafe_mode or entity_type not in confirmed:
                    actions[entity_type] = PrivacyAction.BLOCK
                    exceptions.append(f"{entity_type.value}:critical_allow_rejected")
                    continue
            if action == PrivacyAction.ALLOW and entity_type in SPECIAL_CATEGORY_TYPES:
                if entity_type not in confirmed:
                    actions[entity_type] = PrivacyAction.REVIEW
                    exceptions.append(f"{entity_type.value}:allow_confirmation_required")
                    continue
            actions[entity_type] = action
            if action == PrivacyAction.ALLOW:
                exceptions.append(f"{entity_type.value}:explicitly_allowed")
        return policy, actions, exceptions
