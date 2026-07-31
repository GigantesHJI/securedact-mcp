from __future__ import annotations

import builtins

from pydantic import BaseModel, Field

from .models import DetectionSource, EntityType, PrivacyAction, RedactionMode
from .taxonomy import (
    CATEGORY_DEFINITIONS,
    CRITICAL_TYPES,
    SPECIAL_CATEGORY_TYPES,
    CategoryGroup,
)

PROFILE_SCHEMA_VERSION = 1
ALL_ENTITY_TYPES = frozenset(EntityType)


class Policy(BaseModel):
    schema_version: int = PROFILE_SCHEMA_VERSION
    name: str
    display_name: str | None = None
    description: str
    category_actions: dict[EntityType, PrivacyAction] = Field(default_factory=dict)
    enabled_entity_types: frozenset[EntityType] = ALL_ENTITY_TYPES
    minimum_confidence: float = Field(default=0.30, ge=0.0, le=1.0)
    auto_accept_confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    always_review_types: frozenset[EntityType] = frozenset()
    review_sources: frozenset[DetectionSource] = frozenset(
        {DetectionSource.FLAIR, DetectionSource.CONTEXTUAL}
    )
    review_all_contextual: bool = False
    replacement_mode: RedactionMode = RedactionMode.TYPED_TOKENS
    block_on_unreviewed: bool = True
    block_entity_types: frozenset[EntityType] = frozenset()
    contextual_residual_scan: bool = False
    built_in: bool = True

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
    GDPR_STRICT_POLICY,
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
        self._policies = {policy.name: policy for policy in defaults}

    def get(self, name: str) -> Policy:
        try:
            return self._policies[name]
        except KeyError as exc:
            raise ValueError(f"Unknown privacy policy: {name}") from exc

    def list(self) -> list[Policy]:
        return list(self._policies.values())

    def register(self, policy: Policy) -> None:
        self._policies[policy.name] = policy

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
