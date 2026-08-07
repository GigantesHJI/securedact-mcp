from __future__ import annotations

from pathlib import Path

from pydantic import ValidationError

from securedact_core import (
    CATEGORY_DEFINITIONS,
    SPECIAL_CATEGORY_TYPES,
    AnalysisResult,
    Detection,
    EntityType,
    PrivacyAction,
    PrivacyConfiguration,
    PrivacyEngine,
    PrivacyProfileStore,
    RedactionResult,
    SecuredactPaths,
)
from securedact_core.detectors import (
    ContextualPrivacyDetector,
    CredentialsDetector,
    RegexDetector,
)


def test_every_entity_has_exactly_one_canonical_group() -> None:
    assert set(CATEGORY_DEFINITIONS) == set(EntityType)
    assert all(definition.group for definition in CATEGORY_DEFINITIONS.values())


def test_all_nine_gdpr_special_categories_are_first_class_and_never_allow_by_default() -> None:
    nine_categories = {
        EntityType.RACIAL_OR_ETHNIC_ORIGIN,
        EntityType.POLITICAL_OPINION,
        EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF,
        EntityType.TRADE_UNION_MEMBERSHIP,
        EntityType.GENETIC_DATA,
        EntityType.BIOMETRIC_DATA,
        EntityType.HEALTH_DATA,
        EntityType.SEX_LIFE,
        EntityType.SEXUAL_ORIENTATION,
    }
    assert nine_categories <= SPECIAL_CATEGORY_TYPES
    engine = PrivacyEngine([])
    for profile in engine.policies.list():
        for entity_type in nine_categories:
            assert profile.action_for(entity_type) != PrivacyAction.ALLOW
    strict = engine.policies.get("special_category_strict")
    assert strict.action_for(EntityType.GENETIC_DATA) == PrivacyAction.BLOCK
    assert strict.action_for(EntityType.BIOMETRIC_DATA) == PrivacyAction.BLOCK


def test_dangerous_allow_requires_advanced_mode_and_category_confirmation() -> None:
    policies = PrivacyEngine([]).policies
    _, rejected, warnings = policies.resolve_actions(
        "gdpr_strict",
        {EntityType.API_TOKEN: PrivacyAction.ALLOW},
    )
    assert rejected[EntityType.API_TOKEN] == PrivacyAction.BLOCK
    assert "api_token:critical_allow_rejected" in warnings

    _, still_rejected, _ = policies.resolve_actions(
        "gdpr_strict",
        {EntityType.API_TOKEN: PrivacyAction.ALLOW},
        advanced_unsafe_mode=True,
    )
    assert still_rejected[EntityType.API_TOKEN] == PrivacyAction.BLOCK

    _, allowed, warnings = policies.resolve_actions(
        "gdpr_strict",
        {EntityType.API_TOKEN: PrivacyAction.ALLOW},
        advanced_unsafe_mode=True,
        confirmed_allow_categories={EntityType.API_TOKEN},
    )
    assert allowed[EntityType.API_TOKEN] == PrivacyAction.ALLOW
    assert "api_token:explicitly_allowed" in warnings


def test_special_category_allow_requires_current_session_confirmation() -> None:
    policies = PrivacyEngine([]).policies
    _, actions, warnings = policies.resolve_actions(
        "gdpr_strict",
        {EntityType.POLITICAL_OPINION: PrivacyAction.ALLOW},
    )
    assert actions[EntityType.POLITICAL_OPINION] == PrivacyAction.REVIEW
    assert "political_opinion:allow_confirmation_required" in warnings

    _, confirmed, _ = policies.resolve_actions(
        "gdpr_strict",
        {EntityType.POLITICAL_OPINION: PrivacyAction.ALLOW},
        confirmed_allow_categories={EntityType.POLITICAL_OPINION},
    )
    assert confirmed[EntityType.POLITICAL_OPINION] == PrivacyAction.ALLOW


def test_corrupt_profile_storage_falls_back_to_gdpr_strict(tmp_path: Path) -> None:
    paths = SecuredactPaths.resolve(tmp_path / "app-data")
    store = PrivacyProfileStore(paths)
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text('{"active_profile":"unknown","category_actions":{"api_token":"allow"}}')
    loaded = store.load()
    assert loaded.active_profile == "gdpr_strict"
    assert loaded.category_actions == {}
    assert not loaded.advanced_unsafe_mode


def test_profile_schema_rejects_unknown_or_malformed_actions() -> None:
    try:
        PrivacyConfiguration.model_validate(
            {
                "active_profile": "gdpr_strict",
                "category_actions": {"api_token": "unexpected"},
            }
        )
    except ValidationError:
        pass
    else:
        raise AssertionError("Malformed action unexpectedly weakened the profile")


def test_audit_is_local_and_redacts_high_indirect_disclosure() -> None:
    engine = PrivacyEngine([RegexDetector(), ContextualPrivacyDetector()])
    audit = engine.audit(
        "Emma attends a mosque every Sunday.",
        "gdpr_strict",
    )
    assert not audit.provider_invoked
    assert "mosque" not in audit.sanitized_text.casefold()
    assert audit.residual_scan.safe_to_send
    assert audit.assertions


def test_residual_scan_fails_closed_when_detector_raises() -> None:
    class FailingOnSecondPass:
        name = "regex"
        contextual = False

        def __init__(self) -> None:
            self.calls = 0

        def detect(self, _text: str) -> list[Detection]:
            self.calls += 1
            if self.calls > 1:
                raise RuntimeError("synthetic detector failure")
            return []

    detector = FailingOnSecondPass()
    engine = PrivacyEngine([detector])
    analysis = engine.analyze("plain text", "gdpr_strict")
    redaction = engine.redact(
        "plain text",
        "gdpr_strict",
        analysis=analysis,
        audit_mode=True,
    )
    residual = engine.scan_residual(
        "plain text",
        redaction,
        analysis,
        "gdpr_strict",
    )
    assert not residual.safe_to_send
    assert residual.critical_residual_count == 1
    assert residual.partial_match_findings[0].reason == "residual_detector_failed"


def test_residual_scan_catches_normalized_remnants_and_malformed_placeholders() -> None:
    engine = PrivacyEngine([RegexDetector()])
    source = "Case number: CASE-NL-7731"
    entity = engine.analyze(source, "gdpr_strict").entities[0]
    leaked = RedactionResult(
        sanitized_text="Case number: case nl 7731",
        mapping={},
        entities=[entity],
        entity_counts={entity.entity_type.value: 1},
    )
    residual = engine.scan_residual(
        source,
        leaked,
        AnalysisResult(entities=[entity], requires_review=False),
        "gdpr_strict",
    )
    assert not residual.safe_to_send
    assert residual.partial_match_findings

    malformed = RedactionResult(
        sanitized_text="safe [bad placeholder]",
        mapping={},
        entities=[],
        entity_counts={},
    )
    malformed_result = engine.scan_residual(
        "safe",
        malformed,
        AnalysisResult(entities=[], requires_review=False),
        "gdpr_strict",
    )
    assert not malformed_result.safe_to_send
    assert malformed_result.malformed_placeholders == ["[bad placeholder]"]


def test_residual_scan_reruns_credentials_and_contextual_rules() -> None:
    engine = PrivacyEngine(
        [CredentialsDetector(), RegexDetector(), ContextualPrivacyDetector()]
    )
    empty_analysis = AnalysisResult(entities=[], requires_review=False)

    for source, expected_type in (
        ("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", EntityType.API_TOKEN),
        ("Emma Stone has BRCA1.", EntityType.GENETIC_DATA),
    ):
        leaked = RedactionResult(
            sanitized_text=source,
            mapping={},
            entities=[],
            entity_counts={},
        )

        residual = engine.scan_residual(
            source,
            leaked,
            empty_analysis,
            "gdpr_strict",
        )

        assert not residual.safe_to_send
        assert expected_type in {item.entity_type for item in residual.residual_findings}


def test_residual_normalization_catches_encoded_sensitive_values() -> None:
    engine = PrivacyEngine([RegexDetector()])
    source = "user@example.test"
    finding = engine.analyze(source, "gdpr_strict").entities[0]
    leaked = RedactionResult(
        sanitized_text="user%40example.test",
        mapping={},
        entities=[finding],
        entity_counts={finding.entity_type.value: 1},
    )

    residual = engine.scan_residual(
        source,
        leaked,
        AnalysisResult(entities=[finding], requires_review=False),
        "gdpr_strict",
    )

    assert not residual.safe_to_send
    assert residual.partial_match_findings
