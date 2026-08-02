from __future__ import annotations

from pathlib import Path

from securedact_core import EntityType, evaluate_corpus, load_corpus

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "tests" / "privacy_corpus"


def test_versioned_corpus_has_all_required_sections_and_passes() -> None:
    required_sections = {
        "en",
        "nl",
        "structured",
        "contextual",
        "special_categories",
        "adversarial",
        "negative_controls",
        "mixed_language",
    }
    assert required_sections <= {path.name for path in CORPUS.iterdir() if path.is_dir()}
    report = evaluate_corpus(CORPUS)
    assert report.fixture_count >= 15
    assert report.failed_fixture_ids == []


def test_curated_critical_categories_have_exact_spans_and_no_partial_leaks() -> None:
    required = {
        EntityType.API_TOKEN,
        EntityType.ACCESS_TOKEN,
        EntityType.SESSION_TOKEN,
        EntityType.CARD_SECURITY_CODE,
        EntityType.CREDIT_CARD_NUMBER,
        EntityType.IBAN,
        EntityType.BSN,
        EntityType.MAC_ADDRESS,
        EntityType.IPV4,
        EntityType.IPV6,
    }
    metrics = evaluate_corpus(CORPUS).stage_metrics["merged"]
    for entity_type in required:
        metric = metrics[entity_type.value]
        assert metric.true_positives > 0, entity_type.value
        assert metric.recall == 1.0, entity_type.value
        assert metric.exact_span_accuracy == 1.0, entity_type.value
        assert metric.partial_span_failures == 0, entity_type.value


def test_special_category_release_thresholds_are_explicitly_met() -> None:
    metrics = evaluate_corpus(CORPUS).assertion_metrics
    assert metrics.precision >= 0.90
    assert metrics.recall >= 0.95
    assert metrics.subject_linking_accuracy >= 0.95
    assert metrics.negation_accuracy >= 0.95
    assert metrics.general_discussion_false_positive_rate <= 0.05


def test_release_metrics_cover_deterministic_spans_replacement_and_runtime_parity() -> None:
    report = evaluate_corpus(CORPUS)
    email = report.stage_metrics["deterministic"][EntityType.EMAIL.value]

    assert email.recall == 1.0
    assert email.exact_span_accuracy == 1.0
    assert email.partial_span_failures == 0
    assert report.critical_deterministic_span_recall == 1.0
    assert report.full_span_replacement_rate == 1.0
    assert report.residual_leakage_count == 0
    assert report.production_runtime_parity is True
    # The real stdio deadline is measured by the subprocess release test, not
    # inferred from the in-process corpus evaluator.
    assert report.stdio_startup_deadline_compliance is None


def test_corpus_contains_only_versioned_complete_fixture_contracts() -> None:
    fixtures = load_corpus(CORPUS)
    assert len({fixture.id for fixture in fixtures}) == len(fixtures)
    for fixture in fixtures:
        assert fixture.language in {"en", "nl", "mixed"}
        assert fixture.input
        assert fixture.provider_dispatch in {"permit", "review", "block"}
        assert isinstance(fixture.sanitized_must_not_contain, list)
        assert isinstance(fixture.expected_policy_actions, dict)
