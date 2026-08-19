from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from securedact_eval.gates import (
    Thresholds,
    evaluate_performance_gate,
    evaluate_quality_gate,
    load_thresholds,
)
from securedact_eval.quality import (
    EvaluationConfigurationError,
    _engine_for_mode,
    load_evaluation_corpus,
    run_quality_evaluation,
)
from securedact_eval.reporting import quality_markdown, write_quality_outputs

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "benchmarks" / "corpora"


def test_frozen_corpus_manifest_and_schema_are_valid() -> None:
    samples, digest = load_evaluation_corpus(CORPUS)
    assert len(samples) >= 30
    assert len(digest) == 64
    assert {sample.sample.language for sample in samples}.issuperset({"en", "nl"})
    assert {
        "development",
        "validation",
        "release_gate",
        "adversarial",
        "negative",
    } == {sample.split for sample in samples}


def test_quality_report_is_deterministic_and_has_required_groupings() -> None:
    first = run_quality_evaluation(CORPUS)
    second = run_quality_evaluation(CORPUS)

    assert first.model_dump(exclude={"metadata"}) == second.model_dump(exclude={"metadata"})
    assert first.exact.precision is not None
    assert first.exact.recall is not None
    assert first.exact.f1 is not None
    assert first.exact.false_positive_rate is not None
    assert first.exact.false_negative_rate is not None
    assert set(first.per_language) == {"en", "nl"}
    assert "healthcare" in first.per_domain
    assert "email" in first.per_entity
    assert [item.id for item in first.sample_results] == sorted(
        item.id for item in first.sample_results
    )
    assert first.metadata["evaluation_unit"].startswith("character spans")
    assert first.document_decisions is not None
    assert first.document_decisions.review_rate is not None
    assert first.document_decisions.automatic_pseudonymization_rate is not None
    assert first.document_decisions.sensitive_category_block_or_review_rate == 1.0


def test_json_csv_and_markdown_outputs_are_content_safe(tmp_path: Path) -> None:
    report = run_quality_evaluation(CORPUS)
    outputs = write_quality_outputs(report, tmp_path)

    assert set(outputs) == {"json", "markdown", "csv"}
    assert json.loads(outputs["json"].read_text(encoding="utf-8"))["mode"] == "deterministic"
    assert "True negatives are document-level negatives" in quality_markdown(report)
    assert "alex.dev@example.test" not in outputs["csv"].read_text(encoding="utf-8")


def test_release_gate_passes_baseline_and_reports_hand_verifiable_failure() -> None:
    report = run_quality_evaluation(CORPUS)
    thresholds = load_thresholds(ROOT / "benchmarks" / "thresholds.json")

    assert evaluate_quality_gate(report, thresholds, report).passed
    impossible = Thresholds.model_validate(
        {
            **thresholds.model_dump(),
            "minimum_global_recall": 1.0,
            "maximum_false_positive_rate": 0.0,
        }
    )
    failed = evaluate_quality_gate(report, impossible)
    assert failed.passed is False
    assert failed.failures == [
        "false_positive_rate_above_maximum",
        "global_recall_below_minimum",
    ]


def test_performance_gate_requires_success_and_bounded_warm_p95() -> None:
    thresholds = load_thresholds(ROOT / "benchmarks" / "thresholds.json")
    report = {
        "first_status": "ok",
        "cold_process": {"status": "ok"},
        "warm_inference": {"p95_ms": thresholds.latency_ceiling_ms},
    }
    assert evaluate_performance_gate(report, thresholds).passed

    report["warm_inference"] = {"p95_ms": thresholds.latency_ceiling_ms + 0.1}
    assert evaluate_performance_gate(report, thresholds).failures == ["warm_p95_above_ceiling"]


def test_manifest_tampering_and_schema_failure_are_rejected(tmp_path: Path) -> None:
    copied = tmp_path / "corpora"
    shutil.copytree(CORPUS, copied)
    (copied / "validation.json").write_text("{}", encoding="utf-8")
    with pytest.raises(EvaluationConfigurationError, match="corpus_manifest_mismatch"):
        load_evaluation_corpus(copied)

    payload = json.loads((CORPUS / "development.json").read_text(encoding="utf-8"))
    payload["samples"][0]["unknown"] = True
    invalid = tmp_path / "invalid"
    invalid.mkdir()
    (invalid / "development.json").write_text(json.dumps(payload), encoding="utf-8")
    digest = __import__("hashlib").sha256((invalid / "development.json").read_bytes()).hexdigest()
    (invalid / "manifest.json").write_text(
        json.dumps({"manifest_version": 1, "files": {"development.json": digest}}),
        encoding="utf-8",
    )
    with pytest.raises(EvaluationConfigurationError, match="corpus_schema_invalid"):
        load_evaluation_corpus(invalid)


def test_flair_mode_accepts_language_specific_model_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ReadyFlair:
        name = "fake_flair"
        contextual = True
        ready = True

        def __init__(self, model_path: str) -> None:
            self.model_path = model_path

        def load(self) -> None:
            return None

        def detect(self, text: str) -> list[object]:
            return []

    monkeypatch.setenv("SECUREDACT_EVAL_FLAIR_MODEL_EN", "english.bin")
    monkeypatch.setenv("SECUREDACT_EVAL_FLAIR_MODEL_NL", "dutch.bin")
    monkeypatch.delenv("SECUREDACT_EVAL_FLAIR_MODEL", raising=False)
    monkeypatch.setattr("securedact_eval.quality.FlairDetector", ReadyFlair)

    engine, identifier = _engine_for_mode("flair")

    assert engine.full_ready()
    assert identifier == "configured-flair-en+nl"
    router = next(detector for detector in engine.detectors if detector.contextual)
    assert set(router.detectors) == {"en", "nl"}
