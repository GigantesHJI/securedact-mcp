from __future__ import annotations

import json
from pathlib import Path

import pytest

from securedact_core import Detection, build_production_engine
from securedact_eval.diagnostics import (
    ERROR_TAXONOMY,
    AdversarialAuditReport,
    adversarial_audit_markdown,
    run_adversarial_audit,
    write_adversarial_audit_outputs,
)
from securedact_eval.models import CorpusSample

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def audit_report() -> AdversarialAuditReport:
    thresholds = json.loads(
        (ROOT / "benchmarks" / "adversarial_thresholds.json").read_text(encoding="utf-8")
    )
    return run_adversarial_audit(
        ROOT / "benchmarks" / "fixtures" / "smoke",
        clean_root=ROOT / "benchmarks" / "corpora",
        thresholds=thresholds,
    )


def test_release_groups_are_separate_visible_and_only_supported_groups_gate(
    audit_report: AdversarialAuditReport,
) -> None:
    report = audit_report
    deterministic = report.modes["deterministic_only"]
    assert set(deterministic.release_score_groups) == {
        "standard_clean",
        "negative_controls",
        "supported_adversarial",
        "partially_supported_adversarial",
        "unsupported_challenge",
    }
    assert deterministic.release_score_groups["unsupported_challenge"].documents > 0
    evaluation = report.release_thresholds["evaluation"]
    assert evaluation["passed"] is True
    assert {name for name, result in evaluation["groups"].items() if result["gated"]} == {
        "standard_clean",
        "supported_adversarial",
    }


def test_every_failed_record_has_a_known_taxonomy_and_mock_is_not_quality_evidence(
    audit_report: AdversarialAuditReport,
) -> None:
    report = audit_report
    deterministic = report.modes["deterministic_only"]
    assert deterministic.failed_records
    assert all(
        record.failure_types and set(record.failure_types) <= set(ERROR_TAXONOMY)
        for record in deterministic.failed_records
    )
    assert report.modes["mocked_contextual"].quality_claim is False
    assert report.modes["mocked_contextual"].label.startswith("MOCKED")


def test_integrity_audit_and_content_safe_outputs(
    audit_report: AdversarialAuditReport,
    tmp_path: Path,
) -> None:
    report = audit_report
    assert all(report.benchmark_integrity.checks.values())
    assert report.benchmark_integrity.observed_duplicate_predictions == 0
    outputs = write_adversarial_audit_outputs(report, tmp_path)
    payload = json.loads(outputs["json"].read_text(encoding="utf-8"))
    assert payload["original_reported_headline"]["exact_f1"] == 0.2438
    assert (
        "unsupported challenge is informational only" in adversarial_audit_markdown(report).lower()
    )
    assert all(
        "text" not in record for record in payload["modes"]["deterministic_only"]["failed_records"]
    )


def test_adversarial_diagnostics_route_the_annotated_language() -> None:
    from securedact_eval.diagnostics import _run_records

    class CapturingContextualDetector:
        name = "capturing_contextual"
        contextual = True
        ready = True

        def __init__(self) -> None:
            self.languages: list[str] = []

        def detect_for_language(self, text: str, language: str) -> list[Detection]:
            self.languages.append(language)
            return []

        def detect(self, text: str) -> list[Detection]:
            raise AssertionError("explicit benchmark language must be used")

    detector = CapturingContextualDetector()
    engine = build_production_engine([detector], require_contextual=True)
    samples = [
        CorpusSample(
            id="synthetic-en",
            language="en",
            domain="general",
            text="No sensitive value.",
            entities=[],
        ),
        CorpusSample(
            id="synthetic-nl",
            language="nl",
            domain="general",
            text="Geen gevoelig gegeven.",
            entities=[],
        ),
    ]

    _run_records(samples, engine)

    assert detector.languages[::2] == ["en", "nl"]
