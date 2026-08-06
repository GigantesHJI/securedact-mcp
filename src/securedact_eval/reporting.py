# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import csv
import json
from pathlib import Path

from .quality import QualityReport


def quality_markdown(report: QualityReport) -> str:
    lines = [
        f"# Securedact quality report ({report.mode})",
        "",
        f"Samples: {report.sample_count}; annotated support: {report.support_count}.",
        "",
        "| Match | Precision | Recall | F1 | FP rate | FN rate |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for label, metric in (("Exact", report.exact), ("Relaxed", report.relaxed)):
        values = [
            metric.precision,
            metric.recall,
            metric.f1,
            metric.false_positive_rate,
            metric.false_negative_rate,
        ]
        formatted = ["undefined" if value is None else f"{value:.4f}" for value in values]
        lines.append(f"| {label} | " + " | ".join(formatted) + " |")
    lines.extend(
        [
            "",
            "True negatives are document-level negatives, not token-level safety claims.",
            "This synthetic detection evaluation is not GDPR compliance certification.",
            "",
            "## Per entity (exact)",
            "",
            "| Entity | TP | FP | FN | Precision | Recall | F1 |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for name, evaluation in report.per_entity.items():
        metric = evaluation.exact
        values = [metric.precision, metric.recall, metric.f1]
        formatted = ["undefined" if value is None else f"{value:.4f}" for value in values]
        lines.append(
            f"| {name} | {metric.true_positives} | {metric.false_positives} | "
            f"{metric.false_negatives} | " + " | ".join(formatted) + " |"
        )
    return "\n".join(lines) + "\n"


def write_quality_outputs(report: QualityReport, output_dir: Path) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    prefix = f"quality-{report.mode}"
    json_path = output_dir / f"{prefix}.json"
    markdown_path = output_dir / f"{prefix}.md"
    csv_path = output_dir / f"{prefix}-details.csv"
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8", newline="\n")
    markdown_path.write_text(quality_markdown(report), encoding="utf-8", newline="\n")
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(
            [
                "id",
                "split",
                "language",
                "domain",
                "exact_tp",
                "exact_fp",
                "exact_fn",
                "relaxed_tp",
                "relaxed_fp",
                "relaxed_fn",
            ]
        )
        for item in report.sample_results:
            writer.writerow(
                [
                    item.id,
                    item.split,
                    item.language,
                    item.domain,
                    item.exact.true_positives,
                    item.exact.false_positives,
                    item.exact.false_negatives,
                    item.relaxed.true_positives,
                    item.relaxed.false_positives,
                    item.relaxed.false_negatives,
                ]
            )
    return {"json": json_path, "markdown": markdown_path, "csv": csv_path}


def comparison_markdown(deterministic: QualityReport, flair: QualityReport) -> str:
    deterministic_f1 = deterministic.exact.f1
    flair_f1 = flair.exact.f1
    delta = (
        flair_f1 - deterministic_f1
        if deterministic_f1 is not None and flair_f1 is not None
        else None
    )
    delta_text = "undefined" if delta is None else f"{delta:+.4f}"
    return (
        "# Deterministic versus Flair evaluation\n\n"
        "| Mode | Exact precision | Exact recall | Exact F1 |\n"
        "|---|---:|---:|---:|\n"
        f"| deterministic | {deterministic.exact.precision} | {deterministic.exact.recall} | {deterministic.exact.f1} |\n"
        f"| flair | {flair.exact.precision} | {flair.exact.recall} | {flair.exact.f1} |\n\n"
        f"Exact F1 delta (Flair - deterministic): {delta_text}.\n"
    )


def load_quality_report(path: Path) -> QualityReport:
    return QualityReport.model_validate(json.loads(path.read_text(encoding="utf-8")))
