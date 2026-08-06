# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from .gates import evaluate_performance_gate, evaluate_quality_gate, load_thresholds
from .performance import cold_worker, run_performance_evaluation
from .quality import EvaluationConfigurationError, run_quality_evaluation
from .reporting import (
    comparison_markdown,
    load_quality_report,
    quality_markdown,
    write_quality_outputs,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="securedact-eval")
    subparsers = parser.add_subparsers(dest="command", required=True)
    quality = subparsers.add_parser("quality")
    quality.add_argument("--mode", choices=("deterministic", "flair"), default="deterministic")
    quality.add_argument("--corpus", type=Path, default=Path("benchmarks/corpora"))
    quality.add_argument("--output-dir", type=Path)
    quality.add_argument("--format", choices=("json", "markdown"), default="json")
    quality.add_argument("--gate", action="store_true")
    quality.add_argument("--thresholds", type=Path, default=Path("benchmarks/thresholds.json"))
    quality.add_argument("--baseline", type=Path)

    performance = subparsers.add_parser("performance")
    performance.add_argument("--mode", choices=("deterministic", "flair"), default="deterministic")
    performance.add_argument("--repetitions", type=int, default=20)
    performance.add_argument("--warmups", type=int, default=3)
    performance.add_argument("--output", type=Path)
    performance.add_argument("--gate", action="store_true")
    performance.add_argument("--thresholds", type=Path, default=Path("benchmarks/thresholds.json"))

    report = subparsers.add_parser("report")
    report.add_argument("--deterministic", type=Path, required=True)
    report.add_argument("--flair", type=Path, required=True)
    report.add_argument("--output", type=Path)

    cold = subparsers.add_parser("_cold_worker")
    cold.add_argument("--mode", choices=("deterministic", "flair"), required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "quality":
            quality = run_quality_evaluation(arguments.corpus, mode=arguments.mode)
            if arguments.output_dir is not None:
                write_quality_outputs(quality, arguments.output_dir)
            if arguments.gate:
                baseline = (
                    load_quality_report(arguments.baseline)
                    if arguments.baseline is not None
                    else None
                )
                gate = evaluate_quality_gate(
                    quality,
                    load_thresholds(arguments.thresholds),
                    baseline,
                )
                if not gate.passed:
                    print(gate.model_dump_json(), file=sys.stderr)
                    return 3
            output = (
                quality_markdown(quality)
                if arguments.format == "markdown"
                else quality.model_dump_json(indent=2)
            )
        elif arguments.command == "performance":
            performance = run_performance_evaluation(
                mode=arguments.mode,
                repetitions=arguments.repetitions,
                warmups=arguments.warmups,
            )
            output = json.dumps(performance, indent=2, sort_keys=True)
            if arguments.output is not None:
                arguments.output.write_text(output + "\n", encoding="utf-8", newline="\n")
            if arguments.gate:
                gate = evaluate_performance_gate(
                    performance,
                    load_thresholds(arguments.thresholds),
                )
                if not gate.passed:
                    print(gate.model_dump_json(), file=sys.stderr)
                    return 3
        elif arguments.command == "report":
            output = comparison_markdown(
                load_quality_report(arguments.deterministic),
                load_quality_report(arguments.flair),
            )
            if arguments.output is not None:
                arguments.output.write_text(output, encoding="utf-8", newline="\n")
        else:
            output = json.dumps(cold_worker(arguments.mode), sort_keys=True)
    except EvaluationConfigurationError as exc:
        print(json.dumps({"status": "blocked", "error_code": str(exc)}), file=sys.stderr)
        return 2
    print(output)
    return 0
