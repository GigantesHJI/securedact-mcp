# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from .benchmark.generator import generate_profile, load_jsonl
from .benchmark.integrity import validate_integrity
from .benchmark.manifest import verify_benchmark
from .benchmark.profiles import load_profiles
from .benchmark.registry import load_registry, verify_source_file
from .benchmark.workspace import resolve_workspace
from .diagnostics import (
    adversarial_audit_markdown,
    run_adversarial_audit,
    write_adversarial_audit_outputs,
)
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
    quality.add_argument("--aggregate-only", action="store_true")

    audit = subparsers.add_parser("audit")
    audit.add_argument("--corpus", type=Path, default=Path("benchmarks/fixtures/smoke"))
    audit.add_argument("--clean-corpus", type=Path, default=Path("benchmarks/corpora"))
    audit.add_argument("--thresholds", type=Path)
    audit.add_argument("--output-dir", type=Path)
    audit.add_argument("--format", choices=("json", "markdown"), default="markdown")

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

    generate = subparsers.add_parser("generate")
    generate.add_argument("--profile", required=True)
    generate.add_argument(
        "--profiles", type=Path, default=Path("benchmarks/generators/profiles.yml")
    )
    generate.add_argument("--output", type=Path)
    generate.add_argument("--allow-repository-output", action="store_true")

    validate = subparsers.add_parser("validate")
    validate.add_argument("--dataset", type=Path, required=True)

    workspace = subparsers.add_parser("workspace")
    workspace.add_argument("--no-create", action="store_true")

    verify_source = subparsers.add_parser("verify-source")
    verify_source.add_argument(
        "--registry", type=Path, default=Path("benchmarks/registry/sources.yml")
    )
    verify_source.add_argument("--source", required=True)
    verify_source.add_argument("--file-name", required=True)
    verify_source.add_argument("--path", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "quality":
            quality = run_quality_evaluation(
                arguments.corpus,
                mode=arguments.mode,
                aggregate_only=arguments.aggregate_only,
            )
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
        elif arguments.command == "audit":
            threshold_payload = (
                json.loads(arguments.thresholds.read_text(encoding="utf-8"))
                if arguments.thresholds is not None
                else None
            )
            audit_report = run_adversarial_audit(
                arguments.corpus,
                clean_root=arguments.clean_corpus,
                thresholds=threshold_payload,
            )
            if arguments.output_dir is not None:
                write_adversarial_audit_outputs(audit_report, arguments.output_dir)
            output = (
                adversarial_audit_markdown(audit_report)
                if arguments.format == "markdown"
                else audit_report.model_dump_json(indent=2)
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
        elif arguments.command == "generate":
            profiles = load_profiles(arguments.profiles)
            if arguments.profile not in profiles:
                raise EvaluationConfigurationError("benchmark_profile_unknown")
            repository_root = Path.cwd().resolve()
            target = arguments.output
            if target is None:
                workspace = resolve_workspace(repository_root=repository_root)
                target = workspace.generated / arguments.profile
            manifest = generate_profile(
                profiles[arguments.profile],
                target,
                repository_root=repository_root,
                allow_repository_output=arguments.allow_repository_output,
            )
            output = manifest.model_dump_json(indent=2)
        elif arguments.command == "validate":
            manifest = verify_benchmark(arguments.dataset)
            report = validate_integrity(load_jsonl(arguments.dataset / "corpus.jsonl"))
            if not report.valid:
                print(report.model_dump_json(), file=sys.stderr)
                return 3
            output = json.dumps(
                {
                    "manifest": manifest.model_dump(mode="json"),
                    "integrity": report.model_dump(mode="json"),
                },
                indent=2,
                sort_keys=True,
            )
        elif arguments.command == "workspace":
            workspace = resolve_workspace(
                repository_root=Path.cwd(), create=not arguments.no_create
            )
            output = json.dumps({"root": str(workspace.root)}, sort_keys=True)
        elif arguments.command == "verify-source":
            source = load_registry(arguments.registry).require(arguments.source)
            approved = next(
                (item for item in source.files if item.name == arguments.file_name), None
            )
            if approved is None:
                raise EvaluationConfigurationError("source_file_not_registered")
            verify_source_file(arguments.path, approved)
            output = json.dumps({"status": "verified", "source": source.id, "file": approved.name})
        else:
            output = json.dumps(cold_worker(arguments.mode), sort_keys=True)
    except (EvaluationConfigurationError, ValueError) as exc:
        print(json.dumps({"status": "blocked", "error_code": str(exc)}), file=sys.stderr)
        return 2
    print(output)
    return 0
