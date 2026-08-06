"""Enforce repository and benchmark data-boundary size limits."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

MIB = 1024 * 1024
GENERAL_LIMIT = 5 * MIB
FIXTURE_TOTAL_LIMIT = 25 * MIB
REPORT_LIMIT = 10 * MIB
FORBIDDEN_BENCHMARK_PREFIXES = (
    "benchmarks/downloads/",
    "benchmarks/external/",
    "benchmarks/external-data/",
    "benchmarks/extracted/",
    "benchmarks/generated/",
    "benchmarks/private/",
    "benchmarks/private-holdout/",
    "benchmarks/raw/",
    "benchmarks/restricted/",
    "benchmarks/restricted-data/",
)


def tracked_files(root: Path) -> list[Path]:
    result = subprocess.run(
        [  # noqa: S607 - Git is a documented local prerequisite
            "git",
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        cwd=root,
        capture_output=True,
        check=True,
    )
    return [root / item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def validate_sizes(root: Path, files: list[Path] | None = None) -> list[str]:
    candidates = tracked_files(root) if files is None else files
    errors: list[str] = []
    fixture_total = 0
    for path in candidates:
        relative = path.relative_to(root).as_posix()
        if not path.is_file():
            continue
        size = path.stat().st_size
        if relative.startswith(FORBIDDEN_BENCHMARK_PREFIXES):
            errors.append(f"tracked raw/generated benchmark path is forbidden: {relative}")
        if relative.startswith("benchmarks/fixtures/"):
            fixture_total += size
        limit = REPORT_LIMIT if relative.startswith("benchmarks/reports/") else GENERAL_LIMIT
        if size > limit:
            errors.append(f"file exceeds {limit // MIB} MiB limit: {relative}")
        if relative.startswith("benchmarks/") and path.suffix in {".json", ".jsonl"}:
            for line in path.read_text(encoding="utf-8").splitlines():
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(payload, dict) and payload.get("split") == "private_holdout":
                    errors.append(f"private holdout record is tracked: {relative}")
    if fixture_total > FIXTURE_TOTAL_LIMIT:
        errors.append("committed benchmark fixtures exceed 25 MiB total")
    return sorted(set(errors))


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors = validate_sizes(root)
    if errors:
        print("Repository size validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("Repository size and benchmark data-boundary validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
