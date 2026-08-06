# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from securedact_mcp.model_registry import SUPPORTED_MODELS, SUPPORTED_RUNTIME_COMPONENTS

ROOT = Path(__file__).resolve().parents[1]


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(*arguments: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        raise RuntimeError("release_git_unavailable")
    completed = subprocess.run(  # noqa: S603
        [executable, *arguments],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("release_git_validation_failed")
    return completed.stdout.strip()


def _version() -> str:
    with (ROOT / "pyproject.toml").open("rb") as stream:
        return str(tomllib.load(stream)["project"]["version"])


def _module_version() -> str:
    source = (ROOT / "src" / "securedact_mcp" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*"([^"]+)"$', source, re.MULTILINE)
    if match is None:
        raise RuntimeError("release_module_version_missing")
    return match.group(1)


def validate_release(tag: str) -> None:
    version = _version()
    if _module_version() != version:
        raise RuntimeError("release_module_version_mismatch")
    if tag != f"v{version}":
        raise RuntimeError("release_tag_version_mismatch")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if not re.search(
        rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}$",
        changelog,
        re.MULTILINE,
    ):
        raise RuntimeError("release_changelog_version_missing")
    if _git("cat-file", "-t", tag) != "tag":
        raise RuntimeError("release_tag_must_be_annotated")
    if _git("rev-parse", f"{tag}^{{}}") != _git("rev-parse", "HEAD"):
        raise RuntimeError("release_tag_must_reference_head")
    if _git("status", "--porcelain"):
        raise RuntimeError("release_commit_not_clean")


def create_metadata(dist: Path, output: Path, tag: str) -> dict[str, Any]:
    artifacts = sorted(
        path
        for path in dist.iterdir()
        if path.is_file() and path.name not in {output.name, "SHA256SUMS"}
    )
    artifact_digests = {path.name: _digest(path) for path in artifacts}
    checksum_path = dist / "SHA256SUMS"
    checksum_path.write_text(
        "".join(f"{digest}  {name}\n" for name, digest in artifact_digests.items()),
        encoding="ascii",
        newline="\n",
    )
    benchmark_path = dist / "quality-deterministic.json"
    sbom_path = dist / "securedact-mcp.cdx.json"
    metadata = {
        "provenance_version": "1",
        "git_commit": _git("rev-parse", "HEAD"),
        "git_tag": tag,
        "package_version": _version(),
        "python_version": sys.version.split()[0],
        "operating_system": sys.platform,
        "dependency_lock_digest": _digest(ROOT / "uv.lock"),
        "workflow_identity": os.getenv("GITHUB_WORKFLOW_REF"),
        "sbom_digest": _digest(sbom_path) if sbom_path.is_file() else None,
        "artifact_digests": artifact_digests,
        "model_registry": {
            "models": [
                {
                    "id": model.id,
                    "repository": model.upstream_repo,
                    "revision": model.upstream_revision,
                    "required_files": {
                        path: {
                            "size": model.expected_sizes[path],
                            "sha256": model.expected_hashes[path],
                        }
                        for path in model.required_files
                    },
                }
                for model in SUPPORTED_MODELS
            ],
            "runtime_components": [
                {
                    "id": component.id,
                    "repository": component.upstream_repo,
                    "revision": component.upstream_revision,
                    "required_files": {
                        path: {
                            "size": component.expected_sizes[path],
                            "sha256": component.expected_hashes[path],
                        }
                        for path in component.required_files
                    },
                }
                for component in SUPPORTED_RUNTIME_COMPONENTS
            ],
        },
        "benchmark_corpus_manifest_digest": _digest(
            ROOT / "benchmarks" / "corpora" / "manifest.json"
        ),
        "benchmark_result_digest": (_digest(benchmark_path) if benchmark_path.is_file() else None),
    }
    output.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return metadata


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--tag", default=os.getenv("GITHUB_REF_NAME"))
    metadata = subparsers.add_parser("metadata")
    metadata.add_argument("--tag", default=os.getenv("GITHUB_REF_NAME"))
    metadata.add_argument("--dist", type=Path, default=Path("dist"))
    metadata.add_argument("--output", type=Path, default=Path("dist/provenance.json"))
    arguments = parser.parse_args(argv)
    if not arguments.tag:
        print("ERROR: release_tag_missing", file=sys.stderr)
        return 2
    try:
        if arguments.command == "validate":
            validate_release(arguments.tag)
        else:
            create_metadata(arguments.dist.resolve(), arguments.output.resolve(), arguments.tag)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
