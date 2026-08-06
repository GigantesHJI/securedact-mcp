"""Run the network-free checks used by essential CI."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path


def _run(command: list[str], *, root: Path) -> int:
    environment = os.environ.copy()
    environment.setdefault("UV_CACHE_DIR", str(root / ".tmp" / "uv-cache"))
    environment.setdefault("UV_PYTHON_INSTALL_DIR", str(root / ".tmp" / "uv-python"))
    result = subprocess.run(  # noqa: S603 - commands are fixed local verification steps
        command, cwd=root, check=False, env=environment
    )
    return result.returncode


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    temporary_root = root / ".tmp"
    temporary_root.mkdir(exist_ok=True)
    commands = (
        [sys.executable, "-m", "uv", "lock", "--check", "--python", sys.executable],
        [sys.executable, "scripts/validate_repo.py", "--require-implementation"],
        [sys.executable, "scripts/validate_repository_size.py"],
        [sys.executable, "scripts/validate_workflows.py"],
        [
            sys.executable,
            "-m",
            "securedact_eval",
            "validate",
            "--dataset",
            "benchmarks/fixtures/smoke",
        ],
        [sys.executable, "-m", "ruff", "format", "--check", "."],
        [sys.executable, "-m", "ruff", "check", "."],
        [sys.executable, "-m", "mypy", "src", "scripts"],
        [sys.executable, "-m", "pytest"],
        [
            sys.executable,
            "-m",
            "securedact_eval",
            "quality",
            "--corpus",
            "benchmarks/fixtures/smoke",
            "--aggregate-only",
            "--format",
            "markdown",
        ],
    )
    for command in commands:
        if returncode := _run(command, root=root):
            return returncode

    with tempfile.TemporaryDirectory(prefix="verify-dist-", dir=temporary_root) as directory:
        artifact_dir = Path(directory)
        if returncode := _run(
            [
                sys.executable,
                "-m",
                "build",
                "--no-isolation",
                "--outdir",
                str(artifact_dir),
            ],
            root=root,
        ):
            return returncode
        artifacts = [str(path) for path in sorted(artifact_dir.iterdir()) if path.is_file()]
        if returncode := _run([sys.executable, "-m", "twine", "check", *artifacts], root=root):
            return returncode
        if returncode := _run(
            [sys.executable, "scripts/validate_release_artifacts.py", str(artifact_dir)],
            root=root,
        ):
            return returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
