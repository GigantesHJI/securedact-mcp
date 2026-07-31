"""Run the release-critical privacy suite only when the real server tests exist."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    server = root / "src" / "securedact_mcp" / "server.py"
    privacy_tests = root / "tests" / "privacy"

    missing: list[str] = []
    if not server.exists():
        missing.append("src/securedact_mcp/server.py")
    if not privacy_tests.is_dir() or not any(privacy_tests.glob("test_*.py")):
        missing.append("tests/privacy/test_*.py")

    if missing:
        print(
            "Privacy release tests cannot run; reviewed implementation artifacts are missing:",
            file=sys.stderr,
        )
        for item in missing:
            print(f"- {item}", file=sys.stderr)
        print("This is a release blocker, not a skipped or passing test.", file=sys.stderr)
        return 2

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/privacy",
            "tests/unit/test_mcp_tools.py",
            "tests/integration/test_stdio_server.py",
        ],
        cwd=root,
        check=False,
    )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
