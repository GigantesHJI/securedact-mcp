from __future__ import annotations

import base64
import sys
from pathlib import Path

from securedact_enforced.adapter import EnforcementOutcome, EnforcementResult
from securedact_enforced.claude_runtime import _serve


class _AllowingEnforcer:
    """Minimal enforcer for authenticated runtime lifecycle tests."""

    @staticmethod
    def inspect_text(_text: str) -> EnforcementResult:
        return EnforcementResult(EnforcementOutcome.ALLOW)


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        return 2
    state_file, encoded_token, session_digest = argv
    try:
        token = base64.b64decode(encoded_token.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError):
        return 2
    _serve(Path(state_file), token, session_digest, _AllowingEnforcer)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
