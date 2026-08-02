from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys
from pathlib import Path

from .runtime_environment import configure_managed_offline_environment


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--entrypoint", required=True)
    parser.add_argument("--cache-root", required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    entrypoint = Path(arguments.entrypoint).resolve()
    cache_root = Path(arguments.cache_root).resolve()
    configure_managed_offline_environment(cache_root)
    os.environ["PYTHONNOUSERSITE"] = "1"

    # Flair and Transformers may write informational messages while importing
    # and loading. They must never escape onto an MCP stdio channel.
    captured_stdout = io.StringIO()
    captured_stderr = io.StringIO()
    try:
        with (
            contextlib.redirect_stdout(captured_stdout),
            contextlib.redirect_stderr(captured_stderr),
        ):
            from flair.models.sequence_tagger_model import SequenceTagger

            SequenceTagger.load(entrypoint)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "failure_code": "contextual_model_offline_load_failed",
                    "exception_type": type(exc).__name__,
                }
            ),
            file=sys.stderr,
        )
        return 23
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
