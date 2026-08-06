"""Run a repository-controlled network command with bounded transient-only retries."""

from __future__ import annotations

import argparse
import random
import subprocess
import sys
import time
from collections.abc import Sequence

TRANSIENT_MARKERS = (
    "timed out",
    "timeout",
    "connection reset",
    "connection refused",
    "connection error",
    "tcp connect error",
    "failed to establish a new connection",
    "service unavailable",
    "temporary failure",
    "temporarily unavailable",
    "name resolution",
    "remote end closed",
    "http 429",
    "status code 429",
    "http 500",
    "http 502",
    "http 503",
    "http 504",
    "status code 500",
    "status code 502",
    "status code 503",
    "status code 504",
)
NON_RETRYABLE_MARKERS = (
    "401 unauthorized",
    "403 forbidden",
    "authentication failed",
    "invalid token",
    "permission denied",
    "hash mismatch",
    "digest mismatch",
    "checksum mismatch",
    "license",
    "test failed",
    "assertion failed",
)


def is_transient(output: str) -> bool:
    lowered = output.casefold()
    return not any(marker in lowered for marker in NON_RETRYABLE_MARKERS) and any(
        marker in lowered for marker in TRANSIENT_MARKERS
    )


def run_with_retry(
    command: Sequence[str],
    *,
    attempts: int,
    attempt_timeout: float,
    overall_timeout: float,
) -> int:
    if not command:
        raise ValueError("a command is required after --")
    started = time.monotonic()
    secure_random = random.SystemRandom()
    for attempt in range(1, attempts + 1):
        remaining = overall_timeout - (time.monotonic() - started)
        if remaining <= 0:
            print("network command exceeded its overall timeout", file=sys.stderr)
            return 124
        try:
            result = subprocess.run(  # noqa: S603 - argv is explicit and shell is disabled
                list(command),
                check=False,
                capture_output=True,
                text=True,
                timeout=min(attempt_timeout, remaining),
            )
            sys.stdout.write(result.stdout)
            sys.stderr.write(result.stderr)
            if result.returncode == 0:
                return 0
            combined = f"{result.stdout}\n{result.stderr}"
            if attempt == attempts or not is_transient(combined):
                return result.returncode
        except subprocess.TimeoutExpired as exc:
            if exc.stdout:
                sys.stdout.write(str(exc.stdout))
            if exc.stderr:
                sys.stderr.write(str(exc.stderr))
            if attempt == attempts:
                return 124
        delay = min(2 ** (attempt - 1), 8) + secure_random.uniform(0, 0.5)
        if time.monotonic() - started + delay >= overall_timeout:
            return 124
        print(f"transient network failure; bounded retry {attempt + 1}/{attempts}", file=sys.stderr)
        time.sleep(delay)
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attempts", type=int, default=3, choices=range(1, 6))
    parser.add_argument("--attempt-timeout", type=float, default=180)
    parser.add_argument("--overall-timeout", type=float, default=420)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args(argv)
    command = arguments.command[1:] if arguments.command[:1] == ["--"] else arguments.command
    return run_with_retry(
        command,
        attempts=arguments.attempts,
        attempt_timeout=arguments.attempt_timeout,
        overall_timeout=arguments.overall_timeout,
    )


if __name__ == "__main__":
    raise SystemExit(main())
