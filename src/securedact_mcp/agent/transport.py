# SPDX-License-Identifier: Apache-2.0
"""HTTP transport for control-plane requests (AGENT-005).

A minimal, dependency-free transport built on :mod:`urllib`. It speaks only JSON,
retries transient failures with bounded backoff, and never logs tokens, headers,
or response bodies. All authentication is the caller's responsibility (the agent
credential is attached as a ``Bearer`` header by the client).
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class HTTPResponse:
    """A parsed control-plane response (body is ``None`` when not JSON)."""

    status: int
    body: dict[str, Any] | None
    raw_text: str


@dataclass(slots=True)
class RetryPolicy:
    """Bounded retry policy for transient transport failures."""

    max_attempts: int = 3
    backoff_base: float = 0.5
    retry_statuses: frozenset[int] = frozenset({429, 500, 502, 503, 504})
    retry_on_connect_error: bool = True


class TransportError(Exception):
    """Raised when the transport cannot complete a request after retries."""


def _backoff(attempt: int, base: float) -> float:
    return min(base * (2 ** (attempt - 1)), 8.0)


class HTTPTransport:
    """urllib-based JSON transport with bounded retries."""

    def __init__(self, *, timeout: float = 30.0, retry: RetryPolicy | None = None) -> None:
        self._timeout = timeout
        self._retry = retry or RetryPolicy()

    def post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        json_body: dict[str, Any] | None,
    ) -> HTTPResponse:
        payload = json.dumps(json_body or {}).encode("utf-8")
        last_exc: Exception | None = None
        for attempt in range(1, self._retry.max_attempts + 1):
            request = urllib.request.Request(  # noqa: S310  # URL is always a normalized https control-plane URL (see config.normalize_control_plane_url)
                url,
                data=payload,
                headers={**headers, "Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=self._timeout) as resp:  # noqa: S310
                    raw = resp.read().decode("utf-8", "replace")
                    return HTTPResponse(status=resp.status, body=_maybe_json(raw), raw_text=raw)
            except urllib.error.HTTPError as exc:  # non-2xx -> returned to caller
                raw = _safe_read(exc)
                return HTTPResponse(status=exc.code, body=_maybe_json(raw), raw_text=raw)
            except urllib.error.URLError as exc:  # transient network failure
                last_exc = exc
                if not self._retry.retry_on_connect_error:
                    break
            except Exception as exc:
                last_exc = exc
                if not self._retry.retry_on_connect_error:
                    break
            if attempt < self._retry.max_attempts:
                time.sleep(_backoff(attempt, self._retry.backoff_base))
        raise TransportError(f"request to {url} failed after retries: {last_exc}")


def _safe_read(exc: urllib.error.HTTPError) -> str:
    try:
        return exc.read().decode("utf-8", "replace")
    except Exception:
        return ""


def _maybe_json(raw: str) -> dict[str, Any] | None:
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None
