# SPDX-License-Identifier: Apache-2.0
"""Concrete Google Drive transport (control plane, GWS-110).

This is the only place that imports the Google auth/HTTP libraries, and it does
so lazily so the rest of ``securedact_mcp`` (and the whole MCP server) keeps
working without the optional ``google`` extra installed. The transport pins the
Drive v3 host, owns the OAuth credentials, refreshes expired tokens, retries
transient read errors with bounded backoff, and never logs token material.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any, Protocol, cast

from securedact_core.connectors.google import (
    CANONICAL_DRIVE_BASE,
    GoogleApiError,
    GoogleAuthError,
)

logger = logging.getLogger(__name__)

# Bounded retry for transient read failures only (never for auth errors).
_MAX_RETRIES = 3
_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
# Google ``reason`` tokens that are safe to retry even on a 4xx.
_RETRYABLE_REASONS = frozenset(
    {"rateLimitExceeded", "userRateLimitExceeded", "backendError", "internalError"}
)


class _GoogleResponse(Protocol):
    """Narrow surface of the HTTP response consumed by this transport."""

    @property
    def status_code(self) -> int: ...
    @property
    def content(self) -> bytes: ...
    def json(self) -> Any: ...


class _GoogleSession(Protocol):
    """Narrow surface of ``google.auth.transport.requests.AuthorizedSession`` consumed here."""

    def get(self, url: str, *, timeout: float) -> _GoogleResponse: ...


def _category_for(status: int | None, reason: str | None) -> str:
    if status == 401:
        return "auth"
    if status == 403:
        return "permission"
    if status == 400:
        return "invalid_request"
    if status == 404:
        return "not_found"
    if status == 429:
        return "rate_limit"
    if status is not None and status >= 500:
        return "server"
    if reason in _RETRYABLE_REASONS:
        return "transient"
    return "unknown"


def _extract_reason(response: Any) -> str | None:
    """Pull the safe Google ``reason`` token from an error body, if present.

    Only the short enum ``reason`` is read (e.g. ``invalidParameter``); full
    error messages and any response bodies are deliberately ignored so no token,
    header, or secret can leak through diagnostics.
    """

    try:
        body = response.json()
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    err = body.get("error") or {}
    if not isinstance(err, dict):
        return None
    errors = err.get("errors") or []
    if errors and isinstance(errors[0], dict) and errors[0].get("reason"):
        return str(errors[0]["reason"])
    if err.get("reason"):
        return str(err["reason"])
    return None


class GoogleApiTransport:
    """REST implementation of :class:`GoogleDriveTransport` using google-auth."""

    def __init__(self, credentials: Any, *, user_id: str | None = None) -> None:
        # Lazy import: google is an optional dependency.
        from google.auth.transport.requests import AuthorizedSession

        self._credentials = credentials
        # Narrow typed boundary over the optional, untyped third-party ctor so
        # strict mypy is satisfied whether or not google-auth is installed.
        session_ctor = cast("Callable[[Any], _GoogleSession]", AuthorizedSession)
        self._session: _GoogleSession = session_ctor(credentials)
        self._cached_user_id = user_id

    @property
    def base_url(self) -> str:
        return CANONICAL_DRIVE_BASE

    @property
    def user_id(self) -> str:
        if self._cached_user_id is None:
            self._cached_user_id = self._resolve_user_id()
        return self._cached_user_id

    def _resolve_user_id(self) -> str:
        try:
            data = self.get_json("about?fields=user(permissionId,emailAddress)")
            user = data.get("user") or {}
            pid = user.get("permissionId")
            if pid:
                return str(pid)
        except GoogleApiError:
            pass
        return "google-user"

    def get_json(self, path: str) -> dict[str, Any]:
        return cast("dict[str, Any]", self._request(path, as_bytes=False))

    def get_content(self, path: str, *, max_bytes: int | None = None) -> bytes:
        return cast("bytes", self._request(path, as_bytes=True, max_bytes=max_bytes))

    def _request(self, path: str, *, as_bytes: bool, max_bytes: int | None = None) -> Any:
        url = f"{CANONICAL_DRIVE_BASE}/{path}"
        # Strip the query string so only the safe endpoint path is reported.
        safe_endpoint = path.split("?")[0]
        last_error: GoogleApiError | None = None
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                response = self._session.get(url, timeout=30)
            except Exception as exc:  # network failure
                last_error = GoogleApiError(
                    f"Google request failed: {type(exc).__name__}",
                    category="network",
                )
                logger.debug("Google network error (attempt %d)", attempt)
                time.sleep(min(0.5 * attempt, 4.0))
                continue

            status = response.status_code
            if status == 401:
                raise GoogleAuthError(
                    "Google authorization failed or the token was revoked",
                    status_code=401,
                    reason=_extract_reason(response),
                    endpoint=safe_endpoint,
                    retryable=False,
                    category="auth",
                )
            if status == 403:
                raise self._error(
                    "Google refused the request (insufficient scope or API disabled)",
                    response,
                    safe_endpoint,
                )
            if status in _RETRYABLE_STATUS:
                last_error = self._error("Google temporarily unavailable", response, safe_endpoint)
                logger.debug("Google retryable status %d (attempt %d)", status, attempt)
                time.sleep(min(0.5 * attempt, 4.0))
                continue
            if status != 200:
                raise self._error("Google Drive request failed", response, safe_endpoint)

            if as_bytes:
                content = response.content
                if max_bytes is not None and len(content) > max_bytes:
                    raise GoogleApiError(
                        "Google Drive item exceeds the maximum inspectable size",
                        status_code=413,
                        endpoint=safe_endpoint,
                        retryable=False,
                        category="invalid_request",
                    )
                return content
            try:
                return response.json()
            except ValueError as exc:
                raise GoogleApiError(
                    "Google returned non-JSON response",
                    status_code=status,
                    endpoint=safe_endpoint,
                    category="invalid_response",
                ) from exc

        # Exhausted retries.
        if last_error is not None:
            # A 429 at the last attempt becomes a clean rate-limited error.
            if last_error.status_code == 429:
                raise GoogleApiError(
                    "Google rate limit exceeded; retry later",
                    status_code=429,
                    reason=last_error.reason,
                    endpoint=last_error.endpoint,
                    retryable=True,
                    category="rate_limit",
                )
            raise last_error
        raise GoogleApiError("Google Drive request failed")

    def _error(self, message: str, response: Any, safe_endpoint: str) -> GoogleApiError:
        """Build a safe, metadata-rich error from a non-OK response."""

        status = response.status_code
        reason = _extract_reason(response)
        retryable = status in _RETRYABLE_STATUS or reason in _RETRYABLE_REASONS
        return GoogleApiError(
            message,
            status_code=status,
            reason=reason,
            endpoint=safe_endpoint,
            retryable=retryable,
            category=_category_for(status, reason),
        )
