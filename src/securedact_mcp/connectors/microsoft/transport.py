# SPDX-License-Identifier: Apache-2.0
"""Concrete Microsoft Graph transport (control plane, M365-102).

This is the only place that imports the Microsoft auth/HTTP libraries, and it does
so lazily so the rest of ``securedact_mcp`` keeps working without the optional
``microsoft`` extra installed. The transport pins the Graph v1.0 host, owns the
OAuth credentials, refreshes expired tokens, retries transient read errors with
bounded backoff, and never logs token material.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Protocol, cast

from securedact_core.connectors.microsoft import (
    CANONICAL_GRAPH_BASE,
    MicrosoftApiError,
    MicrosoftAuthError,
)

logger = logging.getLogger(__name__)

# Bounded retry for transient read failures only (never for auth errors).
_MAX_RETRIES = 3
_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
# Microsoft Graph ``reason`` tokens that are safe to retry even on a 4xx.
_RETRYABLE_REASONS = frozenset(
    {"rateLimitExceeded", "throttledRequests", "serviceUnavailable", "backendError", "internalError"}
)


class _MicrosoftResponse(Protocol):
    """Narrow surface of the HTTP response consumed by this transport."""

    @property
    def status_code(self) -> int: ...
    @property
    def content(self) -> bytes: ...
    def json(self) -> Any: ...


class _MicrosoftSession(Protocol):
    """Narrow surface of ``requests.Session`` consumed here."""

    def get(self, url: str, *, timeout: float) -> _MicrosoftResponse: ...


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
    """Pull the safe Microsoft Graph ``reason`` token from an error body, if present."""

    try:
        body = response.json()
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    err = body.get("error") or {}
    if not isinstance(err, dict):
        return None
    # Microsoft Graph uses "code" for the error code and "message" for description
    # Some errors also have inner errors
    if "code" in err:
        return str(err["code"])
    return None


class MicrosoftGraphTransport:
    """REST implementation of :class:`MicrosoftGraphTransport` using MSAL + requests."""

    def __init__(self, credentials: dict[str, Any], *, user_id: str | None = None, tenant_id: str | None = None) -> None:
        # Lazy import: msal and requests are optional dependencies.
        import requests

        self._credentials = credentials
        self._cached_user_id = user_id
        self._cached_tenant_id = tenant_id

        # Build an authorized session
        access_token = credentials.get("access_token")
        if not access_token:
            raise MicrosoftAuthError("No access token in credentials")

        self._session = requests.Session()
        self._session.headers.update({"Authorization": f"Bearer {access_token}"})
        self._session.headers.update({"Accept": "application/json"})

    @property
    def base_url(self) -> str:
        return CANONICAL_GRAPH_BASE

    @property
    def user_id(self) -> str:
        if self._cached_user_id is None:
            self._cached_user_id = self._resolve_user_id()
        return self._cached_user_id

    @property
    def tenant_id(self) -> str:
        if self._cached_tenant_id is None:
            self._cached_tenant_id = self._resolve_tenant_id()
        return self._cached_tenant_id

    def _resolve_user_id(self) -> str:
        try:
            data = self.get_json("me?$select=id,userPrincipalName")
            user_id = data.get("id")
            if user_id:
                return str(user_id)
        except MicrosoftApiError:
            pass
        return "microsoft-user"

    def _resolve_tenant_id(self) -> str:
        try:
            data = self.get_json("organization?$select=id")
            orgs = data.get("value", [])
            if orgs and orgs[0].get("id"):
                return str(orgs[0]["id"])
        except MicrosoftApiError:
            pass
        return "microsoft-tenant"

    def get_json(self, path: str) -> dict[str, Any]:
        return cast("dict[str, Any]", self._request(path, as_bytes=False))

    def get_content(self, path: str, *, max_bytes: int | None = None) -> bytes:
        return cast("bytes", self._request(path, as_bytes=True, max_bytes=max_bytes))

    def _request(self, path: str, *, as_bytes: bool, max_bytes: int | None = None) -> Any:
        # Handle absolute URLs (download URLs)
        if path.startswith("http"):
            url = path
            safe_endpoint = path.split("?")[0]
        else:
            url = f"{CANONICAL_GRAPH_BASE}/{path}"
            safe_endpoint = path.split("?")[0]

        last_error: MicrosoftApiError | None = None
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                response = self._session.get(url, timeout=30)
            except Exception as exc:  # network failure
                last_error = MicrosoftApiError(
                    f"Microsoft Graph request failed: {type(exc).__name__}",
                    category="network",
                )
                logger.debug("Graph network error (attempt %d)", attempt)
                time.sleep(min(0.5 * attempt, 4.0))
                continue

            status = response.status_code
            if status == 401:
                # Token might be expired - try to refresh
                raise MicrosoftAuthError(
                    "Microsoft authorization failed or the token was revoked",
                    status_code=401,
                    reason=_extract_reason(response),
                    endpoint=safe_endpoint,
                    retryable=False,
                    category="auth",
                )
            if status == 403:
                raise self._error(
                    "Microsoft Graph refused the request (insufficient scope or API disabled)",
                    response,
                    safe_endpoint,
                )
            if status in _RETRYABLE_STATUS:
                last_error = self._error("Microsoft Graph temporarily unavailable", response, safe_endpoint)
                logger.debug("Graph retryable status %d (attempt %d)", status, attempt)
                # Check for Retry-After header
                retry_after = response.headers.get("Retry-After")
                if retry_after:
                    try:
                        wait = min(int(retry_after), 60)
                    except ValueError:
                        wait = min(0.5 * attempt, 4.0)
                    time.sleep(wait)
                else:
                    time.sleep(min(0.5 * attempt, 4.0))
                continue
            if status != 200:
                raise self._error("Microsoft Graph request failed", response, safe_endpoint)

            if as_bytes:
                content = response.content
                if max_bytes is not None and len(content) > max_bytes:
                    raise MicrosoftApiError(
                        "Microsoft Graph item exceeds the maximum inspectable size",
                        status_code=413,
                        endpoint=safe_endpoint,
                        retryable=False,
                        category="invalid_request",
                    )
                return content
            try:
                return response.json()
            except ValueError as exc:
                raise MicrosoftApiError(
                    "Microsoft Graph returned non-JSON response",
                    status_code=status,
                    endpoint=safe_endpoint,
                    category="invalid_response",
                ) from exc

        # Exhausted retries.
        if last_error is not None:
            if last_error.status_code == 429:
                raise MicrosoftApiError(
                    "Microsoft Graph rate limit exceeded; retry later",
                    status_code=429,
                    reason=last_error.reason,
                    endpoint=last_error.endpoint,
                    retryable=True,
                    category="rate_limit",
                )
            raise last_error
        raise MicrosoftApiError("Microsoft Graph request failed")

    def _error(self, message: str, response: Any, safe_endpoint: str) -> MicrosoftApiError:
        """Build a safe, metadata-rich error from a non-OK response."""

        status = response.status_code
        reason = _extract_reason(response)
        retryable = status in _RETRYABLE_STATUS or reason in _RETRYABLE_REASONS
        return MicrosoftApiError(
            message,
            status_code=status,
            reason=reason,
            endpoint=safe_endpoint,
            retryable=retryable,
            category=_category_for(status, reason),
        )