# SPDX-License-Identifier: Apache-2.0
"""Shared fakes and signing helpers for managed-agent tests (AGENT-TEST).

These are support modules (not collected as tests). They let the agent be
exercised end-to-end without a real control plane or Google SDK.
"""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Callable
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from securedact_core.connectors.scan import (
    ScanError,
    ScanErrorCode,
    ScanResult,
    ScanSeverity,
    ScanStatus,
)
from securedact_mcp.agent.transport import HTTPResponse


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def public_key_to_jwk(pub: Ed25519PublicKey, *, kid: str) -> dict[str, Any]:
    raw = pub.public_bytes_raw()
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "kid": kid,
        "x": _b64url(raw),
    }


def encode_eddsa_jwt(
    priv: Ed25519PrivateKey,
    *,
    kid: str,
    issuer: str,
    audience: str,
    exp: float | None = None,
    nbf: float | None = None,
    issued_at: float | None = None,
    extra: dict[str, Any] | None = None,
) -> str:
    header = {"alg": "EdDSA", "kid": kid, "typ": "JWT"}
    now = issued_at if issued_at is not None else time.time()
    payload: dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "iat": int(now),
    }
    if exp is not None:
        payload["exp"] = int(exp)
    if nbf is not None:
        payload["nbf"] = int(nbf)
    if extra:
        payload.update(extra)
    signing_input = f"{_b64url(json.dumps(header, separators=(',', ':')).encode())}.{_b64url(json.dumps(payload, separators=(',', ':')).encode())}".encode()
    sig = priv.sign(signing_input)
    return f"{signing_input.decode()}.{_b64url(sig)}"


def strict_external_ai_snapshot() -> dict[str, Any]:
    """Return a claim policy snapshot whose label resolves to strict_external_ai."""

    return {
        "policy_version_id": None,
        "version": 0,
        "content": {
            "version": 1,
            "label": "strict_external_ai",
            "detection": {"mode": "all", "categories": ["email"]},
            "severity": {"escalate_on_secret": True, "escalate_on_special_category": True},
            "review": {"required_when": "findings"},
            "actions": {"allow": True, "redact": True, "review": True, "block": False},
        },
        "content_digest": "unused-by-agent",
    }


def fake_claim(
    *,
    job_id: str = "job-1",
    platform: str = "google_workspace",
    integration_id: str = "int-1",
    target_type: str = "resource",
    target_ref: str = "file-abc",
    lease_secret: str = "lease-secret-1",  # noqa: S107  # intentional fake test-only lease secret
    lease_generation: int = 1,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "job_id": job_id,
        "schedule_id": "sched-1",
        "organization_id": "org-1",
        "platform": platform,
        "integration_id": integration_id,
        "target_type": target_type,
        "target_ref": target_ref,
        "attempt": 1,
        "max_attempts": 3,
        "lease_id": "sl_abc",
        "lease_secret": lease_secret,
        "lease_generation": lease_generation,
        "lease_expires_at": (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 1800))),
        "policy": policy or strict_external_ai_snapshot(),
    }


class FakeTransport:
    """Scriptable transport that records requests and returns canned responses."""

    def __init__(
        self,
        responder: Callable[[str, dict[str, str], dict[str, Any]], HTTPResponse] | None = None,
    ) -> None:
        self.responder = responder
        self.requests: list[tuple[str, dict[str, str], dict[str, Any]]] = []
        self.get_requests: list[tuple[str, dict[str, str]]] = []

    def post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        json_body: dict[str, Any] | None,
    ) -> HTTPResponse:
        body = json_body or {}
        self.requests.append((url, dict(headers), body))
        if self.responder is not None:
            return self.responder(url, headers, body)
        return HTTPResponse(status=200, body={}, raw_text="")

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str],
    ) -> HTTPResponse:
        self.get_requests.append((url, dict(headers)))
        if self.responder is not None:
            # The GET responder contract ignores the (absent) body.
            return self.responder(url, headers, {})
        return HTTPResponse(status=200, body={}, raw_text="")

    def last_request(self) -> tuple[str, dict[str, str], dict[str, Any]]:
        return self.requests[-1]


def scan_result_with(
    *,
    status: ScanStatus = ScanStatus.COMPLETED,
    severity: ScanSeverity = ScanSeverity.NONE,
    counts: dict[str, int] | None = None,
    requires_review: bool = False,
    error_code: ScanErrorCode | None = None,
) -> ScanResult:
    error = ScanError(code=error_code, message="test error") if error_code is not None else None
    return ScanResult(
        status=status,
        severity=severity,
        resource_id="file-1",
        platform="google_workspace",
        org_id="google",
        tenant_id="t",
        integration_id="int-1",
        categories=list((counts or {}).keys()),
        counts=counts or {},
        findings=[],
        policy_decision=None,
        supported_action="none",
        redaction_available=False,
        requires_review=requires_review,
        warnings=[],
        error=error,
        scan_metadata={},
        correlation_id=None,
    )


class FakeScanProvider:
    """Returns a fixed list of ScanResults regardless of target (test double)."""

    def __init__(self, results: list[ScanResult], *, error: Exception | None = None) -> None:
        self.results = results
        self.error = error
        self.calls: list[Any] = []

    def scan(
        self, target: Any, context: Any, engine: Any, *, heartbeat: Callable[[], None] | None = None
    ) -> list[ScanResult]:
        self.calls.append(target)
        if self.error is not None:
            raise self.error
        if heartbeat is not None:
            heartbeat()
        return list(self.results)
