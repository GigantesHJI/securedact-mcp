# SPDX-License-Identifier: Apache-2.0
"""Entitlement verification and caching (AGENT-007).

The control plane issues a signed EdDSA (Ed25519) JWT entitlement. The agent
verifies it locally against the published JWKS (``/.well-known/jwks.json``),
pinning the issuer to ``https://www.securedact.com`` and the audience to
``securedact-agent``. Verification is strict: algorithm must be ``EdDSA``, the
``kid`` must be present in the JWKS, and issuer/audience/exp/nbf are all checked.
The raw token is cached for offline grace so the agent can keep operating briefly
without the control plane. The agent never *uses* the entitlement to authorize
itself — that is the control plane's job at claim time; the local copy only
supports offline continuity and status reporting.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .client import ControlPlaneClient
from .errors import (
    ControlPlaneError,
    EntitlementError,
    EntitlementVerificationError,
    TransportError,
)

ENTITLEMENT_ISSUER = "https://www.securedact.com"
ENTITLEMENT_AUDIENCE = "securedact-agent"
ENTITLEMENT_REFRESH_INTERVAL_SECONDS = 86400
ENTITLEMENT_CLOCK_SKEW_SECONDS = 60
ENTITLEMENT_OFFLINE_GRACE_SECONDS = 7 * 86400
ENTITLEMENT_OFFLINE_GRACE_SECONDS_ENTERPRISE = 14 * 86400
ENTITLEMENT_JWKS_CACHE_SECONDS = 3600


def _b64url_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded)


def decode_eddsa_jwt(
    token: str,
    key: Ed25519PublicKey,
    *,
    issuer: str,
    audience: str,
    leeway: int = ENTITLEMENT_CLOCK_SKEW_SECONDS,
) -> dict[str, Any]:
    """Verify an EdDSA JWT and return its claims. Raises on any failure."""

    parts = token.split(".")
    if len(parts) != 3:
        raise EntitlementVerificationError("malformed entitlement token")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, UnicodeDecodeError) as exc:
        raise EntitlementVerificationError("entitlement token is not valid JSON") from exc

    if header.get("alg") != "EdDSA":
        raise EntitlementVerificationError("entitlement uses an unsupported algorithm")
    if not isinstance(payload, dict):
        raise EntitlementVerificationError("entitlement payload is not an object")

    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    try:
        key.verify(_b64url_decode(parts[2]), signing_input)
    except InvalidSignature as exc:
        raise EntitlementVerificationError("entitlement signature is invalid") from exc
    except Exception as exc:  # noqa: BLE001
        raise EntitlementVerificationError(f"entitlement signature failed: {exc}") from exc

    now = time.time()
    if "iss" in payload and payload["iss"] != issuer:
        raise EntitlementVerificationError("entitlement issuer mismatch")
    aud = payload.get("aud")
    if aud is None:
        raise EntitlementVerificationError("entitlement missing audience")
    if isinstance(aud, list):
        if audience not in aud:
            raise EntitlementVerificationError("entitlement audience mismatch")
    elif aud != audience:
        raise EntitlementVerificationError("entitlement audience mismatch")

    exp = payload.get("exp")
    if exp is not None:
        try:
            exp_f = float(exp)
        except (TypeError, ValueError) as exc:
            raise EntitlementVerificationError("entitlement exp is invalid") from exc
        if now > exp_f + leeway:
            raise EntitlementVerificationError("entitlement expired")
    nbf = payload.get("nbf")
    if nbf is not None:
        try:
            nbf_f = float(nbf)
        except (TypeError, ValueError) as exc:
            raise EntitlementVerificationError("entitlement nbf is invalid") from exc
        if now < nbf_f - leeway:
            raise EntitlementVerificationError("entitlement not yet valid")
    return payload


@dataclass(frozen=True, slots=True)
class Entitlement:
    """A verified entitlement token and its decoded timing claims."""

    raw: str
    claims: dict[str, Any]
    kid: str | None
    not_before: float | None
    expires_at: float | None
    issued_at: float


class JwksCache:
    """Caches and verifies control-plane signing keys by ``kid``."""

    def __init__(self, client: ControlPlaneClient, *, cache_ttl: int = ENTITLEMENT_JWKS_CACHE_SECONDS) -> None:
        self._client = client
        self._cache_ttl = cache_ttl
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._fetched_at: float = 0.0

    def get_key(self, kid: str) -> Ed25519PublicKey:
        if self._needs_refresh():
            self._refresh()
        key = self._keys.get(kid)
        if key is None:
            # Fall back to a forced refresh in case the kid rotated.
            self._refresh()
            key = self._keys.get(kid)
        if key is None:
            raise EntitlementVerificationError(f"no signing key for kid={kid}")
        return key

    def _needs_refresh(self) -> bool:
        if not self._keys:
            return True
        return (time.time() - self._fetched_at) > self._cache_ttl

    def _refresh(self) -> None:
        doc = self._client.get_jwks()
        keys = doc.get("keys")
        if not isinstance(keys, list):
            raise EntitlementVerificationError("jwks document missing keys")
        parsed: dict[str, Ed25519PublicKey] = {}
        for entry in keys:
            if not isinstance(entry, dict):
                continue
            if entry.get("kty") != "OKP" or entry.get("crv") != "Ed25519":
                continue
            if entry.get("alg") not in (None, "EdDSA"):
                continue
            kid = entry.get("kid")
            x = entry.get("x")
            if not kid or not x:
                continue
            try:
                parsed[str(kid)] = Ed25519PublicKey.from_public_bytes(_b64url_decode(str(x)))
            except Exception:  # noqa: BLE001
                continue
        if not parsed:
            raise EntitlementVerificationError("jwks contained no usable Ed25519 keys")
        self._keys = parsed
        self._fetched_at = time.time()


class EntitlementManager:
    """Owns entitlement activation, refresh, verification, and offline grace."""

    def __init__(
        self,
        client: ControlPlaneClient,
        *,
        enterprise: bool = False,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._client = client
        self._jwks = JwksCache(client)
        self._enterprise = enterprise
        self._clock = clock or time.time
        self._entitlement: Entitlement | None = None

    @property
    def current(self) -> Entitlement | None:
        return self._entitlement

    def activate(self) -> Entitlement:
        try:
            token = self._client.activate_entitlement()
        except (ControlPlaneError, TransportError) as exc:
            raise EntitlementError(f"entitlement activation failed: {exc}") from exc
        ent = self._verify(token)
        self._entitlement = ent
        return ent

    def refresh(self) -> Entitlement | None:
        try:
            token = self._client.refresh_entitlement()
        except ControlPlaneError as exc:  # offline / auth failure -> keep cached
            raise EntitlementError(f"entitlement refresh failed: {exc.message}") from exc
        except TransportError as exc:  # noqa: F821
            raise EntitlementError(f"entitlement refresh failed: {exc}") from exc
        ent = self._verify(token)
        self._entitlement = ent
        return ent

    def ensure_valid(self, *, force: bool = False) -> Entitlement:
        """Return a usable entitlement, refreshing online or using offline grace."""

        if not force and self._entitlement is not None and self._still_valid(self._entitlement):
            return self._entitlement
        try:
            refreshed = self.refresh()
        except EntitlementError:
            refreshed = None
        if refreshed is not None:
            return refreshed
        if self._entitlement is not None and self._within_grace(self._entitlement):
            return self._entitlement
        raise EntitlementError("no valid entitlement and refresh is unavailable")

    def _verify(self, token: str) -> Entitlement:
        header = _decode_header(token)
        kid = header.get("kid")
        if not kid:
            raise EntitlementVerificationError("entitlement missing kid")
        key = self._jwks.get_key(str(kid))
        claims = decode_eddsa_jwt(
            token, key, issuer=ENTITLEMENT_ISSUER, audience=ENTITLEMENT_AUDIENCE
        )
        now = self._clock()
        exp = _as_float(claims.get("exp"))
        nbf = _as_float(claims.get("nbf"))
        return Entitlement(
            raw=token,
            claims=claims,
            kid=str(kid),
            not_before=nbf,
            expires_at=exp,
            issued_at=now,
        )

    def _still_valid(self, ent: Entitlement) -> bool:
        exp = ent.expires_at
        if exp is None:
            return True
        return self._clock() <= exp + ENTITLEMENT_CLOCK_SKEW_SECONDS

    def _within_grace(self, ent: Entitlement) -> bool:
        if ent.expires_at is None:
            return True
        grace = (
            ENTITLEMENT_OFFLINE_GRACE_SECONDS_ENTERPRISE
            if self._enterprise
            else ENTITLEMENT_OFFLINE_GRACE_SECONDS
        )
        return self._clock() <= ent.expires_at + grace


def _decode_header(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise EntitlementVerificationError("malformed entitlement token")
    try:
        return json.loads(_b64url_decode(parts[0]))
    except (ValueError, UnicodeDecodeError) as exc:
        raise EntitlementVerificationError("entitlement header is invalid") from exc


def _as_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
