# SPDX-License-Identifier: Apache-2.0
"""Safe logging helpers (AGENT-014).

Centralizes secret scrubbing so logs, exceptions, and diagnostics never leak the
agent credential, lease secrets, registration tokens, Google OAuth tokens, or
raw detected content. All modules should route free-form messages through
:func:`scrub` before logging.
"""

from __future__ import annotations

import re

# Matches the structured credential/registration/lease token shapes and long
# base64url secrets. Deliberately conservative: anything that looks like a
# ``sra_``/``srr_``/``sl_`` bearer secret is redacted.
_SECRET_RE = re.compile(
    r"(sra_[A-Za-z0-9_]+_[A-Za-z0-9_\-]+|"
    r"srr_[A-Za-z0-9_]+_[A-Za-z0-9_\-]+|"
    r"sl_[A-Za-z0-9]+)",
    re.IGNORECASE,
)

_BEARER_RE = re.compile(r"(Bearer\s+)\S+", re.IGNORECASE)
_AUTH_RE = re.compile(r"(Authorization\s*[:=]\s*)\S+", re.IGNORECASE)

# Google OAuth access tokens (``ya29.`` prefix) and the JWT-style ``1//`` prefix.
_OAUTH_RE = re.compile(r"(ya29\.[A-Za-z0-9_\-]+|1//[A-Za-z0-9._\-]+)", re.IGNORECASE)

# Token-style assignments such as ``refresh_token=rt_xyz`` or
# ``access_token=...`` / ``entitlement=eyJ...`` / ``lease_secret=...``.
_TOKEN_ASSIGN_RE = re.compile(
    r"((?:refresh_token|access_token|id_token|entitlement|lease_secret|"
    r"registration_token)\s*=\s*)\S+",
    re.IGNORECASE,
)


def scrub(value: str) -> str:
    """Return ``value`` with credential/secret material redacted."""

    if not value:
        return value
    text = _BEARER_RE.sub(r"\1<redacted>", value)
    text = _AUTH_RE.sub(r"\1<redacted>", text)
    text = _OAUTH_RE.sub("<redacted-oauth>", text)
    text = _TOKEN_ASSIGN_RE.sub(r"\1<redacted>", text)
    text = _SECRET_RE.sub("<redacted-credential>", text)
    return text


def safe_repr(obj: object) -> str:
    """Redact secrets from a generic object representation before logging."""

    return scrub(repr(obj))
