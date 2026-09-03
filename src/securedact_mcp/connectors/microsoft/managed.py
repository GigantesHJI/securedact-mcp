# SPDX-License-Identifier: Apache-2.0
"""Resolver for the SecuRedact-managed Microsoft Entra public-client application.

Provides a single authoritative source for the managed Microsoft Entra public-client
application configuration. Mirrors the Google managed-app pattern.

Resolution precedence (public API functions):

1. Explicit DEV/OPS override environment variable
   ``SECUREDACT_MICROSOFT_MANAGED_CLIENT_ID``;
2. The packaged value in :mod:`securedact_mcp.connectors.microsoft.managed_config`;
3. Fail closed (only when both are absent -- e.g. a build that deliberately
   stripped product configuration).

This module intentionally does **not** provide a client secret. The managed
Microsoft Entra application is a public-client (Desktop/Installed) application
that uses PKCE for the token exchange. No client secret is required or used.
"""

from __future__ import annotations

import os
from typing import Any

from .managed_config import (
    MANAGED_MICROSOFT_CLIENT_ID,
    ManagedMicrosoftConfig,
    packaged_managed_microsoft_config,
)

# Environment variable for overriding the managed client id (non-secret,
# public configuration). Used only in CI/testing/enterprise override scenarios.
MANAGED_MICROSOFT_CLIENT_ID_ENV = "SECUREDACT_MICROSOFT_MANAGED_CLIENT_ID"


def _env_override_client_id() -> str | None:
    """Return the managed client id from environment override if set."""
    return os.getenv(MANAGED_MICROSOFT_CLIENT_ID_ENV)


def resolve_managed_microsoft_client_id() -> str:
    """Resolve the managed Microsoft Entra public-client application ID.

    Returns the managed client id following the precedence:
    1. ``SECUREDACT_MICROSOFT_MANAGED_CLIENT_ID`` environment variable;
    2. The packaged value in :data:`MANAGED_MICROSOFT_CLIENT_ID`.

    Raises:
        RuntimeError: If neither the environment override nor the packaged
            value is available (build stripped product configuration).
    """

    # 1. Environment override (CI/testing/enterprise override)
    env_override = _env_override_client_id()
    if env_override:
        return env_override

    # 2. Packaged value (the normal production path)
    if MANAGED_MICROSOFT_CLIENT_ID:
        return MANAGED_MICROSOFT_CLIENT_ID

    # 3. Fail closed — product configuration is missing
    raise RuntimeError(
        "SecuRedact-managed Microsoft Entra client id is not available. "
        "Either set SECUREDACT_MICROSOFT_MANAGED_CLIENT_ID environment variable "
        "or ensure the package includes the managed Microsoft config."
    )


def get_managed_microsoft_config() -> Any:
    """Return the managed Microsoft Entra public-client configuration.

    Uses the resolved client id with the default multi-tenant authority and
    the registered redirect URI. No client secret is included or required.

    Returns:
        A :class:`ManagedMicrosoftConfig` with the resolved client id,
        the "common" multi-tenant authority, and the registered redirect URI.

    Raises:
        RuntimeError: If the managed client id cannot be resolved.
    """

    client_id = resolve_managed_microsoft_client_id()

    # The managed app is registered as multi-tenant with the "common" endpoint
    # and the redirect URI registered in the Entra app registration.
    # This mirrors the Google managed app pattern but with Microsoft-specific
    # endpoints and no client secret.

    base = packaged_managed_microsoft_config()
    return ManagedMicrosoftConfig(
        client_id=client_id,
        authority=base.authority,
        redirect_uri=base.redirect_uri,
        graph_endpoint=base.graph_endpoint,
        display_name=base.display_name,
        tenant_id=base.tenant_id,
    )


def is_managed_microsoft_available() -> bool:
    """Check if the managed Microsoft Entra client id is available.

    Used for feature detection without raising exceptions.

    Returns:
        True if the managed client id can be resolved (packaged or via env
        override), False otherwise.
    """

    try:
        resolve_managed_microsoft_client_id()
        return True
    except RuntimeError:
        return False
