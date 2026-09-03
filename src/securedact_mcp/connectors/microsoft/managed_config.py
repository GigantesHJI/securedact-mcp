# SPDX-License-Identifier: Apache-2.0
"""Authoritative SecuRedact-managed Microsoft Entra public-client application configuration.

This module is the single source of truth for the Microsoft Entra public-client
(Desktop/Installed) application that *SecuRedact owns and operates* on behalf
of normal customers. It is **product configuration**, not customer OAuth state:

* the managed client id is public by design;
* **no client secret exists** — this is a public-client / Desktop application
  that uses PKCE for the token exchange;
* the managed application is registered as a multi-tenant public client in
  SecuRedact's Entra tenant;
* customer OAuth access/refresh tokens remain local and encrypted on the
  customer machine (see ``securedact_mcp.connectors.microsoft.storage``).

Normal customers therefore need no Entra app registration, no client ID prompt,
no client secret prompt, and no tenant ID prompt. The packaged values below are
the default production source of truth.

Resolution precedence (see :mod:`securedact_mcp.connectors.microsoft.managed`):

1. explicit DEV/OPS override environment variables
   ``SECUREDACT_MICROSOFT_MANAGED_CLIENT_ID``;
2. the packaged value in this module;
3. fail closed (only when both are absent -- e.g. a build that deliberately
   stripped product configuration).
"""

from __future__ import annotations

from dataclasses import dataclass

# SecuRedact-managed Microsoft Entra public-client (Desktop/Installed)
# OAuth application. Public product configuration shipped with the package.
# This is a multi-tenant public-client (Desktop/Installed) application
# registered in SecuRedact's Entra tenant.
# NO client secret — this is a public-client / Desktop app using PKCE.
MANAGED_MICROSOFT_CLIENT_ID = "187e325c-7095-429c-9cb6-4feafda2d18d"

# Standard Microsoft Entra public-client endpoints.
# The authority template uses the tenant identifier; for multi-tenant the
# "common" endpoint is used which allows any organizational account.
MANAGED_MICROSOFT_AUTHORITY_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}"
MANAGED_MICROSOFT_COMMON_AUTHORITY = "https://login.microsoftonline.com/common"

# Microsoft Graph API endpoint
MANAGED_MICROSOFT_GRAPH_ENDPOINT = "https://graph.microsoft.com"

# The redirect URI registered for the managed public-client application.
# Must match the redirect URI registered in the Entra app registration.
MANAGED_MICROSOFT_REDIRECT_URI = "http://localhost"

# Microsoft Entra application (client) metadata (informational only).
MANAGED_MICROSOFT_APP_DISPLAY_NAME = "SecuRedact Managed Connector"
MANAGED_MICROSOFT_TENANT_ID = (
    "securedact"  # Informational: the tenant that owns the app registration
)


@dataclass(frozen=True, slots=True)
class ManagedMicrosoftConfig:
    """Structured view of the SecuRedact-managed Microsoft Entra public-client app."""

    client_id: str
    authority: str
    redirect_uri: str
    graph_endpoint: str = MANAGED_MICROSOFT_GRAPH_ENDPOINT
    display_name: str = MANAGED_MICROSOFT_APP_DISPLAY_NAME
    tenant_id: str = MANAGED_MICROSOFT_TENANT_ID


def packaged_managed_microsoft_config() -> ManagedMicrosoftConfig:
    """Return the packaged (default) SecuRedact-managed Microsoft Entra config.

    Uses the "common" multi-tenant authority by default, which allows any
    organizational account to sign in. The application is registered as
    multi-tenant in SecuRedact's Entra tenant.
    """

    return ManagedMicrosoftConfig(
        client_id=MANAGED_MICROSOFT_CLIENT_ID,
        authority=MANAGED_MICROSOFT_COMMON_AUTHORITY,
        redirect_uri=MANAGED_MICROSOFT_REDIRECT_URI,
    )
