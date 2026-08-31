# SPDX-License-Identifier: Apache-2.0
"""Authoritative SecuRedact-managed Google Desktop OAuth application configuration.

This module is the single source of truth for the Google OAuth client that
*SecuRedact owns and operates* on behalf of normal customers: the "managed"
Google Desktop / Installed application. It is **product configuration**, not
customer OAuth state:

* the managed client id is public by design;
* the managed Desktop client secret is published here as open-source package
  configuration -- it is SecuRedact-managed application configuration, *not* a
  customer secret and *not* a customer OAuth token;
* customer OAuth access/refresh tokens remain local and encrypted on the
  customer machine (see ``securedact_mcp.connectors.google.storage``).

Normal customers therefore need no Google Cloud project, no OAuth client id
prompt, and no OAuth client secret prompt. The packaged values below are the
default production source of truth.

Resolution precedence (see
``securedact_mcp.connectors.google.managed``):

1. explicit DEV/OPS override environment variables
   ``SECUREDACT_GOOGLE_MANAGED_CLIENT_ID`` /
   ``SECUREDACT_GOOGLE_MANAGED_CLIENT_SECRET``;
2. the packaged values in this module;
3. fail closed (only when both are absent -- e.g. a build that deliberately
   stripped product configuration).
"""

from __future__ import annotations

from dataclasses import dataclass

# SecuRedact-managed Google Desktop (Installed) OAuth application.
# Public product configuration shipped with the package.
MANAGED_GOOGLE_CLIENT_ID = (
    "905356230572-6umo605o58i25iom0aincloj85hk61n3.apps.googleusercontent.com"
)

# Google-issued Desktop client secret for the managed application. Published as
# open-source package configuration: it is SecuRedact-managed application
# configuration, not a customer secret and not a customer OAuth token. It is
# consumed only inside the local token exchange, never stored outside the local
# machine, never logged, never placed on argv, and never sent to the control
# plane. Google's Desktop OAuth token endpoint for this client requires it
# (a missing value is rejected with ``invalid_request`` / "client_secret is
# missing").
MANAGED_GOOGLE_CLIENT_SECRET = "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"  # noqa: S105 - public product config, not a customer secret

# Standard Google Desktop/Installed application endpoints.
MANAGED_GOOGLE_AUTH_URI = "https://accounts.google.com/o/oauth2/auth"
MANAGED_GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"  # noqa: S105 - public token endpoint URL, not a secret

# Google Cloud project that owns the managed OAuth client (informational only;
# not used for token exchange and not a customer secret).
MANAGED_GOOGLE_PROJECT_ID = "securedact-connector-test"


@dataclass(frozen=True, slots=True)
class ManagedGoogleConfig:
    """Structured view of the SecuRedact-managed Google Desktop OAuth app."""

    client_id: str
    client_secret: str
    auth_uri: str = MANAGED_GOOGLE_AUTH_URI
    token_uri: str = MANAGED_GOOGLE_TOKEN_URI
    project_id: str | None = MANAGED_GOOGLE_PROJECT_ID


def packaged_managed_google_config() -> ManagedGoogleConfig:
    """Return the packaged (default) SecuRedact-managed Google Desktop config."""

    return ManagedGoogleConfig(
        client_id=MANAGED_GOOGLE_CLIENT_ID,
        client_secret=MANAGED_GOOGLE_CLIENT_SECRET,
    )
