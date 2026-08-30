# SPDX-License-Identifier: Apache-2.0
"""SecuRedact-owned (managed) Google OAuth application configuration.

Normal customers connect to Google Workspace through a Google Cloud project and
OAuth client that **SecuRedact owns**. They never create their own Google Cloud
project, OAuth client, or type a client secret. This module is the single source
of truth for the managed (Desktop / Installed application) client id.

A Desktop/Installed OAuth ``client_id`` is public (not a secret). The supported
resolution order, least operationally fragile first, is:

1. the non-secret environment override ``SECUREDACT_GOOGLE_MANAGED_CLIENT_ID``
   (packaging / configuration may set this at build/policy time);
2. a package-compiled default (``MANAGED_GOOGLE_CLIENT_ID``).

No real Google credential is ever invented or committed here. When the managed
client id is not configured, :func:`assert_managed_client_configured` fails closed
with a clear, customer-safe message and normal mode NEVER falls back to prompting
the customer for a client id/secret.
"""

from __future__ import annotations

import os

# Non-secret environment override. This is the least operationally fragile source
# of truth and is what packaging/configuration should supply (e.g. baked into the
# released installer or provided by a configuration management policy).
SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV = "SECUREDACT_GOOGLE_MANAGED_CLIENT_ID"

# Package-compiled default. Intentionally empty: no real Google credential is
# invented or committed. Operators/packaging provide the public client id via the
# environment override above. A non-empty value here would be a placeholder only.
MANAGED_GOOGLE_CLIENT_ID: str = ""

# Clear, customer-safe failure used when the managed app is not configured. Kept as
# a single constant so the message is identical across the setup wizard, the
# machine-runtime bootstrap, and the CLI.
MANAGED_CLIENT_NOT_CONFIGURED_MSG = (
    "SecuRedact Google Workspace authorization is not yet configured for this build. "
    "The SecuRedact-managed Google OAuth application is unavailable in this build."
)

# UX labels that distinguish the normal (managed) path from the advanced/enterprise
# bring-your-own (BYO) path. Normal customers should never see OAuth client prompts.
NORMAL_GOOGLE_LABEL = "Connect Google Workspace"
BYO_GOOGLE_LABEL = "Use your own Google OAuth application"


def resolve_managed_client_id() -> str | None:
    """Return the SecuRedact-managed public Google client id, or ``None``.

    Resolution order: the ``SECUREDACT_GOOGLE_MANAGED_CLIENT_ID`` environment
    override, then the package-compiled default. A blank/whitespace value is
    treated as not configured. Never raises.
    """

    env_id = os.getenv(SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV)
    if env_id and env_id.strip():
        return env_id.strip()
    if MANAGED_GOOGLE_CLIENT_ID and MANAGED_GOOGLE_CLIENT_ID.strip():
        return MANAGED_GOOGLE_CLIENT_ID.strip()
    return None


def is_managed_client_configured() -> bool:
    """True only when a managed (owned) Google client id is available."""

    return resolve_managed_client_id() is not None


def assert_managed_client_configured() -> str:
    """Return the managed client id, or raise :class:`GoogleConfigError` (fail closed).

    The raised message is the exact customer-safe string; normal mode must never
    silently fall back to prompting the customer for an OAuth client id/secret.
    """

    client_id = resolve_managed_client_id()
    if not client_id:
        from .config import GoogleConfigError

        raise GoogleConfigError(MANAGED_CLIENT_NOT_CONFIGURED_MSG)
    return client_id
