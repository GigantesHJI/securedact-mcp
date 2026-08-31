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
 2. the packaged default in
    :mod:`securedact_mcp.connectors.google.managed_config`
    (``MANAGED_GOOGLE_CLIENT_ID``), which is the shipped production source of truth.

The real SecuRedact-managed client id and Desktop client secret are published as
open-source product configuration in
:mod:`securedact_mcp.connectors.google.managed_config` (they are SecuRedact-managed
application configuration, not customer secrets and not customer OAuth tokens).
When neither the env override nor the packaged default is present,
:func:`assert_managed_client_configured` fails closed with a clear, customer-safe
message and normal mode NEVER falls back to prompting the customer for a client
id/secret.
"""

from __future__ import annotations

import os

from . import managed_config

# Non-secret environment override for the SecuRedact-managed (owned) Google OAuth
# *client id*. This is the least operationally fragile source of truth and is what
# packaging/configuration should supply (e.g. baked into the released installer or
# provided by a configuration management policy). A client id is public by design.
# When unset, the packaged default in :mod:`.managed_config` is used.
SECUREDACT_GOOGLE_MANAGED_CLIENT_ID_ENV = "SECUREDACT_GOOGLE_MANAGED_CLIENT_ID"

# Non-secret environment override for the SecuRedact-managed Desktop OAuth *client
# secret*. This is **SecuRedact-managed application configuration**, not a customer
# secret and not a customer OAuth token: normal customers never see, type, or own
# it. It is consumed only inside the local token exchange and is never stored
# outside the local machine, never logged, never placed on argv, and never sent to
# the control plane. Google's Desktop OAuth token endpoint for this client requires
# it (a missing value is rejected with ``invalid_request`` / "client_secret is
# missing"), so it must be configured before the browser authorization begins. When
# unset, the packaged default in :mod:`.managed_config` is used.
SECUREDACT_GOOGLE_MANAGED_CLIENT_SECRET_ENV = "SECUREDACT_GOOGLE_MANAGED_CLIENT_SECRET"  # noqa: S105 - env name, not a secret

# Re-export of the packaged default so existing callers that read this attribute
# continue to work. The canonical value lives in :mod:`.managed_config`; the
# resolvers below read it from there and apply the environment override on top.
MANAGED_GOOGLE_CLIENT_ID: str = managed_config.MANAGED_GOOGLE_CLIENT_ID

# Clear, customer-safe failure used when the managed app is not configured. Kept as
# a single constant so the message is identical across the setup wizard, the
# machine-runtime bootstrap, and the CLI. This only fires in a build that has no
# managed app configured at all (neither env override nor packaged default); a
# normal released build always has the packaged default, so normal customers never
# see this. It intentionally does NOT instruct normal customers to create a Google
# Cloud project, set a machine environment variable, or paste OAuth credentials --
# those are packaging/supply concerns or advanced/enterprise (BYO) choices.
MANAGED_CLIENT_NOT_CONFIGURED_MSG = (
    "SecuRedact Google Workspace authorization is not available in this build: the "
    "SecuRedact-managed Google OAuth application is not configured. This is a "
    "packaging/supply issue, not something a customer configures. Install a released "
    "SecuRedact build, or pass --google-byo to use your own Google Cloud OAuth app "
    "(advanced/enterprise)."
)

# Clear, customer-safe failure used when the managed app id is configured but the
# SecuRedact-managed Desktop client secret is missing. Normal customers must never
# be prompted for this value; it is SecuRedact-managed application configuration
# supplied by packaging/policy.
MANAGED_CLIENT_SECRET_NOT_CONFIGURED_MSG = (
    "The SecuRedact-managed Google Desktop OAuth client secret is not configured. "  # noqa: S105
    "Google rejects the token exchange without it (invalid_request: client_secret is "
    "missing). This is SecuRedact-managed configuration, not a value a customer "
    "supplies; set SECUREDACT_GOOGLE_MANAGED_CLIENT_SECRET (or have it provided by "
    "packaging) and re-run setup."
)

# Safe error code surfaced by the token-exchange pre-check when a managed Desktop
# client is selected but its client secret is absent (fail closed before any
# browser interaction or Google request).
MANAGED_CLIENT_SECRET_MISSING_CODE = "google_managed_client_secret_missing"  # noqa: S105 - error code, not a secret

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
    pkg = managed_config.MANAGED_GOOGLE_CLIENT_ID
    if pkg and pkg.strip():
        return pkg.strip()
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


def resolve_managed_client_secret() -> str | None:
    """Return the SecuRedact-managed Desktop OAuth client secret, or ``None``.

    This is SecuRedact-managed application configuration (not a customer secret and
    not a customer OAuth token). It is resolved from a non-secret environment
    override supplied by packaging/policy. A blank/whitespace value is treated as
    not configured. Never raises.
    """

    env_secret = os.getenv(SECUREDACT_GOOGLE_MANAGED_CLIENT_SECRET_ENV)
    if env_secret and env_secret.strip():
        return env_secret.strip()
    pkg = managed_config.MANAGED_GOOGLE_CLIENT_SECRET
    if pkg and pkg.strip():
        return pkg.strip()
    return None


def is_managed_client_secret_configured() -> bool:
    """True only when a managed (owned) Desktop client secret is available."""

    return resolve_managed_client_secret() is not None


def assert_managed_client_secret_configured() -> str:
    """Return the managed Desktop client secret, or raise (fail closed).

    The managed client id must already be configured (otherwise this is a genuine
    "managed app unavailable" situation, not a missing-secret situation). The raised
    message is customer-safe and must never prompt the customer for this value.
    """

    if not is_managed_client_configured():
        from .config import GoogleConfigError

        raise GoogleConfigError(MANAGED_CLIENT_NOT_CONFIGURED_MSG)
    secret = resolve_managed_client_secret()
    if not secret:
        from .config import GoogleConfigError

        raise GoogleConfigError(MANAGED_CLIENT_SECRET_NOT_CONFIGURED_MSG)
    return secret
