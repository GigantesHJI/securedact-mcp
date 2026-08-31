# SPDX-License-Identifier: Apache-2.0
"""Public surface for the Google connector control plane (GWS-110).

Exports only the dependency-free pieces; the concrete Google transport/auth are
imported lazily by :mod:`client` so importing this package never pulls the
optional ``google`` extra.
"""

from __future__ import annotations

from .client import GoogleConnectorClient, build_client
from .config import (
    GoogleConfigError,
    GoogleConnectorConfig,
    load_google_client_config,
    load_google_config,
    save_google_client_config,
)
from .storage import GoogleClientConfigStore, GoogleCredentialStore

__all__ = [
    "GoogleClientConfigStore",
    "GoogleConfigError",
    "GoogleConnectorClient",
    "GoogleConnectorConfig",
    "GoogleCredentialStore",
    "build_client",
    "load_google_client_config",
    "load_google_config",
    "save_google_client_config",
]
