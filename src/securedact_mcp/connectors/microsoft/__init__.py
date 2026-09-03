# SPDX-License-Identifier: Apache-2.0
"""Microsoft 365 connector package (M365-102)."""

from .auth import (
    MicrosoftLoopbackOutcome,
    exchange_code,
    load_credentials,
    require_valid_credentials,
    revoke_credentials,
    run_local_oauth,
)
from .client import (
    MicrosoftConnectorClient,
    MicrosoftConnectorConfig,
    build_client,
    default_connector_scopes,
)
from .client_config_store import MicrosoftClientConfigStore
from .config import (
    MicrosoftConfigError,
    load_microsoft_client_config,
    load_microsoft_config,
    save_microsoft_client_config,
)
from .managed import (
    MANAGED_MICROSOFT_CLIENT_ID_ENV,
    get_managed_microsoft_config,
    is_managed_microsoft_available,
    resolve_managed_microsoft_client_id,
)
from .storage import MicrosoftCredentialStore
from .target_registry import LocalTargetRecord, TargetRegistryStore
from .transport import MicrosoftGraphTransport

__all__ = [
    "MANAGED_MICROSOFT_CLIENT_ID_ENV",
    "LocalTargetRecord",
    "MicrosoftClientConfigStore",
    "MicrosoftConfigError",
    "MicrosoftConnectorClient",
    "MicrosoftConnectorConfig",
    "MicrosoftCredentialStore",
    "MicrosoftGraphTransport",
    "MicrosoftLoopbackOutcome",
    "TargetRegistryStore",
    "build_client",
    "default_connector_scopes",
    "exchange_code",
    "get_managed_microsoft_config",
    "is_managed_microsoft_available",
    "load_credentials",
    "load_microsoft_client_config",
    "load_microsoft_config",
    "require_valid_credentials",
    "resolve_managed_microsoft_client_id",
    "revoke_credentials",
    "run_local_oauth",
    "save_microsoft_client_config",
]
