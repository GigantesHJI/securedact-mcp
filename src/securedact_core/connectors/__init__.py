# SPDX-License-Identifier: Apache-2.0
"""SecuRedact Enterprise Connector contracts and base orchestration.

Platform-neutral, Microsoft-free. See :mod:`securedact_core.connectors.contracts`
for the resource/capability model and :mod:`securedact_core.connectors.scan` for
the scan request/result model.
"""

from __future__ import annotations

from .base import ConnectorScanner, extract_text, is_text_format
from .contracts import (
    ConnectorCapability,
    ConnectorIdentity,
    ConnectorResource,
    InvalidResourceIdentifierError,
    NormalizedContent,
    ResourceKind,
    ScanContext,
    validate_resource_identifier,
)
from .scan import (
    ScanError,
    ScanErrorCode,
    ScanFinding,
    ScanRequest,
    ScanResult,
    ScanSeverity,
    ScanStatus,
)

__all__ = [
    "ConnectorCapability",
    "ConnectorIdentity",
    "ConnectorResource",
    "ConnectorScanner",
    "InvalidResourceIdentifierError",
    "NormalizedContent",
    "ResourceKind",
    "ScanContext",
    "ScanError",
    "ScanErrorCode",
    "ScanFinding",
    "ScanRequest",
    "ScanResult",
    "ScanSeverity",
    "ScanStatus",
    "extract_text",
    "is_text_format",
    "validate_resource_identifier",
]
