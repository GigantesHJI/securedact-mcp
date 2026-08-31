# SPDX-License-Identifier: Apache-2.0
"""Managed local agent runtime for SecuRedact.com (AGENT-001).

This package implements the customer-local agent side of the SecuRedact control
plane protocol (docs/agent-control-plane-protocol.md in the web app). It is
local-first by construction: raw customer document content never leaves the
machine, the control plane only ever receives a privacy-safe, closed-vocabulary
scan summary, and the agent authenticates with a dedicated ``sra_...`` credential
that is independent of commercial state.
"""

from __future__ import annotations

from .agent_runner import (
    AgentStatus,
    bind_connector,
    list_connectors,
    refresh_entitlement,
    register_agent,
    rotate_credential,
    run_agent_loop,
)
from .config import AgentConfig, AgentFiles, load_config, save_config
from .errors import (
    AgentCredentialError,
    AgentError,
    AgentNotRegisteredError,
    AgentRegistrationError,
    AgentRevokedError,
    ConnectorBindingError,
    ControlPlaneError,
    EntitlementError,
    EntitlementVerificationError,
    JobExecutionError,
    LeaseError,
    PolicyUnsupportedError,
    PolicyValidationError,
    TransportError,
)

__all__ = [
    "AgentConfig",
    "AgentCredentialError",
    "AgentError",
    "AgentFiles",
    "AgentNotRegisteredError",
    "AgentRegistrationError",
    "AgentRevokedError",
    "AgentStatus",
    "ConnectorBindingError",
    "ControlPlaneError",
    "EntitlementError",
    "EntitlementVerificationError",
    "JobExecutionError",
    "LeaseError",
    "PolicyUnsupportedError",
    "PolicyValidationError",
    "TransportError",
    "bind_connector",
    "list_connectors",
    "load_config",
    "refresh_entitlement",
    "register_agent",
    "rotate_credential",
    "run_agent_loop",
    "save_config",
]
