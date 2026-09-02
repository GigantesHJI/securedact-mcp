# SPDX-License-Identifier: Apache-2.0
"""Managed-agent runtime error hierarchy (AGENT-001)."""

from __future__ import annotations


class AgentError(Exception):
    """Base class for all managed-agent runtime errors."""


class AgentNotRegisteredError(AgentError):
    """Local agent identity/credential is missing; register before operating."""


class AgentRegistrationError(AgentError):
    """The control plane rejected agent registration."""

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        status: int | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status


class AgentCredentialError(AgentError):
    """Agent credential is missing, malformed, or rejected by the control plane."""


class AgentRevokedError(AgentError):
    """The control plane reported the agent as revoked."""


class TransportError(AgentError):
    """Network/transport failure talking to the control plane."""


class ControlPlaneError(AgentError):
    """The control plane returned a structured error payload."""

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        status: int | None = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status
        self.retryable = retryable


class EntitlementError(AgentError):
    """Entitlement is missing, expired, or could not be refreshed."""


class EntitlementVerificationError(EntitlementError):
    """Entitlement signature/claims verification failed."""


class PolicyValidationError(AgentError):
    """Policy snapshot failed validation."""


class PolicyUnsupportedError(PolicyValidationError):
    """Policy snapshot references a policy the local core does not implement."""


class LeaseError(AgentError):
    """Job lease is invalid, expired, or conflicts with the current generation."""


class JobExecutionError(AgentError):
    """Local job execution failed before a safe result could be produced."""

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


class ConnectorBindingError(AgentError):
    """Connector binding configuration problem (local integration binding)."""
