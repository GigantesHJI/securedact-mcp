# SPDX-License-Identifier: Apache-2.0
"""Agent capability advertisement (AGENT-002).

Capabilities are the agent's advertised *technical* abilities. They are never
entitlements and can never grant commercial permission (control-plane protocol
§10/§12). The agent must only advertise platforms it can genuinely execute
locally, because the control plane uses the advertisement to dispatch jobs.
"""

from __future__ import annotations

import platform as _platform_mod
import re
from dataclasses import dataclass, field

from .. import __version__ as _MCP_VERSION

# Protocol-version capabilities every claiming agent must advertise.
REQUIRED_CAPABILITIES = frozenset({"job_protocol_v1", "policy_snapshot_v1"})

# Platform -> technical capability token the agent must advertise (mirrors the
# control-plane PLATFORM_CAPABILITY map so capability matching succeeds).
PLATFORM_CAPABILITY = {
    "google_workspace": "google_drive",
    "microsoft365": "microsoft_graph",
}

# Platforms this runtime can genuinely execute locally.
SUPPORTED_PLATFORMS = frozenset({"google_workspace", "microsoft365"})

_CAPABILITY_RE = re.compile(r"^[a-z0-9_]+$")
_MAX_CAPABILITY_LEN = 64
_MAX_CAPABILITIES = 32


def agent_version() -> str:
    """Return the managed-agent (MCP package) version."""

    return _MCP_VERSION


def runtime_platform() -> str:
    """Return a bounded, non-identifying OS label for registration."""

    system = _platform_mod.system().lower()
    if system == "windows":
        return "windows"
    if system == "darwin":
        return "macos"
    if system == "linux":
        return "linux"
    return system or "unknown"


def platform_capability(platform: str) -> str | None:
    """Return the technical capability token an agent must advertise for a platform."""

    return PLATFORM_CAPABILITY.get(platform)


def validate_capabilities(capabilities: frozenset[str]) -> None:
    """Fail closed if the advertised capability set violates the protocol (§10)."""

    if len(capabilities) > _MAX_CAPABILITIES:
        raise ValueError("too many capabilities advertised")
    for cap in capabilities:
        if not isinstance(cap, str) or len(cap) > _MAX_CAPABILITY_LEN:
            raise ValueError(f"capability too long: {cap!r}")
        if not _CAPABILITY_RE.match(cap):
            raise ValueError(f"capability has invalid characters: {cap!r}")


@dataclass(frozen=True, slots=True)
class AgentCapabilities:
    """Advertised technical capabilities and supported platforms."""

    supported_platforms: frozenset[str] = field(
        default_factory=lambda: frozenset(SUPPORTED_PLATFORMS)
    )
    capabilities: frozenset[str] = field(
        default_factory=lambda: (
            frozenset(REQUIRED_CAPABILITIES) | frozenset(PLATFORM_CAPABILITY.values())
        )
    )

    def to_dict(self) -> dict[str, object]:
        return {
            "supported_platforms": sorted(self.supported_platforms),
            "capabilities": sorted(self.capabilities),
        }

    def to_registration_payload(self) -> list[str]:
        """Return the flat capability list the registration endpoint expects."""

        return sorted(self.capabilities)

    @classmethod
    def default(cls) -> AgentCapabilities:
        return cls()

    def supports_platform(self, platform: str) -> bool:
        return platform in self.supported_platforms

    def requires_capability(self, capability: str) -> bool:
        return capability in self.capabilities
