# SPDX-License-Identifier: Apache-2.0
"""Agent identity, on-disk configuration, and storage layout (AGENT-003).

The agent stores only non-secret operational metadata in ``agent.json`` (agent
id, display name, control-plane URL, capabilities). The issued ``sra_`` credential
is kept in OS-protected storage (see :mod:`securedact_mcp.agent.credentials`) and
is never written in clear text to ``agent.json``.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

from securedact_core.app_paths import SecuredactPaths
from .capabilities import (
    REQUIRED_CAPABILITIES,
    SUPPORTED_PLATFORMS,
    AgentCapabilities,
)
from .errors import AgentNotRegisteredError

AGENT_CONFIG_FILENAME = "agent.json"
AGENT_STATE_FILENAME = "agent-state.json"
CONNECTOR_BINDINGS_FILENAME = "connector-bindings.json"

DEFAULT_CONTROL_PLANE_URL = "https://www.securedact.com"
CONTROL_PLANE_URL_ENV = "SECUREDACT_CONTROL_PLANE_URL"


def normalize_control_plane_url(raw: str) -> str:
    """Normalize the control-plane base URL; enforce HTTPS except for localhost.

    Returns ``scheme://netloc`` with any path/query stripped. HTTP is permitted
    only for loopback hosts so developers can run a local control plane; every
    production URL must be HTTPS.
    """

    text = (raw or "").strip()
    if not text:
        raise ValueError("control plane URL must not be empty")
    if not text.startswith("http://") and not text.startswith("https://"):
        text = "https://" + text
    parts = urlsplit(text)
    if parts.scheme not in ("http", "https"):
        raise ValueError("control plane URL must use http or https")
    host = (parts.hostname or "").lower()
    if parts.scheme == "http" and host not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("control plane URL must use https except for localhost")
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def generate_display_name() -> str:
    """Generate a privacy-preserving, non-identifying default display name."""

    return f"securedact-agent-{secrets.token_hex(4)}"


@dataclass(slots=True)
class AgentConfig:
    """Persisted agent identity and control-plane binding."""

    control_plane_url: str
    agent_id: str
    display_name: str
    runtime_platform: str
    agent_version: str
    capabilities: AgentCapabilities = field(default_factory=AgentCapabilities.default)

    @classmethod
    def create(
        cls,
        *,
        control_plane_url: str,
        agent_id: str,
        display_name: str | None = None,
        runtime_platform: str | None = None,
        agent_version: str | None = None,
        capabilities: AgentCapabilities | None = None,
    ) -> AgentConfig:
        from .capabilities import agent_version as _agent_version, runtime_platform as _rt

        return cls(
            control_plane_url=normalize_control_plane_url(control_plane_url),
            agent_id=agent_id,
            display_name=display_name or generate_display_name(),
            runtime_platform=runtime_platform or _rt(),
            agent_version=agent_version or _agent_version(),
            capabilities=capabilities or AgentCapabilities.default(),
        )

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "control_plane_url": self.control_plane_url,
            "agent_id": self.agent_id,
            "display_name": self.display_name,
            "runtime_platform": self.runtime_platform,
            "agent_version": self.agent_version,
            "capabilities": self.capabilities.to_dict(),
        }
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AgentConfig:
        caps_data = data.get("capabilities") or {}
        caps = AgentCapabilities(
            supported_platforms=frozenset(
                caps_data.get("supported_platforms", list(SUPPORTED_PLATFORMS))
            ),
            capabilities=frozenset(caps_data.get("capabilities", list(REQUIRED_CAPABILITIES))),
        )
        return cls(
            control_plane_url=normalize_control_plane_url(str(data["control_plane_url"])),
            agent_id=str(data["agent_id"]),
            display_name=str(data.get("display_name") or generate_display_name()),
            runtime_platform=str(data.get("runtime_platform") or "unknown"),
            agent_version=str(data.get("agent_version") or "0.0.0"),
            capabilities=caps,
        )


@dataclass(frozen=True, slots=True)
class AgentFiles:
    """Paths for all agent state, rooted under the Securedact app data directory."""

    root: Path
    config: Path
    state: Path
    connector_bindings: Path

    @classmethod
    def resolve(
        cls, paths: SecuredactPaths | None = None, *, root: Path | None = None
    ) -> AgentFiles:
        if root is not None:
            base_root = Path(root)
        else:
            base = paths or SecuredactPaths.resolve()
            base_root = base.root / "agent"
        return cls(
            root=base_root,
            config=base_root / AGENT_CONFIG_FILENAME,
            state=base_root / AGENT_STATE_FILENAME,
            connector_bindings=base_root / CONNECTOR_BINDINGS_FILENAME,
        )

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)


def _restrict_file(path: Path) -> None:
    """Best-effort restrictive permissions; no-op where unsupported (Windows)."""

    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _write_json_secure(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    _restrict_file(tmp)
    tmp.replace(path)
    _restrict_file(path)


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def save_config(config: AgentConfig, files: AgentFiles | None = None) -> AgentFiles:
    """Persist the agent config. Does not write the credential (see credentials)."""

    files = files or AgentFiles.resolve()
    files.ensure()
    _write_json_secure(files.config, config.to_dict())
    return files


def load_config(files: AgentFiles | None = None) -> AgentConfig:
    files = files or AgentFiles.resolve()
    if not files.config.is_file():
        raise AgentNotRegisteredError("agent is not registered (missing agent.json)")
    return AgentConfig.from_dict(_read_json(files.config))
