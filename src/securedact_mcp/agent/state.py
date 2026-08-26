# SPDX-License-Identifier: Apache-2.0
"""Agent operational state persistence (AGENT-013).

Holds non-secret runtime state (last heartbeat, current job, entitlement timing,
last error). Used to drive backoff and status reporting without re-querying the
control plane on every loop. No credential or token is ever stored here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .config import AgentFiles


@dataclass(slots=True)
class AgentState:
    """Transient operational state for the running agent."""

    last_heartbeat_at: float | None = None
    current_job_id: str | None = None
    entitlement_expires_at: float | None = None
    entitlement_not_before: float | None = None
    last_error: str | None = None
    last_successful_result_at: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "last_heartbeat_at": self.last_heartbeat_at,
            "current_job_id": self.current_job_id,
            "entitlement_expires_at": self.entitlement_expires_at,
            "entitlement_not_before": self.entitlement_not_before,
            "last_error": self.last_error,
            "last_successful_result_at": self.last_successful_result_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentState:
        return cls(
            last_heartbeat_at=data.get("last_heartbeat_at"),
            current_job_id=data.get("current_job_id"),
            entitlement_expires_at=data.get("entitlement_expires_at"),
            entitlement_not_before=data.get("entitlement_not_before"),
            last_error=data.get("last_error"),
            last_successful_result_at=data.get("last_successful_result_at"),
        )


class AgentStateStore:
    """Persists :class:`AgentState` as JSON next to the agent config."""

    def __init__(self, files: AgentFiles | None = None) -> None:
        self._files = files or AgentFiles.resolve()
        self._path = self._files.state

    def load(self) -> AgentState:
        if not self._path.is_file():
            return AgentState()
        try:
            return AgentState.from_dict(json.loads(self._path.read_text(encoding="utf-8")))
        except (ValueError, OSError):
            return AgentState()

    def save(self, state: AgentState) -> None:
        self._files.ensure()
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self._path)

    def update(self, **changes: Any) -> AgentState:
        state = self.load()
        for key, value in changes.items():
            if hasattr(state, key):
                setattr(state, key, value)
        self.save(state)
        return state
