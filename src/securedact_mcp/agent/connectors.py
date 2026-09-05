# SPDX-License-Identifier: Apache-2.0
"""Local connector bindings (AGENT-010).

A connector binding records that a control-plane integration (e.g. a Google
Workspace integration or Microsoft 365) has been bound locally, so the agent
may use the customer's locally-stored OAuth token to scan that integration's
content. The binding stores only non-secret metadata; the actual OAuth token
lives in the platform's credential store.
"""

from __future__ import annotations

import builtins
import json
import logging
from dataclasses import dataclass
from typing import Any

from .config import AgentFiles
from .errors import ConnectorBindingError
from .safe_log import scrub

SUPPORTED_BINDING_PLATFORMS = frozenset({"google_workspace", "microsoft365"})

# The new connector-binding heartbeat acknowledgement protocol is Microsoft-only.
# Google Workspace retains its existing binding semantics: a Google Workspace
# ``Integration.id`` is bound locally by storing a ``ConnectorBinding`` for the
# agent, but Google is NOT part of the con_* acknowledgement identity contract.
# The control plane rejects any Google binding advertised as a con_*/local
# connector ref, so advertising Google bindings in heartbeat would fail the
# entire heartbeat before the (valid) Microsoft binding can be acknowledged.
HEARTBEAT_ACKNOWLEDGEMENT_PLATFORMS = frozenset({"microsoft365"})

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ConnectorBinding:
    """A locally-bound integration (non-secret metadata only)."""

    integration_id: str
    platform: str
    local_profile: str = "default"
    display_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "platform": self.platform,
            "local_profile": self.local_profile,
            "display_name": self.display_name,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConnectorBinding:
        platform = str(data.get("platform") or "")
        if not platform:
            raise ConnectorBindingError("binding missing platform")
        integration_id = str(data.get("integration_id") or "")
        if not integration_id:
            raise ConnectorBindingError("binding missing integration_id")
        return cls(
            integration_id=integration_id,
            platform=platform,
            local_profile=str(data.get("local_profile") or "default"),
            display_name=data.get("display_name"),
        )


class ConnectorBindingStore:
    """Persists local connector bindings as a JSON map keyed by integration id."""

    def __init__(self, files: AgentFiles | None = None) -> None:
        self._files = files or AgentFiles.resolve()
        self._path = self._files.connector_bindings

    def bind(self, binding: ConnectorBinding) -> None:
        if binding.platform not in SUPPORTED_BINDING_PLATFORMS:
            raise ConnectorBindingError(
                f"platform {binding.platform!r} cannot be bound locally yet "
                f"(supported: {sorted(SUPPORTED_BINDING_PLATFORMS)})"
            )
        bindings = self._load()
        bindings[binding.integration_id] = binding.to_dict()
        self._save(bindings)

    def unbind(self, integration_id: str) -> None:
        bindings = self._load()
        if integration_id in bindings:
            del bindings[integration_id]
            self._save(bindings)

    def get(self, integration_id: str) -> ConnectorBinding | None:
        data = self._load().get(integration_id)
        if data is None:
            return None
        return ConnectorBinding.from_dict(data)

    def list(self) -> list[ConnectorBinding]:
        return [ConnectorBinding.from_dict(d) for d in self._load().values()]

    def _load(self) -> dict[str, dict[str, Any]]:
        if not self._path.is_file():
            return {}
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return {}
        return data if isinstance(data, dict) else {}

    def _save(self, bindings: dict[str, dict[str, Any]]) -> None:
        self._files.ensure()
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(bindings, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self._path)

    def list_for_heartbeat(self) -> builtins.list[dict[str, str]]:
        """Return privacy-bounded bindings for heartbeat advertisement.

        Returns only the minimal metadata required by the control plane:
        - local_connector_ref: the integration_id (opaque reference)
        - platform: the platform identifier (microsoft365)

        Only platforms participating in the heartbeat acknowledgement protocol
        (``HEARTBEAT_ACKNOWLEDGEMENT_PLATFORMS``, currently ``microsoft365``) are
        advertised. Google Workspace bindings are retained locally with their
        existing semantics but are NOT advertised in the heartbeat payload: the
        control plane rejects any binding that is not a Microsoft con_*
        ``local_connector_ref``, so including a Google ``Integration.id`` would
        fail the entire heartbeat before a valid Microsoft binding can be
        acknowledged.

        Never includes: local_profile, display_name, OAuth material, tokens,
        tenant IDs, drive/site/item IDs, or filesystem paths.

        If the binding store is missing or corrupt, returns an empty list
        and logs a scrubbed diagnostic. Heartbeat itself continues to work.
        """
        try:
            bindings = self.list()
        except Exception as exc:
            logger.warning("connector binding store unreadable for heartbeat: %s", scrub(str(exc)))
            return []
        result = []
        for binding in bindings:
            if binding.platform not in HEARTBEAT_ACKNOWLEDGEMENT_PLATFORMS:
                if binding.platform not in SUPPORTED_BINDING_PLATFORMS:
                    logger.warning(
                        "unknown platform in binding store, skipping: %s",
                        scrub(binding.platform),
                    )
                continue
            result.append(
                {
                    "local_connector_ref": binding.integration_id,
                    "platform": binding.platform,
                }
            )
        return result
