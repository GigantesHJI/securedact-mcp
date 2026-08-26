# SPDX-License-Identifier: Apache-2.0
"""Policy snapshot resolution (AGENT-009).

At claim time the control plane returns an immutable policy snapshot (the pinned
or default CP-200 ``strict_external_ai`` document). The agent MUST resolve it to
a policy the local core actually implements; it must never silently run an
unknown or unpinned policy. We map the snapshot's ``label``/``name`` to a core
:class:`Policy`. Any label the core does not implement fails closed with
:class:`PolicyUnsupportedError` (the runner then reports ``policy_invalid``).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from securedact_core.policies import STRICT_EXTERNAL_AI_POLICY, Policy, PolicyRegistry

from .errors import PolicyUnsupportedError, PolicyValidationError

# Maps a control-plane policy label to a locally implemented core policy name.
_LABEL_TO_CORE_POLICY = {
    "strict_external_ai": STRICT_EXTERNAL_AI_POLICY.name,
}


@dataclass(frozen=True, slots=True)
class ResolvedPolicy:
    """A locally-implemented policy plus the provenance returned by the control plane."""

    policy: Policy
    policy_version_id: str | None
    content_digest: str | None


def _registry() -> PolicyRegistry:
    return PolicyRegistry()


def _label_to_policy_name(label: str) -> str:
    if label in _LABEL_TO_CORE_POLICY:
        return _LABEL_TO_CORE_POLICY[label]
    # Allow any core built-in policy name to be used directly as a label.
    registry = _registry()
    try:
        registry.get(label)
    except ValueError as exc:
        raise PolicyUnsupportedError(
            f"policy label {label!r} is not implemented by the local core"
        ) from exc
    return label


def resolve_policy(snapshot: Mapping[str, Any]) -> ResolvedPolicy:
    """Resolve a control-plane policy snapshot to a local core policy.

    Fails closed if the snapshot is malformed or references an unknown policy.
    """

    if not isinstance(snapshot, dict):
        raise PolicyValidationError("policy snapshot must be an object")
    content = snapshot.get("content")
    if not isinstance(content, dict) or not content:
        raise PolicyValidationError("policy snapshot content is missing")
    label = content.get("label") or content.get("name")
    if not isinstance(label, str) or not label:
        raise PolicyUnsupportedError("policy snapshot has no recognizable label")
    policy_name = _label_to_policy_name(label)
    policy = _registry().get(policy_name)
    return ResolvedPolicy(
        policy=policy,
        policy_version_id=snapshot.get("policy_version_id"),
        content_digest=snapshot.get("content_digest"),
    )
