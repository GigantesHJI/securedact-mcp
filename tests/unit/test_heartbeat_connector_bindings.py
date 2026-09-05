# SPDX-License-Identifier: Apache-2.0
"""Regression tests for heartbeat advertisement of local connector bindings.

These tests lock down the MCP-side half of the Microsoft connector-binding
acknowledgement protocol:

* daemon heartbeat includes the current Microsoft con_* binding
* CLI heartbeat sends identical binding metadata
* local_profile is never sent
* OAuth / token / Graph / filesystem / PII data is never sent
* multiple bindings serialize deterministically
* corrupt / missing binding store does not break heartbeat
* unknown platforms fail safely
* rebinding to a con_* integration_id preserves the local Microsoft profile
* no registration token is consumed by heartbeat
* agent_id is unchanged
* missing local binding still causes Microsoft job execution to fail closed
* Google behavior is unchanged
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from securedact_mcp.agent.agent_runner import (
    _heartbeat,
    agent_status,
    bind_connector,
    list_connectors,
)
from securedact_mcp.agent.capabilities import AgentCapabilities, current_agent_capabilities
from securedact_mcp.agent.client import ControlPlaneClient, HeartbeatResponse
from securedact_mcp.agent.config import AgentConfig, AgentFiles, save_config
from securedact_mcp.agent.connectors import (
    SUPPORTED_BINDING_PLATFORMS,
    ConnectorBinding,
    ConnectorBindingStore,
)
from securedact_mcp.agent.credentials import AgentCredential, AgentCredentialStore
from securedact_mcp.agent.state import AgentStateStore
from securedact_mcp.agent.transport import HTTPResponse, HTTPTransport

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _make_config(tmp_path: Path, *, agent_id: str = "agent-test-1") -> AgentConfig:
    files = AgentFiles.resolve(root=tmp_path / "agent")
    files.ensure()
    config = AgentConfig(
        control_plane_url="https://cp.example.com",
        agent_id=agent_id,
        display_name="test",
        runtime_platform="windows",
        agent_version="0.5.0",
        capabilities=current_agent_capabilities(),
    )
    save_config(config, files)
    store = AgentCredentialStore(config.agent_id, root=files.root)
    store.save("sra_test_credential")
    return config


def _make_store(tmp_path: Path) -> ConnectorBindingStore:
    files = AgentFiles.resolve(root=tmp_path / "agent")
    files.ensure()
    return ConnectorBindingStore(files=files)


class _CapturingTransport(HTTPTransport):
    """Transport that captures the most recent POST body for assertion."""

    def __init__(self) -> None:
        self.captured_bodies: list[dict[str, Any]] = []
        self.captured_urls: list[str] = []

    def post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        json_body: dict[str, Any] | None = None,
    ) -> HTTPResponse:
        self.captured_urls.append(url)
        if json_body is not None:
            self.captured_bodies.append(json_body)
        if url.endswith("/v1/agents/heartbeat"):
            return HTTPResponse(
                status=200,
                body={
                    "server_time": "2026-09-05T09:00:00Z",
                    "agent_id": "agent-test-1",
                    "recommended_heartbeat_seconds": 300,
                    "config_refresh_required": False,
                    "entitlement_refresh_required": False,
                },
                raw_text="",
            )
        return HTTPResponse(status=200, body={}, raw_text="")

    def get(self, url: str, *, headers: dict[str, str]) -> HTTPResponse:
        return HTTPResponse(status=200, body={}, raw_text="")


# ---------------------------------------------------------------------------
# 1. list_for_heartbeat privacy boundary
# ---------------------------------------------------------------------------


def test_list_for_heartbeat_returns_only_minimal_fields(tmp_path: Path) -> None:
    """Heartbeat serialization must only expose local_connector_ref and platform."""

    store = _make_store(tmp_path)
    store.bind(
        ConnectorBinding(
            integration_id="con_test_001",
            platform="microsoft365",
            local_profile="default",
            display_name="Acme Corp M365",
        )
    )
    result = store.list_for_heartbeat()
    assert len(result) == 1
    entry = result[0]
    assert set(entry.keys()) == {"local_connector_ref", "platform"}
    assert entry["local_connector_ref"] == "con_test_001"
    assert entry["platform"] == "microsoft365"


def test_list_for_heartbeat_never_includes_local_profile(tmp_path: Path) -> None:
    """local_profile must never appear in the heartbeat payload."""

    store = _make_store(tmp_path)
    store.bind(
        ConnectorBinding(
            integration_id="con_test_002",
            platform="microsoft365",
            local_profile="work-profile",
        )
    )
    result = store.list_for_heartbeat()
    blob = json.dumps(result)
    assert "local_profile" not in blob
    assert "work-profile" not in blob


def test_list_for_heartbeat_never_includes_display_name(tmp_path: Path) -> None:
    """display_name must never appear in the heartbeat payload."""

    store = _make_store(tmp_path)
    store.bind(
        ConnectorBinding(
            integration_id="con_test_003",
            platform="microsoft365",
            display_name="Acme Corporation Highly Sensitive Name",
        )
    )
    result = store.list_for_heartbeat()
    blob = json.dumps(result)
    assert "display_name" not in blob
    assert "Acme Corporation Highly Sensitive Name" not in blob


def test_list_for_heartbeat_never_includes_paths_or_tokens(tmp_path: Path) -> None:
    """OAuth material, tokens, paths, and PII must never appear."""

    store = _make_store(tmp_path)
    store.bind(
        ConnectorBinding(
            integration_id="con_test_004",
            platform="microsoft365",
        )
    )
    result = store.list_for_heartbeat()
    blob = json.dumps(result)
    for forbidden in (
        "access_token",
        "refresh_token",
        "client_secret",
        "C:\\ProgramData",
        "token.json.enc",
        "graph.microsoft.com",
        "driveId",
        "folderId",
        "siteId",
        "tenant_id",
    ):
        assert forbidden not in blob, f"heartbeat payload leaks {forbidden!r}"


# ---------------------------------------------------------------------------
# 2. Deterministic ordering
# ---------------------------------------------------------------------------


def test_list_for_heartbeat_serializes_deterministically(tmp_path: Path) -> None:
    """Multiple bindings must serialize in a stable order (sorted by ref)."""

    store = _make_store(tmp_path)
    store.bind(ConnectorBinding(integration_id="con_zzz", platform="microsoft365"))
    store.bind(ConnectorBinding(integration_id="con_aaa", platform="google_workspace"))
    store.bind(ConnectorBinding(integration_id="con_mmm", platform="microsoft365"))
    result = store.list_for_heartbeat()
    refs = [b["local_connector_ref"] for b in result]
    assert refs == sorted(refs), f"non-deterministic ordering: {refs}"


def test_list_for_heartbeat_deduplicates_identical_bindings(tmp_path: Path) -> None:
    """Binding the same integration_id twice should not produce duplicates."""

    store = _make_store(tmp_path)
    store.bind(ConnectorBinding(integration_id="con_same", platform="microsoft365"))
    store.bind(ConnectorBinding(integration_id="con_same", platform="microsoft365"))
    result = store.list_for_heartbeat()
    assert len(result) == 1


# ---------------------------------------------------------------------------
# 3. Corrupt / missing store safety
# ---------------------------------------------------------------------------


def test_list_for_heartbeat_with_no_store_file(tmp_path: Path) -> None:
    """A missing binding store must return an empty list, not raise."""

    store = _make_store(tmp_path)
    assert store.list_for_heartbeat() == []


def test_list_for_heartbeat_with_corrupt_store_returns_empty(tmp_path: Path) -> None:
    """A corrupt (invalid JSON) binding store must not break heartbeat."""

    store = _make_store(tmp_path)
    store._path.parent.mkdir(parents=True, exist_ok=True)
    store._path.write_text("{not valid json", encoding="utf-8")
    assert store.list_for_heartbeat() == []


def test_list_for_heartbeat_skips_unknown_platforms(tmp_path: Path) -> None:
    """A binding with an unknown platform must be skipped, not advertised."""

    store = _make_store(tmp_path)
    store._path.parent.mkdir(parents=True, exist_ok=True)
    store._path.write_text(
        json.dumps(
            {
                "con_good": {
                    "integration_id": "con_good",
                    "platform": "microsoft365",
                },
                "con_bad": {
                    "integration_id": "con_bad",
                    "platform": "dropbox",
                },
            }
        ),
        encoding="utf-8",
    )
    result = store.list_for_heartbeat()
    refs = [b["local_connector_ref"] for b in result]
    assert "con_good" in refs
    assert "con_bad" not in refs


# ---------------------------------------------------------------------------
# 4. Daemon heartbeat includes bindings
# ---------------------------------------------------------------------------


def test_daemon_heartbeat_includes_current_microsoft_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Daemon heartbeat must advertise the current Microsoft binding."""

    config = _make_config(tmp_path)
    bind_connector(
        config,
        "con_microsoft_prod_001",
        "microsoft365",
        files=AgentFiles.resolve(root=tmp_path / "agent"),
    )
    transport = _CapturingTransport()
    client = ControlPlaneClient(
        "https://cp.example.com",
        credential_provider=lambda: AgentCredential("sra_test"),
        transport=transport,
    )
    state_store = AgentStateStore(AgentFiles.resolve(root=tmp_path / "agent"))
    _heartbeat(
        config,
        client,
        state_store,
        files=AgentFiles.resolve(root=tmp_path / "agent"),
    )
    assert any(url.endswith("/v1/agents/heartbeat") for url in transport.captured_urls)
    heartbeat_body = next(
        b
        for u, b in zip(transport.captured_urls, transport.captured_bodies, strict=False)
        if u.endswith("/v1/agents/heartbeat")
    )
    assert "connector_bindings" in heartbeat_body
    bindings = heartbeat_body["connector_bindings"]
    assert any(
        b.get("local_connector_ref") == "con_microsoft_prod_001"
        and b.get("platform") == "microsoft365"
        for b in bindings
    )


def test_daemon_heartbeat_sends_empty_bindings_when_store_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Daemon heartbeat must send connector_bindings=[] when no bindings exist."""

    config = _make_config(tmp_path)
    transport = _CapturingTransport()
    client = ControlPlaneClient(
        "https://cp.example.com",
        credential_provider=lambda: AgentCredential("sra_test"),
        transport=transport,
    )
    state_store = AgentStateStore(AgentFiles.resolve(root=tmp_path / "agent"))
    _heartbeat(
        config,
        client,
        state_store,
        files=AgentFiles.resolve(root=tmp_path / "agent"),
    )
    heartbeat_body = next(
        b
        for u, b in zip(transport.captured_urls, transport.captured_bodies, strict=False)
        if u.endswith("/v1/agents/heartbeat")
    )
    assert heartbeat_body.get("connector_bindings") == []


def test_daemon_heartbeat_does_not_consume_registration_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Heartbeat must never hit the /v1/agents/register endpoint."""

    config = _make_config(tmp_path)
    transport = _CapturingTransport()
    client = ControlPlaneClient(
        "https://cp.example.com",
        credential_provider=lambda: AgentCredential("sra_test"),
        transport=transport,
    )
    state_store = AgentStateStore(AgentFiles.resolve(root=tmp_path / "agent"))
    _heartbeat(
        config,
        client,
        state_store,
        files=AgentFiles.resolve(root=tmp_path / "agent"),
    )
    for url in transport.captured_urls:
        assert "/v1/agents/register" not in url, "heartbeat must not re-register"


# ---------------------------------------------------------------------------
# 5. CLI heartbeat uses same helper
# ---------------------------------------------------------------------------


def test_cli_heartbeat_uses_same_list_for_heartbeat_helper() -> None:
    """CLI heartbeat must call the same ConnectorBindingStore.list_for_heartbeat helper."""

    import inspect

    from securedact_mcp.agent import cli as cli_mod

    source = inspect.getsource(cli_mod.run_agent)
    assert "list_for_heartbeat" in source, (
        "CLI heartbeat must use ConnectorBindingStore.list_for_heartbeat helper"
    )
    assert "connector_bindings" in source, (
        "CLI heartbeat must pass connector_bindings to client.heartbeat"
    )


def test_cli_and_daemon_heartbeat_share_canonical_helper() -> None:
    """Both CLI and daemon heartbeat must use the same canonical helper."""

    import inspect

    from securedact_mcp.agent import agent_runner
    from securedact_mcp.agent import cli as cli_mod

    runner_src = inspect.getsource(agent_runner._heartbeat)
    cli_src = inspect.getsource(cli_mod.run_agent)
    assert "ConnectorBindingStore(files).list_for_heartbeat()" in runner_src
    assert "ConnectorBindingStore(files).list_for_heartbeat()" in cli_src


# ---------------------------------------------------------------------------
# 6. Rebind to con_* preserves local Microsoft authorization
# ---------------------------------------------------------------------------


def test_rebind_to_con_ref_preserves_local_authorization(tmp_path: Path) -> None:
    """Rebinding an existing Microsoft integration under a new con_* ref must
    not remove the old binding until the new one is proven working, and must
    preserve the local_profile (so the existing OAuth authorization is reused).
    """

    files = AgentFiles.resolve(root=tmp_path / "agent")
    files.ensure()
    config = _make_config(tmp_path, agent_id="agent-rebind")

    old_ref = "srr_dfd319cb74beeadf_kqYfFMr--EMAx-dKydZveeS0Do9Coik_4q1OLEqoKUA"
    new_ref = "con_dedicated_opaque_ref_001"

    bind_connector(config, old_ref, "microsoft365", profile="default", files=files)
    pre_bindings = list_connectors(config, files=files)
    assert len(pre_bindings) == 1
    assert pre_bindings[0].integration_id == old_ref
    assert pre_bindings[0].local_profile == "default"
    assert pre_bindings[0].platform == "microsoft365"

    bind_connector(config, new_ref, "microsoft365", profile="default", files=files)

    post_bindings = list_connectors(config, files=files)
    refs = {b.integration_id for b in post_bindings}
    assert old_ref in refs, "old binding removed before new con_* binding proven"
    assert new_ref in refs, "new con_* binding not present"

    old_binding = next(b for b in post_bindings if b.integration_id == old_ref)
    new_binding = next(b for b in post_bindings if b.integration_id == new_ref)
    assert old_binding.local_profile == new_binding.local_profile == "default"
    assert old_binding.platform == new_binding.platform == "microsoft365"


def test_rebind_to_con_ref_does_not_consume_registration_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rebinding must not touch the control plane (no registration token used)."""

    config = _make_config(tmp_path)
    transport = _CapturingTransport()
    monkeypatch.setattr(
        "securedact_mcp.agent.agent_runner.ControlPlaneClient",
        lambda *a, **k: ControlPlaneClient(
            "https://cp.example.com",
            credential_provider=lambda: AgentCredential("sra_test"),
            transport=transport,
        ),
    )
    files = AgentFiles.resolve(root=tmp_path / "agent")
    bind_connector(config, "con_existing_001", "microsoft365", files=files)
    for url in transport.captured_urls:
        assert "/v1/agents/register" not in url
        assert "registration_token" not in str(url)


# ---------------------------------------------------------------------------
# 7. agent_id unchanged, status includes bindings
# ---------------------------------------------------------------------------


def test_heartbeat_does_not_change_agent_id(tmp_path: Path) -> None:
    """Heartbeat must never mutate the agent_id."""

    config = _make_config(tmp_path, agent_id="agent-immutable-001")
    transport = _CapturingTransport()
    client = ControlPlaneClient(
        "https://cp.example.com",
        credential_provider=lambda: AgentCredential("sra_test"),
        transport=transport,
    )
    state_store = AgentStateStore(AgentFiles.resolve(root=tmp_path / "agent"))
    _heartbeat(config, client, state_store, files=AgentFiles.resolve(root=tmp_path / "agent"))
    assert config.agent_id == "agent-immutable-001"


def test_agent_status_includes_full_bindings(tmp_path: Path) -> None:
    """agent_status may show full local bindings (including local_profile),
    independently from the privacy-bounded heartbeat payload.
    """

    config = _make_config(tmp_path)
    bind_connector(
        config,
        "con_status_001",
        "microsoft365",
        profile="work",
        display_name="Status Test",
        files=AgentFiles.resolve(root=tmp_path / "agent"),
    )
    status = agent_status(config, files=AgentFiles.resolve(root=tmp_path / "agent"))
    assert len(status.bindings) == 1
    assert status.bindings[0]["integration_id"] == "con_status_001"
    assert status.bindings[0]["local_profile"] == "work"
    assert status.bindings[0]["display_name"] == "Status Test"


# ---------------------------------------------------------------------------
# 8. Missing binding still causes Microsoft job to fail closed
# ---------------------------------------------------------------------------


def test_missing_local_binding_still_fails_microsoft_job(tmp_path: Path) -> None:
    """If the binding store is empty, Microsoft job execution must fail closed.

    The new heartbeat advertisement does not weaken the existing fail-closed
    behavior for missing local bindings.
    """

    files = AgentFiles.resolve(root=tmp_path / "agent")
    files.ensure()
    assert ConnectorBindingStore(files).list_for_heartbeat() == []

    from securedact_core import SecuredactEngine
    from securedact_core.connectors.contracts import ScanContext
    from securedact_core.production import build_production_engine
    from securedact_mcp.agent.errors import JobExecutionError
    from securedact_mcp.agent.executor import ScanTarget
    from securedact_mcp.agent.provider_microsoft import MicrosoftScanProvider

    engine = SecuredactEngine(build_production_engine(require_contextual=False))
    provider = MicrosoftScanProvider(files=files)
    with pytest.raises(JobExecutionError):
        provider.scan(
            ScanTarget(
                platform="microsoft365",
                integration_id="int-missing",
                target_type="integration",
                target_ref="",
            ),
            ScanContext(),
            engine,
        )


# ---------------------------------------------------------------------------
# 9. Google behavior unchanged
# ---------------------------------------------------------------------------


def test_google_binding_appears_in_heartbeat(tmp_path: Path) -> None:
    """Google bindings must also appear in the heartbeat payload."""

    config = _make_config(tmp_path)
    bind_connector(
        config,
        "con_google_001",
        "google_workspace",
        files=AgentFiles.resolve(root=tmp_path / "agent"),
    )
    transport = _CapturingTransport()
    client = ControlPlaneClient(
        "https://cp.example.com",
        credential_provider=lambda: AgentCredential("sra_test"),
        transport=transport,
    )
    state_store = AgentStateStore(AgentFiles.resolve(root=tmp_path / "agent"))
    _heartbeat(config, client, state_store, files=AgentFiles.resolve(root=tmp_path / "agent"))
    heartbeat_body = next(
        b
        for u, b in zip(transport.captured_urls, transport.captured_bodies, strict=False)
        if u.endswith("/v1/agents/heartbeat")
    )
    assert any(
        b.get("local_connector_ref") == "con_google_001" and b.get("platform") == "google_workspace"
        for b in heartbeat_body["connector_bindings"]
    )


def test_google_heartbeat_does_not_send_microsoft_metadata(
    tmp_path: Path,
) -> None:
    """If only Google is bound, the heartbeat must not include Microsoft metadata."""

    config = _make_config(tmp_path)
    bind_connector(
        config,
        "con_google_only_001",
        "google_workspace",
        files=AgentFiles.resolve(root=tmp_path / "agent"),
    )
    transport = _CapturingTransport()
    client = ControlPlaneClient(
        "https://cp.example.com",
        credential_provider=lambda: AgentCredential("sra_test"),
        transport=transport,
    )
    state_store = AgentStateStore(AgentFiles.resolve(root=tmp_path / "agent"))
    _heartbeat(config, client, state_store, files=AgentFiles.resolve(root=tmp_path / "agent"))
    heartbeat_body = next(
        b
        for u, b in zip(transport.captured_urls, transport.captured_bodies, strict=False)
        if u.endswith("/v1/agents/heartbeat")
    )
    for binding in heartbeat_body["connector_bindings"]:
        assert binding["platform"] != "microsoft365"


# ---------------------------------------------------------------------------
# 10. Heartbeat client API includes optional connector_bindings
# ---------------------------------------------------------------------------


def test_heartbeat_client_accepts_optional_connector_bindings() -> None:
    """ControlPlaneClient.heartbeat must accept optional connector_bindings."""

    transport = _CapturingTransport()
    client = ControlPlaneClient(
        "https://cp.example.com",
        credential_provider=lambda: AgentCredential("sra_test"),
        transport=transport,
    )
    resp = client.heartbeat(
        agent_version="1.0.0",
        capabilities=AgentCapabilities.default(),
    )
    assert isinstance(resp, HeartbeatResponse)
    assert len(transport.captured_bodies) == 1
    assert "connector_bindings" not in transport.captured_bodies[0]


def test_heartbeat_client_includes_connector_bindings_when_provided() -> None:
    """When connector_bindings is provided, it must appear in the POST body."""

    transport = _CapturingTransport()
    client = ControlPlaneClient(
        "https://cp.example.com",
        credential_provider=lambda: AgentCredential("sra_test"),
        transport=transport,
    )
    client.heartbeat(
        agent_version="1.0.0",
        capabilities=AgentCapabilities.default(),
        connector_bindings=[{"local_connector_ref": "con_001", "platform": "microsoft365"}],
    )
    assert "connector_bindings" in transport.captured_bodies[0]
    assert transport.captured_bodies[0]["connector_bindings"] == [
        {"local_connector_ref": "con_001", "platform": "microsoft365"}
    ]


# ---------------------------------------------------------------------------
# 11. Supported platforms constant unchanged
# ---------------------------------------------------------------------------


def test_supported_binding_platforms_unchanged() -> None:
    """The supported platform set must not have drifted."""

    assert SUPPORTED_BINDING_PLATFORMS == frozenset({"google_workspace", "microsoft365"})
