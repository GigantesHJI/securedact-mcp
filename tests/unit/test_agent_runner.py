# SPDX-License-Identifier: Apache-2.0
"""Integration tests for the managed-agent runner (AGENT-TEST)."""

from __future__ import annotations

import pytest

from securedact_core.connectors.scan import ScanStatus
from securedact_mcp.agent import agent_runner
from securedact_mcp.agent.config import AgentFiles, load_config
from securedact_mcp.agent.credentials import AgentCredentialStore
from securedact_mcp.agent.reducer import validate_safe_result
from tests.unit.agent_helpers import (
    FakeScanProvider,
    FakeTransport,
    fake_claim,
    scan_result_with,
)


def _runner_transport(
    claim_count: dict[str, int], submitted: list[dict], *, always_no_jobs: bool = False
):
    """Transport that registers, heartbeats, claims once, and accepts a result."""

    def responder(url, headers, body):
        from securedact_mcp.agent.transport import HTTPResponse

        if url.endswith("/v1/agents/register"):
            return HTTPResponse(
                status=201,
                body={
                    "agent_id": "a-1",
                    "credential": "sra_id_secret",
                    "control_plane_url": "https://cp.example.com",
                    "heartbeat_interval_seconds": 60,
                },
                raw_text="",
            )
        if url.endswith("/v1/agents/heartbeat"):
            return HTTPResponse(
                status=200,
                body={
                    "server_time": "now",
                    "agent_id": "a-1",
                    "recommended_heartbeat_seconds": 60,
                    "config_refresh_required": False,
                    "entitlement_refresh_required": False,
                },
                raw_text="",
            )
        if url.endswith("/v1/entitlements/activate"):
            # Force offline-grace path: no entitlement available.
            return HTTPResponse(
                status=502, body={"error": {"code": "temporary", "message": "down"}}, raw_text=""
            )
        if url.endswith("/v1/agents/jobs/claim"):
            if not always_no_jobs and claim_count["n"] == 0:
                claim_count["n"] += 1
                return HTTPResponse(status=200, body=fake_claim(), raw_text="")
            return HTTPResponse(status=204, body=None, raw_text="")
        if url.endswith("/result"):
            submitted.append(body)
            return HTTPResponse(status=200, body={"status": "succeeded"}, raw_text="")
        if url.endswith("/heartbeat") and "/jobs/" in url:
            return HTTPResponse(
                status=200,
                body={
                    "job_id": "job-1",
                    "status": "running",
                    "lease_expires_at": "later",
                    "started_at": "now",
                    "server_time": "now",
                },
                raw_text="",
            )
        return HTTPResponse(status=200, body={}, raw_text="")

    return FakeTransport(responder)


@pytest.fixture
def patched(monkeypatch):
    # Avoid building a real privacy engine / real Google provider in tests.
    monkeypatch.setattr(
        agent_runner.SecuredactEngine, "from_environment", staticmethod(lambda: object())
    )
    provider = FakeScanProvider(
        [scan_result_with(status=ScanStatus.COMPLETED, counts={"email": 3})]
    )
    monkeypatch.setattr(agent_runner, "build_provider", lambda platform, **kwargs: provider)
    return provider


def test_register_agent_persists_config_and_credential(tmp_path):
    transport = _runner_transport({"n": 0}, [])
    config = agent_runner.register_agent(
        "srr_tok_secret",
        control_plane_url="https://cp.example.com",
        files=AgentFiles.resolve(root=tmp_path / "agent"),
        transport=transport,
    )
    assert config.agent_id == "a-1"
    store = AgentCredentialStore(config.agent_id, root=tmp_path / "agent")
    assert store.get().raw == "sra_id_secret"
    # Config reloads.
    reloaded = load_config(AgentFiles.resolve(root=tmp_path / "agent"))
    assert reloaded.agent_id == "a-1"


def test_run_loop_claims_executes_and_submits(tmp_path, patched):
    claim_count = {"n": 0}
    submitted: list[dict] = []
    transport = _runner_transport(claim_count, submitted)
    files = AgentFiles.resolve(root=tmp_path / "agent")
    config = agent_runner.register_agent(
        "srr_tok_secret",
        control_plane_url="https://cp.example.com",
        files=files,
        transport=transport,
    )

    agent_runner.run_agent_loop(
        config, transport=transport, idle_sleep=0, max_iterations=5, files=files
    )

    assert claim_count["n"] == 1
    assert len(submitted) == 1
    body = submitted[0]
    # Transport envelope carries lease auth metadata at the top level.
    assert body["lease_secret"] == "lease-secret-1"  # noqa: S105  # fake test-only lease secret from FakeTransport fixture
    assert body["lease_generation"] == 1
    # The safe scan result is nested and must not contain transport fields.
    safe = body["result"]
    assert "lease_secret" not in safe
    assert validate_safe_result(safe) is not None
    assert safe["status"] == "succeeded"
    assert safe["categories"] == ["email"]


def test_run_loop_no_jobs_idles_and_stops(tmp_path, patched):
    claim_count = {"n": 0}
    submitted: list[dict] = []
    transport = _runner_transport(claim_count, submitted, always_no_jobs=True)
    files = AgentFiles.resolve(root=tmp_path / "agent")
    config = agent_runner.register_agent(
        "srr_tok_secret",
        control_plane_url="https://cp.example.com",
        files=files,
        transport=transport,
    )
    iterations = agent_runner.run_agent_loop(
        config, transport=transport, idle_sleep=0, max_iterations=3, files=files
    )
    assert iterations == 3
    assert len(submitted) == 0


def test_agent_status_reports_registration(tmp_path):
    transport = _runner_transport({"n": 0}, [])
    files = AgentFiles.resolve(root=tmp_path / "agent")
    config = agent_runner.register_agent(
        "srr_tok_secret",
        control_plane_url="https://cp.example.com",
        files=files,
        transport=transport,
    )
    status = agent_runner.agent_status(config, files=files)
    assert status.registered is True
    assert status.credential_present is True
    assert status.agent_id == "a-1"
