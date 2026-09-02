# SPDX-License-Identifier: Apache-2.0
"""Regression tests: managed-agent Google integration binding + failure handling.

Covers the production E2E defect investigation (AGENT-E2E):

  * integration_id -> exact local profile resolution (fail closed)
  * robust job failure handling (a claimed job must always reach a safe result,
    never be silently stranded in ``claimed``)
  * heartbeat must not erase a meaningful prior error
  * privacy invariants: no PII / OAuth / secret material in the submitted
    result or the persisted agent state

No Google SDK, no live account, and no real control plane are used.
"""

from __future__ import annotations

import json
import types

import pytest

import securedact_mcp.agent.agent_runner as agent_runner
import securedact_mcp.agent.provider_google as provider_google
from securedact_core.connectors.contracts import ScanContext
from securedact_core.connectors.scan import ScanStatus
from securedact_mcp.agent.client import ControlPlaneClient
from securedact_mcp.agent.config import AgentConfig, AgentFiles
from securedact_mcp.agent.connectors import ConnectorBinding, ConnectorBindingStore
from securedact_mcp.agent.errors import JobExecutionError
from securedact_mcp.agent.executor import JobClaim, ScanTarget, _parse_lease_timestamp
from securedact_mcp.agent.reducer import assert_no_forbidden_substrings, validate_safe_result
from securedact_mcp.agent.state import AgentStateStore
from securedact_mcp.connectors.google.config import GoogleConfigError, load_google_config
from tests.unit.agent_helpers import FakeScanProvider, FakeTransport, fake_claim, scan_result_with

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _store(tmp_path, bindings: list[ConnectorBinding]) -> ConnectorBindingStore:
    # Write the binding map directly so we can exercise the provider's
    # resolution layer (including platform mismatches) without going through
    # the local ``bind()`` registration guard.
    files = AgentFiles.resolve(root=tmp_path / "agent")
    files.ensure()
    data = {b.integration_id: b.to_dict() for b in bindings}
    files.connector_bindings.write_text(
        json.dumps(data, indent=2, sort_keys=True), encoding="utf-8"
    )
    return ConnectorBindingStore(files)


def _run_env(tmp_path, monkeypatch):
    """Build a config/state/control-plane client that records every request."""

    # Avoid building a real privacy engine / real Google provider in these tests.
    monkeypatch.setattr(
        agent_runner.SecuredactEngine, "from_environment", staticmethod(lambda: object())
    )
    files = AgentFiles.resolve(root=tmp_path / "agent")
    config = AgentConfig.create(
        control_plane_url="https://cp.example.test", agent_id="a-1", display_name="d"
    )
    state_store = AgentStateStore(files)
    transport = FakeTransport()
    client = ControlPlaneClient(
        "https://cp.example.test",
        credential_provider=lambda: types.SimpleNamespace(authorization_header="Bearer sra_test"),
        transport=transport,
    )
    return config, files, state_store, client, transport


def _last_result(transport: FakeTransport) -> dict:
    results = [body for (url, _, body) in transport.requests if url.endswith("/result")]
    assert results, "no /result request was made"
    return results[-1]["result"]


# ---------------------------------------------------------------------------
# B. integration_id -> local profile resolution (fail closed)
# ---------------------------------------------------------------------------


def test_binding_resolution_selects_exact_profile(tmp_path):
    store = _store(
        tmp_path,
        [
            ConnectorBinding(
                integration_id="int-A", platform="google_workspace", local_profile="profileA"
            ),
            ConnectorBinding(
                integration_id="int-B", platform="google_workspace", local_profile="profileB"
            ),
        ],
    )
    provider = provider_google.GoogleScanProvider(binding_store=store)

    target_a = ScanTarget(
        platform="google_workspace", integration_id="int-A", target_type="resource", target_ref="x"
    )
    target_b = ScanTarget(
        platform="google_workspace", integration_id="int-B", target_type="resource", target_ref="x"
    )

    # Exact, independent resolution: A -> A, B -> B (never cross-contaminated).
    assert provider._resolve_local_profile(target_a) == "profileA"
    assert provider._resolve_local_profile(target_b) == "profileB"
    # The lookup is keyed by integration_id, so A never resolves to B's profile.
    assert provider._resolve_local_profile(target_a) != "profileB"


def test_missing_binding_fails_closed(tmp_path):
    store = _store(tmp_path, [])  # no bindings at all
    provider = provider_google.GoogleScanProvider(binding_store=store)
    target = ScanTarget(
        platform="google_workspace",
        integration_id="int-missing",
        target_type="resource",
        target_ref="x",
    )

    with pytest.raises(JobExecutionError) as exc_info:
        provider._resolve_local_profile(target)
    assert "no local connector binding" in str(exc_info.value).lower()


def test_platform_mismatch_fails_closed(tmp_path):
    store = _store(
        tmp_path,
        [
            ConnectorBinding(
                integration_id="int-1", platform="microsoft365", local_profile="default"
            )
        ],
    )
    provider = provider_google.GoogleScanProvider(binding_store=store)
    target = ScanTarget(
        platform="google_workspace", integration_id="int-1", target_type="resource", target_ref="x"
    )

    with pytest.raises(JobExecutionError) as exc_info:
        provider._resolve_local_profile(target)
    assert "platform" in str(exc_info.value).lower()


def test_missing_integration_id_fails_closed(tmp_path):
    store = _store(
        tmp_path,
        [
            ConnectorBinding(
                integration_id="int-1", platform="google_workspace", local_profile="default"
            )
        ],
    )
    provider = provider_google.GoogleScanProvider(binding_store=store)
    target = ScanTarget(
        platform="google_workspace", integration_id=None, target_type="resource", target_ref="x"
    )

    with pytest.raises(JobExecutionError):
        provider._resolve_local_profile(target)


# ---------------------------------------------------------------------------
# B (continued). the provider actually loads the selected profile
# ---------------------------------------------------------------------------


class _RecordingGoogleClient:
    def __init__(self, config, engine):
        self.config = config
        self.engine = engine

    def scan_file(self, file_id, context=None, *, integration_id=None, user_id=None):
        return scan_result_with(status=ScanStatus.COMPLETED, counts={"email": 1})


def test_provider_scan_uses_resolved_profile(tmp_path, monkeypatch):
    captured: dict = {}
    real_import = __import__

    client_mod = types.SimpleNamespace(
        GoogleConfigError=GoogleConfigError,
        build_client=lambda config, engine, **kw: _RecordingGoogleClient(config, engine),
    )

    def fake_load(*, require_enabled=False, profile="default"):
        captured["profile"] = profile
        return object()

    def fake_load_credentials(config):
        # Return a dummy credential object
        class FakeCreds:
            pass
        return FakeCreds()

    config_mod = types.SimpleNamespace(
        GoogleConfigError=GoogleConfigError, load_google_config=fake_load
    )

    auth_mod = types.SimpleNamespace(
        load_credentials=fake_load_credentials
    )

    def fake_import(name, *args, **kwargs):
        if name.endswith(".client"):
            return client_mod
        if name.endswith(".config"):
            return config_mod
        if name.endswith(".auth"):
            return auth_mod
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(provider_google.importlib, "import_module", fake_import)

    store = _store(
        tmp_path,
        [
            ConnectorBinding(
                integration_id="int-1", platform="google_workspace", local_profile="work"
            )
        ],
    )
    provider = provider_google.GoogleScanProvider(binding_store=store)
    target = ScanTarget(
        platform="google_workspace",
        integration_id="int-1",
        target_type="resource",
        target_ref="file-1",
    )

    results = provider.scan(target, ScanContext(), object())
    assert results and results[0].status == ScanStatus.COMPLETED
    # The bound profile (not "default", not some other integration) was used.
    assert captured["profile"] == "work"


def test_bound_profile_config_invalid_fails_closed(tmp_path, monkeypatch):
    real_import = __import__

    client_mod = types.SimpleNamespace(
        GoogleConfigError=GoogleConfigError,
        build_client=lambda config, engine, **kw: _RecordingGoogleClient(config, engine),
    )

    def fake_load(*, require_enabled=False, profile="default"):
        raise GoogleConfigError(f"profile {profile!r} not configured")

    def fake_load_credentials(config):
        class FakeCreds:
            pass
        return FakeCreds()

    config_mod = types.SimpleNamespace(
        GoogleConfigError=GoogleConfigError, load_google_config=fake_load
    )

    auth_mod = types.SimpleNamespace(
        load_credentials=fake_load_credentials
    )

    def fake_import(name, *args, **kwargs):
        if name.endswith(".client"):
            return client_mod
        if name.endswith(".config"):
            return config_mod
        if name.endswith(".auth"):
            return auth_mod
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(provider_google.importlib, "import_module", fake_import)

    store = _store(
        tmp_path,
        [
            ConnectorBinding(
                integration_id="int-1", platform="google_workspace", local_profile="work"
            )
        ],
    )
    provider = provider_google.GoogleScanProvider(binding_store=store)
    target = ScanTarget(
        platform="google_workspace",
        integration_id="int-1",
        target_type="resource",
        target_ref="file-1",
    )

    with pytest.raises(JobExecutionError) as exc_info:
        provider.scan(target, ScanContext(), object())
    assert "work" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Direct / local Google config profile behavior (backwards compatible)
# ---------------------------------------------------------------------------


def test_default_profile_token_path_unchanged(monkeypatch):
    monkeypatch.delenv("SECUREDACT_GOOGLE_TOKEN_PATH", raising=False)
    from securedact_core.app_paths import SecuredactPaths

    config = load_google_config()
    expected = SecuredactPaths.resolve().root / "google" / "token.json.enc"
    assert config.token_path == expected


def test_non_default_profile_isolated_token_path(monkeypatch):
    monkeypatch.delenv("SECUREDACT_GOOGLE_TOKEN_PATH", raising=False)
    from securedact_core.app_paths import SecuredactPaths

    config = load_google_config(profile="work")
    expected = SecuredactPaths.resolve().root / "google" / "profiles" / "work" / "token.json.enc"
    assert config.token_path == expected


def test_invalid_profile_name_fails_closed(monkeypatch):
    monkeypatch.delenv("SECUREDACT_GOOGLE_TOKEN_PATH", raising=False)
    with pytest.raises(GoogleConfigError):
        load_google_config(profile="..")


# ---------------------------------------------------------------------------
# C. robust job failure handling (a claimed job must always get a result)
# ---------------------------------------------------------------------------


def test_job_execution_error_submits_failed_result(tmp_path, monkeypatch):
    config, files, state_store, client, transport = _run_env(tmp_path, monkeypatch)
    provider = FakeScanProvider([], error=JobExecutionError("google connector exploded"))
    monkeypatch.setattr(agent_runner, "build_provider", lambda platform, **kw: provider)

    agent_runner._run_one_job(fake_claim(), client, config, state_store, files=files)

    safe = _last_result(transport)
    assert safe["status"] == "failed"
    assert safe["safe_error_code"] in {"connector_unavailable", "agent_execution_error"}
    assert validate_safe_result(safe) is not None
    # Job is no longer stranded: current_job_id cleared.
    assert state_store.load().current_job_id is None


def test_expired_lease_submits_lease_invalid_result(tmp_path, monkeypatch):
    config, files, state_store, client, transport = _run_env(tmp_path, monkeypatch)
    provider = FakeScanProvider([scan_result_with(status=ScanStatus.COMPLETED)])
    monkeypatch.setattr(agent_runner, "build_provider", lambda platform, **kw: provider)

    claim = fake_claim()
    claim["lease_expires_at"] = "2000-01-01T00:00:00Z"  # long expired

    agent_runner._run_one_job(claim, client, config, state_store, files=files)

    safe = _last_result(transport)
    assert safe["status"] == "failed"
    assert safe["safe_error_code"] == "lease_invalid"
    assert state_store.load().current_job_id is None


def test_unexpected_provider_failure_submits_failed_result(tmp_path, monkeypatch):
    config, files, state_store, client, transport = _run_env(tmp_path, monkeypatch)
    # A non-JobExecutionError fault must not silently strand the job.
    provider = FakeScanProvider([], error=RuntimeError("unexpected boom"))
    monkeypatch.setattr(agent_runner, "build_provider", lambda platform, **kw: provider)

    agent_runner._run_one_job(fake_claim(), client, config, state_store, files=files)

    safe = _last_result(transport)
    assert safe["status"] == "failed"
    assert safe["safe_error_code"] == "agent_execution_error"


def test_missing_binding_via_runner_submits_failed_result(tmp_path, monkeypatch):
    config, files, state_store, client, transport = _run_env(tmp_path, monkeypatch)
    # Real GoogleScanProvider with no binding for the claimed integration_id.
    empty_store = _store(tmp_path, [])
    monkeypatch.setattr(
        agent_runner,
        "build_provider",
        lambda platform, **kw: provider_google.GoogleScanProvider(binding_store=empty_store),
    )

    agent_runner._run_one_job(
        fake_claim(integration_id="int-unbound"), client, config, state_store, files=files
    )

    safe = _last_result(transport)
    assert safe["status"] == "failed"
    assert state_store.load().current_job_id is None


# ---------------------------------------------------------------------------
# D. heartbeat must not erase a meaningful prior error
# ---------------------------------------------------------------------------


def test_heartbeat_preserves_prior_error(tmp_path):
    files = AgentFiles.resolve(root=tmp_path / "agent")
    state = AgentStateStore(files)
    state.update(last_error="prior job fault")
    config = AgentConfig.create(
        control_plane_url="https://cp.example.test", agent_id="a-1", display_name="d"
    )
    client = ControlPlaneClient(
        "https://cp.example.test",
        credential_provider=lambda: types.SimpleNamespace(authorization_header="x"),
        transport=FakeTransport(),
    )

    agent_runner._heartbeat(config, client, state)

    # The successful heartbeat refreshed its own stamp but did NOT erase the
    # meaningful prior error.
    loaded = state.load()
    assert loaded.last_error == "prior job fault"
    assert loaded.last_heartbeat_at is not None


def test_heartbeat_failure_records_error(tmp_path):
    files = AgentFiles.resolve(root=tmp_path / "agent")
    state = AgentStateStore(files)
    state.update(last_error=None)

    class _FailTransport(FakeTransport):
        def post(self, url, *, headers, json_body):
            from securedact_mcp.agent.transport import HTTPResponse

            return HTTPResponse(status=500, body={"error": {"message": "boom"}}, raw_text="")

    config = AgentConfig.create(
        control_plane_url="https://cp.example.test", agent_id="a-1", display_name="d"
    )
    client = ControlPlaneClient(
        "https://cp.example.test",
        credential_provider=lambda: types.SimpleNamespace(authorization_header="x"),
        transport=_FailTransport(),
    )

    with pytest.raises(agent_runner.ControlPlaneError):
        agent_runner._heartbeat(config, client, state)

    assert state.load().last_error is not None


# ---------------------------------------------------------------------------
# E. privacy invariants: no PII / OAuth / secret in submitted result or state
# ---------------------------------------------------------------------------


def test_failed_result_contains_no_secrets_or_pii(tmp_path, monkeypatch):
    config, files, state_store, client, transport = _run_env(tmp_path, monkeypatch)
    # Provider fails with a message that would contain a fake token if leaked.
    provider = FakeScanProvider([], error=JobExecutionError("scan failed ya29.FAKEACCESSTOKEN"))
    monkeypatch.setattr(agent_runner, "build_provider", lambda platform, **kw: provider)

    agent_runner._run_one_job(fake_claim(), client, config, state_store, files=files)

    import json

    safe = _last_result(transport)
    blob = json.dumps(safe, sort_keys=True)
    for forbidden in ("ya29.", "FAKEACCESSTOKEN", "jane@example.com", "access_token"):
        assert forbidden not in blob
    assert_no_forbidden_substrings(safe)

    # The persisted agent state must not contain the leaked token either.
    raw_state = files.state.read_text(encoding="utf-8")
    assert "ya29." not in raw_state
    assert "FAKEACCESSTOKEN" not in raw_state


def test_submission_failure_records_safe_error(tmp_path, monkeypatch):
    config, files, state_store, client, _transport = _run_env(tmp_path, monkeypatch)
    provider = FakeScanProvider(
        [scan_result_with(status=ScanStatus.COMPLETED, counts={"email": 1})]
    )
    monkeypatch.setattr(agent_runner, "build_provider", lambda platform, **kw: provider)

    # Control plane rejects the result submission -> must be recorded, not vanish.
    class _RejectTransport(FakeTransport):
        def post(self, url, *, headers, json_body):
            from securedact_mcp.agent.transport import HTTPResponse

            if url.endswith("/result"):
                return HTTPResponse(
                    status=500, body={"error": {"message": "rejected"}}, raw_text=""
                )
            return HTTPResponse(status=200, body={}, raw_text="")

    client._transport = _RejectTransport()
    agent_runner._run_one_job(fake_claim(), client, config, state_store, files=files)

    loaded = state_store.load()
    assert loaded.current_job_id is None
    assert loaded.last_error is not None
    assert "rejected" in loaded.last_error


# ---------------------------------------------------------------------------
# Executor timestamp parsing robustness (root-cause of the E2E no-result)
# ---------------------------------------------------------------------------


def test_parse_lease_timestamp_variants():
    # strict format
    assert _parse_lease_timestamp("2026-08-27T12:34:49Z") is not None
    # sub-second precision
    assert _parse_lease_timestamp("2026-08-27T12:34:49.123456Z") is not None
    # explicit offset
    assert _parse_lease_timestamp("2026-08-27T12:34:49+00:00") is not None
    # non-UTC offset is normalized (later instant than Z equivalent)
    assert _parse_lease_timestamp("2026-08-27T14:34:49+02:00") is not None
    # garbage -> None (caller fails closed)
    assert _parse_lease_timestamp("not-a-time") is None
    assert _parse_lease_timestamp("") is None


def test_expired_lease_true_for_past_timestamp():
    claim_dict = fake_claim()
    claim_dict["lease_expires_at"] = "2000-01-01T00:00:00Z"
    claim = JobClaim.from_claim(claim_dict)
    assert claim.is_expired() is True


def test_future_lease_not_expired():
    claim_dict = fake_claim()
    claim_dict["lease_expires_at"] = "2999-01-01T00:00:00Z"
    claim = JobClaim.from_claim(claim_dict)
    assert claim.is_expired() is False
