# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the managed-agent protocol surface (AGENT-TEST)."""

from __future__ import annotations

import time

import pytest

from securedact_core.connectors.scan import ScanErrorCode, ScanSeverity, ScanStatus
from securedact_mcp.agent.capabilities import AgentCapabilities, validate_capabilities
from securedact_mcp.agent.client import ControlPlaneClient
from securedact_mcp.agent.config import AgentConfig, AgentFiles, normalize_control_plane_url
from securedact_mcp.agent.credentials import AgentCredential, AgentCredentialStore
from securedact_mcp.agent.entitlement import (
    ENTITLEMENT_AUDIENCE,
    ENTITLEMENT_ISSUER,
    EntitlementManager,
    decode_eddsa_jwt,
)
from securedact_mcp.agent.errors import (
    AgentRegistrationError,
    AgentRevokedError,
    ControlPlaneError,
    EntitlementVerificationError,
    PolicyUnsupportedError,
)
from securedact_mcp.agent.executor import JobClaim, execute_job
from securedact_mcp.agent.policy import resolve_policy
from securedact_mcp.agent.reducer import (
    build_safe_result_dict,
    label_for_entity,
    reduce_scan_results,
    validate_safe_result,
)
from tests.unit.agent_helpers import (
    FakeScanProvider,
    FakeTransport,
    encode_eddsa_jwt,
    fake_claim,
    make_ed25519_keypair,
    public_key_to_jwk,
    scan_result_with,
    strict_external_ai_snapshot,
)

# --- capabilities / config ------------------------------------------------


def test_normalize_control_plane_url_enforces_https_except_localhost():
    assert normalize_control_plane_url("http://localhost:8080") == "http://localhost:8080"
    assert normalize_control_plane_url("api.example.com") == "https://api.example.com"
    assert normalize_control_plane_url("https://cp.example.com/path") == "https://cp.example.com"
    with pytest.raises(ValueError):
        normalize_control_plane_url("http://example.com")


def test_capabilities_validation_rejects_bad_tokens():
    validate_capabilities(AgentCapabilities.default().capabilities)
    with pytest.raises(ValueError):
        validate_capabilities(frozenset({"Bad Token!"}))


def test_agent_config_round_trip(tmp_path):
    files = AgentFiles.resolve(root=tmp_path / "agent")
    config = AgentConfig.create(
        control_plane_url="https://cp.example.com",
        agent_id="agent-xyz",
        display_name="test-agent",
        runtime_platform="windows",
        agent_version="9.9.9",
    )
    from securedact_mcp.agent.config import load_config, save_config

    save_config(config, files)
    loaded = load_config(files)
    assert loaded.agent_id == "agent-xyz"
    assert loaded.control_plane_url == "https://cp.example.com"
    assert loaded.capabilities.supports_platform("google_workspace")


# --- credentials ----------------------------------------------------------


def test_credential_store_file_backend_round_trip(tmp_path):
    store = AgentCredentialStore("agent-1", root=tmp_path)
    cred = store.save("sra_id_secret")
    assert cred.credential_id == "id"
    assert store.get() is not None
    assert store.get().raw == "sra_id_secret"
    store.delete()
    assert store.get() is None


# --- reducer --------------------------------------------------------------


def test_label_for_entity_mapping():
    assert label_for_entity("EMAIL") == "email"
    assert label_for_entity("UNKNOWN_SECRET") == "secret"
    assert label_for_entity("GENETIC_DATA") == "special_category"
    assert label_for_entity("RANDOM_TYPE") == "other"


def test_reduce_single_completed_result():
    result = reduce_scan_results(
        [scan_result_with(status=ScanStatus.COMPLETED, counts={"email": 2, "bsn": 1})],
        policy_version_id="pv-1",
        policy_digest="d-1",
        resources_scanned=1,
        duration_ms=10,
    )
    assert result.status == "succeeded"
    assert result.categories == ["bsn", "email"]
    assert result.counts == {"bsn": 1, "email": 2}
    assert result.severity == "medium"
    assert result.policy_decision == "allow"
    assert result.supported_action == "none"
    assert result.review_required is False


def test_reduce_blocked_escalates_review_and_action():
    result = reduce_scan_results(
        [
            scan_result_with(
                status=ScanStatus.BLOCKED, severity=ScanSeverity.HIGH, counts={"bsn": 1}
            )
        ],
        policy_version_id="pv-1",
        policy_digest="d-1",
        resources_scanned=1,
        duration_ms=5,
    )
    assert result.status == "succeeded"
    assert result.policy_decision == "block"
    assert result.supported_action == "block"
    assert result.review_required is True
    assert result.severity == "high"


def test_reduce_review_required():
    result = reduce_scan_results(
        [scan_result_with(status=ScanStatus.REVIEW_REQUIRED, counts={"person": 1})],
        policy_version_id="pv-1",
        policy_digest="d-1",
        resources_scanned=1,
        duration_ms=5,
    )
    assert result.policy_decision == "review"
    assert result.supported_action == "review"
    assert result.review_required is True


def test_reduce_provider_error_becomes_warning():
    result = reduce_scan_results(
        [scan_result_with(status=ScanStatus.ERROR, error_code=ScanErrorCode.RETRIEVAL_FAILED)],
        policy_version_id="pv-1",
        policy_digest="d-1",
        resources_scanned=1,
        duration_ms=5,
    )
    # Per-file errors are reported as safe warnings, not a whole-job failure.
    assert result.status == "succeeded"
    assert result.safe_error_code is None


def test_validate_safe_result_rejects_content_bearing_field():
    with pytest.raises(ValueError):
        validate_safe_result({"status": "succeeded", "text": "secret"})
    with pytest.raises(ValueError):
        validate_safe_result({"status": "succeeded", "match": "x"})


def test_validate_safe_result_fail_closed_for_failed():
    with pytest.raises(ValueError):
        validate_safe_result({"status": "failed", "review_required": False})
    with pytest.raises(ValueError):
        validate_safe_result(
            {
                "status": "failed",
                "review_required": True,
                "policy_decision": "allow",
                "supported_action": "none",
            }
        )
    # Valid failed result passes.
    validate_safe_result(
        {
            "status": "failed",
            "review_required": True,
            "policy_decision": "review",
            "supported_action": "none",
            "safe_error_code": "agent_execution_error",
        }
    )


def test_validate_safe_result_size_cap():
    big = {"status": "succeeded", "categories": ["email"], "counts": {"email": 1}}
    assert validate_safe_result(big)
    huge = {f"k{i}": "v" for i in range(2000)}
    huge["status"] = "succeeded"
    # Not a denied/allowed field, so rejected before size matters.
    with pytest.raises(ValueError):
        validate_safe_result(huge)


# --- policy ---------------------------------------------------------------


def test_resolve_policy_strict_external_ai():
    resolved = resolve_policy(strict_external_ai_snapshot())
    assert resolved.policy.name == "strict_external_ai"
    assert resolved.policy_version_id is None


def test_resolve_policy_unknown_label_fails_closed():
    snapshot = {"policy_version_id": None, "version": 0, "content": {"label": "made_up_policy"}}
    with pytest.raises(PolicyUnsupportedError):
        resolve_policy(snapshot)


# --- entitlement ----------------------------------------------------------


def _entitlement_transport(
    priv, kid, *, issuer=ENTITLEMENT_ISSUER, audience=ENTITLEMENT_AUDIENCE, exp=None
):
    pub = priv.public_key()
    jwk = public_key_to_jwk(pub, kid=kid)
    jwt = encode_eddsa_jwt(priv, kid=kid, issuer=issuer, audience=audience, exp=exp)

    def responder(url, headers, body):
        if url.endswith("/.well-known/jwks.json"):
            return __import__(
                "securedact_mcp.agent.transport", fromlist=["HTTPResponse"]
            ).HTTPResponse(status=200, body={"keys": [jwk]}, raw_text="")
        if url.endswith("/v1/entitlements/activate"):
            return __import__(
                "securedact_mcp.agent.transport", fromlist=["HTTPResponse"]
            ).HTTPResponse(status=200, body={"entitlement": jwt}, raw_text="")
        return __import__("securedact_mcp.agent.transport", fromlist=["HTTPResponse"]).HTTPResponse(
            status=200, body={}, raw_text=""
        )

    return FakeTransport(responder)


def test_entitlement_activate_verifies_signed_jwt():
    priv, _ = make_ed25519_keypair()
    transport = _entitlement_transport(priv, kid="k1")
    client = ControlPlaneClient(
        "https://cp.example.com",
        credential_provider=lambda: AgentCredential("sra_x_y"),
        transport=transport,
    )
    mgr = EntitlementManager(client)
    ent = mgr.activate()
    assert ent.kid == "k1"
    assert ent.expires_at is None


def test_decode_eddsa_jwt_rejects_wrong_key_and_claims():
    priv, _ = make_ed25519_keypair()
    other, _ = make_ed25519_keypair()
    pub = priv.public_key()
    good = encode_eddsa_jwt(
        priv, kid="k1", issuer=ENTITLEMENT_ISSUER, audience=ENTITLEMENT_AUDIENCE
    )
    # Wrong key verification fails.
    with pytest.raises(EntitlementVerificationError):
        decode_eddsa_jwt(
            good, other.public_key(), issuer=ENTITLEMENT_ISSUER, audience=ENTITLEMENT_AUDIENCE
        )
    # Wrong issuer fails.
    bad_iss = encode_eddsa_jwt(
        priv, kid="k1", issuer="https://evil.com", audience=ENTITLEMENT_AUDIENCE
    )
    with pytest.raises(EntitlementVerificationError):
        decode_eddsa_jwt(bad_iss, pub, issuer=ENTITLEMENT_ISSUER, audience=ENTITLEMENT_AUDIENCE)
    # Expired token fails.
    expired = encode_eddsa_jwt(
        priv,
        kid="k1",
        issuer=ENTITLEMENT_ISSUER,
        audience=ENTITLEMENT_AUDIENCE,
        exp=time.time() - 100,
    )
    with pytest.raises(EntitlementVerificationError):
        decode_eddsa_jwt(expired, pub, issuer=ENTITLEMENT_ISSUER, audience=ENTITLEMENT_AUDIENCE)
    # Non-EdDSA algorithm rejected.
    wrong_alg = good.split(".")
    header = '{"alg":"HS256","kid":"k1","typ":"JWT"}'
    import base64

    forged = f"{base64.urlsafe_b64encode(header.encode()).rstrip(b'=').decode()}.{wrong_alg[1]}.{wrong_alg[2]}"
    with pytest.raises(EntitlementVerificationError):
        decode_eddsa_jwt(forged, pub, issuer=ENTITLEMENT_ISSUER, audience=ENTITLEMENT_AUDIENCE)


# --- client ---------------------------------------------------------------


def test_client_register_returns_credential():
    def responder(url, headers, body):
        from securedact_mcp.agent.transport import HTTPResponse

        if url.endswith("/v1/agents/register"):
            return HTTPResponse(
                status=201,
                body={
                    "agent_id": "a-1",
                    "credential": "sra_abc_def",
                    "control_plane_url": "https://cp.example.com",
                    "heartbeat_interval_seconds": 60,
                },
                raw_text="",
            )
        return HTTPResponse(status=200, body={}, raw_text="")

    client = ControlPlaneClient(
        "https://cp.example.com",
        credential_provider=lambda: None,
        transport=FakeTransport(responder),
    )
    resp = client.register(
        "srr_tok",
        display_name="d",
        agent_version="1",
        platform="linux",
        capabilities=AgentCapabilities.default(),
    )
    assert resp.agent_id == "a-1"
    assert resp.credential == "sra_abc_def"


def test_client_revoked_error_is_typed():
    def responder(url, headers, body):
        from securedact_mcp.agent.transport import HTTPResponse

        return HTTPResponse(
            status=403, body={"error": {"code": "agent_revoked", "message": "revoked"}}, raw_text=""
        )

    client = ControlPlaneClient(
        "https://cp.example.com",
        credential_provider=lambda: AgentCredential("sra_x_y"),
        transport=FakeTransport(responder),
    )
    with pytest.raises(AgentRevokedError):
        client.heartbeat(agent_version="1", capabilities=AgentCapabilities.default())


def test_client_result_submission_includes_lease_fields():
    captured: dict[str, object] = {}

    def responder(url, headers, body):
        from securedact_mcp.agent.transport import HTTPResponse

        if url.endswith("/v1/agents/jobs/claim"):
            return HTTPResponse(status=204, body=None, raw_text="")
        if url.endswith("/result"):
            captured["body"] = body
            return HTTPResponse(status=200, body={"status": "succeeded"}, raw_text="")
        return HTTPResponse(status=200, body={}, raw_text="")

    client = ControlPlaneClient(
        "https://cp.example.com",
        credential_provider=lambda: AgentCredential("sra_x_y"),
        transport=FakeTransport(responder),
    )
    claim = fake_claim()
    result = reduce_scan_results(
        [scan_result_with()],
        policy_version_id="pv",
        policy_digest="d",
        resources_scanned=1,
        duration_ms=1,
    )
    client.submit_result(
        claim["job_id"],
        lease_secret=claim["lease_secret"],
        lease_generation=claim["lease_generation"],
        result=build_safe_result_dict(result),
    )
    sent = captured["body"]
    assert sent["lease_secret"] == claim["lease_secret"]
    assert sent["lease_generation"] == claim["lease_generation"]
    assert "text" not in sent and "content" not in sent


def test_safe_result_dict_never_contains_lease_secret():
    result = reduce_scan_results(
        [scan_result_with(counts={"email": 1})],
        policy_version_id="pv",
        policy_digest="d",
        resources_scanned=1,
        duration_ms=1,
    )
    safe = build_safe_result_dict(result)
    # The safe-result object must never carry transport/authorization metadata.
    assert "lease_secret" not in safe
    assert "lease_generation" not in safe
    # It must still satisfy the strict safe-result contract unchanged.
    assert validate_safe_result(safe) is not None


def test_submit_result_envelope_separates_lease_from_safe_result():
    captured: dict[str, object] = {}

    def responder(url, headers, body):
        from securedact_mcp.agent.transport import HTTPResponse

        if url.endswith("/result"):
            captured["body"] = body
            return HTTPResponse(status=200, body={"status": "succeeded"}, raw_text="")
        return HTTPResponse(status=204, body=None, raw_text="")

    client = ControlPlaneClient(
        "https://cp.example.com",
        credential_provider=lambda: AgentCredential("sra_x_y"),
        transport=FakeTransport(responder),
    )
    claim = fake_claim()
    result = reduce_scan_results(
        [scan_result_with(counts={"email": 1})],
        policy_version_id="pv",
        policy_digest="d",
        resources_scanned=1,
        duration_ms=1,
    )
    safe = build_safe_result_dict(result)
    client.submit_result(
        claim["job_id"],
        lease_secret=claim["lease_secret"],
        lease_generation=claim["lease_generation"],
        result=safe,
    )
    sent = captured["body"]
    # Transport envelope carries lease auth metadata at the top level.
    assert sent["lease_secret"] == claim["lease_secret"]
    assert sent["lease_generation"] == claim["lease_generation"]
    # The safe result is nested and free of any transport/lease fields.
    assert "result" in sent
    nested = sent["result"]
    assert "lease_secret" not in nested
    assert "lease_generation" not in nested
    # The strict validator still only ever sees the nested result object.
    assert validate_safe_result(nested) is not None
    # No denied transport/content fields leak into the nested result.
    for denied in ("text", "content", "lease_secret", "lease_generation"):
        assert denied not in nested


# --- executor -------------------------------------------------------------


def test_execute_job_success():
    claim = JobClaim.from_claim(fake_claim())
    provider = FakeScanProvider([scan_result_with(counts={"email": 1})])
    # engine is unused by the fake provider; pass None is not allowed by type but runtime ok.
    result = execute_job(claim, object(), provider, resolve_policy(claim.policy))  # type: ignore[arg-type]
    assert result.status == "succeeded"
    assert result.categories == ["email"]


def test_execute_job_lease_expired_raises():
    import time as _t

    claim_dict = fake_claim()
    claim_dict["lease_expires_at"] = _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime(_t.time() - 10))
    claim = JobClaim.from_claim(claim_dict)
    provider = FakeScanProvider([scan_result_with()])
    from securedact_mcp.agent.errors import LeaseError

    with pytest.raises(LeaseError):
        execute_job(claim, object(), provider, resolve_policy(claim.policy))  # type: ignore[arg-type]


def test_execute_job_provider_error_is_fail_closed():
    claim = JobClaim.from_claim(fake_claim())
    provider = FakeScanProvider([], error=RuntimeError("boom"))
    from securedact_mcp.agent.errors import JobExecutionError

    with pytest.raises(JobExecutionError):
        execute_job(claim, object(), provider, resolve_policy(claim.policy))  # type: ignore[arg-type]


def test_agent_registration_error_accepts_code_and_status() -> None:
    # Regression: AgentRegistrationError must carry the structured control-plane
    # code/status that ControlPlaneClient passes on a non-201 registration.
    err = AgentRegistrationError("rejected", code="agent_token_invalid", status=422)
    assert err.message == "rejected"
    assert err.code == "agent_token_invalid"
    assert err.status == 422
    assert isinstance(err, Exception)

    # Defaults are preserved for backward-compatible single-argument calls.
    plain = AgentRegistrationError("no detail")
    assert plain.message == "no detail"
    assert plain.code is None
    assert plain.status is None


# --- JWKS retrieval (GET, unauthenticated) -----------------------------------


def test_get_jwks_uses_get_not_post():
    transport = FakeTransport()
    client = ControlPlaneClient(
        "https://cp.example.com",
        credential_provider=lambda: AgentCredential("sra_x_y"),
        transport=transport,
    )
    client.get_jwks()
    # JWKS must go out as GET, never as an authenticated POST.
    assert transport.get_requests, "expected a GET request"
    assert not transport.requests, "jwks must not be a POST"


def test_get_jwks_correct_url():
    transport = FakeTransport()
    client = ControlPlaneClient(
        "https://cp.example.com/",
        credential_provider=lambda: AgentCredential("sra_x_y"),
        transport=transport,
    )
    client.get_jwks()
    url, _headers = transport.get_requests[-1]
    assert url == "https://cp.example.com/.well-known/jwks.json"


def test_get_jwks_sends_no_authorization_header():
    transport = FakeTransport()
    client = ControlPlaneClient(
        "https://cp.example.com",
        credential_provider=lambda: AgentCredential("sra_x_y"),
        transport=transport,
    )
    client.get_jwks()
    _url, headers = transport.get_requests[-1]
    assert "Authorization" not in headers
    assert headers.get("User-Agent") == "securedact-mcp-agent"


def test_get_jwks_valid_keys_response_succeeds():
    def responder(url, headers, body):
        from securedact_mcp.agent.transport import HTTPResponse

        if url.endswith("/.well-known/jwks.json"):
            return HTTPResponse(status=200, body={"keys": [{"kid": "k1"}]}, raw_text="")
        return HTTPResponse(status=200, body={}, raw_text="")

    transport = FakeTransport(responder)
    client = ControlPlaneClient(
        "https://cp.example.com",
        credential_provider=lambda: AgentCredential("sra_x_y"),
        transport=transport,
    )
    keys = client.get_jwks()
    assert keys == {"keys": [{"kid": "k1"}]}


def test_get_jwks_non_200_fails_safely():
    def responder(url, headers, body):
        from securedact_mcp.agent.transport import HTTPResponse

        if url.endswith("/.well-known/jwks.json"):
            return HTTPResponse(
                status=503, body={"error": {"code": "unavailable", "message": "x"}}, raw_text=""
            )
        return HTTPResponse(status=200, body={}, raw_text="")

    transport = FakeTransport(responder)
    client = ControlPlaneClient(
        "https://cp.example.com",
        credential_provider=lambda: AgentCredential("sra_x_y"),
        transport=transport,
    )
    with pytest.raises(ControlPlaneError):
        client.get_jwks()


def test_authenticated_operations_remain_post():
    captured: dict[str, object] = {}

    def responder(url, headers, body):
        from securedact_mcp.agent.transport import HTTPResponse

        if url.endswith("/v1/agents/heartbeat"):
            captured["heartbeat"] = (url, headers, body)
            return HTTPResponse(status=200, body={}, raw_text="")
        if url.endswith("/v1/entitlements/activate"):
            captured["activate"] = (url, headers, body)
            return HTTPResponse(status=200, body={"entitlement": "jwt"}, raw_text="")
        return HTTPResponse(status=200, body={}, raw_text="")

    transport = FakeTransport(responder)
    client = ControlPlaneClient(
        "https://cp.example.com",
        credential_provider=lambda: AgentCredential("sra_x_y"),
        transport=transport,
    )
    client.heartbeat(agent_version="1", capabilities=AgentCapabilities.default())
    client.activate_entitlement()
    # No GET requests may have been issued for authenticated operations.
    assert not transport.get_requests
    # Authenticated POSTs must carry the credential.
    for key in ("heartbeat", "activate"):
        _url, headers, _body = captured[key]  # type: ignore[index]
        assert headers.get("Authorization") == "Bearer sra_x_y"
