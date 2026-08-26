# SPDX-License-Identifier: Apache-2.0
"""Execution/reduction aggregation tests for the managed agent (AGENT-TEST)."""

from __future__ import annotations

from securedact_core.connectors.scan import ScanSeverity, ScanStatus

from securedact_mcp.agent.reducer import reduce_scan_results
from tests.unit.agent_helpers import scan_result_with


def test_reduce_aggregates_multiple_files_most_restrictive():
    results = [
        scan_result_with(status=ScanStatus.COMPLETED, counts={"email": 1}),
        scan_result_with(status=ScanStatus.REVIEW_REQUIRED, counts={"person": 2}),
        scan_result_with(status=ScanStatus.COMPLETED, counts={"credit_card_number": 1}),
    ]
    out = reduce_scan_results(results, policy_version_id="pv", policy_digest="d", resources_scanned=3, duration_ms=42)
    # Most restrictive decision across files is review.
    assert out.policy_decision == "review"
    assert out.supported_action == "review"
    assert out.review_required is True
    assert out.severity == "medium"
    assert out.resources_scanned == 3
    assert out.counts == {"email": 1, "person": 2, "credit_card": 1}
    assert out.categories == ["credit_card", "email", "person"]


def test_reduce_block_wins_over_review():
    results = [
        scan_result_with(status=ScanStatus.REVIEW_REQUIRED, counts={"person": 1}),
        scan_result_with(status=ScanStatus.BLOCKED, severity=ScanSeverity.HIGH, counts={"bsn": 1}),
    ]
    out = reduce_scan_results(results, policy_version_id="pv", policy_digest="d", resources_scanned=2, duration_ms=1)
    assert out.policy_decision == "block"
    assert out.supported_action == "block"
    assert out.severity == "high"


def test_reduce_secret_label_escalates_severity():
    results = [scan_result_with(status=ScanStatus.COMPLETED, counts={"api_token": 1})]
    out = reduce_scan_results(results, policy_version_id="pv", policy_digest="d", resources_scanned=1, duration_ms=1)
    # api_key -> secret label -> severity high.
    assert out.severity == "high"
    assert "secret" in out.categories


def test_reduce_mixed_errors_become_warnings_not_failure():
    from securedact_core.connectors.scan import ScanErrorCode

    results = [
        scan_result_with(status=ScanStatus.COMPLETED, counts={"email": 2}),
        scan_result_with(status=ScanStatus.ERROR, error_code=ScanErrorCode.UNSUPPORTED_FORMAT),
    ]
    out = reduce_scan_results(results, policy_version_id="pv", policy_digest="d", resources_scanned=2, duration_ms=1)
    assert out.status == "succeeded"
    assert out.resources_scanned == 2
    assert out.safe_error_code is None
