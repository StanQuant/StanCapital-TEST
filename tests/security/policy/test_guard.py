"""PolicyGuard 測試。"""

from __future__ import annotations

import logging
from typing import Any

import pytest
from src.security.policy.approval import ApprovalCase, ApprovalWorkflow
from src.security.policy.evaluator import PolicyEvaluator
from src.security.policy.guard import PolicyGuard
from src.security.policy.ports import (
    InMemoryApprovalCaseSink,
    InMemoryAuditMetadataSink,
    NoopAuditMetadataSink,
)
from src.security.policy.types import PolicyEffect, PolicyRequest

from .conftest import base_policy_set, base_request


class FailingAuditSink:
    def record(self, metadata: dict[str, Any]) -> None:
        raise RuntimeError("audit down")


class FailingApprovalCaseSink:
    def record(self, case: ApprovalCase) -> None:
        raise RuntimeError("approval queue down")


def _approval_request() -> PolicyRequest:
    return base_request(
        action="submit_real_order",
        resource_id="order-1",
        atr_risk_score=75,
        atr_risk_category="high",
    )


def test_policy_guard_records_all_decision_metadata() -> None:
    sink = InMemoryAuditMetadataSink()
    decision = PolicyGuard(PolicyEvaluator((base_policy_set(),)), audit_sink=sink).evaluate(
        base_request()
    )
    assert decision.effect is PolicyEffect.ALLOW
    assert sink.records[0]["effect"] == "allow"
    NoopAuditMetadataSink().record({})


def test_policy_guard_fail_closed_when_mandatory_audit_fails(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.CRITICAL):
        decision = PolicyGuard(
            PolicyEvaluator((base_policy_set(),)),
            audit_sink=FailingAuditSink(),
        ).evaluate(base_request(action="external_upload", sensitivity_level=5))
    assert decision.effect is PolicyEffect.DENY
    assert decision.reason == "強制稽核 sink 失敗 → fail-closed deny"
    assert decision.audit_mandatory is True
    assert any(r.getMessage().startswith("Policy audit sink 失敗") for r in caplog.records)


def test_policy_guard_keeps_low_risk_allow_when_non_mandatory_audit_fails() -> None:
    decision = PolicyGuard(
        PolicyEvaluator((base_policy_set(),)),
        audit_sink=FailingAuditSink(),
    ).evaluate(base_request())
    assert decision.effect is PolicyEffect.ALLOW


def test_policy_guard_opens_approval_case_on_require_approval() -> None:
    case_sink = InMemoryApprovalCaseSink()
    decision = PolicyGuard(
        PolicyEvaluator((base_policy_set(),)),
        audit_sink=InMemoryAuditMetadataSink(),
        approval_workflow=ApprovalWorkflow(),
        approval_case_sink=case_sink,
    ).evaluate(_approval_request())
    assert decision.effect is PolicyEffect.REQUIRE_APPROVAL
    assert len(case_sink.cases) == 1
    assert case_sink.cases[0].request_id == decision.decision_id
    assert case_sink.cases[0].approver_role == "security_officer"


def test_policy_guard_without_workflow_does_not_open_case() -> None:
    decision = PolicyGuard(
        PolicyEvaluator((base_policy_set(),)),
        audit_sink=InMemoryAuditMetadataSink(),
    ).evaluate(_approval_request())
    assert decision.effect is PolicyEffect.REQUIRE_APPROVAL


def test_policy_guard_allow_does_not_open_case_even_with_workflow() -> None:
    case_sink = InMemoryApprovalCaseSink()
    decision = PolicyGuard(
        PolicyEvaluator((base_policy_set(),)),
        audit_sink=InMemoryAuditMetadataSink(),
        approval_workflow=ApprovalWorkflow(),
        approval_case_sink=case_sink,
    ).evaluate(base_request())
    assert decision.effect is PolicyEffect.ALLOW
    assert case_sink.cases == []


def test_policy_guard_uses_noop_case_sink_by_default() -> None:
    decision = PolicyGuard(
        PolicyEvaluator((base_policy_set(),)),
        audit_sink=InMemoryAuditMetadataSink(),
        approval_workflow=ApprovalWorkflow(),
    ).evaluate(_approval_request())
    assert decision.effect is PolicyEffect.REQUIRE_APPROVAL


def test_policy_guard_fail_closed_when_approval_case_sink_fails(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.CRITICAL):
        decision = PolicyGuard(
            PolicyEvaluator((base_policy_set(),)),
            audit_sink=InMemoryAuditMetadataSink(),
            approval_workflow=ApprovalWorkflow(),
            approval_case_sink=FailingApprovalCaseSink(),
        ).evaluate(_approval_request())
    assert decision.effect is PolicyEffect.DENY
    assert decision.reason == "審批案件 sink 失敗 → fail-closed deny"
    assert decision.audit_mandatory is True
    assert any(r.getMessage().startswith("Policy 審批案件 sink 失敗") for r in caplog.records)
