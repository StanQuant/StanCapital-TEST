"""Approval workflow 測試。"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest
from src.security.policy.approval import (
    ApprovalCase,
    ApprovalStatus,
    ApprovalToken,
    ApprovalWorkflow,
)
from src.security.policy.errors import ApprovalWorkflowError
from src.security.policy.evaluator import PolicyEvaluator
from src.security.policy.types import PolicyEffect

from .conftest import base_policy_set, base_request, raises_starting


def _case() -> ApprovalCase:
    return ApprovalWorkflow().create_case(
        tenant_id="stanley",
        request_id="request-1",
        subject_id="agent-1",
        action="submit_real_order",
        resource_id="order-1",
        approver_role="security_officer",
        trace_id="trace-1",
        timeout_seconds=60,
        escalation_role="compliance_officer",
    )


def test_approval_status_values_are_stable_contracts() -> None:
    assert {status.name: status.value for status in ApprovalStatus} == {
        "PENDING": "pending",
        "APPROVED": "approved",
        "REJECTED": "rejected",
        "EXPIRED": "expired",
        "ESCALATED": "escalated",
    }


def test_approval_case_approve_reject_expire_and_escalate() -> None:
    case = _case()
    approved = case.approve(approved_by="stanley")
    assert approved.status is ApprovalStatus.APPROVED
    assert approved.decision_reason == "approved"
    assert approved.token is not None
    assert approved.token.approved_by == "stanley"
    rejected = _case().reject(rejected_by="stanley", reason="too risky")
    assert rejected.status is ApprovalStatus.REJECTED
    assert rejected.decision_reason == "too risky"
    expired = _case().expire(now=_case().created_at + timedelta(seconds=61))
    assert expired.status is ApprovalStatus.EXPIRED
    assert expired.decision_reason == "expired"
    escalated = _case().escalate(escalated_by="stanley", reason="needs manager")
    assert escalated.status is ApprovalStatus.ESCALATED
    assert escalated.decided_by == "stanley"
    assert escalated.decision_reason == "needs manager"


def test_approval_case_and_token_are_frozen_slotted_value_objects() -> None:
    case = _case()
    assert not hasattr(case, "__dict__")
    assert case.status is ApprovalStatus.PENDING
    assert case.decided_by is None
    assert case.decision_reason is None
    assert case.token is None
    with pytest.raises(FrozenInstanceError):
        case.status = ApprovalStatus.APPROVED  # type: ignore[misc]
    token = case.approve(approved_by="stanley").token
    assert token is not None
    assert not hasattr(token, "__dict__")
    with pytest.raises(FrozenInstanceError):
        token.approved_by = "x"  # type: ignore[misc]


def test_approval_case_timeout_and_ttl_boundaries() -> None:
    # timeout_seconds=1 仍合法(殺 <=0 → <=1 邊界變異)
    one_sec = ApprovalWorkflow().create_case(
        tenant_id="stanley",
        request_id="r",
        subject_id="s",
        action="a",
        resource_id="res",
        approver_role="role",
        trace_id="t",
        timeout_seconds=1,
    )
    assert one_sec.timeout_seconds == 1
    case = _case()
    # 預設 ttl=900(殺 900 → 901)；核准在 created_at 之後，故 delta 介於 [900, 901)。
    default_token = case.approve(approved_by="stanley").token
    assert default_token is not None
    delta = default_token.expires_at - case.created_at
    assert timedelta(seconds=900) <= delta < timedelta(seconds=901)
    # ttl_seconds=1 仍合法(殺 <=0 → <=1)
    short = case.approve(approved_by="stanley", ttl_seconds=1).token
    assert short is not None
    # 剛好到期(now == created_at + timeout)即可 expire(殺 < → <=)
    expired = case.expire(now=case.created_at + timedelta(seconds=case.timeout_seconds))
    assert expired.status is ApprovalStatus.EXPIRED


def test_approval_case_rejects_invalid_transitions_and_inputs() -> None:
    case = _case()
    with raises_starting(ApprovalWorkflowError, "approved_by 不可為空"):
        case.approve(approved_by="")
    with raises_starting(ApprovalWorkflowError, "ttl_seconds 必須大於 0"):
        case.approve(approved_by="stanley", ttl_seconds=0)
    with raises_starting(ApprovalWorkflowError, "rejected_by 不可為空"):
        case.reject(rejected_by="", reason="x")
    with raises_starting(ApprovalWorkflowError, "reason 不可為空"):
        case.reject(rejected_by="stanley", reason="")
    with raises_starting(ApprovalWorkflowError, "now 必須是 tz-aware 時間"):
        case.expire(now=datetime(2026, 6, 23))
    with raises_starting(ApprovalWorkflowError, "approval case 尚未逾時"):
        case.expire(now=case.created_at)
    with raises_starting(ApprovalWorkflowError, "escalated_by 不可為空"):
        case.escalate(escalated_by="", reason="x")
    with raises_starting(ApprovalWorkflowError, "reason 不可為空"):
        case.escalate(escalated_by="stanley", reason="")
    with raises_starting(ApprovalWorkflowError, "approval case 已非 pending"):
        case.approve(approved_by="stanley").reject(rejected_by="stanley", reason="late")
    with raises_starting(ApprovalWorkflowError, "此 approval case 未設定 escalation_role"):
        ApprovalCase(
            tenant_id="stanley",
            request_id="request-1",
            subject_id="agent-1",
            action="submit_real_order",
            resource_id="order-1",
            approver_role="security_officer",
            trace_id="trace-1",
            timeout_seconds=60,
        ).escalate(escalated_by="stanley", reason="needs manager")


def test_open_for_decision_bridges_require_approval_decision_to_case() -> None:
    request = base_request(
        action="submit_real_order",
        resource_id="order-1",
        atr_risk_score=75,
        atr_risk_category="high",
    )
    decision = PolicyEvaluator((base_policy_set(),)).evaluate(request)
    assert decision.effect is PolicyEffect.REQUIRE_APPROVAL
    case = ApprovalWorkflow().open_for_decision(request, decision)
    assert case.status is ApprovalStatus.PENDING
    assert case.request_id == decision.decision_id
    assert case.subject_id == request.subject_id
    assert case.action == "submit_real_order"
    assert case.resource_id == "order-1"
    assert case.approver_role == "security_officer"
    assert case.escalation_role == "compliance_officer"
    assert case.timeout_seconds == 900


def test_open_for_decision_rejects_non_approval_decision() -> None:
    request = base_request()
    decision = PolicyEvaluator((base_policy_set(),)).evaluate(request)
    assert decision.effect is PolicyEffect.ALLOW
    with raises_starting(ApprovalWorkflowError, "只有 require_approval 決策可開審批案件"):
        ApprovalWorkflow().open_for_decision(request, decision)


def test_approval_models_validate_required_fields() -> None:
    with raises_starting(ValueError, "token_id 不可為空"):
        ApprovalToken("", "stanley", "case-1", "stanley", datetime(2026, 6, 23, tzinfo=UTC))
    with raises_starting(ValueError, "expires_at 必須是 tz-aware 時間"):
        ApprovalToken("token-1", "stanley", "case-1", "stanley", datetime(2026, 6, 23))
    with raises_starting(ValueError, "tenant_id 不可為空"):
        ApprovalCase("", "request", "subject", "action", "resource", "role", "trace", 60)
    with raises_starting(ValueError, "timeout_seconds 必須大於 0"):
        ApprovalCase("stanley", "request", "subject", "action", "resource", "role", "trace", 0)
    with raises_starting(ValueError, "created_at 必須是 tz-aware 時間"):
        ApprovalCase(
            "stanley",
            "request",
            "subject",
            "action",
            "resource",
            "role",
            "trace",
            60,
            created_at=datetime(2026, 6, 23),
        )
    with raises_starting(ValueError, "escalation_role 不可為空字串"):
        ApprovalCase("stanley", "request", "subject", "action", "resource", "role", "trace", 60, "")
