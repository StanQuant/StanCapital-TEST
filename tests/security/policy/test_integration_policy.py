"""S08 跨切片整合測試：證明 S06 / S07 的真實型別能接進 S08。

這些測試不需 docker，但標記為 integration：它們驗證的是切片之間的接線(完整 live path
由 S22 Gateway 串起來)，不是 S08 自身的單元行為。重點是「不要有孤島」——S07 的
ThreatScore、S06 的 ApprovalRequestEvent 都要真的能流進 S08。
"""

from __future__ import annotations

import pytest
from src.governance.access_guard import ApprovalRequestEvent
from src.governance.rbac.permissions import Action, Resource
from src.governance.rbac.roles import Role
from src.security.atr.types import ThreatScore, level_for_score
from src.security.policy.approval import ApprovalStatus, ApprovalWorkflow
from src.security.policy.dsl import load_policy_set
from src.security.policy.evaluator import PolicyEvaluator
from src.security.policy.guard import PolicyGuard
from src.security.policy.ports import InMemoryApprovalCaseSink, InMemoryAuditMetadataSink
from src.security.policy.types import ApprovalRequirement, PolicyEffect

from .conftest import base_policy_set, base_request

_BASE_POLICY_PATH = "policies/security/base.yaml"


@pytest.mark.integration
def test_s07_threatscore_feeds_policy_decision() -> None:
    """S07 接點：真實 ThreatScore 的 risk_score/risk_category 餵進 S08 → require_approval。"""
    score = ThreatScore(
        value=75,
        level=level_for_score(75),
        triggered_rules=(),
        context_multiplier=1.0,
        agent_id="agent-1",
        tenant_id="stanley",
        risk_category="high",
        trace_id="trace-atr",
    )
    request = base_request(action="submit_real_order", resource_id="order-1").with_atr(
        risk_score=score.value, risk_category=score.risk_category
    )
    decision = PolicyEvaluator((base_policy_set(),)).evaluate(request)
    assert decision.effect is PolicyEffect.REQUIRE_APPROVAL
    assert request.atr_risk_score == 75
    assert request.atr_risk_category == "high"


@pytest.mark.integration
def test_s07_critical_threatscore_drives_external_upload_deny() -> None:
    """S07 接點：critical(>=81) ThreatScore 讓外部上傳直接被 S08 政策擋下。"""
    score = ThreatScore(
        value=85,
        level=level_for_score(85),
        triggered_rules=(),
        context_multiplier=1.0,
        agent_id="agent-1",
        tenant_id="stanley",
        risk_category="critical",
        trace_id="trace-atr",
    )
    request = base_request(
        action="external_upload", resource_type="document", resource_id="doc-1", sensitivity_level=2
    ).with_atr(risk_score=score.value, risk_category=score.risk_category)
    decision = PolicyEvaluator((load_policy_set(_BASE_POLICY_PATH),)).evaluate(request)
    assert decision.effect is PolicyEffect.DENY
    assert "deny-critical-external-upload" in decision.matched_rule_ids


@pytest.mark.integration
def test_s06_approval_request_event_opens_policy_approval_case() -> None:
    """S06 接點：ApprovalRequestEvent(真實型別)能映射成 S08 ApprovalCase 並走完核准。"""
    event = ApprovalRequestEvent(
        tenant_id="stanley",
        user_id="trader-1",
        role=Role.USER,
        resource=Resource.ORDER,
        action=Action.WRITE,
        sensitivity_level=5,
        risk_category="high",
        matched_policy="abac.real_order.require_approval",
        reason="高風險真實下單需審批",
    )
    # live path 由 S22 Gateway 負責這層映射；此測試證明欄位接得起來、不是孤島。
    requirement = ApprovalRequirement(
        approver_role=Role.SECURITY_OFFICER.value,
        timeout_seconds=900,
        escalation_role=Role.COMPLIANCE_OFFICER.value,
    )
    case = ApprovalWorkflow().create_case(
        tenant_id=event.tenant_id,
        request_id=f"abac:{event.user_id}",
        subject_id=event.user_id,
        action=event.action.value,
        resource_id=event.resource.value,
        approver_role=requirement.approver_role,
        trace_id="trace-abac",
        timeout_seconds=requirement.timeout_seconds,
        escalation_role=requirement.escalation_role,
    )
    assert case.status is ApprovalStatus.PENDING
    assert case.tenant_id == "stanley"
    assert case.subject_id == "trader-1"
    assert case.action == "write"
    assert case.resource_id == "order"
    assert case.approver_role == "security_officer"

    approved = case.approve(approved_by="security-officer-1")
    assert approved.status is ApprovalStatus.APPROVED
    assert approved.token is not None


@pytest.mark.integration
def test_full_s08_path_evaluate_audit_and_open_case() -> None:
    """S08 全鏈：guard 評估 → 送稽核 metadata → require_approval 自動開審批案件。"""
    audit_sink = InMemoryAuditMetadataSink()
    case_sink = InMemoryApprovalCaseSink()
    guard = PolicyGuard(
        PolicyEvaluator((base_policy_set(),)),
        audit_sink=audit_sink,
        approval_workflow=ApprovalWorkflow(),
        approval_case_sink=case_sink,
    )
    decision = guard.evaluate(
        base_request(
            action="submit_real_order",
            resource_id="order-1",
            atr_risk_score=75,
            atr_risk_category="high",
        )
    )
    assert decision.effect is PolicyEffect.REQUIRE_APPROVAL
    assert audit_sink.records[0]["effect"] == "require_approval"
    assert len(case_sink.cases) == 1
    assert case_sink.cases[0].request_id == decision.decision_id
