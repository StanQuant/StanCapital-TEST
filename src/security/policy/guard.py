"""Policy Guard · 評估、audit metadata 與審批案件編排。"""

from __future__ import annotations

import logging

from src.security.policy.approval import ApprovalWorkflow
from src.security.policy.evaluator import PolicyEvaluator
from src.security.policy.ports import (
    ApprovalCaseSink,
    AuditMetadataSink,
    NoopApprovalCaseSink,
    NoopAuditMetadataSink,
)
from src.security.policy.types import PolicyDecision, PolicyEffect, PolicyRequest

logger = logging.getLogger(__name__)


class PolicyGuard:
    """S08 編排入口。

    evaluator 保持純淨。guard 負責三件編排：送 audit metadata、在 require_approval 時
    開出審批案件、並維持 fail-closed——強制稽核或審批案件記錄失敗時，決策一律退成 deny。
    給了 approval_workflow 才會開案，未給時行為與舊版相容(只送稽核)。
    """

    def __init__(
        self,
        evaluator: PolicyEvaluator,
        *,
        audit_sink: AuditMetadataSink | None = None,
        approval_workflow: ApprovalWorkflow | None = None,
        approval_case_sink: ApprovalCaseSink | None = None,
    ) -> None:
        self._evaluator = evaluator
        self._audit_sink = audit_sink or NoopAuditMetadataSink()
        self._approval_workflow = approval_workflow
        self._approval_case_sink = approval_case_sink or NoopApprovalCaseSink()

    def evaluate(self, request: PolicyRequest) -> PolicyDecision:
        """評估、送 audit metadata、必要時開審批案件。"""
        decision = self._evaluator.evaluate(request)
        try:
            self._audit_sink.record(decision.to_audit_metadata())
        except Exception as sink_error:
            logger.critical(
                "Policy audit sink 失敗: tenant=%s decision=%s reason=%s",
                request.tenant_id,
                decision.decision_id,
                sink_error,
            )
            if decision.audit_mandatory:
                return _audit_failure_decision(request, decision)
        return self._with_approval_case(request, decision)

    def _with_approval_case(
        self, request: PolicyRequest, decision: PolicyDecision
    ) -> PolicyDecision:
        """require_approval 決策接成審批案件並記錄；接好評估器→審批工作流的橋。"""
        if decision.effect is not PolicyEffect.REQUIRE_APPROVAL or self._approval_workflow is None:
            return decision
        case = self._approval_workflow.open_for_decision(request, decision)
        try:
            self._approval_case_sink.record(case)
        except Exception as sink_error:
            logger.critical(
                "Policy 審批案件 sink 失敗: tenant=%s decision=%s reason=%s",
                request.tenant_id,
                decision.decision_id,
                sink_error,
            )
            return _approval_failure_decision(request, decision)
        return decision


def _audit_failure_decision(request: PolicyRequest, original: PolicyDecision) -> PolicyDecision:
    return PolicyDecision(
        tenant_id=request.tenant_id,
        effect=PolicyEffect.DENY,
        matched_rule_ids=original.matched_rule_ids,
        policy_set_ids=original.policy_set_ids,
        policy_versions=original.policy_versions,
        reason="強制稽核 sink 失敗 → fail-closed deny",
        trace_id=request.trace_id,
        requires_approval=False,
        audit_required=True,
        audit_mandatory=True,
    )


def _approval_failure_decision(request: PolicyRequest, original: PolicyDecision) -> PolicyDecision:
    return PolicyDecision(
        tenant_id=request.tenant_id,
        effect=PolicyEffect.DENY,
        matched_rule_ids=original.matched_rule_ids,
        policy_set_ids=original.policy_set_ids,
        policy_versions=original.policy_versions,
        reason="審批案件 sink 失敗 → fail-closed deny",
        trace_id=request.trace_id,
        requires_approval=False,
        audit_required=True,
        audit_mandatory=True,
    )
