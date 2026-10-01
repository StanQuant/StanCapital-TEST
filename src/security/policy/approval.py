"""S08 B+ 審批工作流核心。

這裡只做商業化必要的狀態機與 token metadata；完整 UI、通知、簽核矩陣留給後續切片。
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, cast

from ulid import ULID

from src.security.policy.errors import ApprovalWorkflowError
from src.security.policy.types import PolicyEffect

if TYPE_CHECKING:
    from src.security.policy.types import ApprovalRequirement, PolicyDecision, PolicyRequest


def _new_id() -> str:
    return str(ULID())


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ApprovalStatus(StrEnum):
    """審批狀態。"""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    ESCALATED = "escalated"


@dataclass(frozen=True, slots=True)
class ApprovalToken:
    """核准後給 S22 Gateway 驗證重試動作用。"""

    token_id: str
    tenant_id: str
    approval_case_id: str
    approved_by: str
    expires_at: datetime

    def __post_init__(self) -> None:
        for field_name in ("token_id", "tenant_id", "approval_case_id", "approved_by"):
            if not getattr(self, field_name):
                raise ValueError(f"{field_name} 不可為空")
        if self.expires_at.tzinfo is None:
            raise ValueError("expires_at 必須是 tz-aware 時間")


@dataclass(frozen=True, slots=True)
class ApprovalCase:
    """一筆審批案件；狀態轉換回傳新物件，避免原地改寫。"""

    tenant_id: str
    request_id: str
    subject_id: str
    action: str
    resource_id: str
    approver_role: str
    trace_id: str
    timeout_seconds: int
    escalation_role: str | None = None
    status: ApprovalStatus = ApprovalStatus.PENDING
    approval_case_id: str = field(default_factory=_new_id)
    created_at: datetime = field(default_factory=_utc_now)
    decided_by: str | None = None
    decision_reason: str | None = None
    token: ApprovalToken | None = None

    def __post_init__(self) -> None:
        for field_name in (
            "tenant_id",
            "request_id",
            "subject_id",
            "action",
            "resource_id",
            "approver_role",
            "trace_id",
            "approval_case_id",
        ):
            if not getattr(self, field_name):
                raise ValueError(f"{field_name} 不可為空")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds 必須大於 0")
        if self.created_at.tzinfo is None:
            raise ValueError("created_at 必須是 tz-aware 時間")
        if self.escalation_role == "":
            raise ValueError("escalation_role 不可為空字串")

    def approve(self, *, approved_by: str, ttl_seconds: int = 900) -> ApprovalCase:
        """核准案件並產生 token。"""
        self._ensure_pending()
        if not approved_by:
            raise ApprovalWorkflowError("approved_by 不可為空")
        if ttl_seconds <= 0:
            raise ApprovalWorkflowError("ttl_seconds 必須大於 0")
        token = ApprovalToken(
            token_id=_new_id(),
            tenant_id=self.tenant_id,
            approval_case_id=self.approval_case_id,
            approved_by=approved_by,
            expires_at=_utc_now() + timedelta(seconds=ttl_seconds),
        )
        return replace(
            self,
            status=ApprovalStatus.APPROVED,
            decided_by=approved_by,
            decision_reason="approved",
            token=token,
        )

    def reject(self, *, rejected_by: str, reason: str) -> ApprovalCase:
        """拒絕案件。"""
        self._ensure_pending()
        if not rejected_by:
            raise ApprovalWorkflowError("rejected_by 不可為空")
        if not reason:
            raise ApprovalWorkflowError("reason 不可為空")
        return replace(
            self,
            status=ApprovalStatus.REJECTED,
            decided_by=rejected_by,
            decision_reason=reason,
        )

    def expire(self, *, now: datetime | None = None) -> ApprovalCase:
        """逾時案件。未到期不可手動 expire。"""
        self._ensure_pending()
        now = now or _utc_now()
        if now.tzinfo is None:
            raise ApprovalWorkflowError("now 必須是 tz-aware 時間")
        if now < self.created_at + timedelta(seconds=self.timeout_seconds):
            raise ApprovalWorkflowError("approval case 尚未逾時")
        return replace(self, status=ApprovalStatus.EXPIRED, decision_reason="expired")

    def escalate(self, *, escalated_by: str, reason: str) -> ApprovalCase:
        """升級案件，保留給未來多層簽核。"""
        self._ensure_pending()
        if not self.escalation_role:
            raise ApprovalWorkflowError("此 approval case 未設定 escalation_role")
        if not escalated_by:
            raise ApprovalWorkflowError("escalated_by 不可為空")
        if not reason:
            raise ApprovalWorkflowError("reason 不可為空")
        return replace(
            self,
            status=ApprovalStatus.ESCALATED,
            decided_by=escalated_by,
            decision_reason=reason,
        )

    def _ensure_pending(self) -> None:
        if self.status is not ApprovalStatus.PENDING:
            raise ApprovalWorkflowError(f"approval case 已非 pending: {self.status.value}")


class ApprovalWorkflow:
    """最小審批狀態機。"""

    def create_case(
        self,
        *,
        tenant_id: str,
        request_id: str,
        subject_id: str,
        action: str,
        resource_id: str,
        approver_role: str,
        trace_id: str,
        timeout_seconds: int,
        escalation_role: str | None = None,
    ) -> ApprovalCase:
        return ApprovalCase(
            tenant_id=tenant_id,
            request_id=request_id,
            subject_id=subject_id,
            action=action,
            resource_id=resource_id,
            approver_role=approver_role,
            trace_id=trace_id,
            timeout_seconds=timeout_seconds,
            escalation_role=escalation_role,
        )

    def open_for_decision(self, request: PolicyRequest, decision: PolicyDecision) -> ApprovalCase:
        """把 require_approval 的 PolicyDecision 接成審批案件。

        這是 S08 評估器與審批工作流之間的橋：評估器判出 require_approval、決策帶著
        approval 設定，這裡用同一筆 request 的主體/動作/資源開出可追蹤的審批案件，
        避免「判了要審批卻沒人開案」的孤島。非 require_approval 決策一律拒絕(fail-closed)。
        """
        if decision.effect is not PolicyEffect.REQUIRE_APPROVAL:
            raise ApprovalWorkflowError("只有 require_approval 決策可開審批案件")
        # PolicyDecision 不變式保證 require_approval 必帶 approval；cast 僅作型別收斂。
        requirement = cast("ApprovalRequirement", decision.approval)
        return self.create_case(
            tenant_id=request.tenant_id,
            request_id=decision.decision_id,
            subject_id=request.subject_id,
            action=request.action,
            resource_id=request.resource_id,
            approver_role=requirement.approver_role,
            trace_id=request.trace_id,
            timeout_seconds=requirement.timeout_seconds,
            escalation_role=requirement.escalation_role,
        )
