"""L11 治理 · 存取守門(把「權限拒絕」接上不可變稽核)。

為什麼放在 governance 層而不放進 rbac/ 內:
  與 rbac_admin 同理——import-linter 鐵則 `rbac-not-import-audit` 禁止 rbac
  反向 import audit。守門要同時用到 rbac(警衛)與 audit(寫拒絕證據),
  只能放在兩者上層的 governance。

為什麼稽核拒絕做在「守門」而不做在「警衛」內部(2026-06-18 Stanley 裁決 · 彻底版 B):
  - RBACChecker 是「純判斷、要極快」的熱路徑,刻意不碰資料庫/不寫稽核
    (import-linter 鐵則就是為了保護它的純淨)。
  - 守門是「請求進來、身分已驗證」的邊界,手上有完整 AuditContext
    (role / ip / user_agent 都在),稽核拒絕沒有「role 填不出來」的建模難題。
  - 把守門訂為唯一合法入口,覆蓋率即等於「警衛層直接發拒絕事件」那條路,
    卻不犧牲警衛純淨、不踩「新增中性角色」的憲法級紅線。
  S22 API Gateway 落地後,以 import-linter 契約強制「非守門模組不得直呼
  RBACChecker.require」即可達成全流量覆蓋(BACKLOG B-009)。

fail-closed 與不變式:
  拒絕證據走「獨立交易」立即提交(不隨呼叫端 rollback 蒸發)。
  寫稽核失敗採 best-effort + CRITICAL 日誌——**絕不把 deny 變 allow,
  也絕不掩蓋原本的 PermissionDeniedError**(拒絕決策永遠如實上拋)。
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.governance.abac.attributes import AccessRequest
from src.governance.abac.decisions import AbacDecision, AbacEffect
from src.governance.abac.errors import ApprovalRequiredError
from src.governance.abac.evaluator import AbacEvaluator
from src.governance.audit.chain import hash_payload
from src.governance.audit.decorator import AuditContext
from src.governance.audit.repository import AuditLogRepository
from src.governance.audit.types import AuditOutcome, AuditRecordInput
from src.governance.rbac.checker import RbacDecision
from src.governance.rbac.errors import PermissionDeniedError
from src.governance.rbac.permissions import Action, Resource
from src.governance.rbac.roles import Role
from src.governance.rbac.types import AccessSnapshot

logger = logging.getLogger(__name__)

# 拒絕稽核的動作名(固定字串,無空白)
DENIED_ACTION = "rbac.access.denied"


def _utc_now() -> datetime:
    # 預設時鐘集中此處,測試可注入固定時鐘(S02 resilience 同款)
    return datetime.now(UTC)


class SupportsRequire(Protocol):
    """守門只依賴警衛的這一個守門式 API(不綁死具體 RBACChecker)。"""

    async def require(
        self, tenant_id: str, user_id: str, resource: Resource, action: Action
    ) -> None:
        """沒權限拋 PermissionDeniedError;有權限靜默返回。"""


class AccessGuard:
    """權限守門 · 唯一合法的權限強制入口。

    建構時注入:
      - checker: 權限警衛(RBACChecker 或任何提供 require 的物件)
      - audit_session_factory: 拒絕證據的獨立交易來源
      - clock: 可選,給測試注入固定時鐘

    用法: `await guard.require(Resource.ORDER, Action.WRITE, audit_ctx=ctx)`
    租戶與使用者一律取自已驗證的 audit_ctx(不另收參數,杜絕越權冒名)。
    """

    def __init__(
        self,
        checker: SupportsRequire,
        audit_session_factory: async_sessionmaker[AsyncSession],
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._checker = checker
        self._audit_session_factory = audit_session_factory
        self._clock = clock

    async def require(self, resource: Resource, action: Action, *, audit_ctx: AuditContext) -> None:
        """強制權限。沒權限時留一筆 FAILED 拒絕稽核,再把例外原樣上拋。

        RBACUnavailableError(資料來源掛掉的 fail-closed 拒絕)不在此攔截:
        那是基礎設施故障、非「權限不足」,且此刻稽核 DB 也可能同時不可用,
        直接上拋由上層告警處理。
        """
        try:
            await self._checker.require(audit_ctx.tenant_id, audit_ctx.user_id, resource, action)
        except PermissionDeniedError:
            await self._record_denial(audit_ctx, resource, action)
            raise

    async def _record_denial(self, ctx: AuditContext, resource: Resource, action: Action) -> None:
        """寫拒絕證據(獨立交易)。任何失敗都吞下並 CRITICAL,不影響拒絕決策。"""
        try:
            async with self._audit_session_factory() as session:
                repository = AuditLogRepository(session, clock=self._clock)
                await repository.append(
                    AuditRecordInput(
                        tenant_id=ctx.tenant_id,
                        user_id=ctx.user_id,
                        role=ctx.role,
                        action=DENIED_ACTION,
                        resource=f"{resource.value}:{action.value}",
                        request_payload_hash=hash_payload(
                            {"resource": resource.value, "action": action.value}
                        ),
                        response_status=AuditOutcome.FAILED,
                        ip_address=ctx.ip_address,
                        user_agent=ctx.user_agent,
                        risk_score=ctx.risk_score,
                    )
                )
                await session.commit()
        except Exception as audit_error:
            # 絕不把 deny 變 allow、也絕不掩蓋原 PermissionDeniedError:
            # 拒絕稽核遺失要很大聲(CRITICAL + 可告警),但決策本身照常上拋
            logger.critical(
                "拒絕稽核寫入失敗(拒絕決策仍生效): tenant=%s user=%s resource=%s action=%s 原因=%s",
                ctx.tenant_id,
                ctx.user_id,
                resource.value,
                action.value,
                audit_error,
            )


# ============================================================================
# S06 · ABAC 守門(RBAC 粗門禁 → ABAC 細審 → 三態)
# ============================================================================

# ABAC 決策的稽核動作名(固定字串,無空白)。RBAC 拒絕沿用 DENIED_ACTION。
ABAC_DENIED_ACTION = "abac.access.denied"
ABAC_APPROVAL_ACTION = "abac.access.approval_required"


class SupportsAbacRbac(Protocol):
    """ABAC 守門對警衛的依賴:載快照(一趟)+ 用快照算 RBAC 決策(純判斷)。"""

    async def load_snapshot(self, tenant_id: str, user_id: str) -> AccessSnapshot | None:
        """載入存取快照;資料來源連不上拋 RBACUnavailableError(fail-closed)。"""

    def authorize_snapshot(
        self, snapshot: AccessSnapshot, resource: Resource, action: Action
    ) -> RbacDecision:
        """給定已存在的快照算 RBAC 決策(純函式)。"""


@dataclass(frozen=True, slots=True)
class ApprovalRequestEvent:
    """需審批事件(D3) · 發進 S03 匯流排給未來 HITL / S08 消費。

    欄位齊全到審批者不需回查就能判斷;不含請求內容明文(只帶屬性與政策)。
    """

    tenant_id: str
    user_id: str
    role: Role
    resource: Resource
    action: Action
    sensitivity_level: int
    risk_category: str
    matched_policy: str | None
    reason: str


class ApprovalEventSink(Protocol):
    """審批事件出口(port) · S22 接到 S03 事件匯流排;測試/離線可用 fake。"""

    async def publish(self, event: ApprovalRequestEvent) -> None:
        """送出審批事件。"""


class AbacAccessGuard:
    """ABAC 守門 · RBAC 過 → ABAC 細審 → Allow / Deny / RequireApproval。

    為什麼是獨立類別(不擴充 AccessGuard):AccessGuard 是 RBAC-only 的拒絕稽核守門
    (S05),其建構子與精確稽核訊息已被測試釘死;ABAC 多了「載快照取權威屬性 + 三態 +
    審批事件」的編排,獨立成類別避免動到 S05 契約。

    單趟快照(D4 + 5ms 預算):load_snapshot 取一趟,既餵 RBAC(authorize_snapshot)
    又取權威使用者屬性(department/region/project)組 AccessRequest,不重複查資料庫。

    短路(D2):RBAC 拒絕直接上拋,不進 ABAC。
    fail-closed:稽核/審批事件寫失敗都不會把 deny/approval 變 allow(決策照常上拋)。
    """

    def __init__(
        self,
        checker: SupportsAbacRbac,
        evaluator: AbacEvaluator,
        audit_session_factory: async_sessionmaker[AsyncSession],
        approval_sink: ApprovalEventSink,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._checker = checker
        self._evaluator = evaluator
        self._audit_session_factory = audit_session_factory
        self._approval_sink = approval_sink
        self._clock = clock

    async def require_abac(
        self,
        resource: Resource,
        action: Action,
        *,
        sensitivity_level: int,
        risk_category: str,
        audit_ctx: AuditContext,
    ) -> None:
        """RBAC 過 → ABAC 細審。Deny 拋 PermissionDeniedError、Approval 拋
        ApprovalRequiredError(都先留稽核);Allow 靜默返回。

        身分(tenant/user/role)與資源屬性(sensitivity/risk_category)由呼叫端的
        audit_ctx 與參數提供;使用者屬性(部門/區域/專案)取自權威快照,呼叫端無法偽冒。
        """
        snapshot = await self._checker.load_snapshot(audit_ctx.tenant_id, audit_ctx.user_id)
        if snapshot is None:
            await self._record_block(audit_ctx, DENIED_ACTION, resource, action)
            raise PermissionDeniedError(
                tenant_id=audit_ctx.tenant_id,
                user_id=audit_ctx.user_id,
                resource=resource,
                action=action,
                roles=(),
                reason="使用者不存在",
            )

        rbac_decision = self._checker.authorize_snapshot(snapshot, resource, action)
        if not rbac_decision.allowed:
            # 短路(D2):RBAC 拒絕不進 ABAC
            await self._record_block(audit_ctx, DENIED_ACTION, resource, action)
            raise PermissionDeniedError(
                tenant_id=audit_ctx.tenant_id,
                user_id=audit_ctx.user_id,
                resource=resource,
                action=action,
                roles=rbac_decision.roles,
                reason=rbac_decision.reason,
            )

        request = AccessRequest(
            user_id=audit_ctx.user_id,
            tenant_id=audit_ctx.tenant_id,
            role=audit_ctx.role,
            department=snapshot.user.department,
            region=snapshot.user.region,
            project=snapshot.user.project,
            sensitivity_level=sensitivity_level,
            risk_category=risk_category,
            requested_resource=resource,
            requested_action=action,
        )
        decision = self._evaluator.evaluate(request)

        if decision.effect is AbacEffect.DENY:
            await self._record_block(audit_ctx, ABAC_DENIED_ACTION, resource, action)
            raise PermissionDeniedError(
                tenant_id=audit_ctx.tenant_id,
                user_id=audit_ctx.user_id,
                resource=resource,
                action=action,
                roles=rbac_decision.roles,
                reason=decision.reason,
            )

        if decision.effect is AbacEffect.REQUIRE_APPROVAL:
            await self._record_block(audit_ctx, ABAC_APPROVAL_ACTION, resource, action)
            await self._publish_approval(request, decision)
            raise ApprovalRequiredError(
                tenant_id=audit_ctx.tenant_id,
                user_id=audit_ctx.user_id,
                resource=resource,
                action=action,
                matched_policy=decision.matched_policy,
                reason=decision.reason,
            )
        # ALLOW → 靜默返回(後續業務寫操作的 @audited 覆蓋,不在此重複記 allow)

    async def _record_block(
        self, ctx: AuditContext, audit_action: str, resource: Resource, action: Action
    ) -> None:
        """留一筆 FAILED 決策稽核(獨立交易)。任何失敗吞下 + CRITICAL,不影響決策。"""
        try:
            async with self._audit_session_factory() as session:
                repository = AuditLogRepository(session, clock=self._clock)
                await repository.append(
                    AuditRecordInput(
                        tenant_id=ctx.tenant_id,
                        user_id=ctx.user_id,
                        role=ctx.role,
                        action=audit_action,
                        resource=f"{resource.value}:{action.value}",
                        request_payload_hash=hash_payload(
                            {"resource": resource.value, "action": action.value}
                        ),
                        response_status=AuditOutcome.FAILED,
                        ip_address=ctx.ip_address,
                        user_agent=ctx.user_agent,
                        risk_score=ctx.risk_score,
                    )
                )
                await session.commit()
        except Exception as audit_error:
            logger.critical(
                "ABAC 決策稽核寫入失敗(決策仍生效): tenant=%s user=%s action=%s resource=%s 原因=%s",
                ctx.tenant_id,
                ctx.user_id,
                audit_action,
                f"{resource.value}:{action.value}",
                audit_error,
            )

    async def _publish_approval(self, request: AccessRequest, decision: AbacDecision) -> None:
        """發審批事件(D3)。發送失敗不可把『需審批』變『放行』:動作已被擋,
        此處只是大聲警示審批佇列可能漏件。"""
        event = ApprovalRequestEvent(
            tenant_id=request.tenant_id,
            user_id=request.user_id,
            role=request.role,
            resource=request.requested_resource,
            action=request.requested_action,
            sensitivity_level=request.sensitivity_level,
            risk_category=request.risk_category,
            matched_policy=decision.matched_policy,
            reason=decision.reason,
        )
        try:
            await self._approval_sink.publish(event)
        except Exception as sink_error:
            logger.critical(
                "審批事件發送失敗(動作仍被擋): tenant=%s user=%s 政策=%s 原因=%s",
                request.tenant_id,
                request.user_id,
                decision.matched_policy,
                sink_error,
            )
