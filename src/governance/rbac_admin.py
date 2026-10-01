"""L11 治理 · RBAC 管理寫入服務(把 RBAC 寫操作接上不可變稽核)。

為什麼放在 governance 層而不放進 rbac/ 內:
  import-linter 鐵則 `rbac-not-import-audit` 規定「rbac 不可 import audit」
  (依賴方向只能 audit → rbac)。@audited 裝飾器屬於 audit 模組;本服務要
  同時用到 rbac(寫操作)與 audit(裝飾器),只能放在兩者上層的 governance。

契約(滿足 AuditedService,@audited 才能運作):
  - audit_repo: 綁「業務 session」,成功稽核與業務寫在同一交易
    (D4「操作成功 ⟺ 稽核存在」原子成立)
  - audit_session_factory: 失敗證據走「獨立交易」立即提交,
    不隨業務 rollback 蒸發

租戶邊界(fail-closed):
  所有寫操作的租戶一律取自 audit_ctx.tenant_id(已認證的身分脈絡)。
  傳入領域物件時強制其 tenant_id 與 audit_ctx 一致;跨租戶寫入直接擋下,
  並由裝飾器留下一筆 FAILED 稽核(試圖越界本身就是證據)。

交易邊界:
  本服務只 flush 不 commit——呼叫端負責 commit(與裝飾器 D4 同交易契約一致)。
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.governance.audit.decorator import AuditContext, audited
from src.governance.audit.merkle import CHECKPOINT_BATCH_SIZE
from src.governance.audit.repository import AuditLogRepository
from src.governance.rbac.repository import (
    PermissionOverrideRepository,
    RoleAssignmentRepository,
    UserRepository,
)
from src.governance.rbac.roles import Role
from src.governance.rbac.types import PermissionOverride, RoleAssignment, User


class CrossTenantWriteError(ValueError):
    """傳入物件的 tenant_id 與已認證的 audit_ctx 不一致(越界寫入,fail-closed 擋下)。"""


def _utc_now() -> datetime:
    # 預設時鐘集中此處,測試可注入固定時鐘(S02 resilience 同款)
    return datetime.now(UTC)


class RbacAdminService:
    """RBAC 設定的唯一寫入服務 · 每個寫方法自動留不可變稽核。

    建構時注入:
      - session: 業務交易(RBAC 寫入與成功稽核同走這條,呼叫端負責 commit)
      - audit_session_factory: 失敗證據的獨立交易來源
      - clock / checkpoint_batch_size: 可選,給測試與營運調校用
    """

    def __init__(
        self,
        session: AsyncSession,
        audit_session_factory: async_sessionmaker[AsyncSession],
        *,
        clock: Callable[[], datetime] = _utc_now,
        checkpoint_batch_size: int = CHECKPOINT_BATCH_SIZE,
    ) -> None:
        self._session = session
        # AuditedService 契約要求的兩個屬性(裝飾器靠 runtime_checkable 檢查其存在)
        self.audit_repo = AuditLogRepository(
            session, clock=clock, checkpoint_batch_size=checkpoint_batch_size
        )
        self.audit_session_factory = audit_session_factory
        # RBAC 三個寫入窗口都綁同一條業務 session(與成功稽核同交易)
        self._users = UserRepository(session)
        self._assignments = RoleAssignmentRepository(session)
        self._overrides = PermissionOverrideRepository(session)

    # ------------------------------------------------------------------
    # 使用者
    # ------------------------------------------------------------------

    @audited(
        action="rbac.user.save",
        resource=lambda self, user, **_: f"rbac/user/{user.user_id}",
        payload=lambda self, user, **_: {
            "user_id": user.user_id,
            "email": user.email,
            "display_name": user.display_name,
            "is_active": user.is_active,
        },
    )
    async def save_user(self, user: User, *, audit_ctx: AuditContext) -> None:
        """建立或更新使用者(upsert)。跨租戶寫入擋下並留 FAILED 稽核。"""
        _require_same_tenant(user.tenant_id, audit_ctx, "使用者")
        await self._users.save(user)

    @audited(
        action="rbac.user.delete",
        resource=lambda self, user_id, **_: f"rbac/user/{user_id}",
        payload=lambda self, user_id, **_: {"user_id": user_id},
    )
    async def delete_user(self, user_id: str, *, audit_ctx: AuditContext) -> bool:
        """刪除使用者。回傳是否真的有刪到(不存在 = False)。"""
        return await self._users.delete(audit_ctx.tenant_id, user_id)

    # ------------------------------------------------------------------
    # 角色指派
    # ------------------------------------------------------------------

    @audited(
        action="rbac.role.assign",
        resource=lambda self, assignment, **_: (
            f"rbac/user/{assignment.user_id}/role/{assignment.role.value}"
        ),
        payload=lambda self, assignment, **_: {
            "user_id": assignment.user_id,
            "role": assignment.role.value,
        },
    )
    async def assign_role(self, assignment: RoleAssignment, *, audit_ctx: AuditContext) -> None:
        """指派角色(upsert)。跨租戶寫入擋下並留 FAILED 稽核。"""
        _require_same_tenant(assignment.tenant_id, audit_ctx, "角色指派")
        await self._assignments.save(assignment)

    @audited(
        action="rbac.role.revoke",
        resource=lambda self, user_id, role, **_: f"rbac/user/{user_id}/role/{role.value}",
        payload=lambda self, user_id, role, **_: {"user_id": user_id, "role": role.value},
    )
    async def revoke_role(self, user_id: str, role: Role, *, audit_ctx: AuditContext) -> bool:
        """撤銷角色。回傳是否真的有撤到(未指派 = False)。撤銷後 check() 立即生效。"""
        return await self._assignments.revoke(audit_ctx.tenant_id, user_id, role)

    # ------------------------------------------------------------------
    # 租戶權限覆寫
    # ------------------------------------------------------------------

    @audited(
        action="rbac.override.set",
        resource=lambda self, override, **_: (
            f"rbac/override/{override.role.value}/{override.resource.value}/{override.action.value}"
        ),
        payload=lambda self, override, **_: {
            "role": override.role.value,
            "resource": override.resource.value,
            "action": override.action.value,
            "effect": override.effect.value,
        },
    )
    async def set_override(self, override: PermissionOverride, *, audit_ctx: AuditContext) -> None:
        """設定租戶權限覆寫(upsert)。跨租戶寫入擋下並留 FAILED 稽核。"""
        _require_same_tenant(override.tenant_id, audit_ctx, "權限覆寫")
        await self._overrides.save(override)

    @audited(
        action="rbac.override.delete",
        resource=lambda self, override_id, **_: f"rbac/override/{override_id}",
        payload=lambda self, override_id, **_: {"override_id": override_id},
    )
    async def remove_override(self, override_id: str, *, audit_ctx: AuditContext) -> bool:
        """刪除租戶權限覆寫。回傳是否真的有刪到(不存在 = False)。"""
        return await self._overrides.delete(audit_ctx.tenant_id, override_id)


def _require_same_tenant(obj_tenant: str, ctx: AuditContext, what: str) -> None:
    """強制領域物件的租戶與已認證身分一致(防越界寫入)。"""
    if obj_tenant != ctx.tenant_id:
        raise CrossTenantWriteError(
            f"跨租戶{what}寫入被拒: 物件 tenant={obj_tenant!r} 但身分 tenant={ctx.tenant_id!r}"
        )
