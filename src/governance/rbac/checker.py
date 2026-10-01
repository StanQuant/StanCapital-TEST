"""L11 RBAC 警衛 · RBACChecker(依賴注入)。

決策流程(全部 deny-by-default)：
1. 一趟查詢載入存取快照 AccessSnapshot(使用者 + 角色 + 覆寫)——
   p99 < 5ms 預算逼出來的設計，分三趟查的版本尾延遲疊三倍而未過基準
2. 使用者不存在 / 停用 / 無角色 → 拒絕
3. 逐角色算有效權限 = (基底矩陣 ∪ 合法 grants) − revokes，任一角色允許即允許(D2 聯集)
4. 資料來源連不上 → 拋 RBACUnavailableError(D4 fail-closed：狀況不明一律拒絕)

合併期防線(D1 鐵則第三道)：就算注入的資料來源回傳非法覆寫
(HIGH grant / OWNER 削權)，合併時也會忽略 + 警告，不會生效。
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Protocol

from sqlalchemy.exc import SQLAlchemyError

from src.governance.rbac.errors import PermissionDeniedError, RBACUnavailableError
from src.governance.rbac.matrix import DEFAULT_ROLE_PERMISSIONS
from src.governance.rbac.permissions import Action, Permission, Resource, RiskTier
from src.governance.rbac.roles import Role
from src.governance.rbac.types import AccessSnapshot, OverrideEffect, PermissionOverride

logger = logging.getLogger(__name__)


# 依賴注入用的最小介面：checker 只關心這一個查詢，不綁死具體 Repository
class SupportsAccessSnapshot(Protocol):
    async def load_access_snapshot(self, tenant_id: str, user_id: str) -> AccessSnapshot | None:
        """一趟查詢載入使用者 + 角色 + 覆寫，查無使用者回 None。"""


@dataclass(frozen=True, slots=True)
class RbacDecision:
    """一次查核的結論(check / require / 守門共用同一條決策路徑)。

    公開型別:S06 的 AbacAccessGuard 用 authorize_snapshot 取回此決策,
    在 RBAC 過關後接著跑 ABAC(同一趟快照、零額外往返,保住 5ms 預算)。
    """

    allowed: bool
    roles: tuple[Role, ...]
    reason: str


class RBACChecker:
    """權限警衛。建構時注入快照查詢與權限矩陣，不自己連資料庫。"""

    def __init__(
        self,
        snapshot_lookup: SupportsAccessSnapshot,
        role_permissions: Mapping[Role, frozenset[Permission]] | None = None,
    ) -> None:
        self._snapshots = snapshot_lookup
        # None = 用內建基底矩陣；測試與 S26 可注入自訂矩陣
        self._matrix: Mapping[Role, frozenset[Permission]] | None = role_permissions

    async def check(self, tenant_id: str, user_id: str, resource: Resource, action: Action) -> bool:
        """查詢式 API：回 True / False，呼叫端自己決定怎麼處理。"""
        decision = await self._decide(tenant_id, user_id, resource, action)
        return decision.allowed

    async def require(
        self, tenant_id: str, user_id: str, resource: Resource, action: Action
    ) -> None:
        """守門式 API：沒權限直接拋 PermissionDeniedError(S22 中介層用這個)。"""
        decision = await self._decide(tenant_id, user_id, resource, action)
        if not decision.allowed:
            raise PermissionDeniedError(
                tenant_id=tenant_id,
                user_id=user_id,
                resource=resource,
                action=action,
                roles=decision.roles,
                reason=decision.reason,
            )

    def permissions_of(self, role: Role) -> frozenset[Permission]:
        """某角色的基底權限(不含租戶覆寫)。矩陣外的角色 = 空集合(deny-by-default)。"""
        return self._base_matrix().get(role, frozenset())

    def effective_permissions(
        self, tenant_id: str, role: Role, overrides: Iterable[PermissionOverride]
    ) -> frozenset[Permission]:
        """某角色套用覆寫後的有效權限 = (基底 ∪ 合法 grants) − revokes(D1 合併公式)。

        純函式(不碰資料庫)，方便測試與 mutation 驗證；tenant_id 只用於警告日誌。
        """
        base = self.permissions_of(role)
        grants: set[Permission] = set()
        revokes: set[Permission] = set()
        for override in overrides:
            if override.effect is OverrideEffect.GRANT:
                if override.permission.risk_tier is RiskTier.HIGH:
                    # 合併期防線：非法 grant 不生效(正常資料來源不會走到這)
                    logger.warning(
                        "忽略 HIGH 風險 grant 覆寫(合併期防線): tenant=%s role=%s 權限=%s:%s",
                        tenant_id,
                        role.value,
                        override.resource.value,
                        override.action.value,
                    )
                    continue
                grants.add(override.permission)
            else:
                if role is Role.OWNER:
                    # 合併期防線：OWNER 不可被削權(防租戶自鎖)
                    logger.warning(
                        "忽略 OWNER 削權覆寫(合併期防線): tenant=%s 權限=%s:%s",
                        tenant_id,
                        override.resource.value,
                        override.action.value,
                    )
                    continue
                revokes.add(override.permission)
        return frozenset((base | grants) - revokes)

    def _base_matrix(self) -> Mapping[Role, frozenset[Permission]]:
        """回傳注入矩陣或內建矩陣。"""
        return self._matrix if self._matrix is not None else DEFAULT_ROLE_PERMISSIONS

    async def load_snapshot(self, tenant_id: str, user_id: str) -> AccessSnapshot | None:
        """載入存取快照(熱路徑單趟查詢)。資料來源連不上 → fail-closed 拋錯。

        S06 守門用這個取一趟快照,既餵 RBAC(authorize_snapshot)又取權威使用者屬性
        組 ABAC 請求,不重複查資料庫。
        """
        try:
            return await self._snapshots.load_access_snapshot(tenant_id, user_id)
        except (SQLAlchemyError, OSError) as error:
            # D4 fail-closed：資料來源狀況不明，拋明確錯誤，絕不默默放行
            logger.error(
                "RBAC 查核失敗(fail-closed 拒絕): tenant=%s user=%s 原因=%s",
                tenant_id,
                user_id,
                error,
            )
            raise RBACUnavailableError("權限查核資料來源連不上，依 fail-closed 一律拒絕") from error

    def authorize_snapshot(
        self, snapshot: AccessSnapshot, resource: Resource, action: Action
    ) -> RbacDecision:
        """純判斷:給定『已存在』的快照算權限決策(deny-by-default，純函式無 DB)。

        tenant_id / user_id 由 snapshot.user 取(快照即為該使用者載入，兩者相等)。
        """
        tenant_id = snapshot.user.tenant_id
        user_id = snapshot.user.user_id
        if not snapshot.user.is_active:
            return self._deny(tenant_id, user_id, resource, action, (), "使用者已停用")
        if not snapshot.roles:
            return self._deny(tenant_id, user_id, resource, action, (), "未指派任何角色")

        overrides_by_role: dict[Role, list[PermissionOverride]] = {}
        for override in snapshot.overrides:
            overrides_by_role.setdefault(override.role, []).append(override)

        needed = Permission(resource, action)
        for role in snapshot.roles:
            effective = self.effective_permissions(tenant_id, role, overrides_by_role.get(role, []))
            if needed in effective:
                return RbacDecision(allowed=True, roles=snapshot.roles, reason="")
        return self._deny(
            tenant_id, user_id, resource, action, snapshot.roles, "所有角色皆無此權限"
        )

    async def _decide(
        self, tenant_id: str, user_id: str, resource: Resource, action: Action
    ) -> RbacDecision:
        snapshot = await self.load_snapshot(tenant_id, user_id)
        if snapshot is None:
            return self._deny(tenant_id, user_id, resource, action, (), "使用者不存在")
        return self.authorize_snapshot(snapshot, resource, action)

    @staticmethod
    def _deny(
        tenant_id: str,
        user_id: str,
        resource: Resource,
        action: Action,
        roles: tuple[Role, ...],
        reason: str,
    ) -> RbacDecision:
        """拒絕統一出口：S05 稽核落地前，警告日誌是唯一痕跡。"""
        logger.warning(
            "權限拒絕: tenant=%s user=%s resource=%s action=%s 原因=%s",
            tenant_id,
            user_id,
            resource.value,
            action.value,
            reason,
        )
        return RbacDecision(allowed=False, roles=roles, reason=reason)
