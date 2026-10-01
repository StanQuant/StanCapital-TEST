"""L11 RBAC 權限原語 · 資源 × 動作 + 風險分級。

風險分級是 D1 混合式的核心(S04-規格 §5.3)：
- HIGH：只能改後台程式碼，租戶覆寫層的 grant 一律拒絕
- LOW：商業化後租戶可在自己的管理介面 grant / revoke
分級規則寫死在程式碼，租戶永遠改不到。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Resource(StrEnum):
    """受門禁保護的資源(首版 8 項，S04-規格 §5.2)。"""

    ORDER = "order"
    POSITION = "position"
    FILL = "fill"
    TRADE = "trade"
    STRATEGY = "strategy"
    USER = "user"
    ROLE = "role"
    CONFIG = "config"


class Action(StrEnum):
    """對資源的動作(首版 4 項)。manage = 管理級操作(指派角色、改系統設定)。"""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    MANAGE = "manage"


class RiskTier(StrEnum):
    """權限風險分級。HIGH 不可被租戶覆寫 grant(revoke 削權則不限)。"""

    HIGH = "high"
    LOW = "low"


# 治理類資源：動到門禁系統本身，任何動作都是 HIGH
_GOVERNANCE_RESOURCES = frozenset({Resource.USER, Resource.ROLE, Resource.CONFIG})

# 危險動作：刪除金融記錄 / 管理級操作，對任何資源都是 HIGH
_HIGH_RISK_ACTIONS = frozenset({Action.DELETE, Action.MANAGE})


@dataclass(frozen=True, slots=True)
class Permission:
    """一格權限 = 資源 × 動作。frozen + slots 與 L4 值物件同紀律。"""

    resource: Resource
    action: Action

    @property
    def risk_tier(self) -> RiskTier:
        """用兩條規則而非 32 格逐格表：規則少就不會漏改格子。"""
        if self.resource in _GOVERNANCE_RESOURCES or self.action in _HIGH_RISK_ACTIONS:
            return RiskTier.HIGH
        return RiskTier.LOW


# 全部 32 格(8 資源 × 4 動作)，deny-by-default 的「全集」基準
ALL_PERMISSIONS: frozenset[Permission] = frozenset(
    Permission(resource, action) for resource in Resource for action in Action
)
