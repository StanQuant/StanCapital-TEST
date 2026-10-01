"""L11 RBAC 基底權限矩陣 · 8 個內建角色(D1 裁決：基底放程式碼)。

定案原則(S04-規格 §5)：
- deny-by-default：沒列的格子一律拒絕
- AGENT 圍欄：可發策略訊號(strategy:write)，不可直接下單(order:write)、
  不可碰治理資源——訊號需經 S07/S08 風控核可才轉成訂單(Charter 紅線)
- 租戶對 LOW 風險格子的微調走 permission_overrides 表，本矩陣不動
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from src.governance.rbac.permissions import (
    ALL_PERMISSIONS,
    Action,
    Permission,
    Resource,
)
from src.governance.rbac.roles import Role


def _perms(*pairs: tuple[Resource, Action]) -> frozenset[Permission]:
    return frozenset(Permission(resource, action) for resource, action in pairs)


def _read_all() -> frozenset[Permission]:
    """全資源唯讀：法遵官 / 資安官的「看得到全部」基座。"""
    return frozenset(Permission(resource, Action.READ) for resource in Resource)


_MATRIX: dict[Role, frozenset[Permission]] = {
    # 老闆與系統管理員：全權限(S26 多租戶時再評估拆「不含帳務」)
    Role.OWNER: ALL_PERMISSIONS,
    Role.ADMINISTRATOR: ALL_PERMISSIONS,
    # 資安官：讀全部 + 管理使用者/角色 + 風控設定(不含刪設定)
    Role.SECURITY_OFFICER: _read_all()
    | _perms(
        (Resource.USER, Action.WRITE),
        (Resource.USER, Action.DELETE),
        (Resource.USER, Action.MANAGE),
        (Resource.ROLE, Action.WRITE),
        (Resource.ROLE, Action.DELETE),
        (Resource.ROLE, Action.MANAGE),
        (Resource.CONFIG, Action.WRITE),
        (Resource.CONFIG, Action.MANAGE),
    ),
    # 法遵官：只看不動(訂單/成交/全部唯讀)
    Role.COMPLIANCE_OFFICER: _read_all(),
    # 交易主管：下單改單 + 策略管理 + 讀風控設定
    Role.MANAGER: _perms(
        (Resource.ORDER, Action.READ),
        (Resource.ORDER, Action.WRITE),
        (Resource.POSITION, Action.READ),
        (Resource.FILL, Action.READ),
        (Resource.TRADE, Action.READ),
        (Resource.STRATEGY, Action.READ),
        (Resource.STRATEGY, Action.WRITE),
        (Resource.STRATEGY, Action.MANAGE),
        (Resource.CONFIG, Action.READ),
    ),
    # 一般使用者：下單改單 + 讀自己相關資源
    Role.USER: _perms(
        (Resource.ORDER, Action.READ),
        (Resource.ORDER, Action.WRITE),
        (Resource.POSITION, Action.READ),
        (Resource.FILL, Action.READ),
        (Resource.TRADE, Action.READ),
        (Resource.STRATEGY, Action.READ),
    ),
    # 服務帳號：程式對接(訂單回報 / 成交 / 持倉寫入)，細分用途留 S06 ABAC
    Role.SERVICE_ACCOUNT: _perms(
        (Resource.ORDER, Action.READ),
        (Resource.ORDER, Action.WRITE),
        (Resource.FILL, Action.READ),
        (Resource.FILL, Action.WRITE),
        (Resource.POSITION, Action.READ),
        (Resource.POSITION, Action.WRITE),
        (Resource.TRADE, Action.READ),
        (Resource.TRADE, Action.WRITE),
        (Resource.STRATEGY, Action.READ),
    ),
    # AI Agent：讀行情相關 + 發策略訊號；不能直接下單、不能碰治理資源
    Role.AGENT: _perms(
        (Resource.ORDER, Action.READ),
        (Resource.POSITION, Action.READ),
        (Resource.FILL, Action.READ),
        (Resource.TRADE, Action.READ),
        (Resource.STRATEGY, Action.READ),
        (Resource.STRATEGY, Action.WRITE),
    ),
}

# MappingProxyType：唯讀視圖，執行期改矩陣會直接 TypeError(憲法不給動)
DEFAULT_ROLE_PERMISSIONS: Mapping[Role, frozenset[Permission]] = MappingProxyType(_MATRIX)
