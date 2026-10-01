"""S04 · 角色 / 權限原語 / 風險分級的宣告層測試。

釘住「系統憲法」：成員名單、字串值、風險分級規則、不可變性。
任何一格變動都該讓這裡紅燈——改憲法必須是有意識的行為。
"""

from __future__ import annotations

import dataclasses

import pytest
from src.governance.rbac.permissions import (
    ALL_PERMISSIONS,
    Action,
    Permission,
    Resource,
    RiskTier,
)
from src.governance.rbac.roles import Role

# ============================================================================
# Role · 8 個內建角色
# ============================================================================


def test_role_members_exact() -> None:
    """8 個角色一個不多一個不少，字串值逐一釘死。"""
    assert {role.value for role in Role} == {
        "owner",
        "administrator",
        "security_officer",
        "compliance_officer",
        "manager",
        "user",
        "service_account",
        "agent",
    }
    assert len(Role) == 8


def test_role_is_str() -> None:
    """StrEnum 行為：可直接當字串用(存資料庫 / 寫日誌)。"""
    assert Role.AGENT == "agent"
    assert isinstance(Role.OWNER, str)


# ============================================================================
# Resource / Action · 合法值白名單
# ============================================================================


def test_resource_members_exact() -> None:
    assert {resource.value for resource in Resource} == {
        "order",
        "position",
        "fill",
        "trade",
        "strategy",
        "user",
        "role",
        "config",
    }
    assert len(Resource) == 8


def test_action_members_exact() -> None:
    assert {action.value for action in Action} == {"read", "write", "delete", "manage"}
    assert len(Action) == 4


def test_all_permissions_is_full_grid() -> None:
    """全集 = 8 資源 × 4 動作 = 32 格，缺一格 deny-by-default 就會出錯。"""
    assert len(ALL_PERMISSIONS) == 32
    assert ALL_PERMISSIONS == frozenset(
        Permission(resource, action) for resource in Resource for action in Action
    )


# ============================================================================
# RiskTier · D1 混合式的分級規則
# ============================================================================


@pytest.mark.parametrize("resource", [Resource.USER, Resource.ROLE, Resource.CONFIG])
@pytest.mark.parametrize("action", list(Action))
def test_governance_resources_are_high_risk(resource: Resource, action: Action) -> None:
    """治理類資源(user/role/config)任何動作都是 HIGH：動到門禁本身。"""
    assert Permission(resource, action).risk_tier == RiskTier.HIGH


@pytest.mark.parametrize(
    "resource",
    [Resource.ORDER, Resource.POSITION, Resource.FILL, Resource.TRADE, Resource.STRATEGY],
)
@pytest.mark.parametrize("action", [Action.DELETE, Action.MANAGE])
def test_dangerous_actions_are_high_risk(resource: Resource, action: Action) -> None:
    """delete / manage 對任何資源都是 HIGH：刪金融記錄 / 管理級操作。"""
    assert Permission(resource, action).risk_tier == RiskTier.HIGH


@pytest.mark.parametrize(
    "resource",
    [Resource.ORDER, Resource.POSITION, Resource.FILL, Resource.TRADE, Resource.STRATEGY],
)
@pytest.mark.parametrize("action", [Action.READ, Action.WRITE])
def test_trading_read_write_are_low_risk(resource: Resource, action: Action) -> None:
    """交易類資源的 read / write 是 LOW：商業化後租戶可在介面自改。"""
    assert Permission(resource, action).risk_tier == RiskTier.LOW


def test_risk_tier_values_exact() -> None:
    assert {tier.value for tier in RiskTier} == {"high", "low"}


# ============================================================================
# Permission · 不可變值物件紀律(與 L4 同款)
# ============================================================================


def test_permission_is_frozen() -> None:
    permission = Permission(Resource.ORDER, Action.READ)
    with pytest.raises(dataclasses.FrozenInstanceError):
        permission.action = Action.WRITE  # type: ignore[misc]


def test_permission_has_slots() -> None:
    """slots=True：不能隨意掛新屬性(防打字錯誤默默吞掉)，且沒有 __dict__。"""
    permission = Permission(Resource.ORDER, Action.READ)
    with pytest.raises((AttributeError, TypeError)):
        permission.extra = "x"  # type: ignore[attr-defined]
    assert not hasattr(permission, "__dict__")


def test_permission_hashable_and_equal() -> None:
    """可進 frozenset 且值相等即同一格(矩陣運算的基礎)。"""
    a = Permission(Resource.ORDER, Action.READ)
    b = Permission(Resource.ORDER, Action.READ)
    assert a == b
    assert hash(a) == hash(b)
    assert len({a, b}) == 1
