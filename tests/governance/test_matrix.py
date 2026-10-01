"""S04 · 基底權限矩陣逐格釘死(8 角色 × 32 格 = 256 格全驗)。

EXPECTED_CELLS 用純字串獨立重寫一份(不 import matrix 的輔助函式)，
矩陣程式碼任何一格被動到，這裡就紅燈——mutation testing 的主力殺手。
"""

from __future__ import annotations

import pytest
from src.governance.rbac.matrix import DEFAULT_ROLE_PERMISSIONS
from src.governance.rbac.permissions import ALL_PERMISSIONS, Action, Permission, Resource
from src.governance.rbac.roles import Role

# 與 matrix.py 無關的獨立寫法：(資源, 動作) 字串對
Cell = tuple[str, str]

_ALL_RESOURCES = ("order", "position", "fill", "trade", "strategy", "user", "role", "config")
_ALL_ACTIONS = ("read", "write", "delete", "manage")

_FULL_GRID: set[Cell] = {(r, a) for r in _ALL_RESOURCES for a in _ALL_ACTIONS}
_READ_ALL: set[Cell] = {(r, "read") for r in _ALL_RESOURCES}

EXPECTED_CELLS: dict[Role, set[Cell]] = {
    Role.OWNER: set(_FULL_GRID),
    Role.ADMINISTRATOR: set(_FULL_GRID),
    Role.SECURITY_OFFICER: _READ_ALL
    | {
        ("user", "write"),
        ("user", "delete"),
        ("user", "manage"),
        ("role", "write"),
        ("role", "delete"),
        ("role", "manage"),
        ("config", "write"),
        ("config", "manage"),
    },
    Role.COMPLIANCE_OFFICER: set(_READ_ALL),
    Role.MANAGER: {
        ("order", "read"),
        ("order", "write"),
        ("position", "read"),
        ("fill", "read"),
        ("trade", "read"),
        ("strategy", "read"),
        ("strategy", "write"),
        ("strategy", "manage"),
        ("config", "read"),
    },
    Role.USER: {
        ("order", "read"),
        ("order", "write"),
        ("position", "read"),
        ("fill", "read"),
        ("trade", "read"),
        ("strategy", "read"),
    },
    Role.SERVICE_ACCOUNT: {
        ("order", "read"),
        ("order", "write"),
        ("fill", "read"),
        ("fill", "write"),
        ("position", "read"),
        ("position", "write"),
        ("trade", "read"),
        ("trade", "write"),
        ("strategy", "read"),
    },
    Role.AGENT: {
        ("order", "read"),
        ("position", "read"),
        ("fill", "read"),
        ("trade", "read"),
        ("strategy", "read"),
        ("strategy", "write"),
    },
}


def test_matrix_covers_every_role_exactly() -> None:
    """矩陣 key = 8 個角色，不多不少(deny-by-default 靠 checker，矩陣不留洞)。"""
    assert set(DEFAULT_ROLE_PERMISSIONS.keys()) == set(Role)
    assert set(EXPECTED_CELLS.keys()) == set(Role)


@pytest.mark.parametrize("role", list(Role))
def test_matrix_cells_exact(role: Role) -> None:
    """逐格相等：每個角色的允許格集合與獨立預期表完全一致(256 格全驗)。"""
    actual = {
        (permission.resource.value, permission.action.value)
        for permission in DEFAULT_ROLE_PERMISSIONS[role]
    }
    assert actual == EXPECTED_CELLS[role]


def test_owner_and_admin_have_full_grid() -> None:
    assert DEFAULT_ROLE_PERMISSIONS[Role.OWNER] == ALL_PERMISSIONS
    assert DEFAULT_ROLE_PERMISSIONS[Role.ADMINISTRATOR] == ALL_PERMISSIONS


def test_agent_fence_key_cells() -> None:
    """AGENT 圍欄的關鍵格(Charter 紅線 + DoD #12 Demo 場景)。"""
    agent = DEFAULT_ROLE_PERMISSIONS[Role.AGENT]
    # 可以：發策略訊號
    assert Permission(Resource.STRATEGY, Action.WRITE) in agent
    # 不可以：直接下單 / 管理使用者 / 碰設定
    assert Permission(Resource.ORDER, Action.WRITE) not in agent
    assert Permission(Resource.USER, Action.MANAGE) not in agent
    assert Permission(Resource.CONFIG, Action.WRITE) not in agent


def test_compliance_officer_is_read_only() -> None:
    """法遵官只看不動：任何非 read 動作都不在集合裡。"""
    compliance = DEFAULT_ROLE_PERMISSIONS[Role.COMPLIANCE_OFFICER]
    assert all(permission.action == Action.READ for permission in compliance)
    assert len(compliance) == 8


def test_matrix_is_immutable() -> None:
    """MappingProxyType：執行期改矩陣直接 TypeError(憲法不給動)。"""
    with pytest.raises(TypeError):
        DEFAULT_ROLE_PERMISSIONS[Role.AGENT] = ALL_PERMISSIONS  # type: ignore[index]
