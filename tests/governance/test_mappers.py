"""S04 · 領域物件 <-> ORM 列雙向轉換的 round-trip 測試。

columns() 建列 → to_domain() 還原 → 逐欄位相等，欄位清單永不分叉的保證。
"""

from __future__ import annotations

import pytest
from src.governance.rbac.errors import HighRiskGrantError, OwnerRevokeError
from src.governance.rbac.mappers import (
    assignment_columns,
    assignment_to_domain,
    override_columns,
    override_to_domain,
    user_columns,
    user_to_domain,
)
from src.governance.rbac.models import PermissionOverrideRow, RoleAssignmentRow, UserRow
from src.governance.rbac.permissions import Action, Resource
from src.governance.rbac.roles import Role
from src.governance.rbac.types import OverrideEffect

from tests.governance.conftest import make_assignment, make_override, make_user


def test_user_round_trip() -> None:
    user = make_user(is_active=False)
    row = UserRow(**user_columns(user))
    assert user_to_domain(row) == user


def test_user_columns_exact() -> None:
    """欄位 dict 釘死：insert 與 update 共用，少一欄兩條路徑都會壞。"""
    assert user_columns(make_user()) == {
        "user_id": "USR-001",
        "tenant_id": "stanley",
        "email": "trader@stanquant.dev",
        "display_name": "測試交易員",
        "is_active": True,
        # S06 ABAC 屬性(make_user 未指定 → 預設空字串)
        "department": "",
        "region": "",
        "project": "",
    }


def test_assignment_round_trip() -> None:
    assignment = make_assignment(role=Role.COMPLIANCE_OFFICER)
    row = RoleAssignmentRow(**assignment_columns(assignment))
    assert assignment_to_domain(row) == assignment


def test_assignment_columns_exact() -> None:
    assert assignment_columns(make_assignment()) == {
        "assignment_id": "ASG-001",
        "tenant_id": "stanley",
        "user_id": "USR-001",
        "role": "user",
    }


def test_override_round_trip() -> None:
    override = make_override(effect=OverrideEffect.REVOKE)
    row = PermissionOverrideRow(**override_columns(override))
    assert override_to_domain(row) == override


def test_override_columns_exact() -> None:
    assert override_columns(make_override()) == {
        "override_id": "OVR-001",
        "tenant_id": "stanley",
        "role": "user",
        "resource": "trade",
        "action": "write",
        "effect": "grant",
    }


def test_override_to_domain_rejects_illegal_high_grant_row() -> None:
    """直插資料庫的非法列(HIGH grant)在轉換時拋錯——repository 靠這個攔截。"""
    row = PermissionOverrideRow(
        override_id="OVR-BAD",
        tenant_id="stanley",
        role=Role.USER.value,
        resource=Resource.USER.value,
        action=Action.MANAGE.value,
        effect=OverrideEffect.GRANT.value,
    )
    with pytest.raises(HighRiskGrantError):
        override_to_domain(row)


def test_override_to_domain_rejects_illegal_owner_revoke_row() -> None:
    row = PermissionOverrideRow(
        override_id="OVR-BAD2",
        tenant_id="stanley",
        role=Role.OWNER.value,
        resource=Resource.TRADE.value,
        action=Action.READ.value,
        effect=OverrideEffect.REVOKE.value,
    )
    with pytest.raises(OwnerRevokeError):
        override_to_domain(row)
