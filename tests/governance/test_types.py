"""S04 · L11 領域物件的建構期驗證測試。

重點：非法狀態(壞 email、HIGH grant、OWNER 削權)連物件都做不出來——
這是 D1 鐵則的第一道防線。
"""

from __future__ import annotations

import dataclasses

import pytest
from src.governance.rbac.errors import HighRiskGrantError, OwnerRevokeError
from src.governance.rbac.permissions import Action, Permission, Resource
from src.governance.rbac.roles import Role
from src.governance.rbac.types import (
    AccessSnapshot,
    OverrideEffect,
    PermissionOverride,
    RoleAssignment,
    User,
)

from tests.governance.conftest import make_assignment, make_override, make_user

# ============================================================================
# 不可變值物件紀律：四個領域物件都必須 frozen + slots(與 L4 同款)
# ============================================================================


@pytest.mark.parametrize(
    "instance",
    [
        make_user(),
        make_assignment(),
        make_override(),
        AccessSnapshot(user=make_user(), roles=(), overrides=()),
    ],
    ids=["User", "RoleAssignment", "PermissionOverride", "AccessSnapshot"],
)
def test_domain_objects_frozen_with_slots(instance: object) -> None:
    """frozen：欄位不可改；slots：沒有 __dict__(防打字錯誤默默掛新屬性)。"""
    first_field = dataclasses.fields(instance)[0].name  # type: ignore[arg-type]
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(instance, first_field, "tampered")
    assert not hasattr(instance, "__dict__")


# ============================================================================
# User
# ============================================================================


def test_user_defaults() -> None:
    """user_id 預設 ULID(26 字元)、is_active 預設啟用。"""
    fresh = User(tenant_id="t1", email="a@b.c", display_name="x")
    assert len(fresh.user_id) == 26
    assert fresh.is_active is True


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("tenant_id", "", "tenant_id 不可為空"),
        ("email", "not-an-email", "email 格式不正確: 'not-an-email'"),
        ("display_name", "", "display_name 不可為空"),
    ],
)
def test_user_rejects_bad_fields(field: str, value: str, message: str) -> None:
    with pytest.raises(ValueError) as excinfo:
        make_user(**{field: value})
    assert str(excinfo.value) == message


def test_user_is_frozen() -> None:
    user = make_user()
    with pytest.raises(dataclasses.FrozenInstanceError):
        user.email = "x@y.z"  # type: ignore[misc]


# ============================================================================
# RoleAssignment
# ============================================================================


def test_assignment_defaults_ulid() -> None:
    fresh = RoleAssignment(tenant_id="t1", user_id="u1", role=Role.AGENT)
    assert len(fresh.assignment_id) == 26
    assert fresh.role is Role.AGENT


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("tenant_id", "", "tenant_id 不可為空"),
        ("user_id", "", "user_id 不可為空"),
    ],
)
def test_assignment_rejects_bad_fields(field: str, value: str, message: str) -> None:
    with pytest.raises(ValueError) as excinfo:
        make_assignment(**{field: value})
    assert str(excinfo.value) == message


# ============================================================================
# PermissionOverride · D1 鐵則的第一道防線
# ============================================================================


def test_override_grant_low_risk_is_legal() -> None:
    """LOW 風險 grant 合法(交易類資源的 read/write)。"""
    override = make_override(resource=Resource.STRATEGY, action=Action.WRITE)
    assert override.permission == Permission(Resource.STRATEGY, Action.WRITE)
    assert override.effect is OverrideEffect.GRANT


@pytest.mark.parametrize(
    ("resource", "action"),
    [
        (Resource.USER, Action.READ),  # 治理類資源：任何動作都 HIGH
        (Resource.ROLE, Action.WRITE),
        (Resource.CONFIG, Action.READ),
        (Resource.ORDER, Action.DELETE),  # 危險動作：任何資源都 HIGH
        (Resource.STRATEGY, Action.MANAGE),
    ],
)
def test_override_grant_high_risk_is_rejected(resource: Resource, action: Action) -> None:
    """HIGH 風險 grant 在建構期就拋 HighRiskGrantError。"""
    with pytest.raises(HighRiskGrantError) as excinfo:
        make_override(resource=resource, action=action)
    assert str(excinfo.value) == (f"HIGH 風險權限不可由租戶 grant: {resource.value}:{action.value}")


def test_override_revoke_high_risk_is_legal() -> None:
    """revoke 不限風險級：削權只會更安全。"""
    override = make_override(
        role=Role.MANAGER,
        resource=Resource.STRATEGY,
        action=Action.MANAGE,
        effect=OverrideEffect.REVOKE,
    )
    assert override.effect is OverrideEffect.REVOKE


def test_override_revoke_owner_is_rejected() -> None:
    """OWNER 不可被削權(防租戶把自己鎖死在門外)。"""
    with pytest.raises(OwnerRevokeError) as excinfo:
        make_override(
            role=Role.OWNER,
            resource=Resource.TRADE,
            action=Action.READ,
            effect=OverrideEffect.REVOKE,
        )
    assert str(excinfo.value) == "OWNER 不可被削權(防租戶把自己鎖死在門外)"


def test_override_grant_owner_is_legal_but_pointless() -> None:
    """grant 給 OWNER 合法(本來就是全權限，聯集後無感)。"""
    override = make_override(role=Role.OWNER)
    assert override.role is Role.OWNER


def test_override_empty_tenant_rejected() -> None:
    with pytest.raises(ValueError) as excinfo:
        make_override(tenant_id="")
    assert str(excinfo.value) == "tenant_id 不可為空"


def test_override_defaults_ulid() -> None:
    fresh = PermissionOverride(
        tenant_id="t1",
        role=Role.USER,
        resource=Resource.TRADE,
        action=Action.WRITE,
        effect=OverrideEffect.GRANT,
    )
    assert len(fresh.override_id) == 26


def test_override_effect_values_exact() -> None:
    assert {effect.value for effect in OverrideEffect} == {"grant", "revoke"}
