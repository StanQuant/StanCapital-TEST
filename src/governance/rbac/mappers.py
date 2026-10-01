"""L11 領域物件 <-> ORM 列的雙向轉換(S02 同款分離原則)。

`*_columns()` 回傳欄位 dict，insert 與 update 共用同一份，欄位清單永不分叉。
"""

from __future__ import annotations

from src.governance.rbac.models import PermissionOverrideRow, RoleAssignmentRow, UserRow
from src.governance.rbac.permissions import Action, Resource
from src.governance.rbac.roles import Role
from src.governance.rbac.types import OverrideEffect, PermissionOverride, RoleAssignment, User

# ============================================================================
# User
# ============================================================================


def user_columns(user: User) -> dict[str, object]:
    return {
        "user_id": user.user_id,
        "tenant_id": user.tenant_id,
        "email": user.email,
        "display_name": user.display_name,
        "is_active": user.is_active,
        "department": user.department,
        "region": user.region,
        "project": user.project,
    }


def user_to_domain(row: UserRow) -> User:
    return User(
        tenant_id=row.tenant_id,
        email=row.email,
        display_name=row.display_name,
        user_id=row.user_id,
        is_active=row.is_active,
        department=row.department,
        region=row.region,
        project=row.project,
    )


# ============================================================================
# RoleAssignment
# ============================================================================


def assignment_columns(assignment: RoleAssignment) -> dict[str, object]:
    return {
        "assignment_id": assignment.assignment_id,
        "tenant_id": assignment.tenant_id,
        "user_id": assignment.user_id,
        "role": assignment.role.value,
    }


def assignment_to_domain(row: RoleAssignmentRow) -> RoleAssignment:
    return RoleAssignment(
        tenant_id=row.tenant_id,
        user_id=row.user_id,
        role=Role(row.role),
        assignment_id=row.assignment_id,
    )


# ============================================================================
# PermissionOverride
# ============================================================================


def override_columns(override: PermissionOverride) -> dict[str, object]:
    return {
        "override_id": override.override_id,
        "tenant_id": override.tenant_id,
        "role": override.role.value,
        "resource": override.resource.value,
        "action": override.action.value,
        "effect": override.effect.value,
    }


def override_to_domain(row: PermissionOverrideRow) -> PermissionOverride:
    """注意：建構期驗證(D1 鐵則)在這裡同樣生效——
    被直插資料庫的非法覆寫列會在此拋錯，由 repository 捕捉、忽略並留警告。
    """
    return PermissionOverride(
        tenant_id=row.tenant_id,
        role=Role(row.role),
        resource=Resource(row.resource),
        action=Action(row.action),
        effect=OverrideEffect(row.effect),
        override_id=row.override_id,
    )
