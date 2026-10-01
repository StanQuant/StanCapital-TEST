"""L11 RBAC 子層 · 角色 / 權限 / 矩陣 / 警衛 / Repository。

S04 切片產出。對外匯出常用名稱，呼叫端不用記內部檔案位置。
"""

from src.governance.rbac.checker import RBACChecker, RbacDecision
from src.governance.rbac.errors import (
    HighRiskGrantError,
    OwnerRevokeError,
    PermissionDeniedError,
    RBACError,
    RBACUnavailableError,
)
from src.governance.rbac.matrix import DEFAULT_ROLE_PERMISSIONS
from src.governance.rbac.permissions import (
    ALL_PERMISSIONS,
    Action,
    Permission,
    Resource,
    RiskTier,
)
from src.governance.rbac.repository import (
    AccessSnapshotRepository,
    PermissionOverrideRepository,
    RoleAssignmentRepository,
    UserRepository,
)
from src.governance.rbac.roles import Role
from src.governance.rbac.types import (
    AccessSnapshot,
    OverrideEffect,
    PermissionOverride,
    RoleAssignment,
    User,
)

__all__ = [
    "ALL_PERMISSIONS",
    "DEFAULT_ROLE_PERMISSIONS",
    "AccessSnapshot",
    "AccessSnapshotRepository",
    "Action",
    "HighRiskGrantError",
    "OverrideEffect",
    "OwnerRevokeError",
    "Permission",
    "PermissionDeniedError",
    "PermissionOverride",
    "PermissionOverrideRepository",
    "RBACChecker",
    "RBACError",
    "RBACUnavailableError",
    "RbacDecision",
    "Resource",
    "RiskTier",
    "Role",
    "RoleAssignment",
    "RoleAssignmentRepository",
    "User",
    "UserRepository",
]
