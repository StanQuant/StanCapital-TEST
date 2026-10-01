"""S04 · PermissionDeniedError 結構化欄位測試。

S22 中介層靠這些欄位直接轉 HTTP 403，欄位與訊息都是對外契約，要釘住。
"""

from __future__ import annotations

from src.governance.rbac.errors import PermissionDeniedError, RBACError
from src.governance.rbac.permissions import Action, Resource
from src.governance.rbac.roles import Role


def test_permission_denied_fields_and_message() -> None:
    error = PermissionDeniedError(
        tenant_id="stanley",
        user_id="USR-001",
        resource=Resource.USER,
        action=Action.MANAGE,
        roles=(Role.AGENT,),
        reason="角色 (agent) 皆無此權限",
    )
    assert error.tenant_id == "stanley"
    assert error.user_id == "USR-001"
    assert error.resource is Resource.USER
    assert error.action is Action.MANAGE
    assert error.roles == (Role.AGENT,)
    assert error.reason == "角色 (agent) 皆無此權限"
    assert str(error) == (
        "權限不足: tenant=stanley user=USR-001 需要 user:manage (角色 (agent) 皆無此權限)"
    )


def test_permission_denied_is_rbac_error() -> None:
    """上層可用 RBACError 一網打盡 L11 的全部錯誤。"""
    error = PermissionDeniedError(
        tenant_id="t",
        user_id="u",
        resource=Resource.ORDER,
        action=Action.WRITE,
        roles=(),
        reason="使用者不存在",
    )
    assert isinstance(error, RBACError)
