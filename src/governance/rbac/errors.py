"""L11 RBAC 錯誤型別 · 全部掛在 RBACError 下方便上層一網打盡。

PermissionDeniedError 帶結構化欄位：S22 API Gateway 可直接轉 HTTP 403，
不用解析錯誤訊息字串。
"""

from __future__ import annotations

from src.governance.rbac.permissions import Action, Resource
from src.governance.rbac.roles import Role


class RBACError(Exception):
    """L11 RBAC 錯誤基底。"""


class HighRiskGrantError(RBACError, ValueError):
    """租戶覆寫層試圖 grant HIGH 風險權限(D1 鐵則 1：寫入時拒絕)。"""


class OwnerRevokeError(RBACError, ValueError):
    """試圖 revoke OWNER 的權限(D1 鐵則 2：防租戶把自己鎖死在門外)。"""


class RBACUnavailableError(RBACError):
    """權限查核所需的資料來源連不上(D4 fail-closed：狀況不明一律拒絕)。"""


class PermissionDeniedError(RBACError):
    """權限不足。結構化欄位齊全，S22 中介層直接轉 403 回應。"""

    def __init__(
        self,
        *,
        tenant_id: str,
        user_id: str,
        resource: Resource,
        action: Action,
        roles: tuple[Role, ...],
        reason: str,
    ) -> None:
        self.tenant_id = tenant_id
        self.user_id = user_id
        self.resource = resource
        self.action = action
        self.roles = roles
        self.reason = reason
        super().__init__(
            f"權限不足: tenant={tenant_id} user={user_id} "
            f"需要 {resource.value}:{action.value} ({reason})"
        )
