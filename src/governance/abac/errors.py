"""L11 ABAC 錯誤型別 · 全掛在 AbacError 下方便上層一網打盡。

ApprovalRequiredError 帶結構化欄位(matched_policy / reason / 資源 / 動作)：
S22 API Gateway 可直接轉回應 + 觸發審批流程，不用解析錯誤訊息字串
(與 RBAC 的 PermissionDeniedError 同款設計)。
"""

from __future__ import annotations

from src.governance.rbac.permissions import Action, Resource


class AbacError(Exception):
    """L11 ABAC 錯誤基底。"""


class PolicyLoadError(AbacError, ValueError):
    """Policy DSL 解析/驗證失敗。

    fail-closed：政策檔壞掉就不准啟動，絕不帶半套政策上線
    (寧可開不起來，也不要門禁有破洞)。
    """


class ApprovalRequiredError(AbacError):
    """ABAC 命中 require_approval：動作先擋住，待人工/HITL 審批。

    語義是「先擋住、待批准」——所以這是例外(動作不放行)，
    而非靜默返回。結構化欄位齊全，S22 中介層可直接轉回應 + 觸發審批 UI。
    """

    def __init__(
        self,
        *,
        tenant_id: str,
        user_id: str,
        resource: Resource,
        action: Action,
        matched_policy: str | None,
        reason: str,
    ) -> None:
        self.tenant_id = tenant_id
        self.user_id = user_id
        self.resource = resource
        self.action = action
        self.matched_policy = matched_policy
        self.reason = reason
        super().__init__(
            f"需人工審批: tenant={tenant_id} user={user_id} "
            f"{resource.value}:{action.value} 政策={matched_policy} ({reason})"
        )
