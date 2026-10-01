"""L11 ABAC 屬性 · AccessRequest(評估器的輸入)。

欄位依 Architecture §L11 子層 2。與 L4/RBAC 值物件同紀律：
frozen + slots、tenant_id 無預設值、非法狀態建構期就擋下。

權威性(D4)：require_abac 用 users 表(同趟 AccessSnapshot)的「權威」使用者屬性
(department/region/project)組這個物件；呼叫端只提供「資源屬性」
(sensitivity_level/risk_category)。如此使用者屬性無法被呼叫端偽冒。
"""

from __future__ import annotations

from dataclasses import dataclass

from src.governance.rbac.permissions import Action, Resource
from src.governance.rbac.roles import Role

# 資料敏感度合法範圍(Architecture §L11 子層 2：1-5)
MIN_SENSITIVITY = 1
MAX_SENSITIVITY = 5


@dataclass(frozen=True, slots=True)
class AccessRequest:
    """一次存取請求的完整屬性集(ABAC 評估器的輸入)。

    department/region/project/risk_category 允許為空字串(代表「該屬性未設定」)；
    tenant_id 與 user_id 不可為空；sensitivity_level 必須落在 1-5。
    """

    user_id: str
    tenant_id: str
    role: Role
    department: str
    region: str
    project: str
    sensitivity_level: int
    risk_category: str
    requested_resource: Resource
    requested_action: Action

    def __post_init__(self) -> None:
        if not self.tenant_id:
            raise ValueError("tenant_id 不可為空")
        if not self.user_id:
            raise ValueError("user_id 不可為空")
        if not MIN_SENSITIVITY <= self.sensitivity_level <= MAX_SENSITIVITY:
            raise ValueError(
                f"sensitivity_level 必須在 {MIN_SENSITIVITY}-{MAX_SENSITIVITY}: "
                f"{self.sensitivity_level}"
            )
