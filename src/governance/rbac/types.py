"""L11 RBAC 領域物件 · User / RoleAssignment / PermissionOverride。

設計準則(與 L4 同紀律)：
- frozen=True + slots=True 不可變值物件
- tenant_id 必填無預設值(2026-06-10 裁定)
- 不含登入密碼(D3 裁決：認證外包 OIDC，本表只管「你能做什麼」)
- 非法狀態在建構期就擋下(__post_init__)，不讓壞資料流進系統
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from ulid import ULID

from src.governance.rbac.errors import HighRiskGrantError, OwnerRevokeError
from src.governance.rbac.permissions import Action, Permission, Resource, RiskTier
from src.governance.rbac.roles import Role


def _new_id() -> str:
    """ULID：時間戳前綴可排序(S01 ADR-0001 同款)。"""
    return str(ULID())


@dataclass(frozen=True, slots=True)
class User:
    """使用者身分資料。密碼不在這裡(D3：驗證密碼外包 OIDC)。

    department / region / project 是 S06 ABAC 的「權威」使用者屬性(S04 §8 預告可擴充)：
    存這張表、隨 AccessSnapshot 同趟載入,守門用它組 AccessRequest,呼叫端無法偽冒。
    預設空字串代表「未設定」,既相容既有資料、ABAC 也視為未設定屬性。
    """

    tenant_id: str
    email: str
    display_name: str
    user_id: str = field(default_factory=_new_id)
    is_active: bool = True
    department: str = ""
    region: str = ""
    project: str = ""

    def __post_init__(self) -> None:
        if not self.tenant_id:
            raise ValueError("tenant_id 不可為空")
        if "@" not in self.email:
            raise ValueError(f"email 格式不正確: {self.email!r}")
        if not self.display_name:
            raise ValueError("display_name 不可為空")


@dataclass(frozen=True, slots=True)
class RoleAssignment:
    """角色指派 · 自然鍵 = (tenant_id, user_id, role)，一人可多角色(D2)。"""

    tenant_id: str
    user_id: str
    role: Role
    assignment_id: str = field(default_factory=_new_id)

    def __post_init__(self) -> None:
        if not self.tenant_id:
            raise ValueError("tenant_id 不可為空")
        if not self.user_id:
            raise ValueError("user_id 不可為空")


class OverrideEffect(StrEnum):
    """覆寫效果：grant 加權(僅限 LOW 風險) / revoke 削權(不限風險)。"""

    GRANT = "grant"
    REVOKE = "revoke"


@dataclass(frozen=True, slots=True)
class PermissionOverride:
    """租戶權限覆寫(D1 混合式) · 自然鍵 = (tenant_id, role, resource, action)。

    D1 鐵則在建構期就強制：非法覆寫連物件都做不出來，
    寫入層自然擋下(繞過寫入層直插資料庫的，由 checker 合併時忽略 + 警告)。
    """

    tenant_id: str
    role: Role
    resource: Resource
    action: Action
    effect: OverrideEffect
    override_id: str = field(default_factory=_new_id)

    def __post_init__(self) -> None:
        if not self.tenant_id:
            raise ValueError("tenant_id 不可為空")
        permission = Permission(self.resource, self.action)
        if self.effect is OverrideEffect.GRANT and permission.risk_tier is RiskTier.HIGH:
            raise HighRiskGrantError(
                f"HIGH 風險權限不可由租戶 grant: {self.resource.value}:{self.action.value}"
            )
        if self.effect is OverrideEffect.REVOKE and self.role is Role.OWNER:
            raise OwnerRevokeError("OWNER 不可被削權(防租戶把自己鎖死在門外)")

    @property
    def permission(self) -> Permission:
        """這筆覆寫對應的權限格。"""
        return Permission(self.resource, self.action)


@dataclass(frozen=True, slots=True)
class AccessSnapshot:
    """一個使用者的完整存取狀態(警衛熱路徑：一趟查詢的結果)。

    為什麼存在：check() 若分三趟查(使用者/角色/覆寫)，p99 延遲疊三倍、
    超出 Charter §14.2 的 5ms 預算——一趟 JOIN 載入是效能基準逼出來的設計。
    """

    user: User
    roles: tuple[Role, ...]
    overrides: tuple[PermissionOverride, ...]  # 全部角色的覆寫(已過濾非法列)
