"""L11 RBAC Repository · 唯一的資料存取窗口(S02 同款設計規則)。

1. 進出都是 L11 領域物件，呼叫端永遠不知道資料庫存在
2. 所有方法強制帶 tenant_id，沒有「查全部租戶」的方法(防租戶洩漏)
3. save() 是 upsert 語意：同自然鍵存兩次 = 更新
4. 非法覆寫列(繞過寫入層直插的)讀取時忽略 + 警告日誌(D1 鐵則的第二道防線)
"""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

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
from src.governance.rbac.roles import Role
from src.governance.rbac.types import (
    AccessSnapshot,
    PermissionOverride,
    RoleAssignment,
    User,
)

logger = logging.getLogger(__name__)


def _apply(row: object, columns: dict[str, object]) -> None:
    """把欄位 dict 逐欄寫到既有 ORM 列上(update 路徑)。"""
    for key, value in columns.items():
        setattr(row, key, value)


class UserRepository:
    """使用者存取窗口 · 自然鍵 = (tenant_id, user_id)。"""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, user: User) -> None:
        row = await self._session.scalar(
            select(UserRow).where(
                UserRow.tenant_id == user.tenant_id,
                UserRow.user_id == user.user_id,
            )
        )
        if row is None:
            self._session.add(UserRow(**user_columns(user)))
        else:
            _apply(row, user_columns(user))
        await self._session.flush()

    async def get(self, tenant_id: str, user_id: str) -> User | None:
        row = await self._session.scalar(
            select(UserRow).where(
                UserRow.tenant_id == tenant_id,
                UserRow.user_id == user_id,
            )
        )
        return None if row is None else user_to_domain(row)

    async def get_by_email(self, tenant_id: str, email: str) -> User | None:
        row = await self._session.scalar(
            select(UserRow).where(
                UserRow.tenant_id == tenant_id,
                UserRow.email == email,
            )
        )
        return None if row is None else user_to_domain(row)

    async def list_all(self, tenant_id: str) -> list[User]:
        rows = await self._session.scalars(select(UserRow).where(UserRow.tenant_id == tenant_id))
        return [user_to_domain(row) for row in rows]

    async def delete(self, tenant_id: str, user_id: str) -> bool:
        row = await self._session.scalar(
            select(UserRow).where(
                UserRow.tenant_id == tenant_id,
                UserRow.user_id == user_id,
            )
        )
        if row is None:
            return False
        await self._session.delete(row)
        await self._session.flush()
        return True


class RoleAssignmentRepository:
    """角色指派存取窗口 · 自然鍵 = (tenant_id, user_id, role)。"""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, assignment: RoleAssignment) -> None:
        """upsert：同人同角色重複指派 = 更新既有列，不報錯不重複。"""
        row = await self._session.scalar(
            select(RoleAssignmentRow).where(
                RoleAssignmentRow.tenant_id == assignment.tenant_id,
                RoleAssignmentRow.user_id == assignment.user_id,
                RoleAssignmentRow.role == assignment.role.value,
            )
        )
        if row is None:
            self._session.add(RoleAssignmentRow(**assignment_columns(assignment)))
        else:
            _apply(row, assignment_columns(assignment))
        await self._session.flush()

    async def list_roles(self, tenant_id: str, user_id: str) -> list[Role]:
        """某使用者的全部角色(checker 的核心查詢)。"""
        rows = await self._session.scalars(
            select(RoleAssignmentRow).where(
                RoleAssignmentRow.tenant_id == tenant_id,
                RoleAssignmentRow.user_id == user_id,
            )
        )
        return [Role(row.role) for row in rows]

    async def list_assignments(self, tenant_id: str, user_id: str) -> list[RoleAssignment]:
        rows = await self._session.scalars(
            select(RoleAssignmentRow).where(
                RoleAssignmentRow.tenant_id == tenant_id,
                RoleAssignmentRow.user_id == user_id,
            )
        )
        return [assignment_to_domain(row) for row in rows]

    async def revoke(self, tenant_id: str, user_id: str, role: Role) -> bool:
        """撤銷角色。撤銷後 check() 立即生效(D5：無快取)。"""
        row = await self._session.scalar(
            select(RoleAssignmentRow).where(
                RoleAssignmentRow.tenant_id == tenant_id,
                RoleAssignmentRow.user_id == user_id,
                RoleAssignmentRow.role == role.value,
            )
        )
        if row is None:
            return False
        await self._session.delete(row)
        await self._session.flush()
        return True


class PermissionOverrideRepository:
    """租戶覆寫存取窗口 · 自然鍵 = (tenant_id, role, resource, action)。

    寫入合法性由 PermissionOverride 建構期保證(做不出非法物件)；
    讀取時對直插資料庫的非法列做第二道防線(忽略 + 警告)。
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, override: PermissionOverride) -> None:
        row = await self._session.scalar(
            select(PermissionOverrideRow).where(
                PermissionOverrideRow.tenant_id == override.tenant_id,
                PermissionOverrideRow.role == override.role.value,
                PermissionOverrideRow.resource == override.resource.value,
                PermissionOverrideRow.action == override.action.value,
            )
        )
        if row is None:
            self._session.add(PermissionOverrideRow(**override_columns(override)))
        else:
            _apply(row, override_columns(override))
        await self._session.flush()

    async def list_for_role(self, tenant_id: str, role: Role) -> list[PermissionOverride]:
        rows = await self._session.scalars(
            select(PermissionOverrideRow).where(
                PermissionOverrideRow.tenant_id == tenant_id,
                PermissionOverrideRow.role == role.value,
            )
        )
        return self._to_domain_skipping_illegal(list(rows))

    async def list_all(self, tenant_id: str) -> list[PermissionOverride]:
        rows = await self._session.scalars(
            select(PermissionOverrideRow).where(PermissionOverrideRow.tenant_id == tenant_id)
        )
        return self._to_domain_skipping_illegal(list(rows))

    async def delete(self, tenant_id: str, override_id: str) -> bool:
        row = await self._session.scalar(
            select(PermissionOverrideRow).where(
                PermissionOverrideRow.tenant_id == tenant_id,
                PermissionOverrideRow.override_id == override_id,
            )
        )
        if row is None:
            return False
        await self._session.delete(row)
        await self._session.flush()
        return True

    @staticmethod
    def _to_domain_skipping_illegal(
        rows: list[PermissionOverrideRow],
    ) -> list[PermissionOverride]:
        """D1 鐵則第二道防線：非法列(直插資料庫繞過建構期驗證)忽略 + 警告。"""
        return _overrides_skipping_illegal(rows)


def _overrides_skipping_illegal(
    rows: list[PermissionOverrideRow],
) -> list[PermissionOverride]:
    """共用的第二道防線(覆寫 Repository 與快照 Repository 同款行為)。"""
    result: list[PermissionOverride] = []
    for row in rows:
        try:
            result.append(override_to_domain(row))
        except (HighRiskGrantError, OwnerRevokeError) as error:
            logger.warning(
                "忽略非法權限覆寫列: override_id=%s tenant=%s 原因=%s",
                row.override_id,
                row.tenant_id,
                error,
            )
    return result


class AccessSnapshotRepository:
    """警衛熱路徑專用：一趟 SQL 載入使用者 + 角色 + 覆寫。

    為什麼不分三趟查：每趟往返都有網路與排程延遲，p99 會疊三倍、
    超出 Charter §14.2 的 5ms 預算(效能基準實測逼出來的設計)。
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def load_access_snapshot(self, tenant_id: str, user_id: str) -> AccessSnapshot | None:
        stmt = (
            select(UserRow, RoleAssignmentRow.role, PermissionOverrideRow)
            .outerjoin(
                RoleAssignmentRow,
                (RoleAssignmentRow.tenant_id == UserRow.tenant_id)
                & (RoleAssignmentRow.user_id == UserRow.user_id),
            )
            .outerjoin(
                PermissionOverrideRow,
                (PermissionOverrideRow.tenant_id == RoleAssignmentRow.tenant_id)
                & (PermissionOverrideRow.role == RoleAssignmentRow.role),
            )
            .where(UserRow.tenant_id == tenant_id, UserRow.user_id == user_id)
        )
        rows = (await self._session.execute(stmt)).all()
        if not rows:
            return None
        user = user_to_domain(rows[0][0])
        roles: list[Role] = []
        override_rows: dict[str, PermissionOverrideRow] = {}
        for row in rows:
            role_value: str | None = row[1]
            override_row: PermissionOverrideRow | None = row[2]
            if role_value is not None and Role(role_value) not in roles:
                roles.append(Role(role_value))
            if override_row is not None:
                # 同一筆覆寫可能因 JOIN 重複出現，用 override_id 去重
                override_rows[override_row.override_id] = override_row
        overrides = _overrides_skipping_illegal(list(override_rows.values()))
        return AccessSnapshot(user=user, roles=tuple(roles), overrides=tuple(overrides))
