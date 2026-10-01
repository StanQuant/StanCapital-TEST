"""S04 · L11 Repository 行為測試(SQLite in-memory)。

涵蓋：round-trip / upsert / 租戶隔離 / 撤銷立即生效 / 非法覆寫列第二道防線。
"""

from __future__ import annotations

import logging

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from src.governance.rbac.models import PermissionOverrideRow
from src.governance.rbac.permissions import Action, Resource
from src.governance.rbac.repository import (
    AccessSnapshotRepository,
    PermissionOverrideRepository,
    RoleAssignmentRepository,
    UserRepository,
)
from src.governance.rbac.roles import Role
from src.governance.rbac.types import OverrideEffect

from tests.governance.conftest import make_assignment, make_override, make_user

# ============================================================================
# UserRepository
# ============================================================================


class TestUserRepository:
    async def test_round_trip(self, session: AsyncSession) -> None:
        repo = UserRepository(session)
        user = make_user()
        await repo.save(user)
        assert await repo.get("stanley", "USR-001") == user

    async def test_get_missing_returns_none(self, session: AsyncSession) -> None:
        repo = UserRepository(session)
        assert await repo.get("stanley", "nope") is None

    async def test_upsert_updates_in_place(self, session: AsyncSession) -> None:
        repo = UserRepository(session)
        await repo.save(make_user())
        await repo.save(make_user(display_name="改名後", is_active=False))
        got = await repo.get("stanley", "USR-001")
        assert got is not None
        assert got.display_name == "改名後"
        assert got.is_active is False
        assert len(await repo.list_all("stanley")) == 1

    async def test_get_by_email(self, session: AsyncSession) -> None:
        repo = UserRepository(session)
        await repo.save(make_user())
        got = await repo.get_by_email("stanley", "trader@stanquant.dev")
        assert got is not None
        assert got.user_id == "USR-001"
        assert await repo.get_by_email("stanley", "ghost@x.y") is None

    async def test_tenant_isolation(self, session: AsyncSession) -> None:
        """tenant A 的使用者，tenant B 查不到(防租戶洩漏)。"""
        repo = UserRepository(session)
        await repo.save(make_user())
        assert await repo.get("other-tenant", "USR-001") is None
        assert await repo.list_all("other-tenant") == []

    async def test_delete(self, session: AsyncSession) -> None:
        repo = UserRepository(session)
        await repo.save(make_user())
        assert await repo.delete("stanley", "USR-001") is True
        assert await repo.get("stanley", "USR-001") is None
        assert await repo.delete("stanley", "USR-001") is False


# ============================================================================
# RoleAssignmentRepository
# ============================================================================


class TestRoleAssignmentRepository:
    async def test_assign_and_list_roles(self, session: AsyncSession) -> None:
        repo = RoleAssignmentRepository(session)
        await repo.save(make_assignment())
        assert await repo.list_roles("stanley", "USR-001") == [Role.USER]

    async def test_multi_role_union_basis(self, session: AsyncSession) -> None:
        """D2 裁決：一人多角色，list_roles 回傳全部。"""
        repo = RoleAssignmentRepository(session)
        await repo.save(make_assignment())
        await repo.save(make_assignment(role=Role.COMPLIANCE_OFFICER, assignment_id="ASG-002"))
        roles = await repo.list_roles("stanley", "USR-001")
        assert sorted(roles) == sorted([Role.USER, Role.COMPLIANCE_OFFICER])

    async def test_duplicate_assign_is_upsert(self, session: AsyncSession) -> None:
        """同人同角色指派兩次 = 更新，不報錯不重複。"""
        repo = RoleAssignmentRepository(session)
        await repo.save(make_assignment())
        await repo.save(make_assignment(assignment_id="ASG-NEW"))
        assignments = await repo.list_assignments("stanley", "USR-001")
        assert len(assignments) == 1
        assert assignments[0].assignment_id == "ASG-NEW"

    async def test_revoke_takes_effect_immediately(self, session: AsyncSession) -> None:
        """撤銷後立即查不到(D5：無快取，立即生效)。"""
        repo = RoleAssignmentRepository(session)
        await repo.save(make_assignment())
        assert await repo.revoke("stanley", "USR-001", Role.USER) is True
        assert await repo.list_roles("stanley", "USR-001") == []
        assert await repo.revoke("stanley", "USR-001", Role.USER) is False

    async def test_tenant_isolation(self, session: AsyncSession) -> None:
        repo = RoleAssignmentRepository(session)
        await repo.save(make_assignment())
        assert await repo.list_roles("other-tenant", "USR-001") == []
        assert await repo.revoke("other-tenant", "USR-001", Role.USER) is False


# ============================================================================
# PermissionOverrideRepository
# ============================================================================


class TestPermissionOverrideRepository:
    async def test_round_trip(self, session: AsyncSession) -> None:
        repo = PermissionOverrideRepository(session)
        override = make_override()
        await repo.save(override)
        assert await repo.list_for_role("stanley", Role.USER) == [override]

    async def test_upsert_same_cell(self, session: AsyncSession) -> None:
        """同格子存兩次 = 更新 effect，不重複。"""
        repo = PermissionOverrideRepository(session)
        await repo.save(make_override())
        await repo.save(make_override(effect=OverrideEffect.REVOKE, override_id="OVR-002"))
        got = await repo.list_for_role("stanley", Role.USER)
        assert len(got) == 1
        assert got[0].effect is OverrideEffect.REVOKE

    async def test_list_all_and_delete(self, session: AsyncSession) -> None:
        repo = PermissionOverrideRepository(session)
        await repo.save(make_override())
        await repo.save(
            make_override(role=Role.AGENT, resource=Resource.FILL, override_id="OVR-003")
        )
        assert len(await repo.list_all("stanley")) == 2
        assert await repo.delete("stanley", "OVR-001") is True
        # 驗證刪的是指定那一筆，不是「隨便刪一筆湊數」(殺 ==→!= 變異)
        remaining = await repo.list_all("stanley")
        assert [override.override_id for override in remaining] == ["OVR-003"]
        assert await repo.delete("stanley", "OVR-001") is False

    async def test_tenant_isolation(self, session: AsyncSession) -> None:
        repo = PermissionOverrideRepository(session)
        await repo.save(make_override())
        assert await repo.list_for_role("other-tenant", Role.USER) == []
        assert await repo.list_all("other-tenant") == []
        assert await repo.delete("other-tenant", "OVR-001") is False

    async def test_illegal_row_skipped_with_warning(
        self, session: AsyncSession, caplog: pytest.LogCaptureFixture
    ) -> None:
        """D1 鐵則第二道防線：直插資料庫的 HIGH grant 列被忽略 + 警告日誌。"""
        session.add(
            PermissionOverrideRow(
                override_id="OVR-BAD",
                tenant_id="stanley",
                role=Role.USER.value,
                resource=Resource.USER.value,
                action=Action.MANAGE.value,
                effect=OverrideEffect.GRANT.value,
            )
        )
        await session.flush()
        repo = PermissionOverrideRepository(session)
        with caplog.at_level(logging.WARNING, logger="src.governance.rbac.repository"):
            got = await repo.list_for_role("stanley", Role.USER)
        assert got == []
        assert len(caplog.records) == 1
        assert caplog.records[0].getMessage() == (
            "忽略非法權限覆寫列: override_id=OVR-BAD tenant=stanley "
            "原因=HIGH 風險權限不可由租戶 grant: user:manage"
        )

    async def test_illegal_owner_revoke_row_skipped(
        self, session: AsyncSession, caplog: pytest.LogCaptureFixture
    ) -> None:
        session.add(
            PermissionOverrideRow(
                override_id="OVR-BAD2",
                tenant_id="stanley",
                role=Role.OWNER.value,
                resource=Resource.TRADE.value,
                action=Action.READ.value,
                effect=OverrideEffect.REVOKE.value,
            )
        )
        await session.flush()
        repo = PermissionOverrideRepository(session)
        with caplog.at_level(logging.WARNING, logger="src.governance.rbac.repository"):
            got = await repo.list_all("stanley")
        assert got == []
        assert len(caplog.records) == 1
        assert caplog.records[0].getMessage() == (
            "忽略非法權限覆寫列: override_id=OVR-BAD2 tenant=stanley "
            "原因=OWNER 不可被削權(防租戶把自己鎖死在門外)"
        )


# ============================================================================
# AccessSnapshotRepository(警衛熱路徑：一趟 JOIN)
# ============================================================================


class TestAccessSnapshotRepository:
    async def test_missing_user_returns_none(self, session: AsyncSession) -> None:
        repo = AccessSnapshotRepository(session)
        assert await repo.load_access_snapshot("stanley", "ghost") is None

    async def test_user_without_roles(self, session: AsyncSession) -> None:
        await UserRepository(session).save(make_user())
        snapshot = await AccessSnapshotRepository(session).load_access_snapshot(
            "stanley", "USR-001"
        )
        assert snapshot is not None
        assert snapshot.user == make_user()
        assert snapshot.roles == ()
        assert snapshot.overrides == ()

    async def test_full_snapshot_one_query(self, session: AsyncSession) -> None:
        """多角色 + 多覆寫一趟載入，內容與分開查完全一致。"""
        await UserRepository(session).save(make_user())
        assignments = RoleAssignmentRepository(session)
        await assignments.save(make_assignment())
        await assignments.save(make_assignment(role=Role.MANAGER, assignment_id="ASG-002"))
        overrides = PermissionOverrideRepository(session)
        grant = make_override(resource=Resource.TRADE, action=Action.WRITE)
        revoke = make_override(
            role=Role.MANAGER,
            resource=Resource.ORDER,
            action=Action.WRITE,
            effect=OverrideEffect.REVOKE,
            override_id="OVR-002",
        )
        await overrides.save(grant)
        await overrides.save(revoke)

        snapshot = await AccessSnapshotRepository(session).load_access_snapshot(
            "stanley", "USR-001"
        )
        assert snapshot is not None
        assert snapshot.user == make_user()
        assert sorted(snapshot.roles) == sorted((Role.USER, Role.MANAGER))
        assert sorted(snapshot.overrides, key=lambda o: o.override_id) == [grant, revoke]

    async def test_illegal_row_skipped_with_warning(
        self, session: AsyncSession, caplog: pytest.LogCaptureFixture
    ) -> None:
        """第二道防線在快照路徑同樣生效(與覆寫 Repository 同款訊息)。"""
        await UserRepository(session).save(make_user())
        await RoleAssignmentRepository(session).save(make_assignment())
        session.add(
            PermissionOverrideRow(
                override_id="OVR-BAD",
                tenant_id="stanley",
                role=Role.USER.value,
                resource=Resource.USER.value,
                action=Action.MANAGE.value,
                effect=OverrideEffect.GRANT.value,
            )
        )
        await session.flush()
        with caplog.at_level(logging.WARNING, logger="src.governance.rbac.repository"):
            snapshot = await AccessSnapshotRepository(session).load_access_snapshot(
                "stanley", "USR-001"
            )
        assert snapshot is not None
        assert snapshot.overrides == ()
        assert len(caplog.records) == 1
        assert caplog.records[0].getMessage() == (
            "忽略非法權限覆寫列: override_id=OVR-BAD tenant=stanley "
            "原因=HIGH 風險權限不可由租戶 grant: user:manage"
        )

    async def test_tenant_isolation(self, session: AsyncSession) -> None:
        await UserRepository(session).save(make_user())
        repo = AccessSnapshotRepository(session)
        assert await repo.load_access_snapshot("other-tenant", "USR-001") is None

    async def test_snapshot_excludes_other_users_roles(self, session: AsyncSession) -> None:
        """同租戶另一個使用者的角色不可混進快照(殺 JOIN 條件 &→| 變異)。"""
        users = UserRepository(session)
        await users.save(make_user())
        await users.save(make_user(user_id="USR-002", email="b@stanquant.dev"))
        assignments = RoleAssignmentRepository(session)
        await assignments.save(make_assignment())
        await assignments.save(
            make_assignment(user_id="USR-002", role=Role.OWNER, assignment_id="ASG-B")
        )
        snapshot = await AccessSnapshotRepository(session).load_access_snapshot(
            "stanley", "USR-001"
        )
        assert snapshot is not None
        assert snapshot.roles == (Role.USER,)

    async def test_snapshot_excludes_other_tenant_overrides(self, session: AsyncSession) -> None:
        """別租戶對同名角色的覆寫不可混進快照(殺 JOIN 條件 &→| 變異)。"""
        await UserRepository(session).save(make_user())
        await RoleAssignmentRepository(session).save(make_assignment())
        await PermissionOverrideRepository(session).save(make_override(tenant_id="acme"))
        snapshot = await AccessSnapshotRepository(session).load_access_snapshot(
            "stanley", "USR-001"
        )
        assert snapshot is not None
        assert snapshot.overrides == ()
