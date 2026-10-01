"""S05 Batch 6a · RbacAdminService 測試(RBAC 寫操作自動留稽核)。

用「檔案型 SQLite」而非 in-memory: 失敗證據走獨立 session,需要跨連線可見性
才能真實驗證「FAILED 稽核不隨業務 rollback 蒸發」(test_decorator 同款理由)。

涵蓋:
- 六個寫方法各自:RBAC 變更落地 + SUCCESS 稽核(同交易)
- 跨租戶寫入:擋下 + FAILED 稽核走獨立交易(不隨 rollback 蒸發)
- 成功稽核與業務同交易(commit 前其他連線看不到)
- 預設時鐘路徑(_utc_now)
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
import src.governance.audit.models  # noqa: F401  # 註冊稽核表進 Base.metadata
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from src.governance.audit.decorator import AuditContext
from src.governance.audit.repository import AuditLogRepository
from src.governance.audit.types import AuditOutcome, AuditQuery, AuditRecord
from src.governance.rbac.repository import (
    PermissionOverrideRepository,
    RoleAssignmentRepository,
    UserRepository,
)
from src.governance.rbac.roles import Role
from src.governance.rbac_admin import CrossTenantWriteError, RbacAdminService
from src.persistence.engine import create_engine, create_session_factory
from src.persistence.models import Base

from tests.governance.audit.conftest import fixed_clock
from tests.governance.conftest import make_assignment, make_override, make_user

pytestmark = pytest.mark.asyncio

# 管理員身分脈絡(stanley 租戶的 OWNER 操作 RBAC 設定)
CTX = AuditContext(tenant_id="stanley", user_id="USR-ADMIN", role=Role.OWNER)


@pytest_asyncio.fixture
async def file_engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    eng = create_engine(f"sqlite+aiosqlite:///{tmp_path}/rbac_admin.db")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def factory(file_engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return create_session_factory(file_engine)


def _service(session: AsyncSession, factory: async_sessionmaker[AsyncSession]) -> RbacAdminService:
    return RbacAdminService(session, factory, clock=fixed_clock)


async def _audits(
    factory: async_sessionmaker[AsyncSession], tenant_id: str = "stanley"
) -> tuple[AuditRecord, ...]:
    """用新連線讀稽核(驗證已提交與否)。"""
    async with factory() as fresh:
        page = await AuditLogRepository(fresh).query(AuditQuery(tenant_id=tenant_id))
        return page.records


# ============================================================================
# 使用者
# ============================================================================


async def test_save_user_persists_and_audits(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        service = _service(session, factory)
        await service.save_user(make_user(), audit_ctx=CTX)
        await session.commit()

    async with factory() as fresh:
        saved = await UserRepository(fresh).get("stanley", "USR-001")
        assert saved is not None
        assert saved.email == "trader@stanquant.dev"

    records = await _audits(factory)
    assert len(records) == 1
    assert records[0].action == "rbac.user.save"
    assert records[0].resource == "rbac/user/USR-001"
    assert records[0].response_status == AuditOutcome.SUCCESS
    assert records[0].user_id == "USR-ADMIN"
    assert records[0].role == Role.OWNER


async def test_save_user_audit_is_atomic_with_business_commit(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        service = _service(session, factory)
        await service.save_user(make_user(), audit_ctx=CTX)
        # 還沒 commit:其他連線看不到(同一筆交易的證明)
        assert await _audits(factory) == ()
        await session.commit()
    assert len(await _audits(factory)) == 1


async def test_delete_user_existing_returns_true(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        service = _service(session, factory)
        await service.save_user(make_user(), audit_ctx=CTX)
        deleted = await service.delete_user("USR-001", audit_ctx=CTX)
        await session.commit()
    assert deleted is True

    async with factory() as fresh:
        assert await UserRepository(fresh).get("stanley", "USR-001") is None
    # 一筆 save + 一筆 delete = 兩筆稽核
    actions = [r.action for r in await _audits(factory)]
    assert actions == ["rbac.user.save", "rbac.user.delete"]


async def test_delete_user_missing_returns_false_but_still_audits(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        service = _service(session, factory)
        deleted = await service.delete_user("ghost", audit_ctx=CTX)
        await session.commit()
    assert deleted is False
    records = await _audits(factory)
    assert len(records) == 1
    assert records[0].action == "rbac.user.delete"
    assert records[0].resource == "rbac/user/ghost"


# ============================================================================
# 角色指派
# ============================================================================


async def test_assign_role_persists_and_audits(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        service = _service(session, factory)
        await service.assign_role(make_assignment(role=Role.MANAGER), audit_ctx=CTX)
        await session.commit()

    async with factory() as fresh:
        roles = await RoleAssignmentRepository(fresh).list_roles("stanley", "USR-001")
        assert roles == [Role.MANAGER]

    records = await _audits(factory)
    assert records[0].action == "rbac.role.assign"
    assert records[0].resource == "rbac/user/USR-001/role/manager"


async def test_revoke_role_existing_returns_true(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        service = _service(session, factory)
        await service.assign_role(make_assignment(role=Role.MANAGER), audit_ctx=CTX)
        revoked = await service.revoke_role("USR-001", Role.MANAGER, audit_ctx=CTX)
        await session.commit()
    assert revoked is True
    async with factory() as fresh:
        assert await RoleAssignmentRepository(fresh).list_roles("stanley", "USR-001") == []


async def test_revoke_role_missing_returns_false(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        service = _service(session, factory)
        revoked = await service.revoke_role("USR-001", Role.AGENT, audit_ctx=CTX)
        await session.commit()
    assert revoked is False
    records = await _audits(factory)
    assert records[0].action == "rbac.role.revoke"
    assert records[0].resource == "rbac/user/USR-001/role/agent"


# ============================================================================
# 租戶權限覆寫
# ============================================================================


async def test_set_override_persists_and_audits(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        service = _service(session, factory)
        await service.set_override(make_override(), audit_ctx=CTX)
        await session.commit()

    async with factory() as fresh:
        overrides = await PermissionOverrideRepository(fresh).list_all("stanley")
        assert len(overrides) == 1

    records = await _audits(factory)
    assert records[0].action == "rbac.override.set"
    assert records[0].resource == "rbac/override/user/trade/write"


async def test_remove_override_existing_returns_true(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        service = _service(session, factory)
        await service.set_override(make_override(override_id="OVR-X"), audit_ctx=CTX)
        removed = await service.remove_override("OVR-X", audit_ctx=CTX)
        await session.commit()
    assert removed is True
    async with factory() as fresh:
        assert await PermissionOverrideRepository(fresh).list_all("stanley") == []


async def test_remove_override_missing_returns_false(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        service = _service(session, factory)
        removed = await service.remove_override("nope", audit_ctx=CTX)
        await session.commit()
    assert removed is False
    records = await _audits(factory)
    assert records[0].action == "rbac.override.delete"
    assert records[0].resource == "rbac/override/nope"


# ============================================================================
# 跨租戶寫入:擋下 + FAILED 稽核走獨立交易(不隨 rollback 蒸發)
# ============================================================================


async def test_cross_tenant_save_user_blocked_with_failed_audit(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        service = _service(session, factory)
        with pytest.raises(CrossTenantWriteError, match="跨租戶使用者寫入被拒"):
            await service.save_user(make_user(tenant_id="other-corp"), audit_ctx=CTX)
        await session.rollback()  # 業務交易整筆回滾

    # FAILED 證據在 stanley(身分租戶)名下,且活過 rollback
    records = await _audits(factory)
    assert len(records) == 1
    assert records[0].response_status == AuditOutcome.FAILED
    assert records[0].action == "rbac.user.save"
    # 越界目標的 user_id 仍被記錄在 resource(留下「試圖對誰做」的痕跡)
    assert records[0].resource == "rbac/user/USR-001"
    # 另一個租戶名下沒有任何東西落地
    assert await _audits(factory, tenant_id="other-corp") == ()


async def test_cross_tenant_assign_role_blocked_with_failed_audit(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        service = _service(session, factory)
        with pytest.raises(CrossTenantWriteError, match="跨租戶角色指派寫入被拒"):
            await service.assign_role(make_assignment(tenant_id="other-corp"), audit_ctx=CTX)
        await session.rollback()
    records = await _audits(factory)
    assert records[0].response_status == AuditOutcome.FAILED
    assert records[0].action == "rbac.role.assign"


async def test_cross_tenant_set_override_blocked_with_failed_audit(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        service = _service(session, factory)
        with pytest.raises(CrossTenantWriteError, match="跨租戶權限覆寫寫入被拒"):
            await service.set_override(make_override(tenant_id="other-corp"), audit_ctx=CTX)
        await session.rollback()
    records = await _audits(factory)
    assert records[0].response_status == AuditOutcome.FAILED
    assert records[0].action == "rbac.override.set"


# ============================================================================
# 預設時鐘(_utc_now):不注入 clock 也能運作,時間為 tz-aware
# ============================================================================


async def test_default_clock_produces_aware_timestamp(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        service = RbacAdminService(session, factory)  # 不注入 clock → 用 _utc_now
        await service.save_user(make_user(), audit_ctx=CTX)
        await session.commit()
    records = await _audits(factory)
    assert records[0].timestamp.tzinfo is not None
