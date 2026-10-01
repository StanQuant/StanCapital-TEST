"""真 PostgreSQL 整合測試 · RBAC(marker: integration)。

前置: docker compose -f infra/db/docker-compose.yml up -d --wait
本機若 PostgreSQL 未啟動則整批跳過；CI 中不准跳過，直接失敗(防默默漏測)。

重頭戲：8 角色 × 32 格權限矩陣在真資料庫上逐格實測(RoadMap §S04 DoD)。
"""

from __future__ import annotations

import logging
import os
import socket
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from urllib.parse import urlparse

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from src.governance.rbac.checker import RBACChecker
from src.governance.rbac.permissions import Action, Resource
from src.governance.rbac.repository import (
    AccessSnapshotRepository,
    PermissionOverrideRepository,
    RoleAssignmentRepository,
    UserRepository,
)
from src.governance.rbac.roles import Role
from src.governance.rbac.types import OverrideEffect
from src.persistence.engine import create_engine, create_session_factory

from tests.governance.conftest import make_assignment, make_override, make_user
from tests.governance.test_matrix import EXPECTED_CELLS

pytestmark = pytest.mark.integration

PG_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://stanquant:change-me-local-dev-only@localhost:5433/stanquant_test",
)
REPO_ROOT = Path(__file__).parents[2]


def _pg_reachable() -> bool:
    parsed = urlparse(PG_URL.replace("+asyncpg", ""))
    try:
        with socket.create_connection(
            (parsed.hostname or "localhost", parsed.port or 5432), timeout=2
        ):
            return True
    except OSError:
        return False


def _require_pg() -> None:
    if _pg_reachable():
        return
    if os.environ.get("CI"):
        pytest.fail("CI 中 PostgreSQL service 未就緒，整合測試不准跳過")
    pytest.skip("本機 PostgreSQL 未啟動(docker compose -f infra/db/docker-compose.yml up -d)")


def _alembic(*args: str) -> subprocess.CompletedProcess[bytes]:
    # 執行對象是固定的 alembic 指令 + 測試內寫死的參數，非外部輸入
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "alembic", *args],
        cwd=REPO_ROOT,
        env={**os.environ, "DATABASE_URL": PG_URL},
        capture_output=True,
        check=False,
    )


@pytest.fixture(scope="module", autouse=True)
def _migrated() -> None:
    """整個模組跑一次: 確認 PG 可達 + schema 升到最新。"""
    _require_pg()
    result = _alembic("upgrade", "head")
    assert result.returncode == 0, result.stderr.decode()


@pytest_asyncio.fixture
async def pg_session(_migrated: None) -> AsyncIterator[AsyncSession]:
    """每個測試開始前清空三張 RBAC 表，保證測試彼此獨立。"""
    engine: AsyncEngine = create_engine(PG_URL)
    factory = create_session_factory(engine)
    async with factory() as session:
        for table in ("permission_overrides", "role_assignments", "users"):
            await session.execute(text(f"TRUNCATE TABLE {table}"))
        await session.commit()
        yield session
    await engine.dispose()


def _checker(session: AsyncSession) -> RBACChecker:
    """生產組裝方式(S22 同款)：快照 Repository 一趟查詢供警衛決策。"""
    return RBACChecker(AccessSnapshotRepository(session))


class TestMigration:
    def test_可升可降可再升(self, _migrated: None, monkeypatch: pytest.MonkeyPatch) -> None:
        # 稽核 migration downgrade 有 fail-closed 防呆，測試環境明確開啟才放行(S05 Batch 6b)
        monkeypatch.setenv("STANQUANT_ALLOW_AUDIT_DOWNGRADE", "1")
        assert _alembic("downgrade", "base").returncode == 0
        assert _alembic("upgrade", "head").returncode == 0


class TestRoundTripOnPostgres:
    async def test_user_round_trip_含中文(self, pg_session: AsyncSession) -> None:
        repo = UserRepository(pg_session)
        user = make_user(display_name="史丹利·測試員")
        await repo.save(user)
        assert await repo.get("stanley", "USR-001") == user

    async def test_assignment_round_trip(self, pg_session: AsyncSession) -> None:
        users = UserRepository(pg_session)
        assignments = RoleAssignmentRepository(pg_session)
        await users.save(make_user())
        await assignments.save(make_assignment(role=Role.SECURITY_OFFICER))
        assert await assignments.list_roles("stanley", "USR-001") == [Role.SECURITY_OFFICER]

    async def test_override_round_trip(self, pg_session: AsyncSession) -> None:
        repo = PermissionOverrideRepository(pg_session)
        override = make_override()
        await repo.save(override)
        assert await repo.list_for_role("stanley", Role.USER) == [override]


class TestUniqueConstraints:
    async def test_同租戶同email不可重複(self, pg_session: AsyncSession) -> None:
        repo = UserRepository(pg_session)
        await repo.save(make_user())
        with pytest.raises(IntegrityError):
            await repo.save(make_user(user_id="USR-002"))

    async def test_不同租戶同email可以(self, pg_session: AsyncSession) -> None:
        repo = UserRepository(pg_session)
        await repo.save(make_user())
        await repo.save(make_user(tenant_id="acme", user_id="USR-002"))
        assert await repo.get("acme", "USR-002") is not None


class TestFullMatrixOnPostgres:
    """RoadMap §S04 DoD：8 角色 × 32 格全矩陣在真 PG 上逐格實測。"""

    async def test_全矩陣_256格(self, pg_session: AsyncSession) -> None:
        users = UserRepository(pg_session)
        assignments = RoleAssignmentRepository(pg_session)
        checker = _checker(pg_session)
        # 8 個使用者，每人一個角色
        for index, role in enumerate(Role):
            user_id = f"USR-{role.value}"
            await users.save(make_user(user_id=user_id, email=f"{role.value}@stanquant.dev"))
            await assignments.save(
                make_assignment(user_id=user_id, role=role, assignment_id=f"ASG-{index}")
            )
        # 逐格比對(deny-by-default：預期表沒有的格子必須是 False)
        checked = 0
        for role in Role:
            expected_cells = EXPECTED_CELLS[role]
            for resource in Resource:
                for action in Action:
                    expected = (resource.value, action.value) in expected_cells
                    actual = await checker.check("stanley", f"USR-{role.value}", resource, action)
                    assert actual is expected, (
                        f"矩陣不符: {role.value} × {resource.value}:{action.value} "
                        f"預期 {expected} 實際 {actual}"
                    )
                    checked += 1
        assert checked == 256


class TestOverridesOnPostgres:
    async def test_grant與revoke全鏈路(self, pg_session: AsyncSession) -> None:
        """覆寫從寫入到生效的完整鏈路(D1 混合式在真資料庫上成立)。"""
        users = UserRepository(pg_session)
        assignments = RoleAssignmentRepository(pg_session)
        overrides = PermissionOverrideRepository(pg_session)
        checker = _checker(pg_session)
        await users.save(make_user())
        await assignments.save(make_assignment())
        # 基底：USER 沒有 trade:write，有 order:write
        assert await checker.check("stanley", "USR-001", Resource.TRADE, Action.WRITE) is False
        assert await checker.check("stanley", "USR-001", Resource.ORDER, Action.WRITE) is True
        # grant trade:write + revoke order:write
        await overrides.save(make_override(resource=Resource.TRADE, action=Action.WRITE))
        await overrides.save(
            make_override(
                resource=Resource.ORDER,
                action=Action.WRITE,
                effect=OverrideEffect.REVOKE,
                override_id="OVR-002",
            )
        )
        assert await checker.check("stanley", "USR-001", Resource.TRADE, Action.WRITE) is True
        assert await checker.check("stanley", "USR-001", Resource.ORDER, Action.WRITE) is False

    async def test_直插非法覆寫列不生效(
        self, pg_session: AsyncSession, caplog: pytest.LogCaptureFixture
    ) -> None:
        """繞過程式直接 SQL 插入 HIGH grant → 不生效 + 警告(第二道防線實彈驗證)。"""
        users = UserRepository(pg_session)
        assignments = RoleAssignmentRepository(pg_session)
        checker = _checker(pg_session)
        await users.save(make_user())
        await assignments.save(make_assignment())
        await pg_session.execute(
            text(
                "INSERT INTO permission_overrides "
                "(override_id, tenant_id, role, resource, action, effect) "
                "VALUES ('OVR-EVIL', 'stanley', 'user', 'user', 'manage', 'grant')"
            )
        )
        await pg_session.flush()
        with caplog.at_level(logging.WARNING, logger="src.governance.rbac.repository"):
            allowed = await checker.check("stanley", "USR-001", Resource.USER, Action.MANAGE)
        assert allowed is False
        skip_logs = [r for r in caplog.records if "忽略非法權限覆寫列" in r.getMessage()]
        assert len(skip_logs) == 1


class TestTenantIsolationOnPostgres:
    async def test_角色指派不跨租戶(self, pg_session: AsyncSession) -> None:
        """tenant stanley 的 OWNER，在 tenant acme 連使用者都不是。"""
        users = UserRepository(pg_session)
        assignments = RoleAssignmentRepository(pg_session)
        checker = _checker(pg_session)
        await users.save(make_user())
        await assignments.save(make_assignment(role=Role.OWNER))
        assert await checker.check("stanley", "USR-001", Resource.ORDER, Action.READ) is True
        assert await checker.check("acme", "USR-001", Resource.ORDER, Action.READ) is False

    async def test_覆寫不跨租戶(self, pg_session: AsyncSession) -> None:
        """tenant acme 的 grant 對 tenant stanley 的同名角色無效。"""
        users = UserRepository(pg_session)
        assignments = RoleAssignmentRepository(pg_session)
        overrides = PermissionOverrideRepository(pg_session)
        checker = _checker(pg_session)
        await users.save(make_user())
        await assignments.save(make_assignment())
        await overrides.save(
            make_override(tenant_id="acme", resource=Resource.TRADE, action=Action.WRITE)
        )
        assert await checker.check("stanley", "USR-001", Resource.TRADE, Action.WRITE) is False
