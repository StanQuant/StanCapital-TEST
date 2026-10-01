"""真 PostgreSQL 整合測試 · ABAC 全鏈路(marker: integration)。

前置: docker compose -f infra/db/docker-compose.yml up -d --wait
本機若 PostgreSQL 未啟動則整批跳過；CI 中不准跳過(防默默漏測)。

重頭戲(RoadMap §S06 DoD)：部門 × 區域 × 敏感度複雜場景,
且**使用者屬性由真資料庫經 AccessSnapshotRepository 同趟載入**驅動 ABAC 決策——
證明 D4「權威屬性取自 users 表」確實成立(同請求、僅 DB 屬性不同 → 不同結果)。
"""

from __future__ import annotations

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
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from src.governance.abac.dsl import load_policies
from src.governance.abac.errors import ApprovalRequiredError
from src.governance.abac.evaluator import AbacEvaluator
from src.governance.access_guard import (
    ABAC_APPROVAL_ACTION,
    ABAC_DENIED_ACTION,
    AbacAccessGuard,
    ApprovalRequestEvent,
)
from src.governance.audit.decorator import AuditContext
from src.governance.audit.repository import AuditLogRepository
from src.governance.audit.types import AuditQuery, AuditRecord
from src.governance.rbac.checker import RBACChecker
from src.governance.rbac.permissions import Action, Resource
from src.governance.rbac.repository import (
    AccessSnapshotRepository,
    RoleAssignmentRepository,
    UserRepository,
)
from src.governance.rbac.roles import Role
from src.governance.rbac.types import RoleAssignment, User
from src.persistence.engine import create_engine, create_session_factory

pytestmark = pytest.mark.integration

PG_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://stanquant:change-me-local-dev-only@localhost:5433/stanquant_test",
)
REPO_ROOT = Path(__file__).parents[3]
_BASE_POLICIES = load_policies(REPO_ROOT / "policies" / "abac" / "base.yaml")


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
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "alembic", *args],
        cwd=REPO_ROOT,
        env={**os.environ, "DATABASE_URL": PG_URL},
        capture_output=True,
        check=False,
    )


@pytest.fixture(scope="module", autouse=True)
def _migrated() -> None:
    _require_pg()
    result = _alembic("upgrade", "head")
    assert result.returncode == 0, result.stderr.decode()


@pytest_asyncio.fixture
async def pg_factory(_migrated: None) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """每個測試前清 RBAC + 稽核表。稽核表有 append-only 觸發器，
    用 session_replication_role=replica 暫繞過(owner 連線，S05 同款)。"""
    engine: AsyncEngine = create_engine(PG_URL)
    factory = create_session_factory(engine)
    async with factory() as session:
        await session.execute(text("TRUNCATE TABLE permission_overrides, role_assignments, users"))
        await session.execute(text("SET session_replication_role = replica"))
        await session.execute(
            text("TRUNCATE TABLE audit_records, audit_checkpoints, audit_chain_heads")
        )
        await session.execute(text("SET session_replication_role = DEFAULT"))
        await session.commit()
    yield factory
    await engine.dispose()


class _RecordingSink:
    def __init__(self) -> None:
        self.events: list[ApprovalRequestEvent] = []

    async def publish(self, event: ApprovalRequestEvent) -> None:
        self.events.append(event)


def _ctx(user_id: str) -> AuditContext:
    return AuditContext(tenant_id="stanley", user_id=user_id, role=Role.MANAGER)


async def _seed_manager(
    factory: async_sessionmaker[AsyncSession],
    user_id: str,
    *,
    department: str = "trading",
    region: str = "taiwan",
    project: str = "alpha",
) -> None:
    """寫一個帶屬性的 MANAGER 進真 DB 並 commit(讓快照查詢看得到)。"""
    async with factory() as session:
        await UserRepository(session).save(
            User(
                tenant_id="stanley",
                email=f"{user_id}@stanquant.dev",
                display_name="整合測試經理",
                user_id=user_id,
                is_active=True,
                department=department,
                region=region,
                project=project,
            )
        )
        await RoleAssignmentRepository(session).save(
            RoleAssignment(tenant_id="stanley", user_id=user_id, role=Role.MANAGER)
        )
        await session.commit()


async def _audits(factory: async_sessionmaker[AsyncSession]) -> tuple[AuditRecord, ...]:
    async with factory() as session:
        page = await AuditLogRepository(session).query(AuditQuery(tenant_id="stanley"))
        return page.records


async def _run(
    factory: async_sessionmaker[AsyncSession],
    user_id: str,
    *,
    resource: Resource,
    action: Action,
    sensitivity_level: int,
    risk_category: str,
    sink: _RecordingSink,
) -> None:
    async with factory() as read_session:
        guard = AbacAccessGuard(
            RBACChecker(AccessSnapshotRepository(read_session)),
            AbacEvaluator(_BASE_POLICIES),
            factory,
            sink,
        )
        await guard.require_abac(
            resource,
            action,
            sensitivity_level=sensitivity_level,
            risk_category=risk_category,
            audit_ctx=_ctx(user_id),
        )


class TestMigration:
    def test_可升可降可再升(self, _migrated: None) -> None:
        # 只驗 S06 這支 migration 可逆(稽核 migration 的 downgrade 防呆不在本切片範圍)
        assert _alembic("downgrade", "-1").returncode == 0
        assert _alembic("upgrade", "head").returncode == 0


class TestAttributesFromDatabaseDriveDecision:
    """同一段請求,只差 DB 內存的屬性 → 不同 ABAC 結果(D4 權威屬性實證)。"""

    async def test_normal_trading_allowed(
        self, pg_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _seed_manager(pg_factory, "USR-A", department="trading", region="taiwan")
        sink = _RecordingSink()
        await _run(
            pg_factory,
            "USR-A",
            resource=Resource.ORDER,
            action=Action.WRITE,
            sensitivity_level=2,
            risk_category="normal",
            sink=sink,
        )
        assert await _audits(pg_factory) == ()  # ALLOW 不另記稽核

    async def test_quarantine_department_denied(
        self, pg_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        # 與上一案唯一差別:DB 內 department=quarantine → 應被擋
        await _seed_manager(pg_factory, "USR-B", department="quarantine", region="taiwan")
        sink = _RecordingSink()
        with pytest.raises(Exception) as excinfo:
            await _run(
                pg_factory,
                "USR-B",
                resource=Resource.ORDER,
                action=Action.WRITE,
                sensitivity_level=2,
                risk_category="normal",
                sink=sink,
            )
        assert "PermissionDenied" in type(excinfo.value).__name__
        records = await _audits(pg_factory)
        assert len(records) == 1
        assert records[0].action == ABAC_DENIED_ACTION

    async def test_restricted_region_denied(
        self, pg_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _seed_manager(pg_factory, "USR-C", department="trading", region="restricted")
        sink = _RecordingSink()
        with pytest.raises(Exception) as excinfo:
            await _run(
                pg_factory,
                "USR-C",
                resource=Resource.ORDER,
                action=Action.WRITE,  # MANAGER 有 order:write，RBAC 過 → ABAC 因 restricted 區域擋
                sensitivity_level=1,
                risk_category="normal",
                sink=sink,
            )
        assert "PermissionDenied" in type(excinfo.value).__name__
        assert (await _audits(pg_factory))[0].action == ABAC_DENIED_ACTION


class TestApprovalOnPostgres:
    async def test_high_sensitivity_requires_approval(
        self, pg_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        await _seed_manager(pg_factory, "USR-D", department="trading", region="taiwan")
        sink = _RecordingSink()
        with pytest.raises(ApprovalRequiredError):
            await _run(
                pg_factory,
                "USR-D",
                resource=Resource.ORDER,
                action=Action.WRITE,
                sensitivity_level=4,
                risk_category="normal",
                sink=sink,
            )
        # 真稽核 + 真事件
        records = await _audits(pg_factory)
        assert len(records) == 1
        assert records[0].action == ABAC_APPROVAL_ACTION
        assert len(sink.events) == 1
        assert sink.events[0].matched_policy == "approval-high-sensitivity-write"
