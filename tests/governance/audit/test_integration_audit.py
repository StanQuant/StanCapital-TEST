"""真 PostgreSQL 整合測試 · Audit(marker: integration)。

前置: docker compose -f infra/db/docker-compose.yml up -d --wait
本機若 PostgreSQL 未啟動則整批跳過；CI 中不准跳過(防默默漏測)。

重頭戲(RoadMap §S05 DoD):
- 觸發器實彈: UPDATE / DELETE / TRUNCATE 被資料庫本身拒絕
- 低權帳號實彈(D2 裁決 c): stanquant_app 連 UPDATE 權限都沒有
- 並行 append 鏈不分叉(FOR UPDATE 行鎖實彈)
- 篡改(owner 暫停觸發器偷改)被驗證器抓到
"""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from urllib.parse import urlparse

import pytest
import pytest_asyncio
from sqlalchemy import make_url, text
from sqlalchemy.exc import DBAPIError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from src.governance.audit.repository import AuditLogRepository
from src.governance.audit.types import AuditQuery
from src.governance.audit.verifier import ChainVerifier
from src.persistence.engine import create_engine, create_session_factory

from tests.governance.audit.conftest import make_input

pytestmark = pytest.mark.integration

PG_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://stanquant:change-me-local-dev-only@localhost:5433/stanquant_test",
)
# 低權執行帳號(D2 裁決 c)·開發/CI 用密碼，生產由部署腳本另設。
# 用 URL 解析換帳密(不靠脆弱的字串 replace——本機 stanquant / CI stanquant_test 格式不同)。
APP_ROLE = "stanquant_app"
APP_ROLE_PASSWORD = "stanquant_app_dev"
# 注意:不可用 str(URL)——SQLAlchemy 為防洩漏會把密碼遮成 ***,送去連線必 auth 失敗
# (本機 trust 認證放行故假綠,CI scram 驗密碼才現形)。須 render_as_string 取真實密碼。
APP_ROLE_URL = (
    make_url(PG_URL)
    .set(username=APP_ROLE, password=APP_ROLE_PASSWORD)
    .render_as_string(hide_password=False)
)
REPO_ROOT = Path(__file__).parents[3]
TENANT = "tenant-a"

# 與 migration c4e82a51b9d7 的 DO 區塊同一套權限(fixture 在角色建立後重放，冪等)。
# asyncpg 一次只能跑一句，DO $$...$$ 區塊內含分號不可被拆——故逐句獨立執行。
_APP_ROLE_STATEMENTS = (
    """
    DO $$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'stanquant_app') THEN
            CREATE ROLE stanquant_app LOGIN PASSWORD 'stanquant_app_dev';
        END IF;
    END
    $$
    """,
    "GRANT CONNECT ON DATABASE stanquant_test TO stanquant_app",
    "GRANT USAGE ON SCHEMA public TO stanquant_app",
    "GRANT SELECT, INSERT ON audit_records, audit_checkpoints TO stanquant_app",
    "REVOKE UPDATE, DELETE, TRUNCATE ON audit_records, audit_checkpoints FROM stanquant_app",
    "GRANT SELECT, INSERT, UPDATE ON audit_chain_heads TO stanquant_app",
    "REVOKE DELETE, TRUNCATE ON audit_chain_heads FROM stanquant_app",
    "GRANT USAGE, SELECT ON SEQUENCE "
    "audit_records_id_seq, audit_chain_heads_id_seq, audit_checkpoints_id_seq "
    "TO stanquant_app",
)


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


async def _setup_app_role() -> None:
    """建立低權測試帳號 + 重放權限(冪等)。"""
    engine = create_engine(PG_URL)
    async with engine.begin() as conn:
        for statement in _APP_ROLE_STATEMENTS:
            await conn.execute(text(statement))
    await engine.dispose()


@pytest.fixture(scope="module", autouse=True)
def _migrated() -> None:
    """整個模組跑一次: PG 可達 + schema 升到最新 + 低權帳號就緒。

    用 **sync** fixture(與 S04 _migrated 一致): async module-scoped autouse
    fixture 在 CI 的 pytest-asyncio loop scope 下不穩——角色建立的連線跑在
    與測試不同的 event loop, CREATE ROLE 未生效 → CI 報 InvalidPasswordError。
    改 sync + asyncio.run 用獨立 loop 建角色, 不依賴 module loop scope。
    """
    _require_pg()
    result = _alembic("upgrade", "head")
    assert result.returncode == 0, result.stderr.decode()
    asyncio.run(_setup_app_role())


async def _truncate_audit_tables(session: AsyncSession) -> None:
    """測試隔離用清表: owner 暫停觸發器才truncate得動(這正是防線有效的證明)。"""
    await session.execute(text("SET session_replication_role = replica"))
    await session.execute(
        text("TRUNCATE TABLE audit_records, audit_checkpoints, audit_chain_heads")
    )
    await session.execute(text("SET session_replication_role = DEFAULT"))
    await session.commit()


@pytest_asyncio.fixture
async def pg_engine(_migrated: None) -> AsyncIterator[AsyncEngine]:
    engine = create_engine(PG_URL)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def pg_session(pg_engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    factory = create_session_factory(pg_engine)
    async with factory() as session:
        await _truncate_audit_tables(session)
        yield session


class TestMigration:
    def test_可升可降可再升(self, _migrated: None, monkeypatch: pytest.MonkeyPatch) -> None:
        # 稽核 migration downgrade 有 fail-closed 防呆，測試環境明確開啟才放行(S05 Batch 6b)
        monkeypatch.setenv("STANQUANT_ALLOW_AUDIT_DOWNGRADE", "1")
        assert _alembic("downgrade", "base").returncode == 0
        assert _alembic("upgrade", "head").returncode == 0


class TestRoundTripOnPostgres:
    async def test_append_round_trip_含中文與時區(self, pg_session: AsyncSession) -> None:
        repo = AuditLogRepository(pg_session)
        written = await repo.append(make_input(resource="order/台積電-2330"))
        await pg_session.commit()
        page = await repo.query(AuditQuery(tenant_id=TENANT))
        assert page.records == (written,)
        assert page.records[0].timestamp.tzinfo is not None

    async def test_checkpoint_sealed_on_postgres(self, pg_session: AsyncSession) -> None:
        repo = AuditLogRepository(pg_session, checkpoint_batch_size=5)
        await repo.append_many([make_input(action=f"op.{i}") for i in range(5)])
        await pg_session.commit()
        checkpoints = await repo.list_checkpoints(TENANT)
        assert len(checkpoints) == 1
        assert checkpoints[0].end_sequence == 5


class TestAppendOnlyTriggers:
    """防線 3 實彈: 連 owner 帳號的 UPDATE / DELETE / TRUNCATE 都被觸發器擋。"""

    async def _seed(self, session: AsyncSession) -> None:
        await AuditLogRepository(session).append(make_input())
        await session.commit()

    async def test_update_blocked(self, pg_session: AsyncSession) -> None:
        await self._seed(pg_session)
        with pytest.raises(DBAPIError, match="append-only"):
            await pg_session.execute(text("UPDATE audit_records SET action = 'evil'"))
        await pg_session.rollback()

    async def test_delete_blocked(self, pg_session: AsyncSession) -> None:
        await self._seed(pg_session)
        with pytest.raises(DBAPIError, match="append-only"):
            await pg_session.execute(text("DELETE FROM audit_records"))
        await pg_session.rollback()

    async def test_truncate_blocked(self, pg_session: AsyncSession) -> None:
        await self._seed(pg_session)
        with pytest.raises(DBAPIError, match="append-only"):
            await pg_session.execute(text("TRUNCATE TABLE audit_records"))
        await pg_session.rollback()

    async def test_checkpoint_update_blocked(self, pg_session: AsyncSession) -> None:
        repo = AuditLogRepository(pg_session, checkpoint_batch_size=1)
        await repo.append(make_input())
        await pg_session.commit()
        with pytest.raises(DBAPIError, match="append-only"):
            await pg_session.execute(
                text("UPDATE audit_checkpoints SET merkle_root = repeat('e', 64)")
            )
        await pg_session.rollback()

    async def test_chain_head_delete_blocked(self, pg_session: AsyncSession) -> None:
        await self._seed(pg_session)
        with pytest.raises(DBAPIError, match="append-only"):
            await pg_session.execute(text("DELETE FROM audit_chain_heads"))
        await pg_session.rollback()

    async def test_chain_head_truncate_blocked(self, pg_session: AsyncSession) -> None:
        await self._seed(pg_session)
        with pytest.raises(DBAPIError, match="append-only"):
            await pg_session.execute(text("TRUNCATE TABLE audit_chain_heads"))
        await pg_session.rollback()


class TestLowPrivilegeRole:
    """防線 2 實彈(D2 裁決 c): 低權帳號連權限都沒有，比觸發器更早被擋。"""

    async def test_app_role_can_append(self, pg_session: AsyncSession) -> None:
        engine = create_engine(APP_ROLE_URL)
        try:
            factory = create_session_factory(engine)
            async with factory() as session:
                record = await AuditLogRepository(session).append(make_input())
                await session.commit()
                assert record.sequence == 1
        finally:
            await engine.dispose()

    @pytest.mark.parametrize(
        "statement",
        [
            "UPDATE audit_records SET action = 'evil'",
            "DELETE FROM audit_records",
            "TRUNCATE TABLE audit_records",
            "DELETE FROM audit_chain_heads",
            "UPDATE audit_checkpoints SET merkle_root = repeat('e', 64)",
        ],
        ids=["update-records", "delete-records", "truncate-records", "delete-head", "update-ckpt"],
    )
    async def test_app_role_mutations_denied(
        self, pg_session: AsyncSession, statement: str
    ) -> None:
        await AuditLogRepository(pg_session).append(make_input())
        await pg_session.commit()
        engine = create_engine(APP_ROLE_URL)
        try:
            factory = create_session_factory(engine)
            async with factory() as session:
                with pytest.raises(ProgrammingError, match="permission denied"):
                    await session.execute(text(statement))
        finally:
            await engine.dispose()


class TestConcurrentAppend:
    """FOR UPDATE 行鎖實彈: 同租戶兩條連線並行寫，鏈不分叉、不跳號、不重號。"""

    async def test_parallel_appends_keep_chain_intact(self, pg_session: AsyncSession) -> None:
        per_worker = 15

        async def worker(worker_id: int) -> None:
            engine = create_engine(APP_ROLE_URL)  # 順便用低權帳號跑生產路徑
            try:
                factory = create_session_factory(engine)
                for i in range(per_worker):
                    async with factory() as session:
                        await AuditLogRepository(session).append(
                            make_input(action=f"op.w{worker_id}.{i}")
                        )
                        await session.commit()
            finally:
                await engine.dispose()

        await asyncio.gather(worker(1), worker(2))

        repo = AuditLogRepository(pg_session)
        head = await repo.get_chain_head(TENANT)
        assert head is not None
        assert head.last_sequence == per_worker * 2

        report = await ChainVerifier(repo).verify_tenant_chain(TENANT)
        assert report.is_intact, report
        assert report.checked_count == per_worker * 2


class TestTamperDetectionOnPostgres:
    """Demo 場景前哨: owner 暫停觸發器偷改一筆 → 驗證器當場抓到。"""

    async def test_tamper_behind_triggers_is_detected(self, pg_session: AsyncSession) -> None:
        repo = AuditLogRepository(pg_session)
        await repo.append_many([make_input(action=f"op.{i}") for i in range(3)])
        await pg_session.commit()

        await pg_session.execute(text("SET session_replication_role = replica"))
        await pg_session.execute(
            text("UPDATE audit_records SET action = 'order.evil' WHERE sequence = 2")
        )
        await pg_session.execute(text("SET session_replication_role = DEFAULT"))
        await pg_session.commit()

        report = await ChainVerifier(repo).verify_tenant_chain(TENANT)
        assert not report.is_intact
        assert report.mismatched_sequences == (2,)
