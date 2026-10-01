"""真 PostgreSQL 整合測試(marker: integration)。

前置: docker compose -f infra/db/docker-compose.yml up -d --wait
本機若 PostgreSQL 未啟動則整批跳過；CI 中不准跳過，直接失敗(防默默漏測)。
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
from collections.abc import AsyncIterator
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlparse

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from src.persistence.engine import create_engine, create_session_factory
from src.persistence.models import FillRow, OrderRow, PositionRow, TradeRow
from src.persistence.repository import (
    FillRepository,
    OrderRepository,
    PositionRepository,
    TradeRepository,
)

from tests.persistence.conftest import make_fill, make_order, make_position, make_trade

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
    """每個測試開始前清空四張表，保證測試彼此獨立。"""
    engine: AsyncEngine = create_engine(PG_URL)
    factory = create_session_factory(engine)
    async with factory() as session:
        for table in ("fills", "trades", "orders", "positions"):
            await session.execute(text(f"TRUNCATE TABLE {table}"))
        await session.commit()
        yield session
    await engine.dispose()


class TestMigration:
    def test_可升可降可再升(self, _migrated: None, monkeypatch: pytest.MonkeyPatch) -> None:
        # 稽核 migration downgrade 有 fail-closed 防呆，測試環境明確開啟才放行(S05 Batch 6b)
        monkeypatch.setenv("STANQUANT_ALLOW_AUDIT_DOWNGRADE", "1")
        assert _alembic("downgrade", "base").returncode == 0
        assert _alembic("upgrade", "head").returncode == 0


class TestRoundTripOnPostgres:
    """真 PG 的存取保真 · Decimal 精度與 UTC 時區由 PG 原生型別承載。"""

    async def test_order_含高精度decimal(self, pg_session: AsyncSession) -> None:
        repo = OrderRepository(pg_session)
        order = make_order(price=Decimal("612.12345678"))
        await repo.save(order)
        restored = await repo.get("stanley", "ORD-001")
        assert restored is not None
        assert restored == order
        assert restored.timestamp.tzinfo is not None

    async def test_position_round_trip(self, pg_session: AsyncSession) -> None:
        repo = PositionRepository(pg_session)
        await repo.save(make_position())
        assert await repo.get("stanley", "2330.TW") == make_position()

    async def test_fill_round_trip(self, pg_session: AsyncSession) -> None:
        repo = FillRepository(pg_session)
        await repo.save(make_fill())
        assert await repo.get("stanley", "FILL-001") == make_fill()

    async def test_trade_round_trip(self, pg_session: AsyncSession) -> None:
        repo = TradeRepository(pg_session)
        await repo.save(make_trade())
        assert await repo.get("stanley", "TRD-001") == make_trade()

    async def test_market單_price_null(self, pg_session: AsyncSession) -> None:
        from src.core.types import OrderType

        repo = OrderRepository(pg_session)
        order = make_order(order_type=OrderType.MARKET, price=None)
        await repo.save(order)
        restored = await repo.get("stanley", "ORD-001")
        assert restored is not None
        assert restored.price is None


class TestConstraintsOnPostgres:
    async def test_positions_唯一鍵_同租戶同標的擋重複(self, pg_session: AsyncSession) -> None:
        from src.persistence.mappers import position_columns

        pg_session.add(PositionRow(**position_columns(make_position())))
        await pg_session.flush()
        pg_session.add(PositionRow(**position_columns(make_position())))
        with pytest.raises(IntegrityError):
            await pg_session.flush()

    async def test_orders_複合鍵_同租戶同id擋重複(self, pg_session: AsyncSession) -> None:
        from src.persistence.mappers import order_columns

        pg_session.add(OrderRow(**order_columns(make_order())))
        await pg_session.flush()
        pg_session.add(OrderRow(**order_columns(make_order())))
        with pytest.raises(IntegrityError):
            await pg_session.flush()

    async def test_orders_複合鍵_跨租戶同id可並存(self, pg_session: AsyncSession) -> None:
        from src.persistence.mappers import order_columns

        pg_session.add(OrderRow(**order_columns(make_order(tenant_id="stanley"))))
        pg_session.add(OrderRow(**order_columns(make_order(tenant_id="other"))))
        await pg_session.flush()  # 全域唯一已解除，跨租戶同 order_id 不應衝突

    async def test_fills_複合鍵_跨租戶同id可並存(self, pg_session: AsyncSession) -> None:
        from src.persistence.mappers import fill_columns

        pg_session.add(FillRow(**fill_columns(make_fill(tenant_id="stanley"))))
        pg_session.add(FillRow(**fill_columns(make_fill(tenant_id="other"))))
        await pg_session.flush()

    async def test_trades_複合鍵_跨租戶同id可並存(self, pg_session: AsyncSession) -> None:
        from src.persistence.mappers import trade_columns

        pg_session.add(TradeRow(**trade_columns(make_trade(tenant_id="stanley"))))
        pg_session.add(TradeRow(**trade_columns(make_trade(tenant_id="other"))))
        await pg_session.flush()

    async def test_紅線欄位自動填寫(self, pg_session: AsyncSession) -> None:
        repo = OrderRepository(pg_session)
        await repo.save(make_order())
        row = (await pg_session.execute(text("SELECT created_at, updated_at FROM orders"))).one()
        assert row.created_at is not None
        assert row.updated_at is not None


class TestTenantIsolationOnPostgres:
    async def test_跨租戶看不到也刪不掉(self, pg_session: AsyncSession) -> None:
        repo = OrderRepository(pg_session)
        await repo.save(make_order())
        assert await repo.get("other", "ORD-001") is None
        assert await repo.delete("other", "ORD-001") is False
        assert await repo.get("stanley", "ORD-001") is not None
