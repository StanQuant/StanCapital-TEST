"""persistence 測試共用 fixture 與測試資料工廠。

單元測試用 SQLite in-memory(秒跑、不依賴 Docker)；
PostgreSQL 特有行為由整合測試守住(test_integration_pg.py)。
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from src.core.types import (
    Fill,
    Order,
    OrderSide,
    OrderStatus,
    OrderType,
    Position,
    Trade,
)
from src.persistence.engine import create_engine, create_session_factory
from src.persistence.models import Base

# 固定測試時間(tz-aware UTC)
TS = datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC)


@pytest_asyncio.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    """SQLite in-memory engine，每個測試獨立建表。"""
    eng = create_engine("sqlite+aiosqlite://")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    factory = create_session_factory(engine)
    async with factory() as sess:
        yield sess


# ============================================================================
# 測試資料工廠 · 預設值合理，可用 overrides 覆寫任一欄位
# ============================================================================


def make_order(**overrides: Any) -> Order:
    fields: dict[str, Any] = {
        "order_id": "ORD-001",
        "tenant_id": "stanley",
        "symbol": "2330.TW",
        "side": OrderSide.BUY,
        "order_type": OrderType.LIMIT,
        "quantity": Decimal("1000"),
        "price": Decimal("612.50"),
        "stop_price": None,
        "status": OrderStatus.PENDING,
        "timestamp": TS,
        "strategy_id": "lf_trend_v1",
        "parent_order_id": None,
    }
    fields.update(overrides)
    return Order(**fields)


def make_position(**overrides: Any) -> Position:
    fields: dict[str, Any] = {
        "tenant_id": "stanley",
        "symbol": "2330.TW",
        "quantity": Decimal("2000"),
        "avg_price": Decimal("605.25"),
        "market_value": Decimal("1225000"),
        "unrealized_pnl": Decimal("14500.50"),
        "realized_pnl": Decimal("0"),
        "last_updated": TS,
    }
    fields.update(overrides)
    return Position(**fields)


def make_fill(**overrides: Any) -> Fill:
    fields: dict[str, Any] = {
        "fill_id": "FILL-001",
        "order_id": "ORD-001",
        "tenant_id": "stanley",
        "symbol": "2330.TW",
        "side": OrderSide.BUY,
        "quantity": Decimal("1000"),
        "price": Decimal("612.00"),
        "commission": Decimal("523.26"),
        "timestamp": TS,
    }
    fields.update(overrides)
    return Fill(**fields)


def make_trade(**overrides: Any) -> Trade:
    fields: dict[str, Any] = {
        "trade_id": "TRD-001",
        "tenant_id": "stanley",
        "symbol": "2330.TW",
        "open_fill_id": "FILL-001",
        "close_fill_id": "FILL-002",
        "quantity": Decimal("1000"),
        "open_price": Decimal("612.00"),
        "close_price": Decimal("625.00"),
        "pnl": Decimal("11953.48"),
        "duration_ms": 86400000,
    }
    fields.update(overrides)
    return Trade(**fields)
