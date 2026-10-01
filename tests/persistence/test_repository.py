"""repository 單元測試 · CRUD + upsert + 租戶隔離(SQLite in-memory)。"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import ClassVar

import pytest
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.ext.asyncio import AsyncSession
from src.core.types import OrderStatus, OrderType
from src.persistence.models import OrderRow
from src.persistence.repository import (
    FillRepository,
    OrderRepository,
    PositionRepository,
    TradeRepository,
    _build_upsert,
)

from tests.persistence.conftest import make_fill, make_order, make_position, make_trade


class TestOrderRepository:
    async def test_round_trip(self, session: AsyncSession) -> None:
        repo = OrderRepository(session)
        order = make_order()
        await repo.save(order)
        assert await repo.get("stanley", "ORD-001") == order

    async def test_market單_price_none_round_trip(self, session: AsyncSession) -> None:
        repo = OrderRepository(session)
        order = make_order(order_type=OrderType.MARKET, price=None)
        await repo.save(order)
        restored = await repo.get("stanley", "ORD-001")
        assert restored == order

    async def test_get_不存在回傳none(self, session: AsyncSession) -> None:
        assert await OrderRepository(session).get("stanley", "NO-SUCH") is None

    async def test_upsert_同鍵存兩次是更新(self, session: AsyncSession) -> None:
        repo = OrderRepository(session)
        await repo.save(make_order())
        await repo.save(make_order(status=OrderStatus.FILLED))
        assert (await repo.get("stanley", "ORD-001")).status == OrderStatus.FILLED  # type: ignore[union-attr]
        # 確認沒有重複插入
        assert len(await repo.list_by_symbol("stanley", "2330.TW")) == 1

    async def test_list_by_status(self, session: AsyncSession) -> None:
        repo = OrderRepository(session)
        await repo.save(make_order())
        await repo.save(make_order(order_id="ORD-002", status=OrderStatus.FILLED))
        pending = await repo.list_by_status("stanley", OrderStatus.PENDING)
        assert [o.order_id for o in pending] == ["ORD-001"]

    async def test_list_by_symbol(self, session: AsyncSession) -> None:
        repo = OrderRepository(session)
        await repo.save(make_order())
        await repo.save(make_order(order_id="ORD-002", symbol="2317.TW"))
        result = await repo.list_by_symbol("stanley", "2317.TW")
        assert [o.order_id for o in result] == ["ORD-002"]

    async def test_delete(self, session: AsyncSession) -> None:
        repo = OrderRepository(session)
        await repo.save(make_order())
        assert await repo.delete("stanley", "ORD-001") is True
        assert await repo.get("stanley", "ORD-001") is None
        assert await repo.delete("stanley", "ORD-001") is False

    async def test_delete_命中留INFO痕跡(
        self, session: AsyncSession, caplog: pytest.LogCaptureFixture
    ) -> None:
        # 破壞性操作須留痕(最小可觀測性);未命中不發(無噪音)
        repo = OrderRepository(session)
        await repo.save(make_order())
        with caplog.at_level(logging.INFO, logger="src.persistence.repository"):
            await repo.delete("stanley", "ORD-001")
            await repo.delete("stanley", "ORD-001")  # 第二次未命中
        info = [r for r in caplog.records if r.levelno == logging.INFO]
        assert len(info) == 1
        assert "刪除" in info[0].getMessage()

    async def test_租戶隔離(self, session: AsyncSession) -> None:
        repo = OrderRepository(session)
        await repo.save(make_order())
        assert await repo.get("other", "ORD-001") is None
        assert await repo.list_by_symbol("other", "2330.TW") == []
        assert await repo.delete("other", "ORD-001") is False
        # stanley 的資料原封不動
        assert await repo.get("stanley", "ORD-001") is not None

    async def test_跨租戶可用同一order_id(self, session: AsyncSession) -> None:
        # 自然鍵是每租戶唯一(複合鍵)，非全域唯一：A、B 各自用 ORD-001 不互相干擾
        repo = OrderRepository(session)
        await repo.save(make_order(tenant_id="stanley", order_id="ORD-001"))
        await repo.save(make_order(tenant_id="other", order_id="ORD-001"))
        assert await repo.get("stanley", "ORD-001") is not None
        assert await repo.get("other", "ORD-001") is not None

    async def test_寫後即讀到最新值_同session(self, session: AsyncSession) -> None:
        # 先讀載入 identity map，再 upsert，再讀——core upsert 後須看到新值(非快取舊值)
        repo = OrderRepository(session)
        await repo.save(make_order(status=OrderStatus.PENDING))
        assert (await repo.get("stanley", "ORD-001")).status == OrderStatus.PENDING  # type: ignore[union-attr]
        await repo.save(make_order(status=OrderStatus.FILLED))
        assert (await repo.get("stanley", "ORD-001")).status == OrderStatus.FILLED  # type: ignore[union-attr]


class TestPositionRepository:
    async def test_round_trip(self, session: AsyncSession) -> None:
        repo = PositionRepository(session)
        position = make_position()
        await repo.save(position)
        assert await repo.get("stanley", "2330.TW") == position

    async def test_get_不存在回傳none(self, session: AsyncSession) -> None:
        assert await PositionRepository(session).get("stanley", "NO.TW") is None

    async def test_upsert_同標的存兩次是更新(self, session: AsyncSession) -> None:
        repo = PositionRepository(session)
        await repo.save(make_position())
        await repo.save(make_position(quantity=Decimal("3000")))
        assert (await repo.get("stanley", "2330.TW")).quantity == Decimal("3000")  # type: ignore[union-attr]
        assert len(await repo.list_all("stanley")) == 1

    async def test_list_all(self, session: AsyncSession) -> None:
        repo = PositionRepository(session)
        await repo.save(make_position())
        await repo.save(make_position(symbol="2317.TW"))
        assert len(await repo.list_all("stanley")) == 2

    async def test_delete(self, session: AsyncSession) -> None:
        repo = PositionRepository(session)
        await repo.save(make_position())
        assert await repo.delete("stanley", "2330.TW") is True
        assert await repo.delete("stanley", "2330.TW") is False

    async def test_租戶隔離(self, session: AsyncSession) -> None:
        repo = PositionRepository(session)
        await repo.save(make_position())
        assert await repo.get("other", "2330.TW") is None
        assert await repo.list_all("other") == []
        assert await repo.delete("other", "2330.TW") is False


class TestFillRepository:
    async def test_round_trip(self, session: AsyncSession) -> None:
        repo = FillRepository(session)
        fill = make_fill()
        await repo.save(fill)
        assert await repo.get("stanley", "FILL-001") == fill

    async def test_get_不存在回傳none(self, session: AsyncSession) -> None:
        assert await FillRepository(session).get("stanley", "NO-SUCH") is None

    async def test_upsert_同鍵存兩次是更新(self, session: AsyncSession) -> None:
        repo = FillRepository(session)
        await repo.save(make_fill())
        await repo.save(make_fill(price=Decimal("613.00")))
        assert (await repo.get("stanley", "FILL-001")).price == Decimal("613.00")  # type: ignore[union-attr]
        assert len(await repo.list_by_order("stanley", "ORD-001")) == 1

    async def test_list_by_order(self, session: AsyncSession) -> None:
        repo = FillRepository(session)
        await repo.save(make_fill())
        await repo.save(make_fill(fill_id="FILL-002"))
        await repo.save(make_fill(fill_id="FILL-003", order_id="ORD-099"))
        assert len(await repo.list_by_order("stanley", "ORD-001")) == 2

    async def test_delete(self, session: AsyncSession) -> None:
        repo = FillRepository(session)
        await repo.save(make_fill())
        assert await repo.delete("stanley", "FILL-001") is True
        assert await repo.delete("stanley", "FILL-001") is False

    async def test_租戶隔離(self, session: AsyncSession) -> None:
        repo = FillRepository(session)
        await repo.save(make_fill())
        assert await repo.get("other", "FILL-001") is None
        assert await repo.list_by_order("other", "ORD-001") == []
        assert await repo.delete("other", "FILL-001") is False

    async def test_跨租戶可用同一fill_id(self, session: AsyncSession) -> None:
        repo = FillRepository(session)
        await repo.save(make_fill(tenant_id="stanley", fill_id="FILL-001"))
        await repo.save(make_fill(tenant_id="other", fill_id="FILL-001"))
        assert await repo.get("stanley", "FILL-001") is not None
        assert await repo.get("other", "FILL-001") is not None


class TestTradeRepository:
    async def test_round_trip(self, session: AsyncSession) -> None:
        repo = TradeRepository(session)
        trade = make_trade()
        await repo.save(trade)
        assert await repo.get("stanley", "TRD-001") == trade

    async def test_get_不存在回傳none(self, session: AsyncSession) -> None:
        assert await TradeRepository(session).get("stanley", "NO-SUCH") is None

    async def test_upsert_同鍵存兩次是更新(self, session: AsyncSession) -> None:
        repo = TradeRepository(session)
        await repo.save(make_trade())
        await repo.save(make_trade(pnl=Decimal("12000")))
        assert (await repo.get("stanley", "TRD-001")).pnl == Decimal("12000")  # type: ignore[union-attr]
        assert len(await repo.list_by_symbol("stanley", "2330.TW")) == 1

    async def test_list_by_symbol(self, session: AsyncSession) -> None:
        repo = TradeRepository(session)
        await repo.save(make_trade())
        await repo.save(make_trade(trade_id="TRD-002", symbol="2317.TW"))
        result = await repo.list_by_symbol("stanley", "2317.TW")
        assert [t.trade_id for t in result] == ["TRD-002"]

    async def test_delete(self, session: AsyncSession) -> None:
        repo = TradeRepository(session)
        await repo.save(make_trade())
        assert await repo.delete("stanley", "TRD-001") is True
        assert await repo.delete("stanley", "TRD-001") is False

    async def test_租戶隔離(self, session: AsyncSession) -> None:
        repo = TradeRepository(session)
        await repo.save(make_trade())
        assert await repo.get("other", "TRD-001") is None
        assert await repo.list_by_symbol("other", "2330.TW") == []
        assert await repo.delete("other", "TRD-001") is False

    async def test_跨租戶可用同一trade_id(self, session: AsyncSession) -> None:
        repo = TradeRepository(session)
        await repo.save(make_trade(tenant_id="stanley", trade_id="TRD-001"))
        await repo.save(make_trade(tenant_id="other", trade_id="TRD-001"))
        assert await repo.get("stanley", "TRD-001") is not None
        assert await repo.get("other", "TRD-001") is not None


class TestBuildUpsert:
    """純函式驗證 · 兩個方言分支都組出 ON CONFLICT(不需連線即可覆蓋 PG 分支)。"""

    _VALUES: ClassVar[dict[str, str]] = {
        "tenant_id": "stanley",
        "order_id": "ORD-001",
        "symbol": "2330.TW",
    }
    _CONFLICT: ClassVar[tuple[str, str]] = ("tenant_id", "order_id")

    def test_postgresql_分支組出on_conflict(self) -> None:
        stmt = _build_upsert("postgresql", OrderRow, self._VALUES, self._CONFLICT)
        sql = str(stmt.compile(dialect=postgresql.dialect()))
        assert "ON CONFLICT" in sql
        assert "updated_at" in sql  # 衝突更新時一併推進紅線欄位

    def test_sqlite_分支組出on_conflict(self) -> None:
        stmt = _build_upsert("sqlite", OrderRow, self._VALUES, self._CONFLICT)
        sql = str(stmt.compile(dialect=sqlite.dialect()))
        assert "ON CONFLICT" in sql
        assert "updated_at" in sql
