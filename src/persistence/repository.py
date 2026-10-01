"""Repository · 唯一的資料存取窗口。

設計規則:
1. 進出都是 L4 領域物件(Order，不是 OrderRow)，呼叫端永遠不知道資料庫存在
2. 所有讀寫方法強制帶 tenant_id，沒有「查全部租戶」的方法(防租戶洩漏)
3. save() 是 upsert 語意: 同自然鍵存兩次 = 更新，不是重複插入
4. 只做 OLTP CRUD，複雜分析查詢屬 S15 BigQuery
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import Insert, func, select
from sqlalchemy.dialects.postgresql import Insert as PgInsert
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import Insert as SqliteInsert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.types import Fill, Order, OrderStatus, Position, Trade
from src.persistence.mappers import (
    fill_columns,
    fill_to_domain,
    order_columns,
    order_to_domain,
    position_columns,
    position_to_domain,
    trade_columns,
    trade_to_domain,
)
from src.persistence.models import FillRow, OrderRow, PositionRow, TradeRow

logger = logging.getLogger(__name__)


def _build_upsert(
    dialect_name: str,
    model: Any,
    values: Mapping[str, Any],
    conflict_cols: Sequence[str],
) -> Insert:
    """組 INSERT ... ON CONFLICT DO UPDATE(依方言選 PostgreSQL / SQLite 版)。

    為什麼用 ON CONFLICT 而不是「先 SELECT 再 INSERT/UPDATE」:
        後者在 SELECT 與寫入之間有 TOCTOU 空檔——兩個併發寫入同一自然鍵時,
        會有一個撞唯一鍵直接爆掉,而不是預期的 upsert(覆蓋更新)。
        ON CONFLICT 是單一原子語句,沒有那個空檔。

    衝突時更新所有「非衝突鍵」欄位,並手動推進 updated_at:
        ORM 的 onupdate 只在 unit-of-work UPDATE 觸發,不會在 ON CONFLICT DO UPDATE
        觸發,所以必須在此明確帶上 func.now(),維持紅線欄位契約。
    """
    stmt: PgInsert | SqliteInsert
    if dialect_name == "postgresql":
        stmt = pg_insert(model).values(**values)
    else:
        stmt = sqlite_insert(model).values(**values)
    assignments: dict[str, Any] = {
        col: stmt.excluded[col] for col in values if col not in conflict_cols
    }
    assignments["updated_at"] = func.now()
    return stmt.on_conflict_do_update(index_elements=list(conflict_cols), set_=assignments)


async def _run_upsert(
    session: AsyncSession,
    model: Any,
    values: Mapping[str, Any],
    conflict_cols: Sequence[str],
) -> None:
    """執行一次原子 upsert(四個 Repository 共用,避免各自重抄一遍)。"""
    stmt = _build_upsert(session.get_bind().dialect.name, model, values, conflict_cols)
    await session.execute(stmt)
    await session.flush()
    # core 級 upsert 繞過 ORM identity map;expire 讓同一 session 後續讀取重新載入,
    # 保有「寫後即可讀到最新值」的一致性(與舊 ORM 寫入路徑行為對齊)。
    session.expire_all()
    # 最小可觀測性:寫入路徑留痕(DEBUG,高頻故預設安靜)。只記自然鍵,不記金額/數量。
    logger.debug(
        "upsert 表=%s tenant=%s 自然鍵=%s",
        model.__tablename__,
        values.get("tenant_id"),
        {k: values.get(k) for k in conflict_cols if k != "tenant_id"},
    )


async def _run_delete(
    session: AsyncSession,
    model: Any,
    filters: Mapping[str, Any],
) -> bool:
    """依 (tenant_id, 自然鍵) 刪除一列,回傳是否真的有刪到(四個 Repository 共用)。"""
    row = await session.scalar(
        select(model).where(*(getattr(model, key) == value for key, value in filters.items()))
    )
    if row is None:
        return False
    await session.delete(row)
    await session.flush()
    # 刪除是破壞性操作,值得 INFO 留痕(誰的哪一筆被刪)。
    logger.info("刪除 表=%s 鍵=%s", model.__tablename__, dict(filters))
    return True


class OrderRepository:
    """訂單存取窗口 · 自然鍵 = (tenant_id, order_id)。"""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, order: Order) -> None:
        await _run_upsert(self._session, OrderRow, order_columns(order), ("tenant_id", "order_id"))

    async def get(self, tenant_id: str, order_id: str) -> Order | None:
        row = await self._session.scalar(
            select(OrderRow).where(
                OrderRow.tenant_id == tenant_id,
                OrderRow.order_id == order_id,
            )
        )
        return None if row is None else order_to_domain(row)

    async def list_by_status(self, tenant_id: str, status: OrderStatus) -> list[Order]:
        rows = await self._session.scalars(
            select(OrderRow).where(
                OrderRow.tenant_id == tenant_id,
                OrderRow.status == status.value,
            )
        )
        return [order_to_domain(row) for row in rows]

    async def list_by_symbol(self, tenant_id: str, symbol: str) -> list[Order]:
        rows = await self._session.scalars(
            select(OrderRow).where(
                OrderRow.tenant_id == tenant_id,
                OrderRow.symbol == symbol,
            )
        )
        return [order_to_domain(row) for row in rows]

    async def delete(self, tenant_id: str, order_id: str) -> bool:
        return await _run_delete(
            self._session, OrderRow, {"tenant_id": tenant_id, "order_id": order_id}
        )


class PositionRepository:
    """持倉存取窗口 · 自然鍵 = (tenant_id, symbol)。"""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, position: Position) -> None:
        await _run_upsert(
            self._session, PositionRow, position_columns(position), ("tenant_id", "symbol")
        )

    async def get(self, tenant_id: str, symbol: str) -> Position | None:
        row = await self._session.scalar(
            select(PositionRow).where(
                PositionRow.tenant_id == tenant_id,
                PositionRow.symbol == symbol,
            )
        )
        return None if row is None else position_to_domain(row)

    async def list_all(self, tenant_id: str) -> list[Position]:
        rows = await self._session.scalars(
            select(PositionRow).where(PositionRow.tenant_id == tenant_id)
        )
        return [position_to_domain(row) for row in rows]

    async def delete(self, tenant_id: str, symbol: str) -> bool:
        return await _run_delete(
            self._session, PositionRow, {"tenant_id": tenant_id, "symbol": symbol}
        )


class FillRepository:
    """成交回報存取窗口 · 自然鍵 = (tenant_id, fill_id)。"""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, fill: Fill) -> None:
        await _run_upsert(self._session, FillRow, fill_columns(fill), ("tenant_id", "fill_id"))

    async def get(self, tenant_id: str, fill_id: str) -> Fill | None:
        row = await self._session.scalar(
            select(FillRow).where(
                FillRow.tenant_id == tenant_id,
                FillRow.fill_id == fill_id,
            )
        )
        return None if row is None else fill_to_domain(row)

    async def list_by_order(self, tenant_id: str, order_id: str) -> list[Fill]:
        rows = await self._session.scalars(
            select(FillRow).where(
                FillRow.tenant_id == tenant_id,
                FillRow.order_id == order_id,
            )
        )
        return [fill_to_domain(row) for row in rows]

    async def delete(self, tenant_id: str, fill_id: str) -> bool:
        return await _run_delete(
            self._session, FillRow, {"tenant_id": tenant_id, "fill_id": fill_id}
        )


class TradeRepository:
    """完整交易週期存取窗口 · 自然鍵 = (tenant_id, trade_id)。"""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, trade: Trade) -> None:
        await _run_upsert(self._session, TradeRow, trade_columns(trade), ("tenant_id", "trade_id"))

    async def get(self, tenant_id: str, trade_id: str) -> Trade | None:
        row = await self._session.scalar(
            select(TradeRow).where(
                TradeRow.tenant_id == tenant_id,
                TradeRow.trade_id == trade_id,
            )
        )
        return None if row is None else trade_to_domain(row)

    async def list_by_symbol(self, tenant_id: str, symbol: str) -> list[Trade]:
        rows = await self._session.scalars(
            select(TradeRow).where(
                TradeRow.tenant_id == tenant_id,
                TradeRow.symbol == symbol,
            )
        )
        return [trade_to_domain(row) for row in rows]

    async def delete(self, tenant_id: str, trade_id: str) -> bool:
        return await _run_delete(
            self._session, TradeRow, {"tenant_id": tenant_id, "trade_id": trade_id}
        )
