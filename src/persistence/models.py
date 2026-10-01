"""L5 ORM 模型 · 資料庫的形狀(與 L4 領域物件嚴格分離)。

設計準則:
- Schema 紅線(Architecture.md §L5): id BIGSERIAL / tenant_id NOT NULL 無預設值 /
  created_at / updated_at / tenant_id 必有索引
- Decimal 欄位用 PreciseDecimal: PostgreSQL 存 NUMERIC(20, 8)、SQLite 存字串
  (SQLite 的 NUMERIC 底層是浮點，直接存會失真)
- 時間欄位用 UTCDateTime: 讀出時保證 tz-aware UTC(SQLite 會丟失時區資訊)
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    Index,
    Integer,
    Numeric,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, declared_attr, mapped_column
from sqlalchemy.types import TypeDecorator, TypeEngine

logger = logging.getLogger(__name__)

# SQLite 的自增主鍵必須是 INTEGER，PostgreSQL 用 BIGSERIAL
_PrimaryKeyInt = BigInteger().with_variant(Integer(), "sqlite")

# NUMERIC(20, 8) 的儲存契約：總 20 位、小數 8 位 → 整數部分最多 12 位。
_DB_SCALE = 8
_DB_MAX_WHOLE_DIGITS = 20 - _DB_SCALE  # = 12
_QUANTUM = Decimal(1).scaleb(-_DB_SCALE)  # Decimal("0.00000001")，quantize 的目標位數
_MAX_ABS = Decimal(10) ** _DB_MAX_WHOLE_DIGITS  # 10**12，整數部分必須 < 此值


def _to_db_decimal(value: Decimal) -> Decimal:
    """把 Decimal 對齊 NUMERIC(20,8) 的儲存契約：小數捨入到 8 位、整數溢位則擋下。

    為什麼需要(跨方言一致性)：
        SQLite 以字串原樣存、PostgreSQL 存原生 NUMERIC(20,8)。若不在寫入邊界統一，
        同一個「小數超過 8 位」的值會在 SQLite 原樣留存、在 PostgreSQL 被靜默捨入——
        兩方言行為不一致，單元測試(SQLite)綠燈但正式環境(PG)悄悄改值，線上對不上帳。

    行為(fail-closed，且不靜默)：
        - 小數 > 8 位：用 ROUND_HALF_UP 捨入到 8 位(對齊 PostgreSQL NUMERIC 的捨入方式)，
          且僅在「值真的被改動」時發一筆 WARNING(補上尾零不算改動，故正常寫入零噪音)。
        - 整數部分 ≥ 12 位(超出 NUMERIC(20,8) 容量)：PG 會報錯、SQLite 會靜默存壞，
          故在此明確 raise，兩方言一致 fail-closed，不讓存不下的數字悄悄落地。
    """
    if value.copy_abs() >= _MAX_ABS:
        raise ValueError(
            f"Decimal 超出 NUMERIC(20,8) 可儲存範圍(整數部分需 < 10^{_DB_MAX_WHOLE_DIGITS})：{value}"
        )
    quantized = value.quantize(_QUANTUM, rounding=ROUND_HALF_UP)
    if quantized.copy_abs() >= _MAX_ABS:  # 捨入進位剛好頂破上限(如 999...9.999999995)
        raise ValueError(f"Decimal 捨入後進位超出 NUMERIC(20,8) 可儲存範圍：{value} → {quantized}")
    if quantized != value:  # 數值真的被改動才留痕(補尾零數值相等→不發)
        logger.warning("Decimal 寫入前捨入到 %d 位小數：%s → %s", _DB_SCALE, value, quantized)
    return quantized


class PreciseDecimal(TypeDecorator[Decimal]):
    """跨方言精確小數欄位。"""

    impl = Numeric(20, 8)
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect) -> TypeEngine[Any]:
        if dialect.name == "sqlite":
            return dialect.type_descriptor(String(64))
        return dialect.type_descriptor(Numeric(20, 8))

    def process_bind_param(self, value: Decimal | None, dialect: Dialect) -> object:
        if value is None:
            return None
        # 對齊 NUMERIC(20,8)：兩方言一致捨入到 8 位 + 整數溢位 fail-closed(見 _to_db_decimal)
        value = _to_db_decimal(value)
        if dialect.name == "sqlite":
            return str(value)
        return value

    def process_result_value(self, value: object, dialect: Dialect) -> Decimal | None:
        if value is None:
            return None
        return Decimal(str(value))


class UTCDateTime(TypeDecorator[datetime]):
    """tz-aware UTC 時間欄位 · 寫入前統一轉 UTC，讀出時補回時區。"""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            # naive 時間進來代表上游漏了時區，直接擋下比默默猜測安全
            raise ValueError("時間必須是 tz-aware(請用 UTC)")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class Base(DeclarativeBase):
    """所有 ORM 模型的基底。"""


class TenantTableMixin:
    """Schema 紅線欄位 · 每張表必有。tenant_id 無預設值(2026-06-10 裁定)。"""

    id: Mapped[int] = mapped_column(_PrimaryKeyInt, primary_key=True, autoincrement=True)

    @declared_attr
    def tenant_id(cls) -> Mapped[str]:
        return mapped_column(String(32), nullable=False)

    @declared_attr
    def created_at(cls) -> Mapped[datetime]:
        return mapped_column(UTCDateTime(), nullable=False, server_default=func.now())

    @declared_attr
    def updated_at(cls) -> Mapped[datetime]:
        return mapped_column(
            UTCDateTime(), nullable=False, server_default=func.now(), onupdate=func.now()
        )


class OrderRow(Base, TenantTableMixin):
    """orders 表 · 對應 L4 Order。"""

    __tablename__ = "orders"

    # 自然鍵唯一性由 (tenant_id, order_id) 複合鍵保證(見 __table_args__)，
    # 不可用單欄 unique=True——那會讓 order_id 變全域唯一，A 租戶用過 B 就不能用(跨租戶干擾)。
    order_id: Mapped[str] = mapped_column(String(64), nullable=False)
    symbol: Mapped[str] = mapped_column(String(32), nullable=False)
    side: Mapped[str] = mapped_column(String(8), nullable=False)
    order_type: Mapped[str] = mapped_column(String(16), nullable=False)
    quantity: Mapped[Decimal] = mapped_column(PreciseDecimal(), nullable=False)
    price: Mapped[Decimal | None] = mapped_column(PreciseDecimal(), nullable=True)
    stop_price: Mapped[Decimal | None] = mapped_column(PreciseDecimal(), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    strategy_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    parent_order_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        UniqueConstraint("tenant_id", "order_id", name="uq_orders_tenant_order"),
        Index("idx_orders_tenant", "tenant_id"),
        Index("idx_orders_tenant_status", "tenant_id", "status"),
        Index("idx_orders_tenant_symbol", "tenant_id", "symbol"),
    )


class PositionRow(Base, TenantTableMixin):
    """positions 表 · 對應 L4 Position。一個租戶一檔標的只有一筆當前持倉。"""

    __tablename__ = "positions"

    symbol: Mapped[str] = mapped_column(String(32), nullable=False)
    quantity: Mapped[Decimal] = mapped_column(PreciseDecimal(), nullable=False)
    avg_price: Mapped[Decimal] = mapped_column(PreciseDecimal(), nullable=False)
    market_value: Mapped[Decimal] = mapped_column(PreciseDecimal(), nullable=False)
    unrealized_pnl: Mapped[Decimal] = mapped_column(PreciseDecimal(), nullable=False)
    realized_pnl: Mapped[Decimal] = mapped_column(PreciseDecimal(), nullable=False)
    last_updated: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "symbol", name="uq_positions_tenant_symbol"),
        Index("idx_positions_tenant", "tenant_id"),
    )


class FillRow(Base, TenantTableMixin):
    """fills 表 · 對應 L4 Fill。"""

    __tablename__ = "fills"

    # 自然鍵唯一性由 (tenant_id, fill_id) 複合鍵保證(見 __table_args__)，理由同 orders。
    fill_id: Mapped[str] = mapped_column(String(64), nullable=False)
    order_id: Mapped[str] = mapped_column(String(64), nullable=False)
    symbol: Mapped[str] = mapped_column(String(32), nullable=False)
    side: Mapped[str] = mapped_column(String(8), nullable=False)
    quantity: Mapped[Decimal] = mapped_column(PreciseDecimal(), nullable=False)
    price: Mapped[Decimal] = mapped_column(PreciseDecimal(), nullable=False)
    commission: Mapped[Decimal] = mapped_column(PreciseDecimal(), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "fill_id", name="uq_fills_tenant_fill"),
        Index("idx_fills_tenant", "tenant_id"),
        Index("idx_fills_tenant_order", "tenant_id", "order_id"),
    )


class TradeRow(Base, TenantTableMixin):
    """trades 表 · 對應 L4 Trade(純資料容器，PnL 由 S19 計算)。"""

    __tablename__ = "trades"

    # 自然鍵唯一性由 (tenant_id, trade_id) 複合鍵保證(見 __table_args__)，理由同 orders。
    trade_id: Mapped[str] = mapped_column(String(64), nullable=False)
    symbol: Mapped[str] = mapped_column(String(32), nullable=False)
    open_fill_id: Mapped[str] = mapped_column(String(64), nullable=False)
    close_fill_id: Mapped[str] = mapped_column(String(64), nullable=False)
    quantity: Mapped[Decimal] = mapped_column(PreciseDecimal(), nullable=False)
    open_price: Mapped[Decimal] = mapped_column(PreciseDecimal(), nullable=False)
    close_price: Mapped[Decimal] = mapped_column(PreciseDecimal(), nullable=False)
    pnl: Mapped[Decimal] = mapped_column(PreciseDecimal(), nullable=False)
    duration_ms: Mapped[int] = mapped_column(BigInteger, nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "trade_id", name="uq_trades_tenant_trade"),
        Index("idx_trades_tenant", "tenant_id"),
        Index("idx_trades_tenant_symbol", "tenant_id", "symbol"),
    )
