"""L4 核心型別 · Enum + Dataclass(不可變值物件)。

設計準則：
- 全部 enum 繼承 StrEnum(Python 3.12+)，字串值對應方便序列化
- 全部 dataclass 用 frozen=True + slots=True(不可變 + 省記憶體)
- 全部含 tenant_id 欄位(多租戶 SaaS Day-1 設計)
- 金額/數量一律用 Decimal(避免浮點誤差)
- 時間一律用 datetime UTC

依賴限制：只能依賴 Python stdlib + python-ulid(由 import-linter 強制)。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import StrEnum

from src.core.validation import (
    ensure_finite,
    ensure_non_empty,
    ensure_non_negative,
    ensure_non_negative_int,
    ensure_positive,
    ensure_utc,
)

# ============================================================================
# Enum · 5 個
# ============================================================================


class OrderSide(StrEnum):
    """訂單方向：買 / 賣。"""

    BUY = "buy"
    SELL = "sell"


class OrderType(StrEnum):
    """訂單型別：市價 / 限價 / 停損 / 停損限價。"""

    MARKET = "market"
    LIMIT = "limit"
    STOP = "stop"
    STOP_LIMIT = "stop_limit"


class OrderStatus(StrEnum):
    """訂單狀態 · 6 種。

    活躍狀態：PENDING / SUBMITTED / PARTIALLY_FILLED
    終結狀態：FILLED / CANCELLED / REJECTED
    """

    PENDING = "pending"
    SUBMITTED = "submitted"
    PARTIALLY_FILLED = "partially_filled"
    FILLED = "filled"
    CANCELLED = "cancelled"
    REJECTED = "rejected"


class StrategyKind(StrEnum):
    """策略類型 · 雙核心命名(沿襲 StanQuant-Platform)。

    LF 前綴 = Low Frequency 低頻；未來擴充 HF_MAKER / HF_TAKER / HF_ARBITRAGE。
    """

    LF_TREND = "lf_trend"
    LF_MEAN_REVERSION = "lf_mean_reversion"
    LF_FUNDAMENTAL = "lf_fundamental"
    LF_ML = "lf_ml"


class EventType(StrEnum):
    """事件型別 · 對應 4 個事件子類(MarketEvent / SignalEvent / OrderEvent / FillEvent)。"""

    MARKET = "market"
    SIGNAL = "signal"
    ORDER = "order"
    FILL = "fill"


# ============================================================================
# Dataclass · 4 個(全部 frozen + slots，含 tenant_id)
# ============================================================================


@dataclass(frozen=True, slots=True)
class Order:
    """訂單值物件(未成交前的狀態紀錄)。"""

    order_id: str
    tenant_id: str
    symbol: str
    side: OrderSide
    order_type: OrderType
    quantity: Decimal
    price: Decimal | None  # MARKET order 為 None
    stop_price: Decimal | None  # 僅 STOP / STOP_LIMIT 有
    status: OrderStatus
    timestamp: datetime
    strategy_id: str | None  # 手動下單為 None
    parent_order_id: str | None  # 拆單關聯

    def __post_init__(self) -> None:
        """不變式驗證（fail-closed）：髒訂單在最底層就被擋下，不滲到下單路徑。"""
        ensure_non_empty("order_id", self.order_id)
        ensure_non_empty("tenant_id", self.tenant_id)
        ensure_non_empty("symbol", self.symbol)
        ensure_positive("quantity", self.quantity)
        if self.price is not None:  # MARKET 單可為 None；有給就必須 > 0
            ensure_positive("price", self.price)
        if self.stop_price is not None:  # 僅 STOP / STOP_LIMIT 有；有給就必須 > 0
            ensure_positive("stop_price", self.stop_price)
        ensure_utc("timestamp", self.timestamp)


@dataclass(frozen=True, slots=True)
class Position:
    """部位值物件 · 正數=多單、負數=空單、0=平倉。"""

    tenant_id: str
    symbol: str
    quantity: Decimal
    avg_price: Decimal
    market_value: Decimal
    unrealized_pnl: Decimal
    realized_pnl: Decimal
    last_updated: datetime

    def __post_init__(self) -> None:
        """不變式驗證：quantity 允許負（空單）/ 0（平倉），但一律擋 NaN/Infinity 與 naive 時間。"""
        ensure_non_empty("tenant_id", self.tenant_id)
        ensure_non_empty("symbol", self.symbol)
        ensure_finite("quantity", self.quantity)  # 多單正 / 空單負 / 平倉 0
        ensure_non_negative("avg_price", self.avg_price)  # 平倉時可為 0
        ensure_finite("market_value", self.market_value)  # 空單可為負
        ensure_finite("unrealized_pnl", self.unrealized_pnl)
        ensure_finite("realized_pnl", self.realized_pnl)
        ensure_utc("last_updated", self.last_updated)


@dataclass(frozen=True, slots=True)
class Fill:
    """成交回報 · 一次成交事件的紀錄(手續費含交易稅)。"""

    fill_id: str
    order_id: str
    tenant_id: str
    symbol: str
    side: OrderSide
    quantity: Decimal
    price: Decimal
    commission: Decimal
    timestamp: datetime

    def __post_init__(self) -> None:
        """不變式驗證：成交量與價必為正，手續費允許 0（免手續費券商）。"""
        ensure_non_empty("fill_id", self.fill_id)
        ensure_non_empty("order_id", self.order_id)
        ensure_non_empty("tenant_id", self.tenant_id)
        ensure_non_empty("symbol", self.symbol)
        ensure_positive("quantity", self.quantity)
        ensure_positive("price", self.price)
        ensure_non_negative("commission", self.commission)  # 0 = 免手續費
        ensure_utc("timestamp", self.timestamp)


@dataclass(frozen=True, slots=True)
class Trade:
    """完整交易週期(開倉+平倉配對)· 資料容器。

    pnl 與 duration_ms 由 S19 portfolio-risk 切片計算後填入，S01 不負責計算邏輯。
    """

    trade_id: str
    tenant_id: str
    symbol: str
    open_fill_id: str
    close_fill_id: str
    quantity: Decimal
    open_price: Decimal
    close_price: Decimal
    pnl: Decimal
    duration_ms: int

    def __post_init__(self) -> None:
        """不變式驗證：價與量為正，pnl 允許負（虧損），持倉時長非負。"""
        ensure_non_empty("trade_id", self.trade_id)
        ensure_non_empty("tenant_id", self.tenant_id)
        ensure_non_empty("symbol", self.symbol)
        ensure_non_empty("open_fill_id", self.open_fill_id)
        ensure_non_empty("close_fill_id", self.close_fill_id)
        ensure_positive("quantity", self.quantity)
        ensure_positive("open_price", self.open_price)
        ensure_positive("close_price", self.close_price)
        ensure_finite("pnl", self.pnl)  # 獲利正 / 虧損負
        ensure_non_negative_int("duration_ms", self.duration_ms)
