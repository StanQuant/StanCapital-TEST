"""L4 事件型別 · BaseEvent + 4 個事件子類。

設計準則：
- 全部 frozen=True + slots=True
- BaseEvent 含 trace_id(為 S07 ATR 方案 C 事件分離預留接合點)
- 4 個子事件：MarketEvent / SignalEvent / OrderEvent / FillEvent
- 全部含 tenant_id(多租戶 Day-1)

方案 C 設計(S07 落地時對應)：
    L4 OrderEvent ── trace_id ──┐
                                ▼
    L10 RiskAssessmentEvent(S07)── target_event_id 指向 OrderEvent.event_id
                                ──── 同 trace_id 聚合
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal

from src.core.types import (
    EventType,
    Fill,
    Order,
    OrderSide,
    StrategyKind,
)
from src.core.validation import (
    ensure_confidence,
    ensure_non_empty,
    ensure_non_negative,
    ensure_positive,
    ensure_utc,
)


@dataclass(frozen=True, slots=True)
class BaseEvent:
    """事件共同基底。

    trace_id：對齊 L9 Observability W3C Trace Context；
    亦為 S07 ATR RiskAssessmentEvent 與本層事件聚合的關鍵欄位。
    """

    event_id: str
    event_type: EventType
    tenant_id: str
    timestamp: datetime
    trace_id: str | None

    def __post_init__(self) -> None:
        """共同基底不變式（子類會 super() 呼叫本方法後再加自己的檢查）。"""
        ensure_non_empty("event_id", self.event_id)
        ensure_non_empty("tenant_id", self.tenant_id)
        ensure_utc("timestamp", self.timestamp)
        if self.trace_id is not None:  # 可為 None（非 agent 觸發）；有給就不可為空
            ensure_non_empty("trace_id", self.trace_id)


@dataclass(frozen=True, slots=True)
class MarketEvent(BaseEvent):
    """行情事件 · 報價 / 成交 / 委託簿快照。"""

    symbol: str
    price: Decimal
    volume: Decimal
    bid: Decimal | None
    ask: Decimal | None
    market_event_type: str  # "trade" / "quote" / "order_book"

    def __post_init__(self) -> None:
        BaseEvent.__post_init__(self)  # 不用 super(): slots=True 重建類別會讓零參 super 失效
        if self.event_type is not EventType.MARKET:
            raise ValueError(f"MarketEvent.event_type 必須是 MARKET，不可為 {self.event_type}")
        ensure_non_empty("symbol", self.symbol)
        ensure_positive("price", self.price)
        ensure_non_negative("volume", self.volume)  # 報價快照成交量可為 0
        if self.bid is not None:
            ensure_positive("bid", self.bid)
        if self.ask is not None:
            ensure_positive("ask", self.ask)
        ensure_non_empty("market_event_type", self.market_event_type)


@dataclass(frozen=True, slots=True)
class SignalEvent(BaseEvent):
    """策略訊號 · 由 L6 Strategy 產出。"""

    strategy_id: str
    strategy_kind: StrategyKind
    symbol: str
    direction: OrderSide
    confidence: float  # 0.0 - 1.0
    target_quantity: Decimal | None  # None 表示由 Risk 層決定倉位
    metadata: dict[str, str]

    def __post_init__(self) -> None:
        BaseEvent.__post_init__(self)  # 不用 super(): slots=True 重建類別會讓零參 super 失效
        if self.event_type is not EventType.SIGNAL:
            raise ValueError(f"SignalEvent.event_type 必須是 SIGNAL，不可為 {self.event_type}")
        ensure_non_empty("strategy_id", self.strategy_id)
        ensure_non_empty("symbol", self.symbol)
        ensure_confidence("confidence", self.confidence)
        if self.target_quantity is not None:  # 有指定倉位就必須 > 0
            ensure_positive("target_quantity", self.target_quantity)


@dataclass(frozen=True, slots=True)
class OrderEvent(BaseEvent):
    """訂單事件 · 提交 / 修改 / 取消。"""

    order: Order
    action: str  # "submit" / "modify" / "cancel"

    def __post_init__(self) -> None:
        BaseEvent.__post_init__(self)  # 不用 super(): slots=True 重建類別會讓零參 super 失效
        if self.event_type is not EventType.ORDER:
            raise ValueError(f"OrderEvent.event_type 必須是 ORDER，不可為 {self.event_type}")
        ensure_non_empty("action", self.action)


@dataclass(frozen=True, slots=True)
class FillEvent(BaseEvent):
    """成交事件 · 內嵌 Fill 完整資料。"""

    fill: Fill

    def __post_init__(self) -> None:
        BaseEvent.__post_init__(self)  # 不用 super(): slots=True 重建類別會讓零參 super 失效
        if self.event_type is not EventType.FILL:
            raise ValueError(f"FillEvent.event_type 必須是 FILL，不可為 {self.event_type}")
        # fill 本身的不變式已由 Fill.__post_init__ 保證
