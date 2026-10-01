"""S03 messaging 測試共用 · 事件工廠。

欄位值刻意用「會暴露精度問題」的數字(多位小數、tz-aware 時間)。
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from src.core.events import FillEvent, MarketEvent, OrderEvent, SignalEvent
from src.core.types import (
    EventType,
    Fill,
    Order,
    OrderSide,
    OrderStatus,
    OrderType,
    StrategyKind,
)

FIXED_TS = datetime(2026, 6, 11, 9, 30, 0, 123456, tzinfo=UTC)


def make_market_event(tenant_id: str = "acme", **overrides: Any) -> MarketEvent:
    fields: dict[str, Any] = {
        "event_id": "evt-mkt-1",
        "event_type": EventType.MARKET,
        "tenant_id": tenant_id,
        "timestamp": FIXED_TS,
        "trace_id": "trace-1",
        "symbol": "2330.TW",
        "price": Decimal("1085.12345678"),
        "volume": Decimal("1000"),
        "bid": Decimal("1085.00000001"),
        "ask": Decimal("1085.25"),
        "market_event_type": "quote",
    }
    fields.update(overrides)
    return MarketEvent(**fields)


def make_signal_event(tenant_id: str = "acme", **overrides: Any) -> SignalEvent:
    fields: dict[str, Any] = {
        "event_id": "evt-sig-1",
        "event_type": EventType.SIGNAL,
        "tenant_id": tenant_id,
        "timestamp": FIXED_TS,
        "trace_id": None,
        "strategy_id": "strat-001",
        "strategy_kind": StrategyKind.LF_TREND,
        "symbol": "2330.TW",
        "direction": OrderSide.BUY,
        "confidence": 0.87,
        "target_quantity": Decimal("1000.00000001"),
        "metadata": {"source": "backtest", "version": "v1"},
    }
    fields.update(overrides)
    return SignalEvent(**fields)


def make_order_event(tenant_id: str = "acme", **overrides: Any) -> OrderEvent:
    order = Order(
        order_id="ord-1",
        tenant_id=tenant_id,
        symbol="2330.TW",
        side=OrderSide.SELL,
        order_type=OrderType.STOP_LIMIT,
        quantity=Decimal("500"),
        price=Decimal("1080.5"),
        stop_price=Decimal("1079.99999999"),
        status=OrderStatus.PENDING,
        timestamp=FIXED_TS,
        strategy_id="strat-001",
        parent_order_id=None,
    )
    fields: dict[str, Any] = {
        "event_id": "evt-ord-1",
        "event_type": EventType.ORDER,
        "tenant_id": tenant_id,
        "timestamp": FIXED_TS,
        "trace_id": "trace-2",
        "order": order,
        "action": "submit",
    }
    fields.update(overrides)
    return OrderEvent(**fields)


def make_fill_event(tenant_id: str = "acme", **overrides: Any) -> FillEvent:
    fill = Fill(
        fill_id="fil-1",
        order_id="ord-1",
        tenant_id=tenant_id,
        symbol="2330.TW",
        side=OrderSide.SELL,
        quantity=Decimal("500"),
        price=Decimal("1080.5"),
        commission=Decimal("38.52771828"),
        timestamp=FIXED_TS,
    )
    fields: dict[str, Any] = {
        "event_id": "evt-fil-1",
        "event_type": EventType.FILL,
        "tenant_id": tenant_id,
        "timestamp": FIXED_TS,
        "trace_id": "trace-2",
        "fill": fill,
    }
    fields.update(overrides)
    return FillEvent(**fields)
