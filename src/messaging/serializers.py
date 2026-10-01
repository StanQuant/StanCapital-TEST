"""事件序列化 · JSON 實作(D2 裁決)+ 可插拔介面。

精度保真規則：
- Decimal → 字串(不走 float，避免精度損失)
- datetime → ISO-8601 含時區
- StrEnum → 字串值(str 子類，json 原生支援)
- 巢狀 Order / Fill → dict 遞迴

未來量大要換 msgpack：實作同一個 EventSerializer Protocol 即可，匯流排程式碼不動。
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import asdict
from datetime import datetime
from decimal import Decimal
from typing import Any, Protocol

from src.core.events import BaseEvent, FillEvent, MarketEvent, OrderEvent, SignalEvent
from src.core.types import (
    EventType,
    Fill,
    Order,
    OrderSide,
    OrderStatus,
    OrderType,
    StrategyKind,
)


class EventSerializer(Protocol):
    """可插拔序列化介面(D2 保險絲)。"""

    def serialize(self, event: BaseEvent) -> bytes:
        """事件 → bytes。"""

    def deserialize(self, data: bytes) -> BaseEvent:
        """bytes → 事件，逐欄位重建(Decimal / datetime / enum 精度保真)。"""


def _json_default(obj: object) -> str:
    """json.dumps 遇到非原生型別時的轉換規則。"""
    if isinstance(obj, Decimal):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    msg = f"無法序列化的型別: {type(obj).__name__}"
    raise TypeError(msg)


def _dec(value: str) -> Decimal:
    return Decimal(value)


def _dec_opt(value: str | None) -> Decimal | None:
    return None if value is None else Decimal(value)


def _base_kwargs(payload: dict[str, Any]) -> dict[str, Any]:
    """BaseEvent 共同欄位的重建。"""
    return {
        "event_id": payload["event_id"],
        "event_type": EventType(payload["event_type"]),
        "tenant_id": payload["tenant_id"],
        "timestamp": datetime.fromisoformat(payload["timestamp"]),
        "trace_id": payload["trace_id"],
    }


def _order_from_dict(payload: dict[str, Any]) -> Order:
    return Order(
        order_id=payload["order_id"],
        tenant_id=payload["tenant_id"],
        symbol=payload["symbol"],
        side=OrderSide(payload["side"]),
        order_type=OrderType(payload["order_type"]),
        quantity=_dec(payload["quantity"]),
        price=_dec_opt(payload["price"]),
        stop_price=_dec_opt(payload["stop_price"]),
        status=OrderStatus(payload["status"]),
        timestamp=datetime.fromisoformat(payload["timestamp"]),
        strategy_id=payload["strategy_id"],
        parent_order_id=payload["parent_order_id"],
    )


def _fill_from_dict(payload: dict[str, Any]) -> Fill:
    return Fill(
        fill_id=payload["fill_id"],
        order_id=payload["order_id"],
        tenant_id=payload["tenant_id"],
        symbol=payload["symbol"],
        side=OrderSide(payload["side"]),
        quantity=_dec(payload["quantity"]),
        price=_dec(payload["price"]),
        commission=_dec(payload["commission"]),
        timestamp=datetime.fromisoformat(payload["timestamp"]),
    )


def _build_market(payload: dict[str, Any]) -> MarketEvent:
    return MarketEvent(
        **_base_kwargs(payload),
        symbol=payload["symbol"],
        price=_dec(payload["price"]),
        volume=_dec(payload["volume"]),
        bid=_dec_opt(payload["bid"]),
        ask=_dec_opt(payload["ask"]),
        market_event_type=payload["market_event_type"],
    )


def _build_signal(payload: dict[str, Any]) -> SignalEvent:
    return SignalEvent(
        **_base_kwargs(payload),
        strategy_id=payload["strategy_id"],
        strategy_kind=StrategyKind(payload["strategy_kind"]),
        symbol=payload["symbol"],
        direction=OrderSide(payload["direction"]),
        confidence=float(payload["confidence"]),
        target_quantity=_dec_opt(payload["target_quantity"]),
        metadata=dict(payload["metadata"]),
    )


def _build_order(payload: dict[str, Any]) -> OrderEvent:
    return OrderEvent(
        **_base_kwargs(payload),
        order=_order_from_dict(payload["order"]),
        action=payload["action"],
    )


def _build_fill(payload: dict[str, Any]) -> FillEvent:
    return FillEvent(
        **_base_kwargs(payload),
        fill=_fill_from_dict(payload["fill"]),
    )


_BUILDERS: dict[EventType, Callable[[dict[str, Any]], BaseEvent]] = {
    EventType.MARKET: _build_market,
    EventType.SIGNAL: _build_signal,
    EventType.ORDER: _build_order,
    EventType.FILL: _build_fill,
}


class JsonEventSerializer:
    """JSON 序列化(D2 裁決)· 人類可讀，查 DLQ 直接看得懂。"""

    def serialize(self, event: BaseEvent) -> bytes:
        payload = asdict(event)
        return json.dumps(payload, default=_json_default, ensure_ascii=False).encode("utf-8")

    def deserialize(self, data: bytes) -> BaseEvent:
        payload: dict[str, Any] = json.loads(data.decode("utf-8"))
        event_type = EventType(payload["event_type"])
        return _BUILDERS[event_type](payload)
