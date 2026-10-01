"""L2→L4 降維橋 · MarketDataRecord → MarketEvent → EventBus(D6)。

鐵律(規格 §8)：
- src/core 一行不改；MarketEvent 維持現契約，本模組只「產出」它。
- Record 是源頭、Event 是摘要：只做單向降維，永遠不反向。
- 只有 TRADE / QUOTE / ORDER_BOOK 三種 kind 可降維；其餘 kind 的 consumer
  直接訂閱 L2 record stream，不經降維(fail-closed 拋錯，不靜默丟棄)。
- tenant_id 由 record 原樣帶入 event，兩者一致性由測試釘住(§8.2)；
  topic 沿用三段制 {tenant_id}.l2.market。
- 未註冊進 ProviderRegistry 的 provider，其 record 不得經 bridge 發佈。
"""

from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal
from typing import cast

from ulid import ULID

from src.core.event_bus import EventBus
from src.core.events import MarketEvent
from src.core.types import EventType
from src.data.provider import MarketDataProvider
from src.data.registry import ProviderRegistry
from src.data.types import (
    MarketDataRecord,
    OrderBookSnapshot,
    QuoteTick,
    RecordKind,
    TradeTick,
)

# topic 三段制的 layer 段：L2 行情供應層
L2_MARKET_TOPIC_LAYER = "l2"

# RecordKind → MarketEvent.market_event_type(src/core/events.py 註解明載的三值)
_MARKET_EVENT_TYPE_MAP: dict[RecordKind, str] = {
    RecordKind.TRADE: "trade",
    RecordKind.QUOTE: "quote",
    RecordKind.ORDER_BOOK: "order_book",
}


class BridgeError(Exception):
    """降維失敗(kind 不支援 / 快照無任何價格可摘要)。"""


def market_topic(tenant_id: str) -> str:
    """{tenant_id}.l2.market——EventBus 三段制 topic(§8.1-4)。"""
    return f"{tenant_id}.{L2_MARKET_TOPIC_LAYER}.{EventType.MARKET.value}"


def _default_event_id() -> str:
    """事件 ID 沿用專案 ULID 慣例(可排序、全域唯一)。"""
    return str(ULID())


class MarketDataBridge:
    """降維轉換 + 發佈。

    id_factory 可注入(golden 測試決定性)；預設 ULID。
    """

    def __init__(
        self,
        bus: EventBus,
        registry: ProviderRegistry,
        *,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._bus = bus
        self._registry = registry
        self._id_factory = id_factory if id_factory is not None else _default_event_id

    def to_market_event(
        self, record: MarketDataRecord, *, trace_id: str | None = None
    ) -> MarketEvent:
        """純轉換(不發佈)。三種 kind 的降維規則：

        - TRADE：price=成交價、volume=成交量、bid/ask=None
        - QUOTE：bid/ask=最優報價、price=中價((bid+ask)/2)、volume=0(報價快照)
        - ORDER_BOOK：bid/ask=最優檔位、price=中價(單邊市場取有價的一側)、volume=0

        timestamp 用 record.source_timestamp(事件的業務時間，非接收時間)。
        """
        kind = record.record_kind
        event_type_label = _MARKET_EVENT_TYPE_MAP.get(kind)
        if event_type_label is None:
            raise BridgeError(
                f"record kind {kind.value!r} 不支援降維為 MarketEvent"
                "(完整資料請直接訂閱 L2 record stream，見規格 §8.1)"
            )
        payload = record.payload
        if isinstance(payload, TradeTick):
            price = payload.price
            volume = payload.volume
            bid: Decimal | None = None
            ask: Decimal | None = None
        elif isinstance(payload, QuoteTick):
            bid = payload.bid
            ask = payload.ask
            price = (payload.bid + payload.ask) / 2
            volume = Decimal(0)
        else:
            book = cast(OrderBookSnapshot, payload)  # PAYLOAD_KIND_MAP 精確型別保證
            best_bid = book.best_bid
            best_ask = book.best_ask
            bid = best_bid.price if best_bid is not None else None
            ask = best_ask.price if best_ask is not None else None
            if bid is not None and ask is not None:
                price = (bid + ask) / 2
            elif bid is not None:
                price = bid
            elif ask is not None:
                price = ask
            else:
                raise BridgeError(
                    "委託簿快照兩側皆空，無價格可摘要成 MarketEvent(空簿快照請走 L2 record stream)"
                )
            volume = Decimal(0)
        return MarketEvent(
            event_id=self._id_factory(),
            event_type=EventType.MARKET,
            tenant_id=record.tenant_id,  # §8.2：與 record 一致，測試釘住
            timestamp=record.source_timestamp,
            trace_id=trace_id,
            symbol=record.instrument.symbol,
            price=price,
            volume=volume,
            bid=bid,
            ask=ask,
            market_event_type=event_type_label,
        )

    async def publish(
        self, record: MarketDataRecord, *, trace_id: str | None = None
    ) -> MarketEvent:
        """降維並發佈到 {tenant}.l2.market。回傳事件供遙測 / 測試對帳。

        雙層防護第 2 層：record 的來源 provider 未註冊 → RegistryError。
        """
        self._registry.ensure_registered(record.instrument.provider_id)
        event = self.to_market_event(record, trace_id=trace_id)
        await self._bus.publish(market_topic(event.tenant_id), event)
        return event

    async def pump(self, provider: MarketDataProvider) -> int:
        """把 provider 的 record stream 逐筆降維發佈(demo / 整合測試用泵)。

        只泵可降維的三種 kind；其餘 kind 略過計數不發佈(它們本來就
        不屬於 L4 摘要面)。回傳成功發佈筆數。
        """
        self._registry.ensure_registered(provider.provider_id)
        published = 0
        async for record in provider.stream():
            if record.record_kind not in _MARKET_EVENT_TYPE_MAP:
                continue
            await self.publish(record)
            published += 1
        return published
