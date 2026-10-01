"""src/data/bridge.py 單元測試 · 三種降維 golden / tenant 一致 / L4 不變式 / 發佈守門。"""

from __future__ import annotations

from decimal import Decimal

import pytest
from src.core.events import BaseEvent, MarketEvent
from src.core.types import EventType
from src.data.bridge import BridgeError, MarketDataBridge, market_topic
from src.data.registry import ProviderRegistry, RegistryError
from src.data.types import BookLevel, OrderBookSnapshot, RecordKind

from tests.data.test_registry import FakeProvider
from tests.data.test_types import T0, make_record

FIXED_ID = "01JZZZZZZZZZZZZZZZZZZZZZZZ"


class RecordingBus:
    """記錄 publish 呼叫的假匯流排(單元測試用；整合測試用真 InMemoryEventBus)。"""

    def __init__(self) -> None:
        self.published: list[tuple[str, BaseEvent]] = []

    async def publish(self, topic: str, event: BaseEvent) -> None:
        self.published.append((topic, event))


def make_bridge(
    bus: RecordingBus | None = None,
    registry: ProviderRegistry | None = None,
) -> MarketDataBridge:
    if registry is None:
        registry = ProviderRegistry()
        registry.register(FakeProvider("replay"))  # type: ignore[arg-type]
    return MarketDataBridge(
        bus if bus is not None else RecordingBus(),  # type: ignore[arg-type]
        registry,
        id_factory=lambda: FIXED_ID,
    )


class TestMarketTopic:
    def test_three_segment_topic(self) -> None:
        assert market_topic("acme") == "acme.l2.market"


class TestTradeConversion:
    def test_golden(self) -> None:
        # TRADE 降維 golden：全欄位精確釘住
        event = make_bridge().to_market_event(make_record(RecordKind.TRADE))
        assert event == MarketEvent(
            event_id=FIXED_ID,
            event_type=EventType.MARKET,
            tenant_id="acme",
            timestamp=T0,
            trace_id=None,
            symbol="2330",
            price=Decimal("1000"),
            volume=Decimal("2"),
            bid=None,
            ask=None,
            market_event_type="trade",
        )


class TestQuoteConversion:
    def test_golden(self) -> None:
        # QUOTE 降維 golden：price=中價、volume=0(報價快照)
        event = make_bridge().to_market_event(make_record(RecordKind.QUOTE))
        assert event.market_event_type == "quote"
        assert event.bid == Decimal("999")
        assert event.ask == Decimal("1000")
        assert event.price == Decimal("999.5")
        assert event.volume == Decimal(0)


class TestOrderBookConversion:
    def test_golden_two_sided(self) -> None:
        # ORDER_BOOK 降維 golden：取最優檔位入 bid/ask(規格 §8.1-2)
        event = make_bridge().to_market_event(make_record(RecordKind.ORDER_BOOK))
        assert event.market_event_type == "order_book"
        assert event.bid == Decimal("999")
        assert event.ask == Decimal("1000")
        assert event.price == Decimal("999.5")
        assert event.volume == Decimal(0)

    def test_bid_only_book_uses_bid_price(self) -> None:
        book = OrderBookSnapshot(
            bids=(BookLevel(price=Decimal("999"), size=Decimal("5")),), asks=()
        )
        event = make_bridge().to_market_event(make_record(RecordKind.ORDER_BOOK, payload=book))
        assert event.bid == Decimal("999")
        assert event.ask is None
        assert event.price == Decimal("999")

    def test_ask_only_book_uses_ask_price(self) -> None:
        book = OrderBookSnapshot(
            bids=(), asks=(BookLevel(price=Decimal("1000"), size=Decimal("3")),)
        )
        event = make_bridge().to_market_event(make_record(RecordKind.ORDER_BOOK, payload=book))
        assert event.bid is None
        assert event.ask == Decimal("1000")
        assert event.price == Decimal("1000")

    def test_empty_book_rejected(self) -> None:
        empty = OrderBookSnapshot(bids=(), asks=())
        with pytest.raises(BridgeError) as exc:
            make_bridge().to_market_event(make_record(RecordKind.ORDER_BOOK, payload=empty))
        assert str(exc.value).startswith("委託簿快照兩側皆空")


class TestConversionRules:
    @pytest.mark.parametrize(
        "kind",
        [k for k in RecordKind if k.value not in {"trade", "quote", "order_book"}],
    )
    def test_unbridgeable_kinds_rejected(self, kind: RecordKind) -> None:
        # 其餘 8 種 kind 不降維：fail-closed 拋錯，不靜默丟棄(規格 §8.1-3)
        with pytest.raises(BridgeError) as exc:
            make_bridge().to_market_event(make_record(kind))
        assert str(exc.value).startswith(f"record kind {kind.value!r} 不支援降維")

    def test_tenant_id_consistency(self) -> None:
        # §8.2 釘住：record 與 event 的 tenant_id 必須一致
        record = make_record(RecordKind.TRADE, tenant_id="tenant-x")
        event = make_bridge().to_market_event(record)
        assert event.tenant_id == record.tenant_id == "tenant-x"

    def test_trace_id_passthrough(self) -> None:
        event = make_bridge().to_market_event(make_record(RecordKind.TRADE), trace_id="trace-1")
        assert event.trace_id == "trace-1"

    @pytest.mark.parametrize("kind", [RecordKind.TRADE, RecordKind.QUOTE, RecordKind.ORDER_BOOK])
    def test_l4_invariants_hold(self, kind: RecordKind) -> None:
        # MarketEvent.__post_init__ 不變式全通過(能構造出來就代表通過)
        event = make_bridge().to_market_event(make_record(kind))
        assert event.event_type is EventType.MARKET

    def test_default_id_factory_is_ulid(self) -> None:
        registry = ProviderRegistry()
        registry.register(FakeProvider("replay"))  # type: ignore[arg-type]
        bridge = MarketDataBridge(RecordingBus(), registry)  # type: ignore[arg-type]
        event = bridge.to_market_event(make_record(RecordKind.TRADE))
        assert len(event.event_id) == 26  # ULID 標準長度


class TestPublish:
    async def test_publish_routes_to_l2_market_topic(self) -> None:
        bus = RecordingBus()
        event = await make_bridge(bus).publish(make_record(RecordKind.TRADE))
        assert bus.published == [("acme.l2.market", event)]

    async def test_unregistered_provider_rejected(self) -> None:
        # 雙層防護第 2 層：未註冊 provider 的 record 不得經 bridge 發佈
        bus = RecordingBus()
        bridge = MarketDataBridge(bus, ProviderRegistry(), id_factory=lambda: FIXED_ID)  # type: ignore[arg-type]
        with pytest.raises(RegistryError):
            await bridge.publish(make_record(RecordKind.TRADE))
        assert bus.published == []


class StreamProvider(FakeProvider):
    """帶 stream 的假 provider(pump 測試用)。"""

    def __init__(self, records: list[object], provider_id: str = "replay") -> None:
        super().__init__(provider_id)
        self._records = records

    def stream(self) -> object:
        async def _generate() -> object:
            for record in self._records:
                yield record

        return _generate()


class TestPump:
    async def test_pump_publishes_bridgeable_kinds_only(self) -> None:
        # 可降維的 3 種發佈、其餘略過(它們本來就不屬於 L4 摘要面)
        records = [
            make_record(RecordKind.TRADE),
            make_record(RecordKind.FUNDING_RATE),  # 不可降維 → 略過
            make_record(RecordKind.QUOTE),
        ]
        bus = RecordingBus()
        registry = ProviderRegistry()
        provider = StreamProvider(records)
        registry.register(provider)  # type: ignore[arg-type]
        bridge = MarketDataBridge(bus, registry, id_factory=lambda: FIXED_ID)  # type: ignore[arg-type]
        published = await bridge.pump(provider)  # type: ignore[arg-type]
        assert published == 2
        assert [topic for topic, _ in bus.published] == ["acme.l2.market", "acme.l2.market"]

    async def test_pump_rejects_unregistered_provider(self) -> None:
        bus = RecordingBus()
        bridge = MarketDataBridge(bus, ProviderRegistry(), id_factory=lambda: FIXED_ID)  # type: ignore[arg-type]
        with pytest.raises(RegistryError):
            await bridge.pump(StreamProvider([]))  # type: ignore[arg-type]
        assert bus.published == []
