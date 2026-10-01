"""src/core/events.py 的測試。

對應 S01 規格 §6(Event Schema)。
包含「方案 C · 事件分離」設計驗證：BaseEvent 含 trace_id 為 S07 ATR 預留接合點。
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from decimal import Decimal

import pytest
from src.core.events import (
    BaseEvent,
    FillEvent,
    MarketEvent,
    OrderEvent,
    SignalEvent,
)
from src.core.types import (
    EventType,
    Fill,
    Order,
    OrderSide,
    OrderStatus,
    OrderType,
    StrategyKind,
)

# ----------------------------------------------------------------------------
# 共用測試輔助
# ----------------------------------------------------------------------------


def _base_kwargs(event_type: EventType, trace_id: str | None = None) -> dict[str, object]:
    return {
        "event_id": "01HRZX00000000000000000E01",
        "event_type": event_type,
        "tenant_id": "stanley",
        "timestamp": datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC),
        "trace_id": trace_id,
    }


def _make_order() -> Order:
    return Order(
        order_id="01HRZX00000000000000000001",
        tenant_id="stanley",
        symbol="2330.TW",
        side=OrderSide.BUY,
        order_type=OrderType.LIMIT,
        quantity=Decimal("100"),
        price=Decimal("700"),
        stop_price=None,
        status=OrderStatus.PENDING,
        timestamp=datetime(2026, 6, 10, 12, 0, tzinfo=UTC),
        strategy_id="lf_trend_v1",
        parent_order_id=None,
    )


def _make_fill() -> Fill:
    return Fill(
        fill_id="01HRZX00000000000000000A02",
        order_id="01HRZX00000000000000000001",
        tenant_id="stanley",
        symbol="2330.TW",
        side=OrderSide.BUY,
        quantity=Decimal("100"),
        price=Decimal("700.5"),
        commission=Decimal("100"),
        timestamp=datetime(2026, 6, 10, 12, 0, 5, tzinfo=UTC),
    )


# ----------------------------------------------------------------------------
# BaseEvent · 共同基底(trace_id 為 S07 方案 C 接合點)
# ----------------------------------------------------------------------------


class TestBaseEvent:
    """BaseEvent 行為驗證(5 case)。"""

    def test_basic_construction_with_trace_id(self) -> None:
        evt = BaseEvent(**_base_kwargs(EventType.MARKET, trace_id="trace-abc123"))
        assert evt.event_id == "01HRZX00000000000000000E01"
        assert evt.event_type is EventType.MARKET
        assert evt.trace_id == "trace-abc123"

    def test_trace_id_can_be_none(self) -> None:
        # 非由 agent 觸發的事件可能沒有 trace_id
        evt = BaseEvent(**_base_kwargs(EventType.MARKET, trace_id=None))
        assert evt.trace_id is None

    def test_frozen_cannot_mutate(self) -> None:
        evt = BaseEvent(**_base_kwargs(EventType.ORDER))
        with pytest.raises(FrozenInstanceError):
            evt.tenant_id = "other_tenant"  # type: ignore[misc]

    def test_tenant_id_required_no_default(self) -> None:
        # tenant_id 不可省略(避免 專案教訓紀錄 2026-06-01 教訓的反向)
        with pytest.raises(TypeError):
            BaseEvent(  # type: ignore[call-arg]
                event_id="x",
                event_type=EventType.MARKET,
                timestamp=datetime(2026, 6, 10, 12, 0, tzinfo=UTC),
                trace_id=None,
            )

    def test_serialization_roundtrip(self) -> None:
        evt = BaseEvent(**_base_kwargs(EventType.SIGNAL, trace_id="t-1"))
        encoded = json.dumps(dataclasses.asdict(evt), default=str)
        decoded = json.loads(encoded)
        assert decoded["event_type"] == "signal"
        assert decoded["tenant_id"] == "stanley"
        assert decoded["trace_id"] == "t-1"


# ----------------------------------------------------------------------------
# MarketEvent
# ----------------------------------------------------------------------------


class TestMarketEvent:
    """MarketEvent 行為驗證(3 case)。"""

    def test_basic_quote_event(self) -> None:
        evt = MarketEvent(
            **_base_kwargs(EventType.MARKET),
            symbol="2330.TW",
            price=Decimal("700.5"),
            volume=Decimal("1000"),
            bid=Decimal("700"),
            ask=Decimal("701"),
            market_event_type="quote",
        )
        assert evt.symbol == "2330.TW"
        assert evt.bid == Decimal("700")
        assert isinstance(evt, BaseEvent)  # 確認繼承

    def test_trade_event_no_bid_ask(self) -> None:
        # 成交事件可能沒有 bid / ask
        evt = MarketEvent(
            **_base_kwargs(EventType.MARKET),
            symbol="2330.TW",
            price=Decimal("700.5"),
            volume=Decimal("100"),
            bid=None,
            ask=None,
            market_event_type="trade",
        )
        assert evt.bid is None
        assert evt.market_event_type == "trade"

    def test_frozen(self) -> None:
        evt = MarketEvent(
            **_base_kwargs(EventType.MARKET),
            symbol="2330.TW",
            price=Decimal("700"),
            volume=Decimal("100"),
            bid=None,
            ask=None,
            market_event_type="trade",
        )
        with pytest.raises(FrozenInstanceError):
            evt.price = Decimal("999")  # type: ignore[misc]


# ----------------------------------------------------------------------------
# SignalEvent
# ----------------------------------------------------------------------------


class TestSignalEvent:
    """SignalEvent 行為驗證(3 case)。"""

    def test_basic_signal(self) -> None:
        evt = SignalEvent(
            **_base_kwargs(EventType.SIGNAL),
            strategy_id="lf_trend_v1",
            strategy_kind=StrategyKind.LF_TREND,
            symbol="2330.TW",
            direction=OrderSide.BUY,
            confidence=0.85,
            target_quantity=Decimal("100"),
            metadata={"signal_source": "ma_crossover"},
        )
        assert evt.strategy_kind is StrategyKind.LF_TREND
        assert evt.confidence == 0.85
        assert evt.metadata["signal_source"] == "ma_crossover"

    def test_signal_with_none_target_quantity(self) -> None:
        # 純訊號(不指定倉位，由 risk 層決定)
        evt = SignalEvent(
            **_base_kwargs(EventType.SIGNAL),
            strategy_id="lf_ml_v2",
            strategy_kind=StrategyKind.LF_ML,
            symbol="AAPL",
            direction=OrderSide.SELL,
            confidence=0.6,
            target_quantity=None,
            metadata={},
        )
        assert evt.target_quantity is None
        assert evt.metadata == {}

    def test_frozen(self) -> None:
        evt = SignalEvent(
            **_base_kwargs(EventType.SIGNAL),
            strategy_id="lf_trend_v1",
            strategy_kind=StrategyKind.LF_TREND,
            symbol="2330.TW",
            direction=OrderSide.BUY,
            confidence=0.85,
            target_quantity=Decimal("100"),
            metadata={},
        )
        with pytest.raises(FrozenInstanceError):
            evt.confidence = 0.0  # type: ignore[misc]


# ----------------------------------------------------------------------------
# OrderEvent
# ----------------------------------------------------------------------------


class TestOrderEvent:
    """OrderEvent 行為驗證(3 case)。"""

    def test_submit_order_event(self) -> None:
        order = _make_order()
        evt = OrderEvent(**_base_kwargs(EventType.ORDER), order=order, action="submit")
        assert evt.order is order
        assert evt.action == "submit"
        assert isinstance(evt, BaseEvent)

    def test_cancel_order_event(self) -> None:
        evt = OrderEvent(**_base_kwargs(EventType.ORDER), order=_make_order(), action="cancel")
        assert evt.action == "cancel"

    def test_frozen(self) -> None:
        evt = OrderEvent(**_base_kwargs(EventType.ORDER), order=_make_order(), action="submit")
        with pytest.raises(FrozenInstanceError):
            evt.action = "modify"  # type: ignore[misc]


# ----------------------------------------------------------------------------
# FillEvent
# ----------------------------------------------------------------------------


class TestFillEvent:
    """FillEvent 行為驗證(3 case)。"""

    def test_basic_fill_event(self) -> None:
        fill = _make_fill()
        evt = FillEvent(**_base_kwargs(EventType.FILL), fill=fill)
        assert evt.fill is fill
        assert evt.fill.commission == Decimal("100")

    def test_inheritance(self) -> None:
        evt = FillEvent(**_base_kwargs(EventType.FILL), fill=_make_fill())
        assert isinstance(evt, BaseEvent)
        # 確認 BaseEvent 的欄位可從子類存取
        assert evt.tenant_id == "stanley"
        assert evt.event_type is EventType.FILL

    def test_frozen_and_serializable(self) -> None:
        evt = FillEvent(**_base_kwargs(EventType.FILL, trace_id="t-fill"), fill=_make_fill())
        with pytest.raises(FrozenInstanceError):
            evt.tenant_id = "other"  # type: ignore[misc]
        # 序列化整合測試(對應 DoD #4)
        encoded = json.dumps(dataclasses.asdict(evt), default=str)
        decoded = json.loads(encoded)
        assert decoded["event_type"] == "fill"
        assert decoded["trace_id"] == "t-fill"
        assert decoded["fill"]["fill_id"] == "01HRZX00000000000000000A02"


# ----------------------------------------------------------------------------
# 跨 Event 整合 · 方案 C 接合點驗證
# ----------------------------------------------------------------------------


def test_all_events_share_trace_id_for_atr_attachment() -> None:
    """方案 C 接合點驗證：所有 Event 必須有 trace_id(給 S07 RiskAssessmentEvent 串接用)。

    本測試是 S01 對 S07 的契約：未來 S07 寫的 RiskAssessmentEvent 會用同一 trace_id
    與 OrderEvent / FillEvent 聚合，沒有 trace_id 整個方案 C 就會崩。
    """
    trace_id = "shared-trace-abc"
    order_evt = OrderEvent(
        **_base_kwargs(EventType.ORDER, trace_id=trace_id),
        order=_make_order(),
        action="submit",
    )
    fill_evt = FillEvent(**_base_kwargs(EventType.FILL, trace_id=trace_id), fill=_make_fill())
    assert order_evt.trace_id == fill_evt.trace_id == trace_id


def test_event_serialization_roundtrip_integration() -> None:
    """DoD #4 整合測試：事件可序列化 / 反序列化。"""
    fill_evt = FillEvent(**_base_kwargs(EventType.FILL, trace_id="t-int-001"), fill=_make_fill())
    encoded = json.dumps(dataclasses.asdict(fill_evt), default=str)
    decoded = json.loads(encoded)
    # 驗證關鍵欄位完整 round-trip
    assert decoded["event_id"] == "01HRZX00000000000000000E01"
    assert decoded["event_type"] == "fill"
    assert decoded["tenant_id"] == "stanley"
    assert decoded["trace_id"] == "t-int-001"
    assert decoded["fill"]["symbol"] == "2330.TW"
    assert Decimal(decoded["fill"]["commission"]) == Decimal("100")


# ----------------------------------------------------------------------------
# 不變式驗證 · event_type 必須與事件子類相符（fail-closed，2026-06-18 硬化）
# ----------------------------------------------------------------------------


class TestEventTypeMustMatchSubclass:
    """子類 event_type 不符一律拒絕（抓「MarketEvent 卻帶 FILL」這類錯配）。"""

    def test_market_event_型別不符被擋(self) -> None:
        with pytest.raises(ValueError, match="必須是 MARKET"):
            MarketEvent(
                **_base_kwargs(EventType.FILL),  # 錯：應為 MARKET
                symbol="2330.TW",
                price=Decimal("700"),
                volume=Decimal("100"),
                bid=None,
                ask=None,
                market_event_type="trade",
            )

    def test_signal_event_型別不符被擋(self) -> None:
        with pytest.raises(ValueError, match="必須是 SIGNAL"):
            SignalEvent(
                **_base_kwargs(EventType.MARKET),  # 錯：應為 SIGNAL
                strategy_id="lf_trend_v1",
                strategy_kind=StrategyKind.LF_TREND,
                symbol="2330.TW",
                direction=OrderSide.BUY,
                confidence=0.5,
                target_quantity=None,
                metadata={},
            )

    def test_order_event_型別不符被擋(self) -> None:
        with pytest.raises(ValueError, match="必須是 ORDER"):
            OrderEvent(**_base_kwargs(EventType.SIGNAL), order=_make_order(), action="submit")

    def test_fill_event_型別不符被擋(self) -> None:
        with pytest.raises(ValueError, match="必須是 FILL"):
            FillEvent(**_base_kwargs(EventType.ORDER), fill=_make_fill())

    def test_signal_confidence_超出範圍被擋(self) -> None:
        with pytest.raises(ValueError, match=r"\[0.0, 1.0\]"):
            SignalEvent(
                **_base_kwargs(EventType.SIGNAL),
                strategy_id="lf_trend_v1",
                strategy_kind=StrategyKind.LF_TREND,
                symbol="2330.TW",
                direction=OrderSide.BUY,
                confidence=1.5,  # 錯：超出 [0,1]
                target_quantity=None,
                metadata={},
            )

    def test_base_event_naive_時間被擋(self) -> None:
        from datetime import datetime as _dt

        kwargs = _base_kwargs(EventType.MARKET)
        kwargs["timestamp"] = _dt(2026, 6, 18, 12, 0, 0)
        with pytest.raises(ValueError, match="帶時區"):
            BaseEvent(**kwargs)
