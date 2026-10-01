"""src/core/types.py 的測試(TDD 紅燈先行)。

對應 S01 規格 §4(Enum)+ §5(Dataclass)。
本檔案先寫 25 個 enum 測試(5 enum × 5 case)，實作完成後全綠。
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum

import pytest
from src.core.types import (
    EventType,
    Fill,
    Order,
    OrderSide,
    OrderStatus,
    OrderType,
    Position,
    StrategyKind,
    Trade,
)

# ----------------------------------------------------------------------------
# OrderSide
# ----------------------------------------------------------------------------


class TestOrderSide:
    """OrderSide enum 行為驗證(5 case)。"""

    def test_string_values(self) -> None:
        assert OrderSide.BUY.value == "buy"
        assert OrderSide.SELL.value == "sell"

    def test_member_count_and_iteration(self) -> None:
        members = list(OrderSide)
        assert len(members) == 2
        assert members == [OrderSide.BUY, OrderSide.SELL]

    def test_strenum_string_compatibility(self) -> None:
        assert OrderSide.BUY == "buy"
        assert OrderSide.SELL == "sell"
        assert isinstance(OrderSide.BUY, str)

    def test_invalid_member_raises(self) -> None:
        with pytest.raises(ValueError):
            OrderSide("invalid")

    def test_json_roundtrip(self) -> None:
        encoded = json.dumps({"side": OrderSide.BUY.value})
        decoded = json.loads(encoded)
        assert OrderSide(decoded["side"]) is OrderSide.BUY


# ----------------------------------------------------------------------------
# OrderType
# ----------------------------------------------------------------------------


class TestOrderType:
    """OrderType enum 行為驗證(5 case)。"""

    def test_string_values(self) -> None:
        assert OrderType.MARKET.value == "market"
        assert OrderType.LIMIT.value == "limit"
        assert OrderType.STOP.value == "stop"
        assert OrderType.STOP_LIMIT.value == "stop_limit"

    def test_member_count_and_iteration(self) -> None:
        assert len(list(OrderType)) == 4

    def test_strenum_string_compatibility(self) -> None:
        assert OrderType.LIMIT == "limit"
        assert isinstance(OrderType.MARKET, str)

    def test_invalid_member_raises(self) -> None:
        with pytest.raises(ValueError):
            OrderType("iceberg")  # 還沒實作的高階單型別

    def test_json_roundtrip(self) -> None:
        encoded = json.dumps({"order_type": OrderType.STOP_LIMIT.value})
        decoded = json.loads(encoded)
        assert OrderType(decoded["order_type"]) is OrderType.STOP_LIMIT


# ----------------------------------------------------------------------------
# OrderStatus
# ----------------------------------------------------------------------------


class TestOrderStatus:
    """OrderStatus enum 行為驗證(5 case)。"""

    def test_string_values(self) -> None:
        assert OrderStatus.PENDING.value == "pending"
        assert OrderStatus.SUBMITTED.value == "submitted"
        assert OrderStatus.PARTIALLY_FILLED.value == "partially_filled"
        assert OrderStatus.FILLED.value == "filled"
        assert OrderStatus.CANCELLED.value == "cancelled"
        assert OrderStatus.REJECTED.value == "rejected"

    def test_member_count_and_iteration(self) -> None:
        assert len(list(OrderStatus)) == 6

    def test_strenum_string_compatibility(self) -> None:
        assert OrderStatus.FILLED == "filled"
        assert isinstance(OrderStatus.PENDING, str)

    def test_invalid_member_raises(self) -> None:
        with pytest.raises(ValueError):
            OrderStatus("expired")

    def test_terminal_states_distinct_from_active(self) -> None:
        # 終結狀態：FILLED / CANCELLED / REJECTED
        # 活躍狀態：PENDING / SUBMITTED / PARTIALLY_FILLED
        terminal = {OrderStatus.FILLED, OrderStatus.CANCELLED, OrderStatus.REJECTED}
        active = {
            OrderStatus.PENDING,
            OrderStatus.SUBMITTED,
            OrderStatus.PARTIALLY_FILLED,
        }
        assert terminal.isdisjoint(active)
        assert terminal | active == set(OrderStatus)


# ----------------------------------------------------------------------------
# StrategyKind · 雙核心命名(沿襲 StanQuant-Platform)
# ----------------------------------------------------------------------------


class TestStrategyKind:
    """StrategyKind enum 行為驗證(5 case)。"""

    def test_string_values_match_lf_convention(self) -> None:
        # 吸取 專案教訓紀錄 2026-05-23 教訓：禁止憑印象寫 MOMENTUM 等舊名
        assert StrategyKind.LF_TREND.value == "lf_trend"
        assert StrategyKind.LF_MEAN_REVERSION.value == "lf_mean_reversion"
        assert StrategyKind.LF_FUNDAMENTAL.value == "lf_fundamental"
        assert StrategyKind.LF_ML.value == "lf_ml"

    def test_member_count_and_iteration(self) -> None:
        assert len(list(StrategyKind)) == 4

    def test_strenum_string_compatibility(self) -> None:
        assert StrategyKind.LF_TREND == "lf_trend"
        assert isinstance(StrategyKind.LF_ML, str)

    def test_invalid_member_raises(self) -> None:
        # 高頻策略 HF_* 系列在 S01 階段尚未引入
        with pytest.raises(ValueError):
            StrategyKind("hf_maker")
        with pytest.raises(ValueError):
            StrategyKind("momentum")  # 舊命名應被拒絕

    def test_all_members_use_lf_prefix(self) -> None:
        # 確保 S01 階段全部策略屬於低頻
        for kind in StrategyKind:
            assert kind.value.startswith("lf_")


# ----------------------------------------------------------------------------
# EventType
# ----------------------------------------------------------------------------


class TestEventType:
    """EventType enum 行為驗證(5 case)。"""

    def test_string_values(self) -> None:
        assert EventType.MARKET.value == "market"
        assert EventType.SIGNAL.value == "signal"
        assert EventType.ORDER.value == "order"
        assert EventType.FILL.value == "fill"

    def test_member_count_and_iteration(self) -> None:
        assert len(list(EventType)) == 4

    def test_strenum_string_compatibility(self) -> None:
        assert EventType.SIGNAL == "signal"
        assert isinstance(EventType.MARKET, str)

    def test_invalid_member_raises(self) -> None:
        with pytest.raises(ValueError):
            EventType("risk_assessment")  # S07 才會加，S01 不能有

    def test_event_type_aligns_with_event_class_naming(self) -> None:
        # 強制 EventType 成員與未來事件子類名稱對齊
        # 例如 EventType.MARKET 對應 MarketEvent
        expected = {"market", "signal", "order", "fill"}
        actual = {member.value for member in EventType}
        assert actual == expected


# ----------------------------------------------------------------------------
# 跨 enum 整合：所有 enum 必須繼承 StrEnum
# ----------------------------------------------------------------------------


def test_all_enums_inherit_strenum() -> None:
    """確保 5 個 enum 全部繼承 StrEnum(為了 JSON 序列化天然相容)。"""
    for enum_cls in (OrderSide, OrderType, OrderStatus, StrategyKind, EventType):
        assert issubclass(enum_cls, StrEnum), f"{enum_cls.__name__} 必須繼承 StrEnum"


# ============================================================================
# Dataclass 測試 · 4 個(每個 5 case = 20 case)
# ============================================================================


def _make_order(**overrides: object) -> Order:
    """測試輔助：產生合法的 Order，便於各 case 微調單一欄位。"""
    defaults: dict[str, object] = {
        "order_id": "01HRZX00000000000000000001",
        "tenant_id": "stanley",
        "symbol": "2330.TW",
        "side": OrderSide.BUY,
        "order_type": OrderType.LIMIT,
        "quantity": Decimal("100"),
        "price": Decimal("700.00"),
        "stop_price": None,
        "status": OrderStatus.PENDING,
        "timestamp": datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC),
        "strategy_id": "lf_trend_v1",
        "parent_order_id": None,
    }
    defaults.update(overrides)
    return Order(**defaults)  # type: ignore[arg-type]


def _make_fill(**overrides: object) -> Fill:
    defaults: dict[str, object] = {
        "fill_id": "01HRZX00000000000000000A02",
        "order_id": "01HRZX00000000000000000001",
        "tenant_id": "stanley",
        "symbol": "2330.TW",
        "side": OrderSide.BUY,
        "quantity": Decimal("100"),
        "price": Decimal("700.50"),
        "commission": Decimal("100.00"),
        "timestamp": datetime(2026, 6, 10, 12, 0, 5, tzinfo=UTC),
    }
    defaults.update(overrides)
    return Fill(**defaults)  # type: ignore[arg-type]


# ----------------------------------------------------------------------------
# Order
# ----------------------------------------------------------------------------


class TestOrder:
    """Order dataclass 行為驗證(5 case)。"""

    def test_basic_construction(self) -> None:
        order = _make_order()
        assert order.order_id == "01HRZX00000000000000000001"
        assert order.tenant_id == "stanley"
        assert order.symbol == "2330.TW"
        assert order.side is OrderSide.BUY
        assert order.quantity == Decimal("100")

    def test_frozen_cannot_mutate(self) -> None:
        order = _make_order()
        with pytest.raises(FrozenInstanceError):
            order.price = Decimal("800")  # type: ignore[misc]

    def test_slots_cannot_add_new_attribute(self) -> None:
        # frozen+slots 加新屬性：Python 3.12 拋 TypeError、3.14 拋 AttributeError
        order = _make_order()
        with pytest.raises((AttributeError, TypeError)):
            order.extra_field = "not allowed"  # type: ignore[attr-defined]

    def test_market_order_allows_none_price(self) -> None:
        order = _make_order(order_type=OrderType.MARKET, price=None)
        assert order.price is None
        assert order.order_type is OrderType.MARKET

    def test_tenant_id_no_default_enforces_explicit(self) -> None:
        # 吸取 專案教訓紀錄 2026-06-01 教訓：tenant_id 不可給預設值
        # 嘗試省略 tenant_id 必須 raise TypeError
        with pytest.raises(TypeError):
            Order(  # type: ignore[call-arg]
                order_id="01HRZX00000000000000000001",
                symbol="2330.TW",
                side=OrderSide.BUY,
                order_type=OrderType.LIMIT,
                quantity=Decimal("100"),
                price=Decimal("700.00"),
                stop_price=None,
                status=OrderStatus.PENDING,
                timestamp=datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC),
                strategy_id=None,
                parent_order_id=None,
            )


# ----------------------------------------------------------------------------
# Position
# ----------------------------------------------------------------------------


class TestPosition:
    """Position dataclass 行為驗證(5 case)。"""

    def test_basic_long_position(self) -> None:
        pos = Position(
            tenant_id="stanley",
            symbol="2330.TW",
            quantity=Decimal("100"),
            avg_price=Decimal("700"),
            market_value=Decimal("75000"),
            unrealized_pnl=Decimal("5000"),
            realized_pnl=Decimal("0"),
            last_updated=datetime(2026, 6, 10, 12, 0, tzinfo=UTC),
        )
        assert pos.quantity == Decimal("100")
        assert pos.unrealized_pnl == Decimal("5000")

    def test_short_position_negative_quantity(self) -> None:
        # 空單 = 負數倉位
        pos = Position(
            tenant_id="stanley",
            symbol="2330.TW",
            quantity=Decimal("-100"),
            avg_price=Decimal("700"),
            market_value=Decimal("-70000"),
            unrealized_pnl=Decimal("0"),
            realized_pnl=Decimal("0"),
            last_updated=datetime(2026, 6, 10, 12, 0, tzinfo=UTC),
        )
        assert pos.quantity == Decimal("-100")

    def test_flat_position_zero_quantity(self) -> None:
        # 平倉 = 0
        pos = Position(
            tenant_id="stanley",
            symbol="2330.TW",
            quantity=Decimal("0"),
            avg_price=Decimal("0"),
            market_value=Decimal("0"),
            unrealized_pnl=Decimal("0"),
            realized_pnl=Decimal("3000"),
            last_updated=datetime(2026, 6, 10, 12, 0, tzinfo=UTC),
        )
        assert pos.quantity == Decimal("0")
        assert pos.realized_pnl == Decimal("3000")

    def test_frozen_cannot_mutate(self) -> None:
        pos = Position(
            tenant_id="stanley",
            symbol="2330.TW",
            quantity=Decimal("100"),
            avg_price=Decimal("700"),
            market_value=Decimal("75000"),
            unrealized_pnl=Decimal("5000"),
            realized_pnl=Decimal("0"),
            last_updated=datetime(2026, 6, 10, 12, 0, tzinfo=UTC),
        )
        with pytest.raises(FrozenInstanceError):
            pos.market_value = Decimal("80000")  # type: ignore[misc]

    def test_serialization_roundtrip(self) -> None:
        pos = Position(
            tenant_id="stanley",
            symbol="2330.TW",
            quantity=Decimal("100"),
            avg_price=Decimal("700"),
            market_value=Decimal("75000"),
            unrealized_pnl=Decimal("5000"),
            realized_pnl=Decimal("0"),
            last_updated=datetime(2026, 6, 10, 12, 0, tzinfo=UTC),
        )
        encoded = json.dumps(dataclasses.asdict(pos), default=str)
        decoded = json.loads(encoded)
        assert decoded["tenant_id"] == "stanley"
        assert Decimal(decoded["quantity"]) == Decimal("100")


# ----------------------------------------------------------------------------
# Fill
# ----------------------------------------------------------------------------


class TestFill:
    """Fill dataclass 行為驗證(5 case)。"""

    def test_basic_construction(self) -> None:
        fill = _make_fill()
        assert fill.fill_id.startswith("01HRZX")
        assert fill.order_id == "01HRZX00000000000000000001"
        assert fill.commission == Decimal("100.00")

    def test_frozen_cannot_mutate(self) -> None:
        fill = _make_fill()
        with pytest.raises(FrozenInstanceError):
            fill.price = Decimal("999")  # type: ignore[misc]

    def test_partial_fill_smaller_quantity(self) -> None:
        # 部分成交：成交量 < 原訂單量
        fill = _make_fill(quantity=Decimal("30"))
        assert fill.quantity == Decimal("30")

    def test_zero_commission_allowed(self) -> None:
        # 某些券商免手續費
        fill = _make_fill(commission=Decimal("0"))
        assert fill.commission == Decimal("0")

    def test_sell_side_fill(self) -> None:
        fill = _make_fill(side=OrderSide.SELL, price=Decimal("750"))
        assert fill.side is OrderSide.SELL
        assert fill.price == Decimal("750")


# ----------------------------------------------------------------------------
# Trade · 完整週期容器(PnL 由 S19 portfolio-risk 計算後填入)
# ----------------------------------------------------------------------------


class TestTrade:
    """Trade dataclass 行為驗證(5 case)。

    S01 階段 Trade 僅作「資料容器」，PnL 由上層計算後填入。
    """

    def _make_trade(self, **overrides: object) -> Trade:
        defaults: dict[str, object] = {
            "trade_id": "01HRZX0000000000000000T01",
            "tenant_id": "stanley",
            "symbol": "2330.TW",
            "open_fill_id": "01HRZX00000000000000000A02",
            "close_fill_id": "01HRZX00000000000000000B03",
            "quantity": Decimal("100"),
            "open_price": Decimal("700"),
            "close_price": Decimal("750"),
            "pnl": Decimal("5000"),  # 由 S19 算好填入
            "duration_ms": 86_400_000,  # 一天
        }
        defaults.update(overrides)
        return Trade(**defaults)  # type: ignore[arg-type]

    def test_basic_profitable_trade(self) -> None:
        trade = self._make_trade()
        assert trade.pnl == Decimal("5000")
        assert trade.duration_ms == 86_400_000

    def test_losing_trade_negative_pnl(self) -> None:
        # 虧損 = pnl 為負
        trade = self._make_trade(close_price=Decimal("650"), pnl=Decimal("-5000"))
        assert trade.pnl == Decimal("-5000")

    def test_frozen_cannot_mutate(self) -> None:
        trade = self._make_trade()
        with pytest.raises(FrozenInstanceError):
            trade.pnl = Decimal("0")  # type: ignore[misc]

    def test_intraday_trade_short_duration(self) -> None:
        # 日內交易：持倉幾秒
        trade = self._make_trade(duration_ms=5000)
        assert trade.duration_ms == 5000

    def test_serialization_roundtrip(self) -> None:
        trade = self._make_trade()
        encoded = json.dumps(dataclasses.asdict(trade), default=str)
        decoded = json.loads(encoded)
        assert decoded["tenant_id"] == "stanley"
        assert Decimal(decoded["pnl"]) == Decimal("5000")


# ----------------------------------------------------------------------------
# 跨 dataclass 整合：所有 dataclass 必須 frozen + slots + 含 tenant_id
# ----------------------------------------------------------------------------


def test_all_dataclasses_have_tenant_id() -> None:
    """強制 4 個 dataclass 含 tenant_id 欄位(Day-1 multi-tenant 設計)。"""
    for cls in (Order, Position, Fill, Trade):
        field_names = {f.name for f in dataclasses.fields(cls)}
        assert "tenant_id" in field_names, f"{cls.__name__} 必須含 tenant_id 欄位"


def test_all_dataclasses_are_frozen_and_slotted() -> None:
    """強制 4 個 dataclass 全部 frozen=True + slots=True。"""
    for cls in (Order, Position, Fill, Trade):
        params = cls.__dataclass_params__  # type: ignore[attr-defined]
        assert params.frozen is True, f"{cls.__name__} 必須 frozen=True"
        # slots=True 的證據：類別存在 __slots__ 且沒有 __dict__
        assert hasattr(cls, "__slots__"), f"{cls.__name__} 必須有 __slots__"


# ----------------------------------------------------------------------------
# 不變式驗證 · 髒值在建構當場被擋（fail-closed 端到端，2026-06-18 硬化）
# ----------------------------------------------------------------------------


class TestFailClosedValidation:
    """示範髒資料（券商/JSON/手動）在最底層型別就被擋下，不滲到下游。"""

    def test_負數量訂單被擋(self) -> None:
        with pytest.raises(ValueError, match="quantity 必須 > 0"):
            _make_order(quantity=Decimal("-100"))

    def test_零價限價單被擋(self) -> None:
        with pytest.raises(ValueError, match="price 必須 > 0"):
            _make_order(price=Decimal("0"))

    def test_float_冒充_decimal_被擋(self) -> None:
        with pytest.raises(ValueError, match="必須是 Decimal"):
            _make_order(quantity=0.1 + 0.2)  # 浮點誤差來源

    def test_naive_時間被擋(self) -> None:
        with pytest.raises(ValueError, match="帶時區"):
            _make_order(timestamp=datetime(2026, 6, 10, 12, 0, 0))

    def test_空_tenant_id_被擋(self) -> None:
        with pytest.raises(ValueError, match="tenant_id 不可為空"):
            _make_order(tenant_id="")

    def test_nan_價格被擋(self) -> None:
        with pytest.raises(ValueError, match="NaN / Infinity"):
            _make_order(price=Decimal("NaN"))

    def test_fill_負手續費被擋(self) -> None:
        with pytest.raises(ValueError, match="commission 不可為負"):
            _make_fill(commission=Decimal("-1"))

    def test_position_負均價被擋(self) -> None:
        with pytest.raises(ValueError, match="avg_price 不可為負"):
            Position(
                tenant_id="stanley",
                symbol="2330.TW",
                quantity=Decimal("100"),
                avg_price=Decimal("-700"),
                market_value=Decimal("75000"),
                unrealized_pnl=Decimal("0"),
                realized_pnl=Decimal("0"),
                last_updated=datetime(2026, 6, 10, 12, 0, tzinfo=UTC),
            )
