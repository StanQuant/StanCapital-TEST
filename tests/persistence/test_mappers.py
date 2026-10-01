"""mappers 單元測試 · 領域物件 <-> ORM 列雙向轉換保真。"""

from __future__ import annotations

from src.core.types import OrderType
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

from tests.persistence.conftest import make_fill, make_order, make_position, make_trade


class TestOrderMapper:
    def test_columns_enum_存成字串值(self) -> None:
        cols = order_columns(make_order())
        assert cols["side"] == "buy"
        assert cols["order_type"] == "limit"
        assert cols["status"] == "pending"

    def test_round_trip_完全相等(self) -> None:
        order = make_order()
        assert order_to_domain(OrderRow(**order_columns(order))) == order

    def test_round_trip_market單_price_none(self) -> None:
        order = make_order(order_type=OrderType.MARKET, price=None)
        restored = order_to_domain(OrderRow(**order_columns(order)))
        assert restored == order
        assert restored.price is None


class TestPositionMapper:
    def test_round_trip_完全相等(self) -> None:
        position = make_position()
        assert position_to_domain(PositionRow(**position_columns(position))) == position


class TestFillMapper:
    def test_columns_enum_存成字串值(self) -> None:
        assert fill_columns(make_fill())["side"] == "buy"

    def test_round_trip_完全相等(self) -> None:
        fill = make_fill()
        assert fill_to_domain(FillRow(**fill_columns(fill))) == fill


class TestTradeMapper:
    def test_round_trip_完全相等(self) -> None:
        trade = make_trade()
        assert trade_to_domain(TradeRow(**trade_columns(trade))) == trade
