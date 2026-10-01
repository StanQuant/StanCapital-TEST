"""L4 領域物件 <-> L5 ORM 列的雙向轉換。

為什麼分離: L4 是 frozen dataclass(業務語意)，ORM 列是資料庫形狀。
分離後換資料庫不動 L4，L4 演進也不直接綁 schema。

`*_columns()` 回傳欄位 dict，insert(建新列)與 update(逐欄覆寫)共用同一份，
避免兩條路徑欄位清單不同步。
"""

from __future__ import annotations

from src.core.types import (
    Fill,
    Order,
    OrderSide,
    OrderStatus,
    OrderType,
    Position,
    Trade,
)
from src.persistence.models import FillRow, OrderRow, PositionRow, TradeRow

# ============================================================================
# Order
# ============================================================================


def order_columns(order: Order) -> dict[str, object]:
    return {
        "order_id": order.order_id,
        "tenant_id": order.tenant_id,
        "symbol": order.symbol,
        "side": order.side.value,
        "order_type": order.order_type.value,
        "quantity": order.quantity,
        "price": order.price,
        "stop_price": order.stop_price,
        "status": order.status.value,
        "timestamp": order.timestamp,
        "strategy_id": order.strategy_id,
        "parent_order_id": order.parent_order_id,
    }


def order_to_domain(row: OrderRow) -> Order:
    return Order(
        order_id=row.order_id,
        tenant_id=row.tenant_id,
        symbol=row.symbol,
        side=OrderSide(row.side),
        order_type=OrderType(row.order_type),
        quantity=row.quantity,
        price=row.price,
        stop_price=row.stop_price,
        status=OrderStatus(row.status),
        timestamp=row.timestamp,
        strategy_id=row.strategy_id,
        parent_order_id=row.parent_order_id,
    )


# ============================================================================
# Position
# ============================================================================


def position_columns(position: Position) -> dict[str, object]:
    return {
        "tenant_id": position.tenant_id,
        "symbol": position.symbol,
        "quantity": position.quantity,
        "avg_price": position.avg_price,
        "market_value": position.market_value,
        "unrealized_pnl": position.unrealized_pnl,
        "realized_pnl": position.realized_pnl,
        "last_updated": position.last_updated,
    }


def position_to_domain(row: PositionRow) -> Position:
    return Position(
        tenant_id=row.tenant_id,
        symbol=row.symbol,
        quantity=row.quantity,
        avg_price=row.avg_price,
        market_value=row.market_value,
        unrealized_pnl=row.unrealized_pnl,
        realized_pnl=row.realized_pnl,
        last_updated=row.last_updated,
    )


# ============================================================================
# Fill
# ============================================================================


def fill_columns(fill: Fill) -> dict[str, object]:
    return {
        "fill_id": fill.fill_id,
        "order_id": fill.order_id,
        "tenant_id": fill.tenant_id,
        "symbol": fill.symbol,
        "side": fill.side.value,
        "quantity": fill.quantity,
        "price": fill.price,
        "commission": fill.commission,
        "timestamp": fill.timestamp,
    }


def fill_to_domain(row: FillRow) -> Fill:
    return Fill(
        fill_id=row.fill_id,
        order_id=row.order_id,
        tenant_id=row.tenant_id,
        symbol=row.symbol,
        side=OrderSide(row.side),
        quantity=row.quantity,
        price=row.price,
        commission=row.commission,
        timestamp=row.timestamp,
    )


# ============================================================================
# Trade
# ============================================================================


def trade_columns(trade: Trade) -> dict[str, object]:
    return {
        "trade_id": trade.trade_id,
        "tenant_id": trade.tenant_id,
        "symbol": trade.symbol,
        "open_fill_id": trade.open_fill_id,
        "close_fill_id": trade.close_fill_id,
        "quantity": trade.quantity,
        "open_price": trade.open_price,
        "close_price": trade.close_price,
        "pnl": trade.pnl,
        "duration_ms": trade.duration_ms,
    }


def trade_to_domain(row: TradeRow) -> Trade:
    return Trade(
        trade_id=row.trade_id,
        tenant_id=row.tenant_id,
        symbol=row.symbol,
        open_fill_id=row.open_fill_id,
        close_fill_id=row.close_fill_id,
        quantity=row.quantity,
        open_price=row.open_price,
        close_price=row.close_price,
        pnl=row.pnl,
        duration_ms=row.duration_ms,
    )
