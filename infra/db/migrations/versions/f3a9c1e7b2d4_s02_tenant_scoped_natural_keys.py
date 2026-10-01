"""s02 hardening: 自然鍵改為「每租戶唯一」複合鍵(審查 Batch 4b · 4b-1)

原本 orders.order_id / fills.fill_id / trades.trade_id 都是「全域唯一」(單欄 UNIQUE)，
這讓 A 租戶用過某個 id 後 B 租戶就再也不能用——跨租戶命名空間被偷偷綁在一起，
違反多租戶 Day-1 隔離。改為 (tenant_id, 自然鍵) 複合唯一鍵，命名空間以租戶為界。
positions 早已用 (tenant_id, symbol) 複合鍵，本次讓另外三表對齊。

downgrade 防呆：還原成全域唯一鍵前，先檢查資料中是否已有「跨租戶重複的自然鍵」。
複合鍵時期合法產生的 (A, ORD-1) 與 (B, ORD-1) 無法塞回全域唯一鍵——
與其讓 PG 拋出難懂的底層錯誤、或更糟地破壞資料，不如當場以白話訊息中止(fail-closed)。

Revision ID: f3a9c1e7b2d4
Revises: 9b1d4f6a2c8e
Create Date: 2026-06-20

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f3a9c1e7b2d4"
down_revision: str | Sequence[str] | None = "9b1d4f6a2c8e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# (表, 自然鍵欄, PG 自動命名的舊單欄唯一鍵, 新複合鍵名)
# 註：無名單欄 UNIQUE 在 PostgreSQL 會被自動命名為 <table>_<column>_key。
_TABLES = (
    ("orders", "order_id", "orders_order_id_key", "uq_orders_tenant_order"),
    ("fills", "fill_id", "fills_fill_id_key", "uq_fills_tenant_fill"),
    ("trades", "trade_id", "trades_trade_id_key", "uq_trades_tenant_trade"),
)


def _is_postgresql() -> bool:
    # 本專案只有 PostgreSQL 跑 migration；單元測試的 SQLite 由 create_all 直接取得新 schema
    # (與 S05 migration 同慣例)。其餘方言不做事、也不報錯。
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    """Upgrade schema：單欄全域唯一鍵 → (tenant_id, 自然鍵) 複合唯一鍵。"""
    if not _is_postgresql():
        return
    for table, natural_key, old_unique, new_unique in _TABLES:
        op.drop_constraint(old_unique, table, type_="unique")
        op.create_unique_constraint(new_unique, table, ["tenant_id", natural_key])


def downgrade() -> None:
    """Downgrade schema：複合唯一鍵 → 單欄全域唯一鍵(含跨租戶重複防呆)。"""
    if not _is_postgresql():
        return
    for table, natural_key, old_unique, new_unique in _TABLES:
        _abort_if_cross_tenant_duplicates(table, natural_key)
        op.drop_constraint(new_unique, table, type_="unique")
        op.create_unique_constraint(old_unique, table, [natural_key])


def _abort_if_cross_tenant_duplicates(table: str, natural_key: str) -> None:
    """偵測同一自然鍵被多個租戶使用——若有，downgrade 無法還原全域唯一鍵，當場中止。"""
    # table / natural_key 皆為本檔寫死的字面值(非外部輸入)，無注入風險。
    found = (
        op.get_bind()
        .execute(
            sa.text(
                f"SELECT 1 FROM {table} "  # noqa: S608
                f"GROUP BY {natural_key} HAVING COUNT(DISTINCT tenant_id) > 1 LIMIT 1"
            )
        )
        .first()
    )
    if found is not None:
        raise RuntimeError(
            f"downgrade 中止：{table}.{natural_key} 存在跨租戶重複值，"
            "無法還原成全域唯一鍵(會破壞既有資料)。請先人工去重再 downgrade。"
        )
