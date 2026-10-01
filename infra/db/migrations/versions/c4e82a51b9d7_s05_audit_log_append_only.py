"""s05 audit-log: audit_records / audit_chain_heads / audit_checkpoints + append-only 防線

三道資料庫層防線(D2 裁決 c):
1. 觸發器: audit_records / audit_checkpoints 的 UPDATE / DELETE / TRUNCATE 直接拋錯
2. 低權帳號: stanquant_app(若存在)對稽核兩表只有 SELECT / INSERT
   (帳號本身由部署腳本 / 測試 fixture 建立，密碼不進 migration)
3. (應用層的 append-only API 與雜湊鏈見 src/governance/audit/)

Revision ID: c4e82a51b9d7
Revises: 87cb868be9fc
Create Date: 2026-06-13

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from src.governance.audit.migration_guard import require_audit_downgrade_allowed

# revision identifiers, used by Alembic.
revision: str = "c4e82a51b9d7"
down_revision: str | Sequence[str] | None = "87cb868be9fc"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_IMMUTABLE_TABLES = ("audit_records", "audit_checkpoints")


def _tenant_mixin_columns() -> list[sa.Column[object]]:
    """TenantTableMixin 四欄(與 S02/S04 migration 同款)。"""
    return [
        sa.Column(
            "id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("tenant_id", sa.String(length=32), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    ]


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "audit_records",
        sa.Column("record_id", sa.String(length=26), nullable=False),
        sa.Column("user_id", sa.String(length=64), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("resource", sa.String(length=256), nullable=False),
        sa.Column("request_payload_hash", sa.String(length=64), nullable=False),
        sa.Column("response_status", sa.String(length=16), nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=False),
        sa.Column("user_agent", sa.String(length=256), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("record_hash", sa.String(length=64), nullable=False),
        *_tenant_mixin_columns(),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("record_id"),
        sa.UniqueConstraint("tenant_id", "sequence", name="uq_audit_tenant_sequence"),
    )
    op.create_index("idx_audit_tenant_time", "audit_records", ["tenant_id", "timestamp"])
    op.create_index(
        "idx_audit_tenant_user_time", "audit_records", ["tenant_id", "user_id", "timestamp"]
    )
    op.create_index(
        "idx_audit_tenant_action_time", "audit_records", ["tenant_id", "action", "timestamp"]
    )

    op.create_table(
        "audit_chain_heads",
        sa.Column("last_sequence", sa.BigInteger(), nullable=False),
        sa.Column("last_hash", sa.String(length=64), nullable=False),
        *_tenant_mixin_columns(),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", name="uq_chain_heads_tenant"),
    )

    op.create_table(
        "audit_checkpoints",
        sa.Column("checkpoint_index", sa.BigInteger(), nullable=False),
        sa.Column("start_sequence", sa.BigInteger(), nullable=False),
        sa.Column("end_sequence", sa.BigInteger(), nullable=False),
        sa.Column("merkle_root", sa.String(length=64), nullable=False),
        sa.Column("prev_checkpoint_hash", sa.String(length=64), nullable=False),
        sa.Column("checkpoint_hash", sa.String(length=64), nullable=False),
        *_tenant_mixin_columns(),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "checkpoint_index", name="uq_checkpoints_tenant_index"),
    )

    if op.get_bind().dialect.name != "postgresql":
        return  # 觸發器與帳號權限是 PostgreSQL 專屬(SQLite 只用於單元測試)

    # 防線 1: append-only 觸發器(UPDATE / DELETE 逐列擋、TRUNCATE 整句擋)
    op.execute(
        """
        CREATE OR REPLACE FUNCTION forbid_audit_mutation() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit 表是 append-only: 禁止對 % 執行 %',
                TG_TABLE_NAME, TG_OP;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    for table in _IMMUTABLE_TABLES:
        op.execute(
            f"""
            CREATE TRIGGER trg_{table}_no_mutation
            BEFORE UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION forbid_audit_mutation();
            """
        )
        op.execute(
            f"""
            CREATE TRIGGER trg_{table}_no_truncate
            BEFORE TRUNCATE ON {table}
            FOR EACH STATEMENT EXECUTE FUNCTION forbid_audit_mutation();
            """
        )

    # 防線 2: 低權帳號權限(角色存在才設定；角色由部署腳本 / 測試 fixture 建立)
    # 角色名稱固定寫在 SQL 內，不接受外部輸入，避免形成動態 SQL 注入面。
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'stanquant_app') THEN
                GRANT USAGE ON SCHEMA public TO stanquant_app;
                GRANT SELECT, INSERT ON audit_records, audit_checkpoints TO stanquant_app;
                REVOKE UPDATE, DELETE, TRUNCATE
                    ON audit_records, audit_checkpoints FROM stanquant_app;
                -- 鏈頭是唯一可更新的稽核表(鏈頭推進)，但不可刪
                GRANT SELECT, INSERT, UPDATE ON audit_chain_heads TO stanquant_app;
                REVOKE DELETE, TRUNCATE ON audit_chain_heads FROM stanquant_app;
                GRANT USAGE, SELECT ON SEQUENCE
                    audit_records_id_seq, audit_chain_heads_id_seq,
                    audit_checkpoints_id_seq TO stanquant_app;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    """Downgrade schema。

    注意: 降級會刪除稽核資料表——僅供開發環境 schema 演進使用，
    生產環境的稽核資料受法遵保存義務約束，禁止 downgrade(部署流程把關)。
    防呆: 預設 fail-closed 擋下，必須明確設 STANQUANT_ALLOW_AUDIT_DOWNGRADE=1 才放行。
    """
    require_audit_downgrade_allowed()  # 防呆閘：未明確授權直接拋錯，保護稽核資料

    if op.get_bind().dialect.name == "postgresql":
        for table in _IMMUTABLE_TABLES:
            op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_no_mutation ON {table}")
            op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_no_truncate ON {table}")
        op.execute("DROP FUNCTION IF EXISTS forbid_audit_mutation()")

    op.drop_table("audit_checkpoints")
    op.drop_table("audit_chain_heads")
    op.drop_index("idx_audit_tenant_action_time", table_name="audit_records")
    op.drop_index("idx_audit_tenant_user_time", table_name="audit_records")
    op.drop_index("idx_audit_tenant_time", table_name="audit_records")
    op.drop_table("audit_records")
