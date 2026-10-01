"""s05 hardening: block audit_chain_heads delete/truncate.

S05 原本讓 audit_chain_heads 可 UPDATE，因為 append 時必須推進鏈頭。
但鏈頭不應被 DELETE / TRUNCATE；否則 owner 誤操作會讓鏈頭狀態消失，
即使 audit_records 還在，也會破壞後續 append 與驗證的商業可信度。

Revision ID: 9b1d4f6a2c8e
Revises: c4e82a51b9d7
Create Date: 2026-06-17

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "9b1d4f6a2c8e"
down_revision: str | Sequence[str] | None = "c4e82a51b9d7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    if op.get_bind().dialect.name != "postgresql":
        return

    op.execute(
        """
        CREATE OR REPLACE FUNCTION forbid_audit_chain_head_removal() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit 鏈頭是 append-only: 禁止對 % 執行 %',
                TG_TABLE_NAME, TG_OP;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_audit_chain_heads_no_delete
        BEFORE DELETE ON audit_chain_heads
        FOR EACH ROW EXECUTE FUNCTION forbid_audit_chain_head_removal();
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_audit_chain_heads_no_truncate
        BEFORE TRUNCATE ON audit_chain_heads
        FOR EACH STATEMENT EXECUTE FUNCTION forbid_audit_chain_head_removal();
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'stanquant_app') THEN
                REVOKE DELETE, TRUNCATE ON audit_chain_heads FROM stanquant_app;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    """Downgrade schema."""
    if op.get_bind().dialect.name != "postgresql":
        return

    op.execute("DROP TRIGGER IF EXISTS trg_audit_chain_heads_no_truncate ON audit_chain_heads")
    op.execute("DROP TRIGGER IF EXISTS trg_audit_chain_heads_no_delete ON audit_chain_heads")
    op.execute("DROP FUNCTION IF EXISTS forbid_audit_chain_head_removal()")
