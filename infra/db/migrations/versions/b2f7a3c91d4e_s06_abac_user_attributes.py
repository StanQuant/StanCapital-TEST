"""s06 abac: users 加 department / region / project（ABAC 權威使用者屬性）

Revision ID: b2f7a3c91d4e
Revises: f3a9c1e7b2d4
Create Date: 2026-06-21 16:00:00.000000

S06 ABAC：使用者屬性隨 AccessSnapshot 同趟載入(零額外往返)。
server_default="" 讓既有列自動補空字串(代表「未設定」)，相容既有資料。
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b2f7a3c91d4e"
down_revision: str | Sequence[str] | None = "f3a9c1e7b2d4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "users",
        sa.Column("department", sa.String(length=64), nullable=False, server_default=""),
    )
    op.add_column(
        "users",
        sa.Column("region", sa.String(length=64), nullable=False, server_default=""),
    )
    op.add_column(
        "users",
        sa.Column("project", sa.String(length=64), nullable=False, server_default=""),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("users", "project")
    op.drop_column("users", "region")
    op.drop_column("users", "department")
