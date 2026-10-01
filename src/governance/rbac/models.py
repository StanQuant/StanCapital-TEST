"""L11 RBAC ORM 模型 · users / role_assignments / permission_overrides。

沿用 S02 紅線：繼承 Base + TenantTableMixin(id BIGSERIAL / tenant_id NOT NULL
無預設值 / created_at / updated_at / tenant_id 必有索引)。
與領域物件嚴格分離，轉換走 mappers.py。
"""

from __future__ import annotations

from sqlalchemy import Boolean, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from src.persistence.models import Base, TenantTableMixin


class UserRow(Base, TenantTableMixin):
    """users 表 · 對應 L11 User。email 同租戶內唯一。"""

    __tablename__ = "users"

    user_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False)
    # S06 ABAC 權威使用者屬性(server_default="" 讓既有列與 SQLite 自動填空)
    department: Mapped[str] = mapped_column(String(64), nullable=False, server_default="")
    region: Mapped[str] = mapped_column(String(64), nullable=False, server_default="")
    project: Mapped[str] = mapped_column(String(64), nullable=False, server_default="")

    __table_args__ = (
        UniqueConstraint("tenant_id", "email", name="uq_users_tenant_email"),
        Index("idx_users_tenant", "tenant_id"),
    )


class RoleAssignmentRow(Base, TenantTableMixin):
    """role_assignments 表 · 一人可多角色(D2)，同人同角色只一筆。"""

    __tablename__ = "role_assignments"

    assignment_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "user_id", "role", name="uq_assignments_tenant_user_role"),
        Index("idx_assignments_tenant", "tenant_id"),
        Index("idx_assignments_tenant_user", "tenant_id", "user_id"),
    )


class PermissionOverrideRow(Base, TenantTableMixin):
    """permission_overrides 表 · D1 混合式的租戶覆寫(同格子只一筆)。"""

    __tablename__ = "permission_overrides"

    override_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    resource: Mapped[str] = mapped_column(String(32), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    effect: Mapped[str] = mapped_column(String(16), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "role", "resource", "action", name="uq_overrides_tenant_cell"
        ),
        Index("idx_overrides_tenant", "tenant_id"),
        Index("idx_overrides_tenant_role", "tenant_id", "role"),
    )
