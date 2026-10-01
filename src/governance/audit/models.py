"""L11 Audit ORM 模型 · 三張表的資料庫形狀(與領域物件嚴格分離，S02 同款)。

append-only 防線(本檔只描述形狀，強制在 migration 落地):
- audit_records / audit_checkpoints 掛 UPDATE/DELETE 觸發器直接 RAISE EXCEPTION
- 應用程式執行帳號對這兩張表只有 SELECT / INSERT(D2 裁決 c)
- audit_chain_heads 是唯一可 UPDATE 的表(鏈頭推進)，但 DELETE/TRUNCATE 仍由觸發器阻擋
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from src.persistence.models import Base, TenantTableMixin, UTCDateTime


class AuditRecordRow(Base, TenantTableMixin):
    """audit_records 表 · 對應 AuditRecord。寫入後永不更新。"""

    __tablename__ = "audit_records"

    record_id: Mapped[str] = mapped_column(String(26), unique=True, nullable=False)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    resource: Mapped[str] = mapped_column(String(256), nullable=False)
    request_payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    response_status: Mapped[str] = mapped_column(String(16), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False)
    user_agent: Mapped[str] = mapped_column(String(256), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        # (tenant, sequence) 唯一 = 鏈不分叉的資料庫級保證；同時就是 keyset 分頁索引
        UniqueConstraint("tenant_id", "sequence", name="uq_audit_tenant_sequence"),
        # 三種查詢模式各配一條複合索引(規格 §2 效能預算)
        Index("idx_audit_tenant_time", "tenant_id", "timestamp"),
        Index("idx_audit_tenant_user_time", "tenant_id", "user_id", "timestamp"),
        Index("idx_audit_tenant_action_time", "tenant_id", "action", "timestamp"),
    )


class ChainHeadRow(Base, TenantTableMixin):
    """audit_chain_heads 表 · 每租戶一列，append 時 SELECT ... FOR UPDATE 鎖此列。"""

    __tablename__ = "audit_chain_heads"

    last_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    last_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (UniqueConstraint("tenant_id", name="uq_chain_heads_tenant"),)


class MerkleCheckpointRow(Base, TenantTableMixin):
    """audit_checkpoints 表 · 批次封印(D1 裁決 c)。寫入後永不更新。"""

    __tablename__ = "audit_checkpoints"

    checkpoint_index: Mapped[int] = mapped_column(BigInteger, nullable=False)
    start_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    end_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    merkle_root: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_checkpoint_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    checkpoint_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "checkpoint_index", name="uq_checkpoints_tenant_index"),
    )
