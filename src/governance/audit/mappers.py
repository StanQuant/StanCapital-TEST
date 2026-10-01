"""L11 Audit 領域物件 <-> ORM 列的雙向轉換(S02 同款分離原則)。

audit 表 append-only，columns dict 只供 insert 使用(沒有 update 路徑)。
"""

from __future__ import annotations

from src.governance.audit.models import AuditRecordRow, ChainHeadRow, MerkleCheckpointRow
from src.governance.audit.types import (
    AuditOutcome,
    AuditRecord,
    ChainHead,
    MerkleCheckpoint,
)
from src.governance.rbac.roles import Role

# ============================================================================
# AuditRecord
# ============================================================================


def record_columns(record: AuditRecord) -> dict[str, object]:
    return {
        "record_id": record.record_id,
        "tenant_id": record.tenant_id,
        "user_id": record.user_id,
        "role": record.role.value,
        "action": record.action,
        "resource": record.resource,
        "request_payload_hash": record.request_payload_hash,
        "response_status": record.response_status.value,
        "ip_address": record.ip_address,
        "user_agent": record.user_agent,
        "risk_score": record.risk_score,
        "timestamp": record.timestamp,
        "sequence": record.sequence,
        "prev_hash": record.prev_hash,
        "record_hash": record.record_hash,
    }


def record_to_domain(row: AuditRecordRow) -> AuditRecord:
    return AuditRecord(
        tenant_id=row.tenant_id,
        user_id=row.user_id,
        role=Role(row.role),
        action=row.action,
        resource=row.resource,
        request_payload_hash=row.request_payload_hash,
        response_status=AuditOutcome(row.response_status),
        ip_address=row.ip_address,
        user_agent=row.user_agent,
        risk_score=row.risk_score,
        timestamp=row.timestamp,
        sequence=row.sequence,
        prev_hash=row.prev_hash,
        record_hash=row.record_hash,
        record_id=row.record_id,
    )


# ============================================================================
# ChainHead
# ============================================================================


def chain_head_to_domain(row: ChainHeadRow) -> ChainHead:
    return ChainHead(
        tenant_id=row.tenant_id,
        last_sequence=row.last_sequence,
        last_hash=row.last_hash,
    )


# ============================================================================
# MerkleCheckpoint
# ============================================================================


def checkpoint_columns(checkpoint: MerkleCheckpoint) -> dict[str, object]:
    return {
        "tenant_id": checkpoint.tenant_id,
        "checkpoint_index": checkpoint.checkpoint_index,
        "start_sequence": checkpoint.start_sequence,
        "end_sequence": checkpoint.end_sequence,
        "merkle_root": checkpoint.merkle_root,
        "prev_checkpoint_hash": checkpoint.prev_checkpoint_hash,
        "checkpoint_hash": checkpoint.checkpoint_hash,
    }


def checkpoint_to_domain(row: MerkleCheckpointRow) -> MerkleCheckpoint:
    return MerkleCheckpoint(
        tenant_id=row.tenant_id,
        checkpoint_index=row.checkpoint_index,
        start_sequence=row.start_sequence,
        end_sequence=row.end_sequence,
        merkle_root=row.merkle_root,
        prev_checkpoint_hash=row.prev_checkpoint_hash,
        checkpoint_hash=row.checkpoint_hash,
    )
