"""S05 · mappers 雙向轉換測試 · domain -> columns -> Row -> domain 逐欄位一致。"""

from __future__ import annotations

from datetime import UTC, datetime

from src.governance.audit.mappers import (
    chain_head_to_domain,
    checkpoint_columns,
    checkpoint_to_domain,
    record_columns,
    record_to_domain,
)
from src.governance.audit.models import AuditRecordRow, ChainHeadRow, MerkleCheckpointRow
from src.governance.audit.types import GENESIS_HASH, AuditOutcome, ChainHead, MerkleCheckpoint
from src.governance.rbac.roles import Role

from tests.governance.audit.conftest import make_record

# ============================================================================
# AuditRecord: 完整 round-trip
# ============================================================================


def test_record_round_trip_all_fields() -> None:
    record = make_record(
        role=Role.AGENT,
        response_status=AuditOutcome.FAILED,
        risk_score=87,
        timestamp=datetime(2026, 6, 12, 3, 4, 5, 678901, tzinfo=UTC),
        sequence=42,
        prev_hash="c" * 64,
        record_hash="d" * 64,
    )
    row = AuditRecordRow(**record_columns(record))  # type: ignore[arg-type]
    restored = record_to_domain(row)
    assert restored == record


def test_record_columns_enum_values_are_strings() -> None:
    # DB 存字串不存 enum 物件(跨語言可讀，S01 StrEnum 同紀律)
    columns = record_columns(make_record(role=Role.OWNER))
    assert columns["role"] == "owner"
    assert columns["response_status"] == "success"


def test_record_columns_complete() -> None:
    # 欄位清單與 ORM 對齊(漏一欄 insert 會缺資料，多一欄會 TypeError)
    columns = record_columns(make_record())
    expected_keys = {
        "record_id",
        "tenant_id",
        "user_id",
        "role",
        "action",
        "resource",
        "request_payload_hash",
        "response_status",
        "ip_address",
        "user_agent",
        "risk_score",
        "timestamp",
        "sequence",
        "prev_hash",
        "record_hash",
    }
    assert set(columns) == expected_keys


# ============================================================================
# ChainHead
# ============================================================================


def test_chain_head_to_domain() -> None:
    row = ChainHeadRow(tenant_id="tenant-a", last_sequence=99, last_hash="e" * 64)
    assert chain_head_to_domain(row) == ChainHead(
        tenant_id="tenant-a", last_sequence=99, last_hash="e" * 64
    )


# ============================================================================
# MerkleCheckpoint: 完整 round-trip
# ============================================================================


def _checkpoint() -> MerkleCheckpoint:
    return MerkleCheckpoint(
        tenant_id="tenant-a",
        checkpoint_index=3,
        start_sequence=2001,
        end_sequence=3000,
        merkle_root="a" * 64,
        prev_checkpoint_hash=GENESIS_HASH,
        checkpoint_hash="b" * 64,
    )


def test_checkpoint_round_trip_all_fields() -> None:
    checkpoint = _checkpoint()
    row = MerkleCheckpointRow(**checkpoint_columns(checkpoint))  # type: ignore[arg-type]
    assert checkpoint_to_domain(row) == checkpoint


def test_checkpoint_columns_complete() -> None:
    columns = checkpoint_columns(_checkpoint())
    expected_keys = {
        "tenant_id",
        "checkpoint_index",
        "start_sequence",
        "end_sequence",
        "merkle_root",
        "prev_checkpoint_hash",
        "checkpoint_hash",
    }
    assert set(columns) == expected_keys
