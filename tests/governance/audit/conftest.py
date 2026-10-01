"""S05 audit 測試共用工廠 · 預設值集中一處，個別測試只覆寫關心的欄位。

engine / session fixture 繼承自 tests/governance/conftest.py(SQLite in-memory)；
這裡 import audit models 確保三張稽核表註冊進 Base.metadata。
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import src.governance.audit.models  # noqa: F401  # 註冊稽核表進 Base.metadata
from src.governance.audit.types import (
    GENESIS_HASH,
    AuditOutcome,
    AuditRecord,
    AuditRecordInput,
)
from src.governance.rbac.roles import Role

# 固定時鐘: 測試不依賴真時間(S02 resilience 同款注入模式)
FIXED_NOW = datetime(2026, 6, 12, 10, 0, 0, tzinfo=UTC)


def fixed_clock() -> datetime:
    return FIXED_NOW


# 合法的 SHA256 hex 樣本(內容不重要，格式正確即可)
SAMPLE_HASH = "a" * 64


def make_input(**overrides: Any) -> AuditRecordInput:
    defaults: dict[str, Any] = {
        "tenant_id": "tenant-a",
        "user_id": "user-1",
        "role": Role.USER,
        "action": "order.submit",
        "resource": "order/abc123",
        "request_payload_hash": SAMPLE_HASH,
        "response_status": AuditOutcome.SUCCESS,
        "ip_address": "internal",
        "user_agent": "internal",
        "risk_score": 0,
    }
    defaults.update(overrides)
    return AuditRecordInput(**defaults)


def make_record(**overrides: Any) -> AuditRecord:
    defaults: dict[str, Any] = {
        "tenant_id": "tenant-a",
        "user_id": "user-1",
        "role": Role.USER,
        "action": "order.submit",
        "resource": "order/abc123",
        "request_payload_hash": SAMPLE_HASH,
        "response_status": AuditOutcome.SUCCESS,
        "ip_address": "internal",
        "user_agent": "internal",
        "risk_score": 0,
        "timestamp": datetime(2026, 6, 12, 10, 0, 0, tzinfo=UTC),
        "sequence": 1,
        "prev_hash": GENESIS_HASH,
        "record_hash": SAMPLE_HASH,
    }
    defaults.update(overrides)
    return AuditRecord(**defaults)
