"""L11 Audit 雜湊鏈引擎 · 記錄指紋的鑄造與重算。

鏈規則:
- 創世: 每個租戶第一筆的 prev_hash = GENESIS_HASH(64 個 0)
- 指紋: record_hash = SHA256(prev_hash + canonical(記錄欄位))
- 決定性: 欄位鍵排序、Decimal/datetime 走字串(S03 serializer 同紀律)，
  同一筆記錄永遠算出同一個指紋——這是驗證器不誤報的根基
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal
from enum import Enum
from typing import Any

from src.governance.audit.signing import DEFAULT_SIGNER, Signer
from src.governance.audit.types import AuditRecord, AuditRecordInput


def _jsonify(value: object) -> str:
    """canonical JSON 的非原生型別降級規則(Decimal 不經 float，精度保真)。"""
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, datetime):
        return _canonical_timestamp(value)
    if isinstance(value, Enum):
        return str(value.value)
    raise TypeError(f"無法序列化進稽核雜湊的型別: {type(value).__name__}")


def _canonical_timestamp(value: datetime) -> str:
    """時間正規化: 統一轉 UTC ISO-8601，確保跨時區來源算出同一個指紋。"""
    return value.astimezone(UTC).isoformat()


def canonical_json(payload: dict[str, Any]) -> str:
    """正規化 JSON: 鍵排序、無多餘空白、中文不逃脫(人類可讀，S03 同紀律)。"""
    return json.dumps(
        payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=_jsonify
    )


def hash_payload(payload: dict[str, Any]) -> str:
    """請求內容指紋 · 裝飾器用它算 request_payload_hash(內容不落地，只留指紋)。"""
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def compute_record_hash(
    *,
    prev_hash: str,
    record_id: str,
    timestamp: datetime,
    sequence: int,
    record_input: AuditRecordInput,
    signer: Signer = DEFAULT_SIGNER,
) -> str:
    """鑄造一筆記錄的指紋(append 路徑: AuditRecord 建構前先算 hash)。

    signer 預設純 SHA256(與歷史位元相同);注入 HMAC 簽章器即啟用信任根外移(B-006)。
    """
    preimage = prev_hash + canonical_json(
        {
            "record_id": record_id,
            "timestamp": _canonical_timestamp(timestamp),
            "sequence": sequence,
            "tenant_id": record_input.tenant_id,
            "user_id": record_input.user_id,
            "role": str(record_input.role.value),
            "action": record_input.action,
            "resource": record_input.resource,
            "request_payload_hash": record_input.request_payload_hash,
            "response_status": str(record_input.response_status.value),
            "ip_address": record_input.ip_address,
            "user_agent": record_input.user_agent,
            "risk_score": record_input.risk_score,
        }
    )
    return signer(preimage)


def recompute_hash(record: AuditRecord, *, signer: Signer = DEFAULT_SIGNER) -> str:
    """重算既有記錄的指紋(驗證路徑: 與存的 record_hash 比對，不同 = 被改過)。

    驗證時必須用與寫入時相同的 signer,否則指紋對不上(這正是 HMAC 防偽的根據)。
    """
    return compute_record_hash(
        prev_hash=record.prev_hash,
        record_id=record.record_id,
        timestamp=record.timestamp,
        sequence=record.sequence,
        record_input=AuditRecordInput(
            tenant_id=record.tenant_id,
            user_id=record.user_id,
            role=record.role,
            action=record.action,
            resource=record.resource,
            request_payload_hash=record.request_payload_hash,
            response_status=record.response_status,
            ip_address=record.ip_address,
            user_agent=record.user_agent,
            risk_score=record.risk_score,
        ),
        signer=signer,
    )
