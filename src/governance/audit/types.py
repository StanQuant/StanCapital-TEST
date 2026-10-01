"""L11 Audit 領域物件 · AuditRecord / AuditQuery / ChainHead / TamperReport。

設計準則(與 S01/S04 同紀律):
- frozen=True + slots=True 不可變值物件
- tenant_id 必填無預設值(2026-06-10 裁定)
- 非法狀態在建構期就擋下(__post_init__)
- 欄位依 Architecture §L11 子層 3，外加雜湊鏈三欄位(sequence / prev_hash / record_hash)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from ulid import ULID

from src.governance.rbac.roles import Role

# SHA256 十六進位摘要: 64 個 hex 字元
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")

# 創世記錄的 prev_hash(每個租戶的鏈各自從這裡開始)
GENESIS_HASH = "0" * 64


def _new_id() -> str:
    """ULID: 時間戳前綴可排序(S01 ADR-0001 同款)。"""
    return str(ULID())


def _require_sha256_hex(value: str, field_name: str) -> None:
    if not _SHA256_HEX.fullmatch(value):
        raise ValueError(f"{field_name} 必須是 64 字元小寫 hex 的 SHA256 摘要: {value!r}")


def _require_aware(value: datetime, field_name: str) -> None:
    # naive 時間代表上游漏了時區，直接擋下比默默猜測安全(S02 同紀律)
    if value.tzinfo is None:
        raise ValueError(f"{field_name} 必須是 tz-aware 時間(請用 UTC)")


class AuditOutcome(StrEnum):
    """操作結果 · 失敗的操作也要留稽核(試圖做壞事本身就是證據)。"""

    SUCCESS = "success"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class AuditRecordInput:
    """呼叫端提供的稽核內容(鏈欄位由 repository 在 append 時計算補上)。

    - risk_score: S07 ATR 落地前由呼叫端傳 0
    - ip_address / user_agent: S22 gateway 落地前，系統內部操作傳 "internal"
    """

    tenant_id: str
    user_id: str
    role: Role
    action: str
    resource: str
    request_payload_hash: str
    response_status: AuditOutcome
    ip_address: str
    user_agent: str
    risk_score: int = 0

    def __post_init__(self) -> None:
        if not self.tenant_id:
            raise ValueError("tenant_id 不可為空")
        if not self.user_id:
            raise ValueError("user_id 不可為空")
        if not self.action or " " in self.action:
            raise ValueError(f"action 不可為空或含空白: {self.action!r}")
        if not self.resource:
            raise ValueError("resource 不可為空")
        _require_sha256_hex(self.request_payload_hash, "request_payload_hash")
        if not self.ip_address:
            raise ValueError("ip_address 不可為空(系統內部操作請傳 'internal')")
        if not self.user_agent:
            raise ValueError("user_agent 不可為空(系統內部操作請傳 'internal')")
        if not 0 <= self.risk_score <= 100:
            raise ValueError(f"risk_score 必須在 0-100 之間: {self.risk_score}")


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """完整稽核記錄 · 含鏈欄位，寫入後不可變(四層防禦見模組 docstring)。"""

    tenant_id: str
    user_id: str
    role: Role
    action: str
    resource: str
    request_payload_hash: str
    response_status: AuditOutcome
    ip_address: str
    user_agent: str
    risk_score: int
    timestamp: datetime
    sequence: int
    prev_hash: str
    record_hash: str
    record_id: str = field(default_factory=_new_id)

    def __post_init__(self) -> None:
        # 與 AuditRecordInput 同套基本驗證(記錄可能從資料庫重建，同樣要擋壞資料)
        AuditRecordInput(
            tenant_id=self.tenant_id,
            user_id=self.user_id,
            role=self.role,
            action=self.action,
            resource=self.resource,
            request_payload_hash=self.request_payload_hash,
            response_status=self.response_status,
            ip_address=self.ip_address,
            user_agent=self.user_agent,
            risk_score=self.risk_score,
        )
        _require_aware(self.timestamp, "timestamp")
        if self.sequence < 1:
            raise ValueError(f"sequence 必須 >= 1: {self.sequence}")
        _require_sha256_hex(self.prev_hash, "prev_hash")
        _require_sha256_hex(self.record_hash, "record_hash")
        if not self.record_id:
            raise ValueError("record_id 不可為空")


@dataclass(frozen=True, slots=True)
class ChainHead:
    """租戶鏈頭快照 · append 的序列化點(行鎖在這一列上)。"""

    tenant_id: str
    last_sequence: int
    last_hash: str

    def __post_init__(self) -> None:
        if not self.tenant_id:
            raise ValueError("tenant_id 不可為空")
        if self.last_sequence < 0:
            raise ValueError(f"last_sequence 必須 >= 0: {self.last_sequence}")
        _require_sha256_hex(self.last_hash, "last_hash")


@dataclass(frozen=True, slots=True)
class AuditQuery:
    """查詢條件 · tenant_id 必填(跨租戶查詢在 API 層面不可能)。

    keyset 分頁: after_sequence 帶上一頁最後一筆的 sequence，跨頁不重不漏。
    """

    tenant_id: str
    user_id: str | None = None
    action: str | None = None
    resource: str | None = None
    response_status: AuditOutcome | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    after_sequence: int = 0
    limit: int = 100

    def __post_init__(self) -> None:
        if not self.tenant_id:
            raise ValueError("tenant_id 不可為空")
        if self.start_time is not None:
            _require_aware(self.start_time, "start_time")
        if self.end_time is not None:
            _require_aware(self.end_time, "end_time")
        if (
            self.start_time is not None
            and self.end_time is not None
            and self.start_time > self.end_time
        ):
            raise ValueError("start_time 不可晚於 end_time")
        if self.after_sequence < 0:
            raise ValueError(f"after_sequence 必須 >= 0: {self.after_sequence}")
        if not 1 <= self.limit <= 1000:
            raise ValueError(f"limit 必須在 1-1000 之間: {self.limit}")


@dataclass(frozen=True, slots=True)
class AuditPage:
    """查詢結果一頁 · next_after_sequence 為 None 代表沒有下一頁。"""

    records: tuple[AuditRecord, ...]
    next_after_sequence: int | None


@dataclass(frozen=True, slots=True)
class MerkleCheckpoint:
    """批次封印(D1 裁決 c) · 每滿一批對該批 record_hash 建 Merkle 樹存根。

    checkpoint 之間也串鏈(prev_checkpoint_hash)，形成雙層保護:
    記錄層鏈抓逐筆篡改，checkpoint 層抓「整批換掉重算」的進階攻擊。
    """

    tenant_id: str
    checkpoint_index: int
    start_sequence: int
    end_sequence: int
    merkle_root: str
    prev_checkpoint_hash: str
    checkpoint_hash: str

    def __post_init__(self) -> None:
        if not self.tenant_id:
            raise ValueError("tenant_id 不可為空")
        if self.checkpoint_index < 1:
            raise ValueError(f"checkpoint_index 必須 >= 1: {self.checkpoint_index}")
        if self.start_sequence < 1:
            raise ValueError(f"start_sequence 必須 >= 1: {self.start_sequence}")
        if self.end_sequence < self.start_sequence:
            raise ValueError(
                f"end_sequence 不可小於 start_sequence: {self.end_sequence} < {self.start_sequence}"
            )
        _require_sha256_hex(self.merkle_root, "merkle_root")
        _require_sha256_hex(self.prev_checkpoint_hash, "prev_checkpoint_hash")
        _require_sha256_hex(self.checkpoint_hash, "checkpoint_hash")


@dataclass(frozen=True, slots=True)
class TamperReport:
    """鏈驗證報告 · 三種篡改各自獨立列出，空 = 該類無異常。

    - mismatched_sequences: 內容被改(重算雜湊對不上)
    - missing_sequences: 記錄被刪(sequence 跳號)
    - head_mismatch: 鏈頭表與實際最後一筆對不上(插假記錄 / 鏈頭被動)
    """

    tenant_id: str
    checked_count: int
    mismatched_sequences: tuple[int, ...] = ()
    missing_sequences: tuple[int, ...] = ()
    head_mismatch: bool = False

    def __post_init__(self) -> None:
        if not self.tenant_id:
            raise ValueError("tenant_id 不可為空")
        if self.checked_count < 0:
            raise ValueError(f"checked_count 必須 >= 0: {self.checked_count}")

    @property
    def is_intact(self) -> bool:
        """鏈是否完好(三類異常皆空)。"""
        return (
            not self.mismatched_sequences and not self.missing_sequences and not self.head_mismatch
        )
