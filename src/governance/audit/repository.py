"""L11 Audit 倉庫 · 稽核日誌的唯一存取窗口。

設計規則:
1. append-only: 只有 append / 查詢 / 鏈頭讀取方法，刻意不提供 update / delete
   (DB 層另有低權帳號 + 觸發器兩道防線，見 migration)
2. 所有方法強制 tenant_id 語意(查詢物件必填 tenant)，沒有跨租戶方法
3. 鏈寫入序列化: append 先 SELECT ... FOR UPDATE 鎖住租戶鏈頭列，
   同租戶嚴格排隊(鏈不分叉)、不同租戶完全並行
4. 封印自動觸發: sequence 每跨過 checkpoint_batch_size 的倍數，
   在同一交易內蓋一個 Merkle 封印(D1 裁決 c)
5. commit 由呼叫端管(與業務操作同一交易，D4 裁決)，本類只 flush
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from sqlalchemy import insert, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from ulid import ULID

from src.governance.audit.chain import compute_record_hash
from src.governance.audit.errors import ChainCorruptionError
from src.governance.audit.mappers import (
    chain_head_to_domain,
    checkpoint_columns,
    checkpoint_to_domain,
    record_columns,
    record_to_domain,
)
from src.governance.audit.merkle import (
    CHECKPOINT_BATCH_SIZE,
    compute_checkpoint_hash,
    merkle_root,
)
from src.governance.audit.models import AuditRecordRow, ChainHeadRow, MerkleCheckpointRow
from src.governance.audit.signing import DEFAULT_SIGNER, Signer
from src.governance.audit.types import (
    GENESIS_HASH,
    AuditPage,
    AuditQuery,
    AuditRecord,
    AuditRecordInput,
    ChainHead,
    MerkleCheckpoint,
)

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AuditLogRepository:
    """稽核倉庫 · clock 可注入(測試不需等真時間，S02 resilience 同款)。"""

    def __init__(
        self,
        session: AsyncSession,
        *,
        clock: Callable[[], datetime] = _utc_now,
        checkpoint_batch_size: int = CHECKPOINT_BATCH_SIZE,
        signer: Signer = DEFAULT_SIGNER,
    ) -> None:
        if checkpoint_batch_size < 1:
            raise ValueError(f"checkpoint_batch_size 必須 >= 1: {checkpoint_batch_size}")
        self._session = session
        self._clock = clock
        self._batch = checkpoint_batch_size
        # 簽章器: 預設純 SHA256(向後相容);注入 HMAC 即信任根外移(B-006)。
        # 寫入與驗證必須用同一個 signer，故部署時 repository 與 verifier 同源注入。
        self._signer = signer

    @property
    def checkpoint_batch_size(self) -> int:
        """每個 Merkle checkpoint 應涵蓋的記錄數。"""
        return self._batch

    # ------------------------------------------------------------------
    # 寫入路徑(append-only)
    # ------------------------------------------------------------------

    async def append(self, record_input: AuditRecordInput) -> AuditRecord:
        """寫一筆稽核記錄。內部走 append_many 單一程式路徑。"""
        records = await self.append_many([record_input])
        return records[0]

    async def append_many(self, inputs: Sequence[AuditRecordInput]) -> list[AuditRecord]:
        """批次寫入: 鏈頭鎖一次、指紋逐筆串、單趟 bulk INSERT(1M 基準路徑)。"""
        if not inputs:
            return []
        tenant_id = inputs[0].tenant_id
        for item in inputs:
            if item.tenant_id != tenant_id:
                raise ValueError("append_many 一批只能屬於同一個租戶(鏈是逐租戶的)")

        head_row = await self._lock_head(tenant_id)
        old_sequence = head_row.last_sequence
        sequence = old_sequence
        prev_hash = head_row.last_hash

        records: list[AuditRecord] = []
        for item in inputs:
            sequence += 1
            record_id = str(ULID())
            timestamp = self._clock()
            record_hash = compute_record_hash(
                prev_hash=prev_hash,
                record_id=record_id,
                timestamp=timestamp,
                sequence=sequence,
                record_input=item,
                signer=self._signer,
            )
            records.append(
                AuditRecord(
                    tenant_id=item.tenant_id,
                    user_id=item.user_id,
                    role=item.role,
                    action=item.action,
                    resource=item.resource,
                    request_payload_hash=item.request_payload_hash,
                    response_status=item.response_status,
                    ip_address=item.ip_address,
                    user_agent=item.user_agent,
                    risk_score=item.risk_score,
                    timestamp=timestamp,
                    sequence=sequence,
                    prev_hash=prev_hash,
                    record_hash=record_hash,
                    record_id=record_id,
                )
            )
            prev_hash = record_hash

        await self._session.execute(
            insert(AuditRecordRow), [record_columns(record) for record in records]
        )
        head_row.last_sequence = sequence
        head_row.last_hash = prev_hash
        await self._seal_due_checkpoints(tenant_id, old_sequence, sequence)
        await self._session.flush()
        return records

    async def _lock_head(self, tenant_id: str) -> ChainHeadRow:
        """鎖住租戶鏈頭列(append 序列化點)。第一筆時建創世鏈頭。

        並行的「同租戶第一筆」會撞 tenant 唯一鍵: 用 SAVEPOINT 包住插入，
        撞鍵就回滾再重鎖(輸的那邊鎖到贏家建好的列，鏈仍然不分叉)。
        """
        stmt = select(ChainHeadRow).where(ChainHeadRow.tenant_id == tenant_id).with_for_update()
        row = await self._session.scalar(stmt)
        if row is not None:
            return row
        try:
            async with self._session.begin_nested():
                self._session.add(
                    ChainHeadRow(tenant_id=tenant_id, last_sequence=0, last_hash=GENESIS_HASH)
                )
        except IntegrityError:
            logger.info("鏈頭創世撞唯一鍵(並行首寫)，改鎖既有列: tenant=%s", tenant_id)
        retry_row: ChainHeadRow | None = await self._session.scalar(stmt)
        if retry_row is None:
            raise ChainCorruptionError(f"鏈頭建立後仍讀不到: tenant={tenant_id}")
        return retry_row

    async def _seal_due_checkpoints(
        self, tenant_id: str, old_sequence: int, new_sequence: int
    ) -> None:
        """sequence 跨過批次倍數就蓋封印(一次 append_many 可能跨多批)。"""
        first_due = old_sequence // self._batch + 1
        last_due = new_sequence // self._batch
        for index in range(first_due, last_due + 1):
            await self._seal_checkpoint(tenant_id, index)

    async def _seal_checkpoint(self, tenant_id: str, checkpoint_index: int) -> None:
        start_sequence = (checkpoint_index - 1) * self._batch + 1
        end_sequence = checkpoint_index * self._batch

        leaf_hashes = list(
            await self._session.scalars(
                select(AuditRecordRow.record_hash)
                .where(
                    AuditRecordRow.tenant_id == tenant_id,
                    AuditRecordRow.sequence >= start_sequence,
                    AuditRecordRow.sequence <= end_sequence,
                )
                .order_by(AuditRecordRow.sequence)
            )
        )
        if len(leaf_hashes) != self._batch:
            raise ChainCorruptionError(
                f"封印批記錄數不符: tenant={tenant_id} index={checkpoint_index} "
                f"預期 {self._batch} 實際 {len(leaf_hashes)}"
            )

        if checkpoint_index == 1:
            prev_checkpoint_hash = GENESIS_HASH
        else:
            prev_row = await self._session.scalar(
                select(MerkleCheckpointRow).where(
                    MerkleCheckpointRow.tenant_id == tenant_id,
                    MerkleCheckpointRow.checkpoint_index == checkpoint_index - 1,
                )
            )
            if prev_row is None:
                raise ChainCorruptionError(
                    f"前一個封印不存在: tenant={tenant_id} index={checkpoint_index - 1}"
                )
            prev_checkpoint_hash = prev_row.checkpoint_hash

        batch_root = merkle_root(leaf_hashes)
        checkpoint = MerkleCheckpoint(
            tenant_id=tenant_id,
            checkpoint_index=checkpoint_index,
            start_sequence=start_sequence,
            end_sequence=end_sequence,
            merkle_root=batch_root,
            prev_checkpoint_hash=prev_checkpoint_hash,
            checkpoint_hash=compute_checkpoint_hash(
                prev_checkpoint_hash=prev_checkpoint_hash,
                tenant_id=tenant_id,
                checkpoint_index=checkpoint_index,
                start_sequence=start_sequence,
                end_sequence=end_sequence,
                batch_merkle_root=batch_root,
                signer=self._signer,
            ),
        )
        self._session.add(MerkleCheckpointRow(**checkpoint_columns(checkpoint)))

    # ------------------------------------------------------------------
    # 讀取路徑
    # ------------------------------------------------------------------

    async def query(self, query: AuditQuery) -> AuditPage:
        """條件查詢 · keyset 分頁(多撈 1 筆判斷有沒有下一頁，不用 COUNT)。"""
        stmt = select(AuditRecordRow).where(
            AuditRecordRow.tenant_id == query.tenant_id,
            AuditRecordRow.sequence > query.after_sequence,
        )
        if query.user_id is not None:
            stmt = stmt.where(AuditRecordRow.user_id == query.user_id)
        if query.action is not None:
            stmt = stmt.where(AuditRecordRow.action == query.action)
        if query.resource is not None:
            stmt = stmt.where(AuditRecordRow.resource == query.resource)
        if query.response_status is not None:
            stmt = stmt.where(AuditRecordRow.response_status == query.response_status.value)
        if query.start_time is not None:
            stmt = stmt.where(AuditRecordRow.timestamp >= query.start_time)
        if query.end_time is not None:
            stmt = stmt.where(AuditRecordRow.timestamp <= query.end_time)
        stmt = stmt.order_by(AuditRecordRow.sequence).limit(query.limit + 1)

        rows = list(await self._session.scalars(stmt))
        has_more = len(rows) > query.limit
        page_rows = rows[: query.limit]
        records = tuple(record_to_domain(row) for row in page_rows)
        next_after = records[-1].sequence if has_more else None
        return AuditPage(records=records, next_after_sequence=next_after)

    async def get_chain_head(self, tenant_id: str) -> ChainHead | None:
        row = await self._session.scalar(
            select(ChainHeadRow).where(ChainHeadRow.tenant_id == tenant_id)
        )
        return None if row is None else chain_head_to_domain(row)

    async def records_in_range(
        self, tenant_id: str, start_sequence: int, end_sequence: int
    ) -> list[AuditRecord]:
        """依 sequence 範圍取記錄(驗證器深掃 / Merkle 證明用)，升冪排序。"""
        rows = await self._session.scalars(
            select(AuditRecordRow)
            .where(
                AuditRecordRow.tenant_id == tenant_id,
                AuditRecordRow.sequence >= start_sequence,
                AuditRecordRow.sequence <= end_sequence,
            )
            .order_by(AuditRecordRow.sequence)
        )
        return [record_to_domain(row) for row in rows]

    async def get_checkpoint(
        self, tenant_id: str, checkpoint_index: int
    ) -> MerkleCheckpoint | None:
        row = await self._session.scalar(
            select(MerkleCheckpointRow).where(
                MerkleCheckpointRow.tenant_id == tenant_id,
                MerkleCheckpointRow.checkpoint_index == checkpoint_index,
            )
        )
        return None if row is None else checkpoint_to_domain(row)

    async def list_checkpoints(self, tenant_id: str) -> list[MerkleCheckpoint]:
        """租戶全部封印，依 index 升冪(驗證器封印層掃描用)。"""
        rows = await self._session.scalars(
            select(MerkleCheckpointRow)
            .where(MerkleCheckpointRow.tenant_id == tenant_id)
            .order_by(MerkleCheckpointRow.checkpoint_index)
        )
        return [checkpoint_to_domain(row) for row in rows]
