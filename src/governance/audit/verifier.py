"""L11 Audit 鏈驗證器 · 抓「改內容」「刪記錄」「動鏈頭」三種篡改 + 發警報。

兩層驗證(D1 裁決 c):
- verify_tenant_chain: 記錄層深掃(逐筆重算指紋 + 連結 + 跳號 + 鏈頭比對)，
  支援增量(from_sequence 之後續驗，1M 條不用每次全掃)
- verify_checkpoint_layer: 封印層快驗(量是記錄層的 1/批次大小)
- verify_batch: 對單一封印批深掃(重算 Merkle 根與封印比對)

警報設計: CRITICAL 結構化日誌 + 可注入 alert_sink 回呼。
不直接發 L4 事件——EventType 是 L4 純市場概念，塞「稽核篡改」會污染核心層
(ADR-0001 AgentRiskLevel 同款教訓)；S09 observability 把 alert_sink 接上
通知通道(匯流排 / Slack)即可。
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from src.governance.audit.chain import recompute_hash
from src.governance.audit.merkle import merkle_root, recompute_checkpoint_hash
from src.governance.audit.repository import AuditLogRepository
from src.governance.audit.signing import DEFAULT_SIGNER, Signer
from src.governance.audit.types import GENESIS_HASH, AuditQuery, TamperReport

logger = logging.getLogger(__name__)

# 警報接收端: S09 observability 接上通知通道(本切片預設只留 CRITICAL 日誌)
AlertSink = Callable[[TamperReport], Awaitable[None]]


class ChainVerifier:
    """鏈驗證器 · repository 注入(不自己連資料庫，S04 checker 同款)。"""

    def __init__(
        self,
        repository: AuditLogRepository,
        *,
        alert_sink: AlertSink | None = None,
        page_size: int = 1000,
        signer: Signer = DEFAULT_SIGNER,
    ) -> None:
        if not 1 <= page_size <= 1000:
            raise ValueError(f"page_size 必須在 1-1000 之間: {page_size}")
        self._repository = repository
        self._alert_sink = alert_sink
        self._page_size = page_size
        # 驗證用的 signer 必須與寫入該鏈時相同(否則指紋全對不上)——
        # 部署時與對應 repository 同源注入(預設純 SHA256，向後相容)。
        self._signer = signer

    # ------------------------------------------------------------------
    # 記錄層深掃
    # ------------------------------------------------------------------

    async def verify_tenant_chain(self, tenant_id: str, *, from_sequence: int = 0) -> TamperReport:
        """逐筆重算指紋驗證整條鏈(from_sequence > 0 時做增量續驗)。

        增量語義: 驗證 sequence > from_sequence 的記錄，
        以 from_sequence 那筆(已驗證過的信任錨點)的 record_hash 為起始連結。

        偵測範圍限制(fail-closed 須知 · 尾端截斷盲點 T008):
          本深掃驗證「現存記錄彼此自洽且與鏈頭一致」，但抓不到「攻擊者(有 DB 寫權)
          刪掉尾端若干筆、再把鏈頭回捲到截斷點」這種截斷攻擊——截斷後的前段鏈與
          回捲後的鏈頭仍然自洽，雜湊鏈本質無法自證「原本應該有幾筆」。
          根治需 DB 外部的單調高水位錨點(每日把最大 sequence / 鏈頭匯出到
          WORM / Object Lock，見 S05-商業化硬化清單 S05-H04 與 BACKLOG B-006)；
          在那之前，例行排程須以「外部留存的上次鏈長」交叉比對，本方法不可作為
          截斷攻擊的唯一防線。現況由釘住測試
          tests/governance/audit/test_verifier.py::test_tail_truncation_with_head_rollback_not_detected
          鎖死——行為若改變(真的補上錨點)該測試會紅，逼迫同步更新本揭露。
        """
        if from_sequence < 0:
            raise ValueError(f"from_sequence 必須 >= 0: {from_sequence}")

        if from_sequence == 0:
            expected_prev = GENESIS_HASH
            last_seen_sequence = 0
            last_seen_hash = GENESIS_HASH
        else:
            anchors = await self._repository.records_in_range(
                tenant_id, from_sequence, from_sequence
            )
            if not anchors:
                raise ValueError(f"增量驗證起點不存在: tenant={tenant_id} sequence={from_sequence}")
            expected_prev = anchors[0].record_hash
            last_seen_sequence = from_sequence
            last_seen_hash = anchors[0].record_hash

        mismatched: list[int] = []
        missing: list[int] = []
        checked = 0
        expected_sequence = last_seen_sequence + 1
        cursor = last_seen_sequence

        while True:
            page = await self._repository.query(
                AuditQuery(tenant_id=tenant_id, after_sequence=cursor, limit=self._page_size)
            )
            for record in page.records:
                gap_before = record.sequence != expected_sequence
                if gap_before:
                    missing.extend(range(expected_sequence, record.sequence))
                content_ok = recompute_hash(record, signer=self._signer) == record.record_hash
                link_ok = record.prev_hash == expected_prev
                # 跳號時連結必斷(已記為缺漏)，不重複算成內容篡改
                if not content_ok or (not gap_before and not link_ok):
                    mismatched.append(record.sequence)
                expected_prev = record.record_hash
                expected_sequence = record.sequence + 1
                last_seen_sequence = record.sequence
                last_seen_hash = record.record_hash
                checked += 1
            if page.next_after_sequence is None:
                break
            cursor = page.next_after_sequence

        head = await self._repository.get_chain_head(tenant_id)
        if head is None:
            # 有記錄卻沒鏈頭 = 鏈頭被刪；完全空的租戶 = 乾淨
            head_mismatch = last_seen_sequence > 0
        else:
            head_mismatch = (
                head.last_sequence != last_seen_sequence or head.last_hash != last_seen_hash
            )

        report = TamperReport(
            tenant_id=tenant_id,
            checked_count=checked,
            mismatched_sequences=tuple(mismatched),
            missing_sequences=tuple(missing),
            head_mismatch=head_mismatch,
        )
        await self._alert_if_tampered(report, layer="record")
        return report

    # ------------------------------------------------------------------
    # 封印層快驗
    # ------------------------------------------------------------------

    async def verify_checkpoint_layer(self, tenant_id: str) -> TamperReport:
        """封印層掃描(報告中的 sequence 欄位語義 = 封印 index，非記錄 sequence)。

        驗證: index 連續、封印指紋重算一致、prev 連結、批範圍接續、
        以及最後一個封印沒有超出鏈頭(封印不可能蓋到不存在的記錄)。

        注意 · 偵測範圍限制(fail-closed 須知): 本快驗只驗「封印鏈自身自洽」，
        以已存的 merkle_root 欄位重算 checkpoint_hash，不從真實記錄重算
        merkle_root。因此抓不到「攻擊者(暫停觸發器)改批內某筆記錄、再同步
        重算該批 merkle_root 與其後整條封印鏈」這種篡改。要抓批內篡改，
        必須跑 verify_batch(單批重算 Merkle 根)或 verify_tenant_chain
        (全鏈逐筆深掃)；例行排程不可只依賴封印層快驗，須週期穿插記錄層深掃。
        """
        checkpoints = await self._repository.list_checkpoints(tenant_id)
        mismatched: list[int] = []
        missing: list[int] = []
        expected_index = 1
        expected_prev = GENESIS_HASH
        expected_start = 1

        for checkpoint in checkpoints:
            if checkpoint.checkpoint_index != expected_index:
                missing.extend(range(expected_index, checkpoint.checkpoint_index))
                # 跳號後 prev 連結必斷，以實際存的 prev 續走(缺漏已記)
                expected_prev = checkpoint.prev_checkpoint_hash
                expected_start = checkpoint.start_sequence
            hash_ok = (
                recompute_checkpoint_hash(checkpoint, signer=self._signer)
                == checkpoint.checkpoint_hash
            )
            link_ok = checkpoint.prev_checkpoint_hash == expected_prev
            range_ok = checkpoint.start_sequence == expected_start
            if not hash_ok or not link_ok or not range_ok:
                mismatched.append(checkpoint.checkpoint_index)
            expected_index = checkpoint.checkpoint_index + 1
            expected_prev = checkpoint.checkpoint_hash
            expected_start = checkpoint.end_sequence + 1

        head = await self._repository.get_chain_head(tenant_id)
        last_sealed = checkpoints[-1].end_sequence if checkpoints else 0
        expected_checkpoint_count = (
            0 if head is None else head.last_sequence // self._repository.checkpoint_batch_size
        )
        missing.extend(range(expected_index, expected_checkpoint_count + 1))
        head_mismatch = (0 if head is None else head.last_sequence) < last_sealed

        report = TamperReport(
            tenant_id=tenant_id,
            checked_count=len(checkpoints),
            mismatched_sequences=tuple(mismatched),
            missing_sequences=tuple(missing),
            head_mismatch=head_mismatch,
        )
        await self._alert_if_tampered(report, layer="checkpoint")
        return report

    # ------------------------------------------------------------------
    # 單批深掃
    # ------------------------------------------------------------------

    async def verify_batch(self, tenant_id: str, checkpoint_index: int) -> bool:
        """重算單一封印批的 Merkle 根與封印比對(警報後的取證 / 抽查用)。"""
        checkpoint = await self._repository.get_checkpoint(tenant_id, checkpoint_index)
        if checkpoint is None:
            raise ValueError(f"封印不存在: tenant={tenant_id} checkpoint_index={checkpoint_index}")
        records = await self._repository.records_in_range(
            tenant_id, checkpoint.start_sequence, checkpoint.end_sequence
        )
        expected_count = checkpoint.end_sequence - checkpoint.start_sequence + 1
        if len(records) != expected_count:
            await self._alert_batch_failure(tenant_id, checkpoint_index, "批內記錄缺漏")
            return False
        recomputed_root = merkle_root([record.record_hash for record in records])
        if recomputed_root != checkpoint.merkle_root:
            await self._alert_batch_failure(tenant_id, checkpoint_index, "Merkle 根不符")
            return False
        return True

    # ------------------------------------------------------------------
    # 警報
    # ------------------------------------------------------------------

    async def _alert_if_tampered(self, report: TamperReport, *, layer: str) -> None:
        if report.is_intact:
            # 正面完整性訊號(最小可觀測性):驗證有跑且通過,供儀表板/巡檢確認(竄改走 critical)。
            logger.debug(
                "稽核鏈驗證通過: layer=%s tenant=%s 已檢查=%d",
                layer,
                report.tenant_id,
                report.checked_count,
            )
            return
        logger.critical(
            "稽核鏈篡改偵測: layer=%s tenant=%s 內容被改=%s 缺漏=%s 鏈頭異常=%s",
            layer,
            report.tenant_id,
            list(report.mismatched_sequences),
            list(report.missing_sequences),
            report.head_mismatch,
        )
        if self._alert_sink is not None:
            await self._alert_sink(report)

    async def _alert_batch_failure(
        self, tenant_id: str, checkpoint_index: int, reason: str
    ) -> None:
        logger.critical(
            "稽核封印批驗證失敗: tenant=%s checkpoint=%d 原因=%s",
            tenant_id,
            checkpoint_index,
            reason,
        )
        if self._alert_sink is not None:
            await self._alert_sink(
                TamperReport(
                    tenant_id=tenant_id,
                    checked_count=1,
                    mismatched_sequences=(checkpoint_index,),
                )
            )
