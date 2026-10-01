"""S05 · ChainVerifier 測試。

篡改手法用 SQLite 直改(單元環境沒有觸發器，正好模擬「防線被繞過」的世界)，
驗證器必須在這種最壞情況下仍抓得到。警報訊息文字完全相等釘住(S02 教訓)。
"""

from __future__ import annotations

import logging

import pytest
from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession
from src.governance.audit.models import AuditRecordRow, ChainHeadRow, MerkleCheckpointRow
from src.governance.audit.repository import AuditLogRepository
from src.governance.audit.types import TamperReport
from src.governance.audit.verifier import ChainVerifier

from tests.governance.audit.conftest import fixed_clock, make_input

pytestmark = pytest.mark.asyncio

TENANT = "tenant-a"


@pytest.fixture
def repo(session: AsyncSession) -> AuditLogRepository:
    return AuditLogRepository(session, clock=fixed_clock, checkpoint_batch_size=3)


@pytest.fixture
def verifier(repo: AuditLogRepository) -> ChainVerifier:
    return ChainVerifier(repo, page_size=2)  # 小頁強迫走多頁路徑


async def _seed(repo: AuditLogRepository, n: int) -> None:
    await repo.append_many([make_input(action=f"order.submit.{i}") for i in range(n)])


# ============================================================================
# 記錄層深掃: 完好鏈
# ============================================================================


async def test_intact_chain_passes_multi_page(
    repo: AuditLogRepository, verifier: ChainVerifier
) -> None:
    await _seed(repo, 5)
    report = await verifier.verify_tenant_chain(TENANT)
    assert report.is_intact
    assert report.checked_count == 5


async def test_empty_tenant_is_intact(verifier: ChainVerifier) -> None:
    report = await verifier.verify_tenant_chain("nobody")
    assert report.is_intact
    assert report.checked_count == 0


# ============================================================================
# 記錄層深掃: 三種篡改
# ============================================================================


async def test_content_tamper_detected(
    repo: AuditLogRepository, verifier: ChainVerifier, session: AsyncSession
) -> None:
    await _seed(repo, 3)
    await session.execute(
        update(AuditRecordRow).where(AuditRecordRow.sequence == 2).values(action="order.evil")
    )
    report = await verifier.verify_tenant_chain(TENANT)
    assert report.mismatched_sequences == (2,)
    assert report.missing_sequences == ()
    assert not report.head_mismatch


async def test_deleted_record_detected_as_gap(
    repo: AuditLogRepository, verifier: ChainVerifier, session: AsyncSession
) -> None:
    await _seed(repo, 3)
    await session.execute(delete(AuditRecordRow).where(AuditRecordRow.sequence == 2))
    report = await verifier.verify_tenant_chain(TENANT)
    assert report.missing_sequences == (2,)
    assert report.mismatched_sequences == ()  # 跳號不重複算成內容篡改


async def test_rehashed_tamper_caught_by_link_break(
    repo: AuditLogRepository, verifier: ChainVerifier, session: AsyncSession
) -> None:
    # 進階攻擊: 改內容並把該筆指紋也重算到自洽 → 下一筆的 prev 連結會斷
    await _seed(repo, 3)
    records = await repo.records_in_range(TENANT, 2, 2)
    tampered = records[0]
    from dataclasses import replace

    from src.governance.audit.chain import recompute_hash

    consistent = replace(tampered, action="order.evil")
    await session.execute(
        update(AuditRecordRow)
        .where(AuditRecordRow.sequence == 2)
        .values(action="order.evil", record_hash=recompute_hash(consistent))
    )
    report = await verifier.verify_tenant_chain(TENANT)
    assert report.mismatched_sequences == (3,)  # 斷鏈在第 3 筆的連結上現形


async def test_tail_tamper_caught_by_head_check(
    repo: AuditLogRepository, verifier: ChainVerifier, session: AsyncSession
) -> None:
    # 改最後一筆(沒有下一筆的連結可斷)→ 鏈頭比對抓到
    await _seed(repo, 2)
    records = await repo.records_in_range(TENANT, 2, 2)
    from dataclasses import replace

    from src.governance.audit.chain import recompute_hash

    consistent = replace(records[0], action="order.evil")
    await session.execute(
        update(AuditRecordRow)
        .where(AuditRecordRow.sequence == 2)
        .values(action="order.evil", record_hash=recompute_hash(consistent))
    )
    report = await verifier.verify_tenant_chain(TENANT)
    assert report.head_mismatch


async def test_head_tamper_detected(
    repo: AuditLogRepository, verifier: ChainVerifier, session: AsyncSession
) -> None:
    await _seed(repo, 2)
    await session.execute(update(ChainHeadRow).values(last_hash="f" * 64))
    report = await verifier.verify_tenant_chain(TENANT)
    assert report.head_mismatch


async def test_deleted_head_detected(
    repo: AuditLogRepository, verifier: ChainVerifier, session: AsyncSession
) -> None:
    await _seed(repo, 2)
    await session.execute(delete(ChainHeadRow))
    report = await verifier.verify_tenant_chain(TENANT)
    assert report.head_mismatch


# ============================================================================
# 記錄層深掃: 已知盲點(釘住現況)
# ============================================================================


async def test_tail_truncation_with_head_rollback_not_detected(session: AsyncSession) -> None:
    """釘住已知盲點(T008): 砍尾端記錄 + 同步回捲鏈頭 → verify_tenant_chain 抓不到。

    攻擊者(有 DB 寫權)刪掉最後幾筆、再把鏈頭回捲到截斷點，前段鏈與鏈頭自洽，
    深掃看不出少了東西——雜湊鏈無法自證「原本應該有幾筆」，根治需 DB 外部的單調
    高水位錨點(見 verifier.verify_tenant_chain docstring 與 BACKLOG B-006)。
    此測試故意斷言 is_intact==True，把現況釘死: 行為若改變(真的補上錨點)此測試會紅，
    逼迫同步更新揭露文件，避免盲點被默默當成「已防護」。
    """
    repo = AuditLogRepository(session, clock=fixed_clock, checkpoint_batch_size=100)  # 不觸發封印
    await repo.append_many([make_input(action=f"order.submit.{i}") for i in range(5)])
    survivor = (await repo.records_in_range(TENANT, 3, 3))[0]
    # 模擬截斷攻擊: 刪掉 sequence>3 的記錄、鏈頭回捲到 3(與截斷後尾端自洽)
    await session.execute(delete(AuditRecordRow).where(AuditRecordRow.sequence > 3))
    await session.execute(
        update(ChainHeadRow).values(last_sequence=3, last_hash=survivor.record_hash)
    )
    report = await ChainVerifier(repo).verify_tenant_chain(TENANT)
    assert report.is_intact  # ← 盲點: 截斷未被偵測(釘住現況，非「通過」是「抓不到」)
    assert report.checked_count == 3  # 只剩 3 筆，看起來「完整」


# ============================================================================
# 增量驗證
# ============================================================================


async def test_incremental_verifies_only_after_anchor(
    repo: AuditLogRepository, verifier: ChainVerifier, session: AsyncSession
) -> None:
    await _seed(repo, 4)
    await session.execute(
        update(AuditRecordRow).where(AuditRecordRow.sequence == 3).values(action="order.evil")
    )
    report = await verifier.verify_tenant_chain(TENANT, from_sequence=2)
    assert report.checked_count == 2  # 只驗 3、4
    assert report.mismatched_sequences == (3,)


async def test_incremental_consistent_with_full_scan(
    repo: AuditLogRepository, verifier: ChainVerifier
) -> None:
    await _seed(repo, 5)
    full = await verifier.verify_tenant_chain(TENANT)
    incremental = await verifier.verify_tenant_chain(TENANT, from_sequence=3)
    assert full.is_intact and incremental.is_intact
    assert incremental.checked_count == 2


async def test_incremental_missing_anchor_raises(verifier: ChainVerifier) -> None:
    with pytest.raises(ValueError, match="增量驗證起點不存在"):
        await verifier.verify_tenant_chain(TENANT, from_sequence=99)


async def test_negative_from_sequence_raises(verifier: ChainVerifier) -> None:
    with pytest.raises(ValueError, match="from_sequence 必須 >= 0"):
        await verifier.verify_tenant_chain(TENANT, from_sequence=-1)


# ============================================================================
# 警報: CRITICAL 日誌(文字釘住) + alert_sink 回呼
# ============================================================================


async def test_alert_emitted_on_tamper(
    repo: AuditLogRepository,
    session: AsyncSession,
    caplog: pytest.LogCaptureFixture,
) -> None:
    alerts: list[TamperReport] = []

    async def sink(report: TamperReport) -> None:
        alerts.append(report)

    verifier = ChainVerifier(repo, alert_sink=sink)
    await _seed(repo, 3)
    await session.execute(
        update(AuditRecordRow).where(AuditRecordRow.sequence == 2).values(action="order.evil")
    )
    with caplog.at_level(logging.CRITICAL, logger="src.governance.audit.verifier"):
        report = await verifier.verify_tenant_chain(TENANT)

    assert len(alerts) == 1
    assert alerts[0] == report
    assert caplog.records[0].levelname == "CRITICAL"
    assert caplog.records[0].getMessage() == (
        "稽核鏈篡改偵測: layer=record tenant=tenant-a 內容被改=[2] 缺漏=[] 鏈頭異常=False"
    )


async def test_no_alert_when_intact(
    repo: AuditLogRepository, caplog: pytest.LogCaptureFixture
) -> None:
    alerts: list[TamperReport] = []

    async def sink(report: TamperReport) -> None:
        alerts.append(report)

    verifier = ChainVerifier(repo, alert_sink=sink)
    await _seed(repo, 3)
    with caplog.at_level(logging.CRITICAL, logger="src.governance.audit.verifier"):
        await verifier.verify_tenant_chain(TENANT)
    assert alerts == []
    assert caplog.records == []


async def test_alert_without_sink_only_logs(
    repo: AuditLogRepository,
    verifier: ChainVerifier,
    session: AsyncSession,
    caplog: pytest.LogCaptureFixture,
) -> None:
    await _seed(repo, 2)
    await session.execute(delete(ChainHeadRow))
    with caplog.at_level(logging.CRITICAL, logger="src.governance.audit.verifier"):
        report = await verifier.verify_tenant_chain(TENANT)
    assert not report.is_intact
    assert len(caplog.records) == 1  # 沒注入 sink 也不會炸，警報日誌仍在


# ============================================================================
# 封印層快驗
# ============================================================================


async def test_checkpoint_layer_intact(repo: AuditLogRepository, verifier: ChainVerifier) -> None:
    await _seed(repo, 7)  # 批次 3 → 封印 1、2
    report = await verifier.verify_checkpoint_layer(TENANT)
    assert report.is_intact
    assert report.checked_count == 2


async def test_checkpoint_layer_empty_is_intact(verifier: ChainVerifier) -> None:
    report = await verifier.verify_checkpoint_layer("nobody")
    assert report.is_intact
    assert report.checked_count == 0


async def test_checkpoint_root_tamper_detected(
    repo: AuditLogRepository, verifier: ChainVerifier, session: AsyncSession
) -> None:
    await _seed(repo, 6)
    await session.execute(
        update(MerkleCheckpointRow)
        .where(MerkleCheckpointRow.checkpoint_index == 1)
        .values(merkle_root="e" * 64)
    )
    report = await verifier.verify_checkpoint_layer(TENANT)
    assert 1 in report.mismatched_sequences


async def test_checkpoint_deleted_detected_as_missing(
    repo: AuditLogRepository, verifier: ChainVerifier, session: AsyncSession
) -> None:
    await _seed(repo, 6)
    await session.execute(
        delete(MerkleCheckpointRow).where(MerkleCheckpointRow.checkpoint_index == 1)
    )
    report = await verifier.verify_checkpoint_layer(TENANT)
    assert report.missing_sequences == (1,)


async def test_last_checkpoint_deleted_detected_as_missing(
    repo: AuditLogRepository, verifier: ChainVerifier, session: AsyncSession
) -> None:
    await _seed(repo, 6)
    await session.execute(
        delete(MerkleCheckpointRow).where(MerkleCheckpointRow.checkpoint_index == 2)
    )
    report = await verifier.verify_checkpoint_layer(TENANT)
    assert report.missing_sequences == (2,)


async def test_checkpoint_beyond_head_detected(
    repo: AuditLogRepository, verifier: ChainVerifier, session: AsyncSession
) -> None:
    # 鏈頭被回捲到封印涵蓋範圍之前 = 異常(封印不可能蓋到不存在的記錄)
    await _seed(repo, 3)
    await session.execute(update(ChainHeadRow).values(last_sequence=2))
    report = await verifier.verify_checkpoint_layer(TENANT)
    assert report.head_mismatch


async def test_checkpoint_layer_alert_message_pinned(
    repo: AuditLogRepository,
    verifier: ChainVerifier,
    session: AsyncSession,
    caplog: pytest.LogCaptureFixture,
) -> None:
    await _seed(repo, 3)
    await session.execute(update(MerkleCheckpointRow).values(merkle_root="e" * 64))
    with caplog.at_level(logging.CRITICAL, logger="src.governance.audit.verifier"):
        await verifier.verify_checkpoint_layer(TENANT)
    assert caplog.records[0].getMessage() == (
        "稽核鏈篡改偵測: layer=checkpoint tenant=tenant-a 內容被改=[1] 缺漏=[] 鏈頭異常=False"
    )


# ============================================================================
# 單批深掃
# ============================================================================


async def test_verify_batch_passes_for_intact_batch(
    repo: AuditLogRepository, verifier: ChainVerifier
) -> None:
    await _seed(repo, 3)
    assert await verifier.verify_batch(TENANT, 1) is True


async def test_verify_batch_detects_root_mismatch(
    repo: AuditLogRepository,
    verifier: ChainVerifier,
    session: AsyncSession,
    caplog: pytest.LogCaptureFixture,
) -> None:
    await _seed(repo, 3)
    await session.execute(
        update(AuditRecordRow).where(AuditRecordRow.sequence == 2).values(record_hash="e" * 64)
    )
    with caplog.at_level(logging.CRITICAL, logger="src.governance.audit.verifier"):
        assert await verifier.verify_batch(TENANT, 1) is False
    assert caplog.records[0].getMessage() == (
        "稽核封印批驗證失敗: tenant=tenant-a checkpoint=1 原因=Merkle 根不符"
    )


async def test_verify_batch_detects_missing_records(
    repo: AuditLogRepository,
    verifier: ChainVerifier,
    session: AsyncSession,
    caplog: pytest.LogCaptureFixture,
) -> None:
    await _seed(repo, 3)
    await session.execute(delete(AuditRecordRow).where(AuditRecordRow.sequence == 2))
    with caplog.at_level(logging.CRITICAL, logger="src.governance.audit.verifier"):
        assert await verifier.verify_batch(TENANT, 1) is False
    assert caplog.records[0].getMessage() == (
        "稽核封印批驗證失敗: tenant=tenant-a checkpoint=1 原因=批內記錄缺漏"
    )


async def test_verify_batch_sink_receives_failure(
    repo: AuditLogRepository, session: AsyncSession
) -> None:
    alerts: list[TamperReport] = []

    async def sink(report: TamperReport) -> None:
        alerts.append(report)

    verifier = ChainVerifier(repo, alert_sink=sink)
    await _seed(repo, 3)
    await session.execute(delete(AuditRecordRow).where(AuditRecordRow.sequence == 2))
    await verifier.verify_batch(TENANT, 1)
    assert len(alerts) == 1
    assert alerts[0].mismatched_sequences == (1,)
    assert alerts[0].checked_count == 1  # 批驗失敗報告固定 checked_count=1


async def test_verify_batch_unknown_checkpoint_raises(verifier: ChainVerifier) -> None:
    with pytest.raises(ValueError, match="封印不存在"):
        await verifier.verify_batch(TENANT, 9)


# ============================================================================
# 建構參數
# ============================================================================


@pytest.mark.parametrize("bad_size", [0, -1, 1001])
async def test_invalid_page_size_rejected(repo: AuditLogRepository, bad_size: int) -> None:
    with pytest.raises(ValueError, match="page_size 必須在 1-1000 之間"):
        ChainVerifier(repo, page_size=bad_size)
