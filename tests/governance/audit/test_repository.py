"""S05 · AuditLogRepository 單元測試(SQLite in-memory)。

重點: 鏈式串接、封印自動觸發、keyset 分頁、租戶隔離、損毀偵測路徑。
PostgreSQL 特有行為(FOR UPDATE 行鎖、觸發器、低權帳號)由整合測試守住。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from itertools import pairwise
from typing import Any
from unittest.mock import patch

import pytest
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession
from src.governance.audit.chain import recompute_hash
from src.governance.audit.errors import ChainCorruptionError
from src.governance.audit.merkle import merkle_root, recompute_checkpoint_hash
from src.governance.audit.models import AuditRecordRow, MerkleCheckpointRow
from src.governance.audit.repository import AuditLogRepository
from src.governance.audit.types import GENESIS_HASH, AuditOutcome, AuditQuery
from src.governance.rbac.roles import Role

from tests.governance.audit.conftest import FIXED_NOW, fixed_clock, make_input

pytestmark = pytest.mark.asyncio


@pytest.fixture
def repo(session: AsyncSession) -> AuditLogRepository:
    """預設批次 3(小批次讓封印測試不用寫千筆)。"""
    return AuditLogRepository(session, clock=fixed_clock, checkpoint_batch_size=3)


def _inputs(n: int, **overrides: Any) -> list[Any]:
    return [make_input(action=f"order.submit.{i}", **overrides) for i in range(n)]


# ============================================================================
# append: 創世、串鏈、鏈頭推進
# ============================================================================


async def test_first_append_starts_from_genesis(repo: AuditLogRepository) -> None:
    record = await repo.append(make_input())
    assert record.sequence == 1
    assert record.prev_hash == GENESIS_HASH
    assert recompute_hash(record) == record.record_hash
    assert record.timestamp == FIXED_NOW

    head = await repo.get_chain_head("tenant-a")
    assert head is not None
    assert head.last_sequence == 1
    assert head.last_hash == record.record_hash


async def test_second_append_links_to_first(repo: AuditLogRepository) -> None:
    first = await repo.append(make_input())
    second = await repo.append(make_input(action="order.cancel"))
    assert second.sequence == 2
    assert second.prev_hash == first.record_hash
    assert recompute_hash(second) == second.record_hash


async def test_append_round_trip_via_query(repo: AuditLogRepository) -> None:
    written = await repo.append(make_input(role=Role.AGENT, risk_score=55))
    page = await repo.query(AuditQuery(tenant_id="tenant-a"))
    assert page.records == (written,)
    assert page.next_after_sequence is None


async def test_chains_are_independent_per_tenant(repo: AuditLogRepository) -> None:
    record_a = await repo.append(make_input(tenant_id="tenant-a"))
    record_b = await repo.append(make_input(tenant_id="tenant-b"))
    # 兩個租戶都從各自的創世開始，互不影響
    assert record_a.sequence == 1
    assert record_b.sequence == 1
    assert record_b.prev_hash == GENESIS_HASH

    head_a = await repo.get_chain_head("tenant-a")
    head_b = await repo.get_chain_head("tenant-b")
    assert head_a is not None
    assert head_b is not None
    assert head_a.last_hash == record_a.record_hash
    assert head_b.last_hash == record_b.record_hash


async def test_get_chain_head_unknown_tenant_returns_none(repo: AuditLogRepository) -> None:
    assert await repo.get_chain_head("nobody") is None


# ============================================================================
# append_many: 批次寫入
# ============================================================================


async def test_append_many_empty_returns_empty(repo: AuditLogRepository) -> None:
    assert await repo.append_many([]) == []


async def test_append_many_rejects_mixed_tenants(repo: AuditLogRepository) -> None:
    with pytest.raises(ValueError, match="一批只能屬於同一個租戶"):
        await repo.append_many([make_input(tenant_id="a"), make_input(tenant_id="b")])


async def test_append_many_sequences_contiguous_and_linked(repo: AuditLogRepository) -> None:
    records = await repo.append_many(_inputs(5))
    assert [r.sequence for r in records] == [1, 2, 3, 4, 5]
    assert records[0].prev_hash == GENESIS_HASH
    for prev, current in pairwise(records):
        assert current.prev_hash == prev.record_hash
        assert recompute_hash(current) == current.record_hash

    head = await repo.get_chain_head("tenant-a")
    assert head is not None
    assert head.last_sequence == 5
    assert head.last_hash == records[-1].record_hash


async def test_append_many_continues_existing_chain(repo: AuditLogRepository) -> None:
    first = await repo.append(make_input())
    more = await repo.append_many(_inputs(2))
    assert [r.sequence for r in more] == [2, 3]
    assert more[0].prev_hash == first.record_hash


# ============================================================================
# 封印自動觸發(批次 3)
# ============================================================================


async def test_no_checkpoint_before_crossing_batch(repo: AuditLogRepository) -> None:
    await repo.append_many(_inputs(2))
    assert await repo.list_checkpoints("tenant-a") == []


async def test_checkpoint_sealed_on_exact_boundary(repo: AuditLogRepository) -> None:
    records = await repo.append_many(_inputs(3))
    checkpoints = await repo.list_checkpoints("tenant-a")
    assert len(checkpoints) == 1
    sealed = checkpoints[0]
    assert sealed.checkpoint_index == 1
    assert sealed.start_sequence == 1
    assert sealed.end_sequence == 3
    assert sealed.merkle_root == merkle_root([r.record_hash for r in records])
    assert sealed.prev_checkpoint_hash == GENESIS_HASH
    assert recompute_checkpoint_hash(sealed) == sealed.checkpoint_hash


async def test_one_call_can_seal_multiple_checkpoints(repo: AuditLogRepository) -> None:
    records = await repo.append_many(_inputs(7))
    checkpoints = await repo.list_checkpoints("tenant-a")
    assert [c.checkpoint_index for c in checkpoints] == [1, 2]
    # 封印之間串鏈
    assert checkpoints[1].prev_checkpoint_hash == checkpoints[0].checkpoint_hash
    assert checkpoints[1].merkle_root == merkle_root([r.record_hash for r in records[3:6]])
    # 第 7 筆還沒滿批，不封


async def test_checkpoint_sealed_across_separate_appends(repo: AuditLogRepository) -> None:
    await repo.append_many(_inputs(2))
    await repo.append_many(_inputs(2))  # 跨過 3 的倍數
    checkpoints = await repo.list_checkpoints("tenant-a")
    assert len(checkpoints) == 1
    assert checkpoints[0].end_sequence == 3


async def test_checkpoints_are_tenant_isolated(repo: AuditLogRepository) -> None:
    await repo.append_many(_inputs(3, tenant_id="tenant-a"))
    assert await repo.list_checkpoints("tenant-b") == []


# ============================================================================
# 封印損毀偵測(append-only 防線被繞過時的內部斷言)
# ============================================================================


async def test_seal_with_missing_records_raises(
    repo: AuditLogRepository, session: AsyncSession
) -> None:
    await repo.append_many(_inputs(2))
    # 模擬繞過防線直刪一筆(SQLite 單元環境沒有觸發器，正好用來測內部斷言)
    await session.execute(delete(AuditRecordRow).where(AuditRecordRow.sequence == 1))
    with pytest.raises(ChainCorruptionError) as e:
        await repo.append(make_input())
    assert str(e.value) == "封印批記錄數不符: tenant=tenant-a index=1 預期 3 實際 2"


async def test_seal_with_missing_prev_checkpoint_raises(
    repo: AuditLogRepository, session: AsyncSession
) -> None:
    await repo.append_many(_inputs(3))  # 封印 1 蓋好
    await session.execute(delete(MerkleCheckpointRow))  # 偷刪封印 1
    with pytest.raises(ChainCorruptionError) as e:
        await repo.append_many(_inputs(3))  # 蓋封印 2 時找不到前手
    assert str(e.value) == "前一個封印不存在: tenant=tenant-a index=1"


# ============================================================================
# 鏈頭並行創世(SAVEPOINT 補救路徑，用 mock 模擬競態)
# ============================================================================


async def test_lock_head_race_falls_back_to_existing_row(
    session: AsyncSession,
) -> None:
    repo = AuditLogRepository(session, clock=fixed_clock, checkpoint_batch_size=3)
    await repo.append(make_input())  # 鏈頭已存在

    real_scalar = session.scalar
    call_count = 0

    async def racy_scalar(stmt: Any, *args: Any, **kwargs: Any) -> Any:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return None  # 模擬: 第一次查鏈頭時對方還沒 commit
        return await real_scalar(stmt, *args, **kwargs)

    with patch.object(session, "scalar", side_effect=racy_scalar):
        record = await repo.append(make_input())
    # 撞鍵後改鎖既有列，鏈繼續長而不是分叉
    assert record.sequence == 2


async def test_lock_head_unreachable_raises_corruption(session: AsyncSession) -> None:
    repo = AuditLogRepository(session, clock=fixed_clock)

    async def always_none(*args: Any, **kwargs: Any) -> None:
        return None

    with (
        patch.object(session, "scalar", side_effect=always_none),
        pytest.raises(ChainCorruptionError) as e,
    ):
        await repo.append(make_input())
    assert str(e.value) == "鏈頭建立後仍讀不到: tenant=tenant-a"


# ============================================================================
# query: 過濾條件
# ============================================================================


async def _seed_for_query(repo: AuditLogRepository) -> None:
    await repo.append(make_input(user_id="alice", action="order.submit"))
    await repo.append(
        make_input(user_id="bob", action="order.cancel", response_status=AuditOutcome.FAILED)
    )
    await repo.append(make_input(user_id="alice", action="role.assign", resource="role/admin"))
    await repo.append(make_input(tenant_id="tenant-b", user_id="alice"))


async def test_query_filter_by_user(repo: AuditLogRepository) -> None:
    await _seed_for_query(repo)
    page = await repo.query(AuditQuery(tenant_id="tenant-a", user_id="alice"))
    assert [r.sequence for r in page.records] == [1, 3]


async def test_query_filter_by_action(repo: AuditLogRepository) -> None:
    await _seed_for_query(repo)
    page = await repo.query(AuditQuery(tenant_id="tenant-a", action="order.cancel"))
    assert [r.user_id for r in page.records] == ["bob"]


async def test_query_filter_by_resource(repo: AuditLogRepository) -> None:
    await _seed_for_query(repo)
    page = await repo.query(AuditQuery(tenant_id="tenant-a", resource="role/admin"))
    assert [r.action for r in page.records] == ["role.assign"]


async def test_query_filter_by_status(repo: AuditLogRepository) -> None:
    await _seed_for_query(repo)
    page = await repo.query(AuditQuery(tenant_id="tenant-a", response_status=AuditOutcome.FAILED))
    assert [r.user_id for r in page.records] == ["bob"]


async def test_query_is_tenant_isolated(repo: AuditLogRepository) -> None:
    await _seed_for_query(repo)
    page = await repo.query(AuditQuery(tenant_id="tenant-b"))
    assert len(page.records) == 1
    assert page.records[0].tenant_id == "tenant-b"


async def test_query_combined_filters(repo: AuditLogRepository) -> None:
    await _seed_for_query(repo)
    page = await repo.query(
        AuditQuery(tenant_id="tenant-a", user_id="alice", action="order.submit")
    )
    assert [r.sequence for r in page.records] == [1]


async def test_query_empty_result(repo: AuditLogRepository) -> None:
    page = await repo.query(AuditQuery(tenant_id="tenant-a", user_id="ghost"))
    assert page.records == ()
    assert page.next_after_sequence is None


# ============================================================================
# query: 時間範圍(含邊界)
# ============================================================================


async def test_query_time_range_boundaries_inclusive(session: AsyncSession) -> None:
    moments = [FIXED_NOW + timedelta(minutes=i) for i in range(3)]
    ticking = iter(moments)
    repo = AuditLogRepository(session, clock=lambda: next(ticking), checkpoint_batch_size=1000)
    await repo.append_many(_inputs(3))

    page = await repo.query(
        AuditQuery(tenant_id="tenant-a", start_time=moments[0], end_time=moments[1])
    )
    assert [r.sequence for r in page.records] == [1, 2]  # 兩端皆含

    page = await repo.query(AuditQuery(tenant_id="tenant-a", start_time=moments[2]))
    assert [r.sequence for r in page.records] == [3]


# ============================================================================
# query: keyset 分頁
# ============================================================================


async def test_query_keyset_pagination_no_overlap_no_gap(repo: AuditLogRepository) -> None:
    await repo.append_many(_inputs(5))
    collected: list[int] = []
    cursor = 0
    pages = 0
    while True:
        page = await repo.query(AuditQuery(tenant_id="tenant-a", after_sequence=cursor, limit=2))
        collected.extend(r.sequence for r in page.records)
        pages += 1
        if page.next_after_sequence is None:
            break
        cursor = page.next_after_sequence
    assert collected == [1, 2, 3, 4, 5]  # 不重不漏
    assert pages == 3


async def test_query_exact_limit_last_page_has_no_cursor(repo: AuditLogRepository) -> None:
    await repo.append_many(_inputs(4))
    page = await repo.query(AuditQuery(tenant_id="tenant-a", after_sequence=2, limit=2))
    assert [r.sequence for r in page.records] == [3, 4]
    assert page.next_after_sequence is None  # 剛好撈完，沒有下一頁


# ============================================================================
# records_in_range / 其他
# ============================================================================


async def test_records_in_range_ordered_and_bounded(repo: AuditLogRepository) -> None:
    await repo.append_many(_inputs(5))
    records = await repo.records_in_range("tenant-a", 2, 4)
    assert [r.sequence for r in records] == [2, 3, 4]


async def test_records_in_range_tenant_isolated(repo: AuditLogRepository) -> None:
    await repo.append_many(_inputs(3))
    assert await repo.records_in_range("tenant-b", 1, 3) == []


@pytest.mark.parametrize("bad_size", [0, -1])
async def test_invalid_checkpoint_batch_size_rejected(session: AsyncSession, bad_size: int) -> None:
    with pytest.raises(ValueError, match="checkpoint_batch_size 必須 >= 1"):
        AuditLogRepository(session, checkpoint_batch_size=bad_size)


async def test_default_clock_produces_aware_utc(session: AsyncSession) -> None:
    repo = AuditLogRepository(session)  # 不注入 clock，走真時鐘路徑
    record = await repo.append(make_input())
    assert record.timestamp.tzinfo is not None
    assert abs((datetime.now(UTC) - record.timestamp).total_seconds()) < 60
