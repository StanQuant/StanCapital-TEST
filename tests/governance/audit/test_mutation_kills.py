"""S05 · Mutation 殺手測試集中營。

mutation testing 找出的「測試太鬆」缺口，在此用更嚴格的斷言釘死:
- 錯誤訊息: 完全相等(子字串 match 殺不掉前後加 XX 的字串 mutant，S02 教訓)
- 邊界值: 剛好合法 / 剛好不合法各測一次(殺 < vs <= 之類的比較 mutant)
- 預設值 / frozen: 對外契約，逐一釘住(殺預設值加料 / frozen=False mutant)
- 關鍵邏輯: 用能區分 mutant 的精準場景(殺 +1/-1、>/>= 之類)
"""

from __future__ import annotations

import dataclasses

import pytest
from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession
from src.governance.audit.chain import recompute_hash
from src.governance.audit.decorator import AuditContext
from src.governance.audit.errors import AuditUnavailableError
from src.governance.audit.models import AuditRecordRow, ChainHeadRow
from src.governance.audit.repository import AuditLogRepository
from src.governance.audit.types import AuditQuery
from src.governance.audit.verifier import ChainVerifier
from src.governance.rbac.roles import Role

from tests.governance.audit.conftest import fixed_clock, make_input

pytestmark = pytest.mark.asyncio

TENANT = "tenant-a"


def _repo(session: AsyncSession, batch: int = 3) -> AuditLogRepository:
    return AuditLogRepository(session, clock=fixed_clock, checkpoint_batch_size=batch)


async def _seed(repo: AuditLogRepository, n: int) -> None:
    await repo.append_many([make_input(action=f"op.{i}") for i in range(n)])


# ============================================================================
# 區 1 · 錯誤訊息完全相等(殺字串前後加料 mutant)
# ============================================================================


async def test_msg_checkpoint_batch_size(session: AsyncSession) -> None:
    with pytest.raises(ValueError) as e:
        AuditLogRepository(session, checkpoint_batch_size=0)
    assert str(e.value) == "checkpoint_batch_size 必須 >= 1: 0"


async def test_msg_append_many_mixed_tenant(session: AsyncSession) -> None:
    with pytest.raises(ValueError) as e:
        await _repo(session).append_many([make_input(tenant_id="a"), make_input(tenant_id="b")])
    assert str(e.value) == "append_many 一批只能屬於同一個租戶(鏈是逐租戶的)"


async def test_msg_page_size(session: AsyncSession) -> None:
    with pytest.raises(ValueError) as e:
        ChainVerifier(_repo(session), page_size=0)
    assert str(e.value) == "page_size 必須在 1-1000 之間: 0"


async def test_msg_from_sequence_negative(session: AsyncSession) -> None:
    with pytest.raises(ValueError) as e:
        await ChainVerifier(_repo(session)).verify_tenant_chain(TENANT, from_sequence=-1)
    assert str(e.value) == "from_sequence 必須 >= 0: -1"


async def test_msg_incremental_anchor_missing(session: AsyncSession) -> None:
    with pytest.raises(ValueError) as e:
        await ChainVerifier(_repo(session)).verify_tenant_chain(TENANT, from_sequence=99)
    assert str(e.value) == "增量驗證起點不存在: tenant=tenant-a sequence=99"


async def test_msg_verify_batch_unknown(session: AsyncSession) -> None:
    with pytest.raises(ValueError) as e:
        await ChainVerifier(_repo(session)).verify_batch(TENANT, 9)
    assert str(e.value) == "封印不存在: tenant=tenant-a checkpoint_index=9"


async def test_msg_missing_audit_ctx(session: AsyncSession) -> None:
    from src.governance.audit.decorator import audited

    class Svc:
        def __init__(self, s: AsyncSession) -> None:
            self.audit_repo = AuditLogRepository(s)
            self.audit_session_factory = None  # type: ignore[assignment]

        @audited(action="x.y", resource="r")
        async def op(self, *, audit_ctx: AuditContext | None = None) -> None: ...

    with pytest.raises(AuditUnavailableError) as e:
        await Svc(session).op()
    assert str(e.value) == (
        "稽核寫入失敗，操作已中止(fail-closed): tenant=unknown action=x.y reason=缺少 audit_ctx 關鍵字參數"
    )


# ============================================================================
# 區 2 · 邊界值(殺 < vs <= / 1-1000 邊界 mutant)
# ============================================================================


async def test_batch_size_one_is_legal(session: AsyncSession) -> None:
    # batch=1 合法(殺 `< 1` → `<= 1`): 每筆都封印
    repo = AuditLogRepository(session, clock=fixed_clock, checkpoint_batch_size=1)
    await repo.append(make_input())
    assert len(await repo.list_checkpoints(TENANT)) == 1


@pytest.mark.parametrize("page_size", [1, 1000])
async def test_page_size_boundaries_legal(session: AsyncSession, page_size: int) -> None:
    # 1 與 1000 合法(殺 `1 <= x <= 1000` 的邊界 mutant)
    v = ChainVerifier(_repo(session), page_size=page_size)
    report = await v.verify_tenant_chain(TENANT)
    assert report.is_intact


async def test_page_size_1001_rejected(session: AsyncSession) -> None:
    with pytest.raises(ValueError):
        ChainVerifier(_repo(session), page_size=1001)


# ============================================================================
# 區 3 · AuditContext 預設值 + frozen(殺預設加料 / frozen=False mutant)
# ============================================================================


async def test_audit_context_defaults() -> None:
    ctx = AuditContext(tenant_id="t", user_id="u", role=Role.USER)
    assert ctx.ip_address == "internal"
    assert ctx.user_agent == "internal"
    assert ctx.risk_score == 0


async def test_audit_context_frozen() -> None:
    ctx = AuditContext(tenant_id="t", user_id="u", role=Role.USER)
    with pytest.raises(dataclasses.FrozenInstanceError):
        ctx.tenant_id = "other"  # type: ignore[misc]
    assert not hasattr(ctx, "__dict__")  # slots=True


# ============================================================================
# 區 4 · 關鍵邏輯殺手
# ============================================================================


async def test_keyset_has_more_exact(session: AsyncSession) -> None:
    # 殺 limit+1 / records[-1] 的 off-by-one: 剛好滿頁時不該有下一頁游標
    repo = _repo(session, batch=1000)
    await _seed(repo, 4)
    page = await repo.query(AuditQuery(tenant_id=TENANT, limit=2))
    assert [r.sequence for r in page.records] == [1, 2]
    assert page.next_after_sequence == 2  # 還有下一頁，游標=最後一筆 sequence
    last = await repo.query(AuditQuery(tenant_id=TENANT, after_sequence=2, limit=2))
    assert [r.sequence for r in last.records] == [3, 4]
    assert last.next_after_sequence is None  # 剛好撈完


async def test_deleted_head_with_single_record(session: AsyncSession) -> None:
    # 殺 head_mismatch 的 `> 0` → `> 1`: 用 last_seen=1 場景區分
    repo = _repo(session, batch=1000)
    await _seed(repo, 1)
    await session.execute(delete(ChainHeadRow))
    report = await ChainVerifier(repo).verify_tenant_chain(TENANT)
    assert report.head_mismatch is True


async def test_checkpoint_head_below_sealed_detected(session: AsyncSession) -> None:
    # 殺封印層 head_mismatch 的 `<` 比較: 鏈頭被回捲到封印範圍之前
    repo = _repo(session, batch=3)
    await _seed(repo, 3)
    await session.execute(update(ChainHeadRow).values(last_sequence=2))
    report = await ChainVerifier(repo).verify_checkpoint_layer(TENANT)
    assert report.head_mismatch is True


async def test_checkpoint_link_break_after_gap(session: AsyncSession) -> None:
    # 殺封印層跳號後 expected_start/prev 續走邏輯
    repo = _repo(session, batch=3)
    await _seed(repo, 9)  # 封印 1,2,3
    from src.governance.audit.models import MerkleCheckpointRow

    await session.execute(
        delete(MerkleCheckpointRow).where(MerkleCheckpointRow.checkpoint_index == 2)
    )
    report = await ChainVerifier(repo).verify_checkpoint_layer(TENANT)
    assert report.missing_sequences == (2,)
    # 殺 L141/142 expected_prev/start=None: 跳號只記缺漏，不該誤報內容篡改
    assert report.mismatched_sequences == ()


async def test_keyset_cursor_is_last_of_page(session: AsyncSession) -> None:
    # 殺 L251 records[-1] → records[+1]: 用 3 筆一頁才能區分「最後一筆」vs「第二筆」
    repo = _repo(session, batch=1000)
    await _seed(repo, 5)
    page = await repo.query(AuditQuery(tenant_id=TENANT, limit=3))
    assert [r.sequence for r in page.records] == [1, 2, 3]
    assert page.next_after_sequence == 3  # records[-1].sequence=3，不是 records[1]=2


async def test_first_record_prev_tamper_detected(session: AsyncSession) -> None:
    # 殺 L76 expected_sequence+1 → +2: 首筆 prev 被改+雜湊重算自洽，靠 link 抓(非 gap)
    repo = _repo(session, batch=1000)
    await _seed(repo, 2)
    rec = (await repo.records_in_range(TENANT, 1, 1))[0]
    forged = dataclasses.replace(rec, prev_hash="b" * 64)
    await session.execute(
        update(AuditRecordRow)
        .where(AuditRecordRow.sequence == 1)
        .values(prev_hash="b" * 64, record_hash=recompute_hash(forged))
    )
    report = await ChainVerifier(repo).verify_tenant_chain(TENANT)
    assert 1 in report.mismatched_sequences  # 首筆 prev≠創世，link 斷


async def test_checkpoint_head_none_with_sealed_detected(session: AsyncSession) -> None:
    # 殺 L154 (0 if head is None) → (1...): 單封印 end=1 + 刪鏈頭 → 仍應偵測異常
    repo = _repo(session, batch=1)
    await _seed(repo, 1)  # 封印 1 end=1
    await session.execute(delete(ChainHeadRow))  # 鏈頭被刪 → head None
    report = await ChainVerifier(repo).verify_checkpoint_layer(TENANT)
    assert report.head_mismatch is True


async def test_checkpoint_head_equals_sealed_is_intact(session: AsyncSession) -> None:
    # 殺封印層 head_mismatch 的 `<` → `<=`: 鏈頭剛好等於最後封印尾(正常完整)
    repo = _repo(session, batch=3)
    await _seed(repo, 6)  # 封印 1(seq1-3),2(seq4-6); head=6 == last_sealed=6
    report = await ChainVerifier(repo).verify_checkpoint_layer(TENANT)
    assert report.is_intact
    assert report.head_mismatch is False


async def test_incremental_from_last_sequence_empty_range(session: AsyncSession) -> None:
    # 殺增量 L71 last_seen_hash=anchor 的改動: from=最後一筆 → 範圍空，靠 anchor hash 比鏈頭
    repo = _repo(session, batch=1000)
    await _seed(repo, 3)
    report = await ChainVerifier(repo).verify_tenant_chain(TENANT, from_sequence=3)
    assert report.is_intact
    assert report.checked_count == 0  # 沒有 sequence > 3 的記錄
