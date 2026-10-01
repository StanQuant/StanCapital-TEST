"""S05 Batch 6a-2 · AccessGuard 測試(權限拒絕自動留稽核 · 彻底版 B)。

用「檔案型 SQLite」: 拒絕證據走獨立 session,需跨連線可見性才能驗證
「不隨呼叫端 rollback 蒸發」(test_decorator / test_rbac_admin 同款理由)。

涵蓋:
- 放行 → 靜默通過、不留任何稽核
- 拒絕 → 原 PermissionDeniedError 原樣上拋 + 一筆 FAILED 拒絕稽核(欄位齊全)
- 拒絕稽核寫入失敗 → 仍原樣上拋 + CRITICAL 日誌(絕不把 deny 變 allow)
- RBACUnavailableError(基礎設施故障)→ 直接上拋、不誤記拒絕稽核
- 預設時鐘(_utc_now)
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
import src.governance.audit.models  # noqa: F401  # 註冊稽核表進 Base.metadata
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from src.governance.access_guard import DENIED_ACTION, AccessGuard
from src.governance.audit.decorator import AuditContext
from src.governance.audit.repository import AuditLogRepository
from src.governance.audit.types import AuditOutcome, AuditQuery, AuditRecord
from src.governance.rbac.errors import PermissionDeniedError, RBACUnavailableError
from src.governance.rbac.permissions import Action, Resource
from src.governance.rbac.roles import Role
from src.persistence.engine import create_engine, create_session_factory
from src.persistence.models import Base

from tests.governance.audit.conftest import fixed_clock

pytestmark = pytest.mark.asyncio

# 帶非預設 ip / user_agent / risk_score,驗證身分脈絡如實落進稽核
CTX = AuditContext(
    tenant_id="stanley",
    user_id="USR-1",
    role=Role.AGENT,
    ip_address="10.0.0.9",
    user_agent="curl/8.0",
    risk_score=42,
)

DENIAL = PermissionDeniedError(
    tenant_id="stanley",
    user_id="USR-1",
    resource=Resource.ORDER,
    action=Action.WRITE,
    roles=(Role.AGENT,),
    reason="所有角色皆無此權限",
)


# ============================================================================
# 假警衛(只實作 require)
# ============================================================================


class AllowChecker:
    async def require(self, tenant_id: str, user_id: str, resource: Any, action: Any) -> None:
        return None


class DenyChecker:
    def __init__(self, error: Exception) -> None:
        self.error = error

    async def require(self, tenant_id: str, user_id: str, resource: Any, action: Any) -> None:
        raise self.error


class _BrokenFactory:
    """模擬稽核交易來源掛掉。"""

    def __call__(self) -> Any:
        raise RuntimeError("audit db down")


# ============================================================================
# fixtures
# ============================================================================


@pytest_asyncio.fixture
async def file_engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    eng = create_engine(f"sqlite+aiosqlite:///{tmp_path}/access_guard.db")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def factory(file_engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return create_session_factory(file_engine)


async def _audits(
    factory: async_sessionmaker[AsyncSession], tenant_id: str = "stanley"
) -> tuple[AuditRecord, ...]:
    async with factory() as fresh:
        page = await AuditLogRepository(fresh).query(AuditQuery(tenant_id=tenant_id))
        return page.records


# ============================================================================
# 放行:靜默通過、零稽核
# ============================================================================


async def test_allow_passes_silently_without_audit(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    guard = AccessGuard(AllowChecker(), factory, clock=fixed_clock)
    await guard.require(Resource.ORDER, Action.WRITE, audit_ctx=CTX)
    assert await _audits(factory) == ()


# ============================================================================
# 拒絕:原例外上拋 + FAILED 拒絕稽核(欄位齊全)
# ============================================================================


async def test_denied_reraises_same_error_and_writes_failed_audit(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    guard = AccessGuard(DenyChecker(DENIAL), factory, clock=fixed_clock)
    with pytest.raises(PermissionDeniedError) as excinfo:
        await guard.require(Resource.ORDER, Action.WRITE, audit_ctx=CTX)
    assert excinfo.value is DENIAL  # 原例外原樣上拋,未被掉包

    records = await _audits(factory)
    assert len(records) == 1
    record = records[0]
    assert record.action == DENIED_ACTION
    assert record.resource == "order:write"
    assert record.response_status == AuditOutcome.FAILED
    assert record.role == Role.AGENT
    assert record.user_id == "USR-1"
    # 身分脈絡如實落進稽核
    assert record.ip_address == "10.0.0.9"
    assert record.user_agent == "curl/8.0"
    assert record.risk_score == 42


# ============================================================================
# 拒絕稽核寫入失敗:仍原樣上拋 + CRITICAL,絕不把 deny 變 allow
# ============================================================================


async def test_denial_audit_failure_still_reraises_and_logs_critical(
    caplog: pytest.LogCaptureFixture,
) -> None:
    guard = AccessGuard(DenyChecker(DENIAL), _BrokenFactory(), clock=fixed_clock)
    with (
        caplog.at_level(logging.CRITICAL, logger="src.governance.access_guard"),
        pytest.raises(PermissionDeniedError) as excinfo,
    ):
        await guard.require(Resource.ORDER, Action.WRITE, audit_ctx=CTX)
    assert excinfo.value is DENIAL  # 拒絕決策仍如實上拋
    assert caplog.records[0].getMessage() == (
        "拒絕稽核寫入失敗(拒絕決策仍生效): "
        "tenant=stanley user=USR-1 resource=order action=write 原因=audit db down"
    )


# ============================================================================
# 基礎設施故障(RBACUnavailableError):直接上拋、不誤記拒絕稽核
# ============================================================================


async def test_unavailable_propagates_without_denial_audit(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    guard = AccessGuard(
        DenyChecker(RBACUnavailableError("資料來源連不上")), factory, clock=fixed_clock
    )
    with pytest.raises(RBACUnavailableError):
        await guard.require(Resource.ORDER, Action.WRITE, audit_ctx=CTX)
    # 不是「權限不足」,不該留拒絕稽核
    assert await _audits(factory) == ()


# ============================================================================
# 預設時鐘(_utc_now):不注入 clock 也能運作
# ============================================================================


async def test_default_clock_produces_aware_timestamp(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    guard = AccessGuard(DenyChecker(DENIAL), factory)  # 不注入 clock → _utc_now
    with pytest.raises(PermissionDeniedError):
        await guard.require(Resource.ORDER, Action.WRITE, audit_ctx=CTX)
    records = await _audits(factory)
    assert records[0].timestamp.tzinfo is not None
