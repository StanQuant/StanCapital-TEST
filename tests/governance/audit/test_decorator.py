"""S05 · @audited 裝飾器測試。

用「檔案型 SQLite」而非 in-memory: 每個 session 拿到獨立連線，
才能真實驗證「成功稽核未 commit 前其他連線看不到(D4 同交易)」與
「失敗證據走獨立交易、不隨業務 rollback 蒸發」兩個關鍵語義。
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from src.governance.audit.chain import hash_payload
from src.governance.audit.decorator import AuditContext, audited
from src.governance.audit.errors import AuditUnavailableError
from src.governance.audit.repository import AuditLogRepository
from src.governance.audit.types import AuditOutcome, AuditQuery
from src.governance.rbac.roles import Role
from src.persistence.engine import create_engine, create_session_factory
from src.persistence.models import Base

from tests.governance.audit.conftest import fixed_clock

pytestmark = pytest.mark.asyncio

CTX = AuditContext(tenant_id="tenant-a", user_id="user-1", role=Role.USER)


@pytest_asyncio.fixture
async def file_engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    eng = create_engine(f"sqlite+aiosqlite:///{tmp_path}/audit.db")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def factory(file_engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return create_session_factory(file_engine)


class OrderService:
    """測試用服務 · 滿足 AuditedService 契約。"""

    def __init__(self, session: AsyncSession, factory: async_sessionmaker[AsyncSession]) -> None:
        self.audit_repo = AuditLogRepository(session, clock=fixed_clock)
        self.audit_session_factory = factory
        self.submitted: list[str] = []

    @audited(
        action="order.submit",
        resource=lambda self, symbol, **_: f"order/{symbol}",
        payload=lambda self, symbol, qty=0, **_: {"symbol": symbol, "qty": qty},
    )
    async def submit(self, symbol: str, qty: int = 0, *, audit_ctx: AuditContext) -> str:
        self.submitted.append(symbol)
        return f"submitted:{symbol}"

    @audited(action="config.update", resource="config/global")
    async def update_config(self, *, audit_ctx: AuditContext) -> None:
        raise RuntimeError("boom")

    @audited(action="order.cancel", resource="order/x")
    async def cancel_with_nested_audit_failure(self, *, audit_ctx: AuditContext) -> None:
        raise AuditUnavailableError(tenant_id="tenant-a", action="inner.op", reason="db down")


async def _fetch_all(
    factory: async_sessionmaker[AsyncSession], tenant_id: str = "tenant-a"
) -> tuple[Any, ...]:
    async with factory() as fresh:
        page = await AuditLogRepository(fresh).query(AuditQuery(tenant_id=tenant_id))
        return page.records


# ============================================================================
# 成功路徑: 同 session 留 SUCCESS 稽核(D4 同交易)
# ============================================================================


async def test_success_appends_audit_with_full_fields(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        service = OrderService(session, factory)
        result = await service.submit("2330", qty=100, audit_ctx=CTX)
        assert result == "submitted:2330"
        assert service.submitted == ["2330"]

        page = await service.audit_repo.query(AuditQuery(tenant_id="tenant-a"))
        record = page.records[0]
        assert record.action == "order.submit"
        assert record.resource == "order/2330"
        assert record.response_status == AuditOutcome.SUCCESS
        assert record.request_payload_hash == hash_payload({"symbol": "2330", "qty": 100})
        assert record.user_id == "user-1"
        assert record.role == Role.USER
        assert record.ip_address == "internal"


async def test_success_audit_is_atomic_with_business_commit(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        service = OrderService(session, factory)
        await service.submit("2330", audit_ctx=CTX)
        # 還沒 commit: 其他連線看不到(同一筆交易的證明)
        assert await _fetch_all(factory) == ()
        await session.commit()
    assert len(await _fetch_all(factory)) == 1


async def test_static_resource_and_default_payload(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        service = OrderService(session, factory)
        with pytest.raises(RuntimeError, match="boom"):
            await service.update_config(audit_ctx=CTX)
    records = await _fetch_all(factory)
    assert records[0].resource == "config/global"
    assert records[0].request_payload_hash == hash_payload({})  # 沒給 payload 函式


async def test_success_留debug可觀測痕跡(
    factory: async_sessionmaker[AsyncSession], caplog: pytest.LogCaptureFixture
) -> None:
    # 所有 @audited 寫入成功的單一可觀測觸點(含 rbac_admin)
    async with factory() as session:
        service = OrderService(session, factory)
        with caplog.at_level(logging.DEBUG, logger="src.governance.audit.decorator"):
            await service.submit("2330", audit_ctx=CTX)
    assert any("稽核完成" in r.getMessage() for r in caplog.records if r.levelno == logging.DEBUG)


# ============================================================================
# 失敗路徑: FAILED 證據走獨立交易，不隨 rollback 蒸發
# ============================================================================


async def test_failure_evidence_survives_business_rollback(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        service = OrderService(session, factory)
        with pytest.raises(RuntimeError, match="boom"):
            await service.update_config(audit_ctx=CTX)
        await session.rollback()  # 業務交易整筆回滾

    records = await _fetch_all(factory)  # 失敗證據還在
    assert len(records) == 1
    assert records[0].response_status == AuditOutcome.FAILED
    assert records[0].action == "config.update"


async def test_failure_留warning可觀測痕跡(
    factory: async_sessionmaker[AsyncSession], caplog: pytest.LogCaptureFixture
) -> None:
    # 失敗證據寫成後給維運一個即時 WARNING(有人試圖做壞事/出錯)
    async with factory() as session:
        service = OrderService(session, factory)
        with caplog.at_level(logging.WARNING, logger="src.governance.audit.decorator"):
            with pytest.raises(RuntimeError, match="boom"):
                await service.update_config(audit_ctx=CTX)
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "已記錄失敗證據" in warnings[0].getMessage()


async def test_business_exception_propagates_unchanged(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        service = OrderService(session, factory)
        with pytest.raises(RuntimeError, match="boom"):
            await service.update_config(audit_ctx=CTX)


async def test_nested_audit_unavailable_not_doubled(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    # 內層已經 fail-closed 的錯誤直接上拋，不再疊一筆失敗證據
    async with factory() as session:
        service = OrderService(session, factory)
        with pytest.raises(AuditUnavailableError, match=r"inner\.op"):
            await service.cancel_with_nested_audit_failure(audit_ctx=CTX)
    assert await _fetch_all(factory) == ()


# ============================================================================
# fail-closed: 缺 ctx / 缺契約 / 稽核失敗
# ============================================================================


async def test_missing_audit_ctx_blocks_execution(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        service = OrderService(session, factory)
        with pytest.raises(AuditUnavailableError, match="缺少 audit_ctx 關鍵字參數"):
            await service.submit("2330")  # type: ignore[call-arg]
        assert service.submitted == []  # 業務邏輯根本沒執行


async def test_service_without_contract_rejected() -> None:
    class Naked:
        @audited(action="x.y", resource="r")
        async def op(self, *, audit_ctx: AuditContext) -> None: ...

    with pytest.raises(TypeError) as e:
        await Naked().op(audit_ctx=CTX)
    assert str(e.value) == (
        "@audited 方法的所屬服務必須提供 audit_repo 與 audit_session_factory: action=x.y"
    )


class _FailingRepo:
    async def append(self, record_input: Any) -> Any:
        raise RuntimeError("db down")


async def test_success_path_audit_failure_raises_fail_closed(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    async with factory() as session:
        service = OrderService(session, factory)
        service.audit_repo = _FailingRepo()  # type: ignore[assignment]
        with pytest.raises(AuditUnavailableError) as exc_info:
            await service.submit("2330", audit_ctx=CTX)
    assert exc_info.value.tenant_id == "tenant-a"
    assert exc_info.value.action == "order.submit"
    assert exc_info.value.reason == "db down"
    # 業務邏輯有跑，但結果被 fail-closed 丟棄、呼叫端必須 rollback
    assert service.submitted == ["2330"]


class _BrokenFactory:
    def __call__(self) -> Any:
        raise RuntimeError("factory down")


async def test_double_fault_raises_and_logs_critical(
    factory: async_sessionmaker[AsyncSession],
    caplog: pytest.LogCaptureFixture,
) -> None:
    async with factory() as session:
        service = OrderService(session, factory)
        service.audit_session_factory = _BrokenFactory()  # type: ignore[assignment]
        with (
            caplog.at_level(logging.CRITICAL, logger="src.governance.audit.decorator"),
            pytest.raises(AuditUnavailableError, match="factory down"),
        ):
            await service.update_config(audit_ctx=CTX)
    assert caplog.records[0].getMessage() == (
        "失敗證據寫入也失敗(雙重故障): tenant=tenant-a action=config.update "
        "業務錯誤=boom 稽核錯誤=factory down"
    )


# ============================================================================
# 其他
# ============================================================================


async def test_wrapper_preserves_function_name() -> None:
    assert OrderService.submit.__name__ == "submit"
