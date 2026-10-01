"""AbacAccessGuard 測試 · RBAC 過 → ABAC 細審 → 三態（含稽核 / 事件 / fail-closed）。

用檔案型 SQLite（決策稽核走獨立 session，需跨連線可見性）+ 真 RBACChecker
（注入 fake 快照查詢）+ 真 AbacEvaluator（載 base.yaml）。
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
import src.governance.audit.models  # 註冊稽核表進 Base.metadata
import src.governance.rbac.models  # noqa: F401  # 註冊 users 表進 Base.metadata
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from src.governance.abac.dsl import load_policies
from src.governance.abac.errors import ApprovalRequiredError
from src.governance.abac.evaluator import AbacEvaluator
from src.governance.access_guard import (
    ABAC_APPROVAL_ACTION,
    ABAC_DENIED_ACTION,
    DENIED_ACTION,
    AbacAccessGuard,
    ApprovalRequestEvent,
)
from src.governance.audit.decorator import AuditContext
from src.governance.audit.repository import AuditLogRepository
from src.governance.audit.types import AuditOutcome, AuditQuery, AuditRecord
from src.governance.rbac.checker import RBACChecker
from src.governance.rbac.errors import PermissionDeniedError
from src.governance.rbac.permissions import Action, Permission, Resource
from src.governance.rbac.roles import Role
from src.governance.rbac.types import AccessSnapshot, User
from src.persistence.engine import create_engine, create_session_factory
from src.persistence.models import Base

from tests.governance.audit.conftest import fixed_clock

pytestmark = pytest.mark.asyncio

# MANAGER 在測試矩陣裡有 ORDER 的讀/寫/刪（讓 RBAC 過，好讓 ABAC 接手細審）
_ALLOW_MATRIX = {
    Role.MANAGER: frozenset(
        {
            Permission(Resource.ORDER, Action.READ),
            Permission(Resource.ORDER, Action.WRITE),
            Permission(Resource.ORDER, Action.DELETE),
        }
    )
}

_BASE_POLICIES = load_policies(Path(__file__).parents[3] / "policies" / "abac" / "base.yaml")


def _ctx() -> AuditContext:
    return AuditContext(
        tenant_id="stanley",
        user_id="USR-1",
        role=Role.MANAGER,
        ip_address="10.0.0.9",
        user_agent="curl/8.0",
        risk_score=7,
    )


def _snapshot(
    *,
    department: str = "trading",
    region: str = "taiwan",
    project: str = "alpha",
    is_active: bool = True,
    roles: tuple[Role, ...] = (Role.MANAGER,),
) -> AccessSnapshot:
    user = User(
        tenant_id="stanley",
        email="m@stanquant.dev",
        display_name="經理",
        user_id="USR-1",
        is_active=is_active,
        department=department,
        region=region,
        project=project,
    )
    return AccessSnapshot(user=user, roles=roles, overrides=())


class _FakeLookup:
    """固定回傳一個快照（或 None）的假快照查詢。"""

    def __init__(self, snapshot: AccessSnapshot | None) -> None:
        self._snapshot = snapshot

    async def load_access_snapshot(self, tenant_id: str, user_id: str) -> AccessSnapshot | None:
        return self._snapshot


class _SpyEvaluator(AbacEvaluator):
    """記錄 evaluate 被呼叫幾次，用來驗證 RBAC deny 時的短路。"""

    def __init__(self, policies: Any) -> None:
        super().__init__(policies)
        self.calls = 0

    def evaluate(self, request: Any) -> Any:
        self.calls += 1
        return super().evaluate(request)


class _RecordingSink:
    def __init__(self) -> None:
        self.events: list[ApprovalRequestEvent] = []

    async def publish(self, event: ApprovalRequestEvent) -> None:
        self.events.append(event)


class _FailingSink:
    async def publish(self, event: ApprovalRequestEvent) -> None:
        raise RuntimeError("bus down")


class _BrokenFactory:
    def __call__(self) -> Any:
        raise RuntimeError("audit db down")


@pytest_asyncio.fixture
async def file_engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    eng = create_engine(f"sqlite+aiosqlite:///{tmp_path}/abac_guard.db")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def factory(file_engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return create_session_factory(file_engine)


async def _audits(factory: async_sessionmaker[AsyncSession]) -> tuple[AuditRecord, ...]:
    async with factory() as fresh:
        page = await AuditLogRepository(fresh).query(AuditQuery(tenant_id="stanley"))
        return page.records


def _guard(
    factory: async_sessionmaker[AsyncSession],
    snapshot: AccessSnapshot | None,
    sink: Any,
    *,
    matrix: Any = _ALLOW_MATRIX,
    evaluator: AbacEvaluator | None = None,
) -> AbacAccessGuard:
    checker = RBACChecker(_FakeLookup(snapshot), role_permissions=matrix)
    return AbacAccessGuard(
        checker,
        evaluator or AbacEvaluator(_BASE_POLICIES),
        factory,
        sink,
        clock=fixed_clock,
    )


# ============================================================================
# ALLOW：靜默通過、不另記稽核
# ============================================================================
async def test_allow_passes_silently_without_audit(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    guard = _guard(factory, _snapshot(), _RecordingSink())
    await guard.require_abac(
        Resource.ORDER, Action.WRITE, sensitivity_level=2, risk_category="normal", audit_ctx=_ctx()
    )
    assert await _audits(factory) == ()


async def test_read_is_allowed(factory: async_sessionmaker[AsyncSession]) -> None:
    guard = _guard(factory, _snapshot(), _RecordingSink())
    await guard.require_abac(
        Resource.ORDER, Action.READ, sensitivity_level=5, risk_category="high", audit_ctx=_ctx()
    )
    assert await _audits(factory) == ()


# ============================================================================
# ABAC DENY：擋下 + ABAC 拒絕稽核
# ============================================================================
async def test_abac_deny_top_secret(factory: async_sessionmaker[AsyncSession]) -> None:
    guard = _guard(factory, _snapshot(), _RecordingSink())
    with pytest.raises(PermissionDeniedError) as excinfo:
        await guard.require_abac(
            Resource.ORDER,
            Action.WRITE,
            sensitivity_level=5,
            risk_category="normal",
            audit_ctx=_ctx(),
        )
    assert "敏感度 5" in excinfo.value.reason
    records = await _audits(factory)
    assert len(records) == 1
    assert records[0].action == ABAC_DENIED_ACTION
    assert records[0].resource == "order:write"
    assert records[0].response_status == AuditOutcome.FAILED


async def test_abac_deny_quarantine_department(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    guard = _guard(factory, _snapshot(department="quarantine"), _RecordingSink())
    with pytest.raises(PermissionDeniedError):
        await guard.require_abac(
            Resource.ORDER,
            Action.WRITE,
            sensitivity_level=2,
            risk_category="normal",
            audit_ctx=_ctx(),
        )
    assert (await _audits(factory))[0].action == ABAC_DENIED_ACTION


async def test_abac_deny_restricted_region(factory: async_sessionmaker[AsyncSession]) -> None:
    guard = _guard(factory, _snapshot(region="restricted"), _RecordingSink())
    with pytest.raises(PermissionDeniedError):
        await guard.require_abac(
            Resource.ORDER,
            Action.DELETE,
            sensitivity_level=1,
            risk_category="normal",
            audit_ctx=_ctx(),
        )
    assert (await _audits(factory))[0].action == ABAC_DENIED_ACTION


# ============================================================================
# ABAC REQUIRE_APPROVAL：擋下 + 稽核 + 發審批事件
# ============================================================================
async def test_abac_approval_high_sensitivity(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    sink = _RecordingSink()
    guard = _guard(factory, _snapshot(), sink)
    with pytest.raises(ApprovalRequiredError) as excinfo:
        await guard.require_abac(
            Resource.ORDER,
            Action.WRITE,
            sensitivity_level=4,
            risk_category="normal",
            audit_ctx=_ctx(),
        )
    assert excinfo.value.matched_policy == "approval-high-sensitivity-write"
    # 稽核
    records = await _audits(factory)
    assert len(records) == 1
    assert records[0].action == ABAC_APPROVAL_ACTION
    # 事件（欄位齊全、權威屬性如實帶出）
    assert len(sink.events) == 1
    event = sink.events[0]
    assert event.tenant_id == "stanley"
    assert event.user_id == "USR-1"
    assert event.resource is Resource.ORDER
    assert event.action is Action.WRITE
    assert event.sensitivity_level == 4
    assert event.matched_policy == "approval-high-sensitivity-write"


# ============================================================================
# RBAC 短路：RBAC 拒絕不進 ABAC
# ============================================================================
async def test_rbac_deny_short_circuits_abac(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    spy = _SpyEvaluator(_BASE_POLICIES)
    # 空矩陣 → MANAGER 無任何權限 → RBAC 拒絕
    guard = _guard(factory, _snapshot(), _RecordingSink(), matrix={}, evaluator=spy)
    with pytest.raises(PermissionDeniedError) as excinfo:
        await guard.require_abac(
            Resource.ORDER,
            Action.WRITE,
            sensitivity_level=2,
            risk_category="normal",
            audit_ctx=_ctx(),
        )
    assert excinfo.value.reason == "所有角色皆無此權限"
    assert spy.calls == 0  # ABAC 完全沒被呼叫（短路）
    assert (await _audits(factory))[0].action == DENIED_ACTION


async def test_user_not_found_is_rbac_deny(factory: async_sessionmaker[AsyncSession]) -> None:
    guard = _guard(factory, None, _RecordingSink())
    with pytest.raises(PermissionDeniedError) as excinfo:
        await guard.require_abac(
            Resource.ORDER,
            Action.WRITE,
            sensitivity_level=2,
            risk_category="normal",
            audit_ctx=_ctx(),
        )
    assert excinfo.value.reason == "使用者不存在"
    assert (await _audits(factory))[0].action == DENIED_ACTION


async def test_inactive_user_is_rbac_deny(factory: async_sessionmaker[AsyncSession]) -> None:
    guard = _guard(factory, _snapshot(is_active=False), _RecordingSink())
    with pytest.raises(PermissionDeniedError) as excinfo:
        await guard.require_abac(
            Resource.ORDER,
            Action.WRITE,
            sensitivity_level=2,
            risk_category="normal",
            audit_ctx=_ctx(),
        )
    assert excinfo.value.reason == "使用者已停用"
    assert (await _audits(factory))[0].action == DENIED_ACTION


# ============================================================================
# fail-closed：稽核 / 事件寫失敗都不把 deny/approval 變 allow
# ============================================================================
async def test_audit_write_failure_still_denies(
    caplog: pytest.LogCaptureFixture,
) -> None:
    guard = _guard(_BrokenFactory(), _snapshot(), _RecordingSink())  # type: ignore[arg-type]
    with (
        caplog.at_level(logging.CRITICAL, logger="src.governance.access_guard"),
        pytest.raises(PermissionDeniedError),
    ):
        await guard.require_abac(
            Resource.ORDER,
            Action.WRITE,
            sensitivity_level=5,
            risk_category="normal",
            audit_ctx=_ctx(),
        )
    assert "ABAC 決策稽核寫入失敗" in caplog.records[0].getMessage()


async def test_approval_sink_failure_still_blocks(
    factory: async_sessionmaker[AsyncSession],
    caplog: pytest.LogCaptureFixture,
) -> None:
    guard = _guard(factory, _snapshot(), _FailingSink())
    with (
        caplog.at_level(logging.CRITICAL, logger="src.governance.access_guard"),
        pytest.raises(ApprovalRequiredError),
    ):
        await guard.require_abac(
            Resource.ORDER,
            Action.WRITE,
            sensitivity_level=4,
            risk_category="normal",
            audit_ctx=_ctx(),
        )
    assert "審批事件發送失敗" in caplog.records[0].getMessage()
    # 即使事件發送失敗，仍留了審批稽核（動作確實被擋）
    assert (await _audits(factory))[0].action == ABAC_APPROVAL_ACTION
