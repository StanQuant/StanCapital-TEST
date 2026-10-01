"""S07 ATR 真 PostgreSQL 整合測試。

本檔只驗 S07 與 S05 的接點：ATR 決策產生的 risk_score 能寫進 audit log。
Audit 的 append-only / 權限 / 觸發器細節由 S05 自己的整合測試負責。
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from src.governance.audit.repository import AuditLogRepository
from src.governance.audit.types import AuditQuery
from src.persistence.engine import create_engine, create_session_factory
from src.security.atr.guard import AtrGuard
from src.security.atr.response import AtrResponseHandler

from tests.governance.audit.conftest import make_input
from tests.governance.audit.test_integration_audit import (
    PG_URL,
    _alembic,
    _require_pg,
    _truncate_audit_tables,
)
from tests.security.atr.conftest import make_behavior, make_engine

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module", autouse=True)
def _migrated() -> None:
    _require_pg()
    result = _alembic("upgrade", "head")
    assert result.returncode == 0, result.stderr.decode()


@pytest_asyncio.fixture
async def pg_engine(_migrated: None) -> AsyncIterator[AsyncEngine]:
    engine = create_engine(PG_URL)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def pg_session(pg_engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    factory = create_session_factory(pg_engine)
    async with factory() as session:
        await _truncate_audit_tables(session)
        yield session


async def test_atr_risk_score_round_trips_through_audit_log(
    pg_session: AsyncSession,
) -> None:
    guard = AtrGuard(make_engine(), AtrResponseHandler())
    decision = guard.evaluate(make_behavior(target="~/.ssh/id_rsa"))

    repo = AuditLogRepository(pg_session)
    written = await repo.append(
        make_input(
            tenant_id="tenant-a",
            user_id="security-agent",
            action="atr.decision",
            resource="agent/research-agent",
            risk_score=decision.score.value,
        )
    )
    await pg_session.commit()

    page = await repo.query(AuditQuery(tenant_id="tenant-a"))
    assert written.risk_score == 75
    assert page.records[0].risk_score == 75
    assert page.records[0].action == "atr.decision"


async def test_atr_integration_fixture_uses_running_loop(pg_session: AsyncSession) -> None:
    # 釘住 pytest-asyncio fixture 沒有跨 event loop 污染(S05 教訓)。
    assert asyncio.get_running_loop().is_running()
    assert pg_session.is_active
