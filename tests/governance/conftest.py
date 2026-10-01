"""governance 測試共用 fixture 與測試資料工廠(S02 conftest 同款模式)。

單元測試用 SQLite in-memory(秒跑、不依賴 Docker)；
PostgreSQL 特有行為由整合測試守住(test_integration_rbac.py)。
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest_asyncio
import src.governance.rbac.models  # noqa: F401  # 註冊 L11 表進 Base.metadata
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from src.governance.rbac.permissions import Action, Resource
from src.governance.rbac.roles import Role
from src.governance.rbac.types import OverrideEffect, PermissionOverride, RoleAssignment, User
from src.persistence.engine import create_engine, create_session_factory
from src.persistence.models import Base


@pytest_asyncio.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    """SQLite in-memory engine，每個測試獨立建表。"""
    eng = create_engine("sqlite+aiosqlite://")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    factory = create_session_factory(engine)
    async with factory() as sess:
        yield sess


# ============================================================================
# 測試資料工廠 · 預設值合理，可用 overrides 覆寫任一欄位
# ============================================================================


def make_user(**overrides: Any) -> User:
    fields: dict[str, Any] = {
        "tenant_id": "stanley",
        "email": "trader@stanquant.dev",
        "display_name": "測試交易員",
        "user_id": "USR-001",
        "is_active": True,
    }
    fields.update(overrides)
    return User(**fields)


def make_assignment(**overrides: Any) -> RoleAssignment:
    fields: dict[str, Any] = {
        "tenant_id": "stanley",
        "user_id": "USR-001",
        "role": Role.USER,
        "assignment_id": "ASG-001",
    }
    fields.update(overrides)
    return RoleAssignment(**fields)


def make_override(**overrides: Any) -> PermissionOverride:
    fields: dict[str, Any] = {
        "tenant_id": "stanley",
        "role": Role.USER,
        "resource": Resource.TRADE,
        "action": Action.WRITE,
        "effect": OverrideEffect.GRANT,
        "override_id": "OVR-001",
    }
    fields.update(overrides)
    return PermissionOverride(**fields)
