"""engine 單元測試 · 連線工廠與環境變數讀取。"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.pool import QueuePool
from src.persistence.engine import create_engine, create_engine_from_env, create_session_factory


class TestCreateEngine:
    def test_sqlite_url(self) -> None:
        engine = create_engine("sqlite+aiosqlite://")
        assert engine.dialect.name == "sqlite"

    def test_postgresql_url_含連線池參數(self) -> None:
        # 建 engine 不會真的連線，可以安全測 URL 解析與池設定
        engine = create_engine(
            "postgresql+asyncpg://user:pass@localhost:5432/testdb",
            pool_size=7,
            max_overflow=3,
        )
        assert engine.dialect.name == "postgresql"
        assert isinstance(engine.pool, QueuePool)
        assert engine.pool.size() == 7


class TestCreateEngineFromEnv:
    def test_未設定_database_url_直接報錯(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("DATABASE_URL", raising=False)
        with pytest.raises(RuntimeError, match="DATABASE_URL"):
            create_engine_from_env()

    def test_空字串也視為未設定(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DATABASE_URL", "")
        with pytest.raises(RuntimeError, match="DATABASE_URL"):
            create_engine_from_env()

    def test_有設定就建出engine(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite://")
        assert create_engine_from_env().dialect.name == "sqlite"


class TestCreateSessionFactory:
    async def test_工廠產出async_session(self) -> None:
        engine = create_engine("sqlite+aiosqlite://")
        factory = create_session_factory(engine)
        async with factory() as session:
            assert isinstance(session, AsyncSession)
        await engine.dispose()
