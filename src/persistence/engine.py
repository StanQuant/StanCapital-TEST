"""Async engine 與 session 工廠。

連線字串從環境變數 DATABASE_URL 讀取(禁止寫死，ClaudeC §3.3)。
範例: postgresql+asyncpg://user:pass@localhost:5432/stanquant
"""

from __future__ import annotations

import os

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def create_engine(url: str, *, pool_size: int = 5, max_overflow: int = 10) -> AsyncEngine:
    """建立 async engine。pool_pre_ping 在取連線前先探活，擋掉已死連線。"""
    if url.startswith("sqlite"):
        # SQLite 不支援 pool_size / max_overflow 參數(測試用，無連線池概念)
        return create_async_engine(url, pool_pre_ping=True)
    return create_async_engine(
        url,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_pre_ping=True,
    )


def create_engine_from_env() -> AsyncEngine:
    """從環境變數 DATABASE_URL 建立 engine，未設定就直接報錯(不給隱性預設)。"""
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("缺少 DATABASE_URL 環境變數(請設定於 .env，禁止寫死在程式碼)")
    return create_engine(url)


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """建立 session 工廠。expire_on_commit=False 讓 commit 後物件仍可讀。"""
    return async_sessionmaker(engine, expire_on_commit=False)
