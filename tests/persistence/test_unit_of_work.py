"""src/persistence/unit_of_work.py 的測試 · 韌性交易邊界（審查 H4）。

用假 session（不需真 DB）驗證：成功 commit、連線錯誤重試整個工作單元、
資料錯誤不重試、熔斷器開路快速失敗。
"""

from __future__ import annotations

import logging
from typing import Any

import pytest
from src.persistence.resilience import CircuitBreaker, CircuitBreakerOpenError
from src.persistence.unit_of_work import run_resilient


class _FakeSession:
    def __init__(self) -> None:
        self.committed = False
        self.closed = False

    async def commit(self) -> None:
        self.committed = True

    async def close(self) -> None:
        self.closed = True

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        await self.close()
        return False


class _FakeFactory:
    """每次呼叫產生新 session（模擬 async_sessionmaker）。"""

    def __init__(self) -> None:
        self.sessions: list[_FakeSession] = []

    def __call__(self) -> _FakeSession:
        session = _FakeSession()
        self.sessions.append(session)
        return session


async def test_成功則_commit_並回傳結果() -> None:
    factory = _FakeFactory()

    async def work(_session: Any) -> str:
        return "done"

    result = await run_resilient(factory, work)  # type: ignore[arg-type]
    assert result == "done"
    assert factory.sessions[0].committed is True
    assert factory.sessions[0].closed is True


async def test_連線類錯誤重試整個工作單元後成功() -> None:
    factory = _FakeFactory()
    calls = 0

    async def flaky(_session: Any) -> str:
        nonlocal calls
        calls += 1
        if calls < 3:
            raise OSError("connection refused")  # 連線類 → 可重試
        return "recovered"

    result = await run_resilient(factory, flaky, attempts=3)  # type: ignore[arg-type]
    assert result == "recovered"
    assert calls == 3
    # 證據：每次重試都用全新 session（共 3 個），且失敗的那兩個沒 commit
    assert len(factory.sessions) == 3
    assert [s.committed for s in factory.sessions] == [False, False, True]


async def test_連線類錯誤耗盡仍拋出() -> None:
    factory = _FakeFactory()

    async def always_down(_session: Any) -> None:
        raise OSError("db gone")

    with pytest.raises(OSError, match="db gone"):
        await run_resilient(factory, always_down, attempts=2)  # type: ignore[arg-type]
    assert len(factory.sessions) == 2  # 重試 2 次都用新 session


async def test_最終失敗留下error痕跡(caplog: pytest.LogCaptureFixture) -> None:
    factory = _FakeFactory()

    async def always_down(_session: Any) -> None:
        raise OSError("db gone")

    with caplog.at_level(logging.ERROR, logger="src.persistence.unit_of_work"):
        with pytest.raises(OSError, match="db gone"):
            await run_resilient(factory, always_down, attempts=1)  # type: ignore[arg-type]
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1
    assert "最終失敗" in errors[0].getMessage()


async def test_資料類錯誤不重試直接拋() -> None:
    factory = _FakeFactory()
    calls = 0

    async def bad_data(_session: Any) -> None:
        nonlocal calls
        calls += 1
        raise ValueError("唯一鍵衝突")  # 非連線類 → 不重試

    with pytest.raises(ValueError, match="唯一鍵衝突"):
        await run_resilient(factory, bad_data, attempts=3)  # type: ignore[arg-type]
    assert calls == 1  # 證據：只試一次，沒重試


async def test_熔斷器開路時快速失敗() -> None:
    factory = _FakeFactory()
    breaker = CircuitBreaker(failure_threshold=1, recovery_seconds=999)

    async def boom(_session: Any) -> None:
        raise OSError("down")

    # 第一次：work 連線失敗、with_retry 耗盡、熔斷器記一次失敗達門檻 → 開路
    with pytest.raises(OSError):
        await run_resilient(factory, boom, attempts=1, breaker=breaker)
    assert breaker.is_open is True
    # 第二次：熔斷器開路，直接快速失敗、不再碰 DB
    sessions_before = len(factory.sessions)
    with pytest.raises(CircuitBreakerOpenError):
        await run_resilient(factory, boom, attempts=1, breaker=breaker)
    assert len(factory.sessions) == sessions_before  # 證據：開路後完全沒建新 session


async def test_熔斷器下成功會重置並_commit() -> None:
    factory = _FakeFactory()
    breaker = CircuitBreaker(failure_threshold=3)

    async def ok(_session: Any) -> str:
        return "ok"

    result = await run_resilient(factory, ok, breaker=breaker)  # type: ignore[arg-type]
    assert result == "ok"
    assert factory.sessions[0].committed is True
    assert breaker.failure_count == 0
