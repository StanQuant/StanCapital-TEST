"""resilience 單元測試 · 重試與熔斷器邏輯。

時間都用假時鐘 / 極短退避，測試不真等。
"""

from __future__ import annotations

import inspect
import logging
import re

import pytest
from sqlalchemy.exc import IntegrityError, OperationalError
from src.persistence.resilience import CircuitBreaker, CircuitBreakerOpenError, with_retry


def _conn_error() -> OperationalError:
    """模擬連線類錯誤(可重試)。"""
    return OperationalError("SELECT 1", None, Exception("connection refused"))


def _data_error() -> IntegrityError:
    """模擬資料類錯誤(不可重試)。"""
    return IntegrityError("INSERT ...", None, Exception("unique violation"))


class TestWithRetry:
    async def test_一次成功不重試(self) -> None:
        calls = 0

        async def operation() -> str:
            nonlocal calls
            calls += 1
            return "ok"

        assert await with_retry(operation) == "ok"
        assert calls == 1

    async def test_連線錯誤重試後成功(self) -> None:
        calls = 0

        async def operation() -> str:
            nonlocal calls
            calls += 1
            if calls < 3:
                raise _conn_error()
            return "ok"

        result = await with_retry(operation, wait_min=0.001, wait_max=0.002)
        assert result == "ok"
        assert calls == 3

    async def test_重試耗盡拋原錯誤(self) -> None:
        calls = 0

        async def operation() -> str:
            nonlocal calls
            calls += 1
            raise _conn_error()

        with pytest.raises(OperationalError):
            await with_retry(operation, attempts=3, wait_min=0.001, wait_max=0.002)
        assert calls == 3

    async def test_OS層連線拒絕也會重試(self) -> None:
        # 2026-06-11 崩潰演練抓到的盲區: 資料庫整台斷線是 ConnectionRefusedError，
        # 不經 SQLAlchemy 包裝，原清單漏了它導致 0 次重試
        calls = 0

        async def operation() -> str:
            nonlocal calls
            calls += 1
            raise ConnectionRefusedError("connection refused")

        with pytest.raises(ConnectionRefusedError):
            await with_retry(operation, attempts=3, wait_min=0.001, wait_max=0.002)
        assert calls == 3

    async def test_資料類錯誤不重試直接拋(self) -> None:
        calls = 0

        async def operation() -> str:
            nonlocal calls
            calls += 1
            raise _data_error()

        with pytest.raises(IntegrityError):
            await with_retry(operation, wait_min=0.001, wait_max=0.002)
        assert calls == 1


class FakeClock:
    """可手動撥快的假時鐘。"""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


async def _fail() -> str:
    raise _conn_error()


async def _succeed() -> str:
    return "ok"


class TestCircuitBreaker:
    async def test_成功時計數重置(self) -> None:
        breaker = CircuitBreaker(failure_threshold=2)
        with pytest.raises(OperationalError):
            await breaker.call(_fail)
        assert breaker.failure_count == 1
        assert await breaker.call(_succeed) == "ok"
        assert breaker.failure_count == 0

    async def test_未達門檻不開路(self) -> None:
        breaker = CircuitBreaker(failure_threshold=3)
        with pytest.raises(OperationalError):
            await breaker.call(_fail)
        assert not breaker.is_open

    async def test_連續失敗達門檻後開路快速失敗(self) -> None:
        clock = FakeClock()
        breaker = CircuitBreaker(failure_threshold=2, recovery_seconds=30.0, clock=clock)
        for _ in range(2):
            with pytest.raises(OperationalError):
                await breaker.call(_fail)
        assert breaker.is_open
        # 開路期間直接拒絕，連 operation 都不會碰
        with pytest.raises(CircuitBreakerOpenError):
            await breaker.call(_succeed)

    async def test_冷卻期過後半開放行並恢復(self) -> None:
        clock = FakeClock()
        breaker = CircuitBreaker(failure_threshold=2, recovery_seconds=30.0, clock=clock)
        for _ in range(2):
            with pytest.raises(OperationalError):
                await breaker.call(_fail)
        clock.advance(30.0)
        assert not breaker.is_open
        assert await breaker.call(_succeed) == "ok"
        assert breaker.failure_count == 0
        # 恢復後必須完全閉路(殺 mutant: _reset 把 _opened_at 設成非 None 的假值)
        assert not breaker.is_open

    async def test_半開試探又失敗會再開路(self) -> None:
        clock = FakeClock()
        breaker = CircuitBreaker(failure_threshold=2, recovery_seconds=30.0, clock=clock)
        for _ in range(2):
            with pytest.raises(OperationalError):
                await breaker.call(_fail)
        clock.advance(30.0)
        with pytest.raises(OperationalError):
            await breaker.call(_fail)
        assert breaker.is_open


class TestDefaults:
    """預設參數是對外契約(mutation testing 驅動補強): 預設值被改必須被抓到。"""

    def test_with_retry_預設參數(self) -> None:
        sig = inspect.signature(with_retry)
        assert sig.parameters["attempts"].default == 3
        assert sig.parameters["wait_min"].default == 0.1
        assert sig.parameters["wait_max"].default == 2.0

    async def test_熔斷預設門檻是連續失敗5次(self) -> None:
        clock = FakeClock()
        breaker = CircuitBreaker(clock=clock)
        for _ in range(4):
            with pytest.raises(OperationalError):
                await breaker.call(_fail)
        assert not breaker.is_open  # 第 4 次還不開路
        with pytest.raises(OperationalError):
            await breaker.call(_fail)
        assert breaker.is_open  # 第 5 次開路

    async def test_熔斷預設冷卻時間是30秒(self) -> None:
        clock = FakeClock()
        breaker = CircuitBreaker(failure_threshold=1, clock=clock)
        with pytest.raises(OperationalError):
            await breaker.call(_fail)
        clock.advance(29.9)
        assert breaker.is_open  # 29.9 秒仍開路
        clock.advance(0.1)
        assert not breaker.is_open  # 滿 30 秒放行


class TestObservability:
    """日誌與錯誤訊息也是行為(維運排障依賴它們)，內容錯誤必須被抓到。"""

    async def test_重試前記錄warning含正確次數(self, caplog: pytest.LogCaptureFixture) -> None:
        calls = 0

        async def operation() -> str:
            nonlocal calls
            calls += 1
            if calls < 2:
                raise _conn_error()
            return "ok"

        with caplog.at_level(logging.WARNING, logger="src.persistence.resilience"):
            await with_retry(operation, wait_min=0.001, wait_max=0.002)
        # 完全相等比對(「包含」比對殺不掉前後加料的 mutant)
        assert [r.getMessage() for r in caplog.records] == ["資料庫操作失敗，準備第 2 次重試"]

    async def test_開路時記錄warning含失敗次數(self, caplog: pytest.LogCaptureFixture) -> None:
        breaker = CircuitBreaker(failure_threshold=1)
        with caplog.at_level(logging.WARNING, logger="src.persistence.resilience"):
            with pytest.raises(OperationalError):
                await breaker.call(_fail)
        assert [r.getMessage() for r in caplog.records] == ["熔斷器開路: 連續失敗 1 次"]

    async def test_開路錯誤訊息含失敗次數(self) -> None:
        clock = FakeClock()
        breaker = CircuitBreaker(failure_threshold=2, clock=clock)
        for _ in range(2):
            with pytest.raises(OperationalError):
                await breaker.call(_fail)
        # 加 ^$ 錨點做全文比對(re.search 預設找子字串，殺不掉前後加料的 mutant)
        expected = "^" + re.escape("熔斷器開路中(連續失敗 2 次)，請稍後再試") + "$"
        with pytest.raises(CircuitBreakerOpenError, match=expected):
            await breaker.call(_succeed)
