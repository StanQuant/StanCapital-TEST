"""資料庫韌性 · 重試(tenacity) + 熔斷器。

重試原則: 只重試「連線類」錯誤(OperationalError / InterfaceError)。
資料類錯誤(如 IntegrityError 唯一鍵衝突)代表程式或資料本身的問題，
重試只會重複失敗，必須直接拋出。

熔斷原則: 連續失敗達門檻後「開路」一段時間，期間所有呼叫快速失敗，
避免對已故障的資料庫雪崩式重試；冷卻期過後放行一次試探(半開)。
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable

from sqlalchemy.exc import InterfaceError, OperationalError
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

logger = logging.getLogger(__name__)

# 可重試的錯誤類型(僅連線類)。
# OSError: 資料庫整台斷線時 asyncpg 拋 OS 層連線錯誤且不被 SQLAlchemy 包裝；
# 多位址(IPv4+IPv6)同時被拒時甚至合併成「普通 OSError」而非 ConnectionError 子類
# (2026-06-11 崩潰演練實測兩輪抓到，原清單漏了導致 0 次重試)。
# 在資料庫操作情境中 OSError ≈ 網路/socket 問題，整類可重試；
# 資料類錯誤(IntegrityError 等)非 OSError 家族，不受影響。
RETRYABLE_ERRORS = (OperationalError, InterfaceError, OSError)


async def with_retry[T](
    operation: Callable[[], Awaitable[T]],
    *,
    attempts: int = 3,
    wait_min: float = 0.1,
    wait_max: float = 2.0,
) -> T:
    """以指數退避重試連線類錯誤，最多 attempts 次，最後一次仍失敗就拋原錯誤。"""
    retrying = AsyncRetrying(
        stop=stop_after_attempt(attempts),
        wait=wait_exponential(min=wait_min, max=wait_max),
        retry=retry_if_exception_type(RETRYABLE_ERRORS),
        reraise=True,
        before_sleep=lambda state: logger.warning(
            "資料庫操作失敗，準備第 %d 次重試", state.attempt_number + 1
        ),
    )
    return await retrying(operation)


class CircuitBreakerOpenError(RuntimeError):
    """熔斷器開路中，呼叫被快速拒絕。"""


class CircuitBreaker:
    """連續失敗達門檻後開路 recovery_seconds 秒。

    clock 參數可注入假時鐘，測試不必真等冷卻時間。
    """

    def __init__(
        self,
        *,
        failure_threshold: int = 5,
        recovery_seconds: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._failure_threshold = failure_threshold
        self._recovery_seconds = recovery_seconds
        self._clock = clock
        self._failure_count = 0
        self._opened_at: float | None = None

    @property
    def is_open(self) -> bool:
        """是否處於開路狀態(冷卻期過後視為半開，放行試探)。"""
        if self._opened_at is None:
            return False
        return self._clock() - self._opened_at < self._recovery_seconds

    @property
    def failure_count(self) -> int:
        return self._failure_count

    async def call[T](self, operation: Callable[[], Awaitable[T]]) -> T:
        """經熔斷器執行操作: 開路時快速失敗，成功時重置計數。"""
        if self.is_open:
            raise CircuitBreakerOpenError(
                f"熔斷器開路中(連續失敗 {self._failure_count} 次)，請稍後再試"
            )
        try:
            result = await operation()
        except Exception:
            self._record_failure()
            raise
        self._reset()
        return result

    def _record_failure(self) -> None:
        self._failure_count += 1
        if self._failure_count >= self._failure_threshold:
            self._opened_at = self._clock()
            logger.warning("熔斷器開路: 連續失敗 %d 次", self._failure_count)

    def _reset(self) -> None:
        self._failure_count = 0
        self._opened_at = None
