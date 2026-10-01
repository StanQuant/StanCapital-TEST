"""L2 重連策略 · exponential backoff + full jitter + circuit breaker(D7)。

參數全部集中在 ReconnectPolicy(1s / 2x / 60s 上限 / 連續失敗 10 次熔斷 /
穩定 60s 重置 / 熔斷後每 60s 降頻探測 / 控制面呼叫 30s 逾時)，golden 測試釘住。

設計：控制器是純狀態機——不 sleep、不連線、不記 log；由 adapter 拿
next_delay() 自行排程並把狀態送 S09 遙測。rng / clock 可注入，測試決定性。

為什麼要 circuit breaker：無上限快速重試會打爆來源限流(Binance 418 封 IP
前例)；熔斷開路讓故障「可觀測」而非無聲重擊，也是 §15 長跑報告判定
「資料黑洞」的依據。
"""

from __future__ import annotations

import math
import random
import time
from collections.abc import Callable
from dataclasses import dataclass

# D7 裁決初值(實測後可調，全部集中此處)
DEFAULT_INITIAL_BACKOFF_SECONDS = 1.0
DEFAULT_MULTIPLIER = 2.0
DEFAULT_MAX_BACKOFF_SECONDS = 60.0
DEFAULT_CIRCUIT_OPEN_THRESHOLD = 10
DEFAULT_STABLE_RESET_SECONDS = 60.0
DEFAULT_PROBE_INTERVAL_SECONDS = 60.0
# 控制面(connect / send)呼叫逾時上限。2026-08-21 事故後新增，見 ReconnectPolicy 欄位說明。
DEFAULT_CONNECT_TIMEOUT_SECONDS = 30.0


def _ensure_positive_float(name: str, value: float) -> None:
    """必須是正的有限浮點數(bool 不算)。"""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} 必須是數值，不可為 {type(value).__name__}")
    if not math.isfinite(value):
        raise ValueError(f"{name} 不可為 NaN / Infinity：{value}")
    if value <= 0:
        raise ValueError(f"{name} 必須 > 0：{value}")


@dataclass(frozen=True, slots=True)
class ReconnectPolicy:
    """重連參數(D7)。預設值即 Stanley 裁決初值。"""

    initial_backoff_seconds: float = DEFAULT_INITIAL_BACKOFF_SECONDS
    multiplier: float = DEFAULT_MULTIPLIER
    max_backoff_seconds: float = DEFAULT_MAX_BACKOFF_SECONDS
    circuit_open_threshold: int = DEFAULT_CIRCUIT_OPEN_THRESHOLD
    stable_reset_seconds: float = DEFAULT_STABLE_RESET_SECONDS
    probe_interval_seconds: float = DEFAULT_PROBE_INTERVAL_SECONDS
    connect_timeout_seconds: float = DEFAULT_CONNECT_TIMEOUT_SECONDS
    """控制面(connect / send / resubscribe)單次呼叫逾時上限。

    為什麼存在(2026-08-21 事故)：24h gate 第三次長跑時，重連呼叫 transport.connect()
    後永久卡死——底層是 to_thread 包裝的同步 SDK 呼叫，hang 住既不回應也不拋錯。
    退避與熔斷因此完全失效：18 小時只嘗試 1 次，週一交易時段零筆行情，
    而心跳仍持續印 'reconnecting'，看起來像在重試(無聲卡死)。
    逾時把「卡死」轉譯成「斷線」，本檔的退避 / 熔斷才真的會運作。
    """

    def __post_init__(self) -> None:
        _ensure_positive_float("initial_backoff_seconds", self.initial_backoff_seconds)
        _ensure_positive_float("multiplier", self.multiplier)
        if self.multiplier < 1.0:
            raise ValueError(f"multiplier 必須 >= 1.0(否則退避會越縮越短)：{self.multiplier}")
        _ensure_positive_float("max_backoff_seconds", self.max_backoff_seconds)
        if self.max_backoff_seconds < self.initial_backoff_seconds:
            raise ValueError(
                f"max_backoff_seconds({self.max_backoff_seconds}) 不可小於 "
                f"initial_backoff_seconds({self.initial_backoff_seconds})"
            )
        if isinstance(self.circuit_open_threshold, bool) or not isinstance(
            self.circuit_open_threshold, int
        ):
            raise ValueError(
                "circuit_open_threshold 必須是正整數，"
                f"不可為 {type(self.circuit_open_threshold).__name__}"
            )
        if self.circuit_open_threshold < 1:
            raise ValueError(f"circuit_open_threshold 必須 >= 1：{self.circuit_open_threshold}")
        _ensure_positive_float("stable_reset_seconds", self.stable_reset_seconds)
        _ensure_positive_float("probe_interval_seconds", self.probe_interval_seconds)
        _ensure_positive_float("connect_timeout_seconds", self.connect_timeout_seconds)


def base_delay(policy: ReconnectPolicy, failure_count: int) -> float:
    """第 N 次連續失敗後的退避基準(未加 jitter)：min(max, initial * mult^(N-1))。

    純函式，golden 測試直接釘序列：1, 2, 4, 8, 16, 32, 60, 60, ...
    """
    if isinstance(failure_count, bool) or not isinstance(failure_count, int):
        raise ValueError(f"failure_count 必須是正整數，不可為 {type(failure_count).__name__}")
    if failure_count < 1:
        raise ValueError(f"failure_count 必須 >= 1：{failure_count}")
    raw = policy.initial_backoff_seconds * policy.multiplier ** (failure_count - 1)
    return min(policy.max_backoff_seconds, raw)


class ReconnectController:
    """重連狀態機 · full jitter 退避 + 熔斷 + 穩定期重置。

    使用方式(adapter 端)：
        斷線 → record_failure() → await sleep(next_delay()) → 重連
        連上 → record_success()
        熔斷開路時 next_delay() 固定回 probe_interval(降頻探測，不再指數增長)
    """

    def __init__(
        self,
        policy: ReconnectPolicy,
        *,
        rng: Callable[[], float] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._policy = policy
        # full jitter 用途是「錯開重連風暴」不是密碼學，random 即可
        self._rng: Callable[[], float] = rng if rng is not None else random.random
        self._clock: Callable[[], float] = clock if clock is not None else time.monotonic
        self._failure_count = 0
        self._circuit_open = False
        self._connected_since: float | None = None

    @property
    def policy(self) -> ReconnectPolicy:
        return self._policy

    @property
    def failure_count(self) -> int:
        """目前連續失敗次數(穩定期後的下一次失敗會從 1 重新起算)。"""
        return self._failure_count

    @property
    def is_circuit_open(self) -> bool:
        return self._circuit_open

    def record_failure(self) -> None:
        """記一次連線失敗；達門檻即熔斷開路。

        若上一段連線已維持滿 stable_reset_seconds，視為「先前故障已痊癒」，
        失敗計數從 1 重新起算(穩定期重置，D7)。
        """
        if self._connected_since is not None:
            stable = self._clock() - self._connected_since >= self._policy.stable_reset_seconds
            self._failure_count = 0 if stable else self._failure_count
            self._connected_since = None
        self._failure_count += 1
        if self._failure_count >= self._policy.circuit_open_threshold:
            self._circuit_open = True

    def record_success(self) -> None:
        """記一次連線成功：熔斷關閉、開始累計穩定期。

        失敗計數不立即歸零——閃斷(連上又立刻掉)不該洗掉退避進度，
        必須穩定滿 stable_reset_seconds 才算痊癒(見 record_failure)。
        """
        self._circuit_open = False
        self._connected_since = self._clock()

    def next_delay(self) -> float:
        """下一次重連前應等待的秒數。

        - 熔斷開路：固定 probe_interval_seconds(降頻探測，可觀測而非無聲重擊)。
        - 正常退避：full jitter = uniform(0, base_delay)，錯開重連風暴。
        - 尚未失敗過：0(立即可連)。
        """
        if self._circuit_open:
            return self._policy.probe_interval_seconds
        if self._failure_count == 0:
            return 0.0
        return base_delay(self._policy, self._failure_count) * self._rng()
