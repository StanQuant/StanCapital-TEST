"""src/data/reconnect.py 單元測試 · backoff golden 序列 / jitter 邊界 / 熔斷遷移。"""

from __future__ import annotations

import pytest
from src.data.reconnect import (
    DEFAULT_CIRCUIT_OPEN_THRESHOLD,
    DEFAULT_CONNECT_TIMEOUT_SECONDS,
    DEFAULT_INITIAL_BACKOFF_SECONDS,
    DEFAULT_MAX_BACKOFF_SECONDS,
    DEFAULT_MULTIPLIER,
    DEFAULT_PROBE_INTERVAL_SECONDS,
    DEFAULT_STABLE_RESET_SECONDS,
    ReconnectController,
    ReconnectPolicy,
    base_delay,
)


class FakeClock:
    """可撥動的假時鐘(monotonic 語意)。"""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class TestConstants:
    def test_d7_defaults_pinned(self) -> None:
        # D7 裁決初值：1s / 2x / 60s / 10 次 / 60s 重置 / 60s 探測 / 30s 控制面逾時
        assert DEFAULT_INITIAL_BACKOFF_SECONDS == 1.0
        assert DEFAULT_MULTIPLIER == 2.0
        assert DEFAULT_MAX_BACKOFF_SECONDS == 60.0
        assert DEFAULT_CIRCUIT_OPEN_THRESHOLD == 10
        assert DEFAULT_STABLE_RESET_SECONDS == 60.0
        assert DEFAULT_PROBE_INTERVAL_SECONDS == 60.0
        # 2026-08-21 事故後新增：控制面呼叫逾時上限
        assert DEFAULT_CONNECT_TIMEOUT_SECONDS == 30.0

    def test_policy_defaults_match_constants(self) -> None:
        policy = ReconnectPolicy()
        assert policy.initial_backoff_seconds == DEFAULT_INITIAL_BACKOFF_SECONDS
        assert policy.multiplier == DEFAULT_MULTIPLIER
        assert policy.max_backoff_seconds == DEFAULT_MAX_BACKOFF_SECONDS
        assert policy.circuit_open_threshold == DEFAULT_CIRCUIT_OPEN_THRESHOLD
        assert policy.stable_reset_seconds == DEFAULT_STABLE_RESET_SECONDS
        assert policy.probe_interval_seconds == DEFAULT_PROBE_INTERVAL_SECONDS
        assert policy.connect_timeout_seconds == DEFAULT_CONNECT_TIMEOUT_SECONDS


class TestPolicyValidation:
    @pytest.mark.parametrize(
        ("field_name", "value", "prefix"),
        [
            ("initial_backoff_seconds", 0, "initial_backoff_seconds 必須 > 0"),
            ("initial_backoff_seconds", float("nan"), "initial_backoff_seconds 不可為 NaN"),
            ("multiplier", 0.5, "multiplier 必須 >= 1.0"),
            ("multiplier", 0, "multiplier 必須 > 0"),
            ("max_backoff_seconds", 0.5, "max_backoff_seconds(0.5) 不可小於"),
            ("circuit_open_threshold", 0, "circuit_open_threshold 必須 >= 1"),
            ("circuit_open_threshold", True, "circuit_open_threshold 必須是正整數"),
            ("stable_reset_seconds", 0, "stable_reset_seconds 必須 > 0"),
            ("probe_interval_seconds", -1, "probe_interval_seconds 必須 > 0"),
            ("connect_timeout_seconds", 0, "connect_timeout_seconds 必須 > 0"),
            ("connect_timeout_seconds", float("nan"), "connect_timeout_seconds 不可為 NaN"),
        ],
    )
    def test_bad_values_rejected(self, field_name: str, value: object, prefix: str) -> None:
        with pytest.raises(ValueError) as exc:
            ReconnectPolicy(**{field_name: value})  # type: ignore[arg-type]
        assert str(exc.value).startswith(prefix)

    def test_bool_initial_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            ReconnectPolicy(initial_backoff_seconds=True)
        assert str(exc.value) == "initial_backoff_seconds 必須是數值，不可為 bool"


class TestBaseDelay:
    def test_golden_sequence(self) -> None:
        # D7 golden：1, 2, 4, 8, 16, 32, 60(封頂), 60, ...
        policy = ReconnectPolicy()
        assert [base_delay(policy, n) for n in range(1, 9)] == [
            1.0,
            2.0,
            4.0,
            8.0,
            16.0,
            32.0,
            60.0,
            60.0,
        ]

    @pytest.mark.parametrize("bad", [0, -1])
    def test_non_positive_failure_count_rejected(self, bad: int) -> None:
        with pytest.raises(ValueError) as exc:
            base_delay(ReconnectPolicy(), bad)
        assert str(exc.value) == f"failure_count 必須 >= 1：{bad}"

    def test_bool_failure_count_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            base_delay(ReconnectPolicy(), True)
        assert str(exc.value) == "failure_count 必須是正整數，不可為 bool"


class TestController:
    def test_initial_state(self) -> None:
        controller = ReconnectController(ReconnectPolicy())
        assert controller.failure_count == 0
        assert controller.is_circuit_open is False
        assert controller.next_delay() == 0.0
        assert controller.policy == ReconnectPolicy()

    def test_full_jitter_bounds(self) -> None:
        # full jitter = uniform(0, base)：rng=0 → 0；rng→1 → 逼近 base
        policy = ReconnectPolicy()
        low = ReconnectController(policy, rng=lambda: 0.0)
        high = ReconnectController(policy, rng=lambda: 1.0)
        for controller in (low, high):
            controller.record_failure()
        assert low.next_delay() == 0.0
        assert high.next_delay() == 1.0

    def test_jitter_scales_with_backoff(self) -> None:
        controller = ReconnectController(ReconnectPolicy(), rng=lambda: 0.5)
        for _ in range(3):
            controller.record_failure()
        assert controller.next_delay() == 4.0 * 0.5  # base=4(第 3 次失敗)、jitter=0.5

    def test_circuit_opens_at_threshold(self) -> None:
        controller = ReconnectController(ReconnectPolicy(circuit_open_threshold=3), rng=lambda: 1.0)
        controller.record_failure()
        controller.record_failure()
        assert controller.is_circuit_open is False
        controller.record_failure()
        assert controller.is_circuit_open is True

    def test_circuit_open_delay_is_probe_interval(self) -> None:
        # 熔斷開路：不再指數增長，固定降頻探測(可觀測而非無聲重擊)
        controller = ReconnectController(
            ReconnectPolicy(circuit_open_threshold=2, probe_interval_seconds=60.0),
            rng=lambda: 0.0,  # 就算 rng=0 也必須回 probe interval(不吃 jitter)
        )
        controller.record_failure()
        controller.record_failure()
        assert controller.next_delay() == 60.0

    def test_success_closes_circuit(self) -> None:
        clock = FakeClock()
        controller = ReconnectController(ReconnectPolicy(circuit_open_threshold=2), clock=clock)
        controller.record_failure()
        controller.record_failure()
        assert controller.is_circuit_open is True
        controller.record_success()
        assert controller.is_circuit_open is False

    def test_flapping_does_not_reset_count(self) -> None:
        # 閃斷(連上又立刻掉)不得洗掉退避進度——計數繼續累積直到熔斷
        clock = FakeClock()
        controller = ReconnectController(
            ReconnectPolicy(circuit_open_threshold=3, stable_reset_seconds=60.0), clock=clock
        )
        controller.record_failure()
        controller.record_failure()
        clock.now = 100.0
        controller.record_success()
        clock.now = 130.0  # 只穩定 30s(< 60s)就又掉線
        controller.record_failure()
        assert controller.failure_count == 3
        assert controller.is_circuit_open is True

    def test_stable_connection_resets_count(self) -> None:
        # 穩定滿 60s 後的下一次失敗：視為新事故，從 1 重新起算
        clock = FakeClock()
        controller = ReconnectController(
            ReconnectPolicy(circuit_open_threshold=3, stable_reset_seconds=60.0), clock=clock
        )
        controller.record_failure()
        controller.record_failure()
        clock.now = 100.0
        controller.record_success()
        clock.now = 161.0  # 穩定 61s(>= 60s)
        controller.record_failure()
        assert controller.failure_count == 1
        assert controller.is_circuit_open is False

    def test_default_rng_and_clock_paths(self) -> None:
        # 預設 rng / clock(真 random 與 monotonic)：驗證行為邊界而非精確值
        controller = ReconnectController(ReconnectPolicy())
        controller.record_failure()
        delay = controller.next_delay()
        assert 0.0 <= delay <= 1.0  # base=1，full jitter 落在 [0, 1)
        controller.record_success()
        controller.record_failure()
        assert controller.failure_count == 2  # monotonic 下不可能瞬間穩定 60s
