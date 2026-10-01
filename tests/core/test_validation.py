"""src/core/validation.py 的測試 · fail-closed 守門函式逐分支驗證。

對應 S01 規格 §8.2「Dataclass __post_init__ 驗證 100% 必達」。
每個 raise 分支都有正反案例，確保髒值一律被擋（熔斷思維）。
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest
from src.core.validation import (
    ensure_confidence,
    ensure_decimal,
    ensure_finite,
    ensure_non_empty,
    ensure_non_negative,
    ensure_non_negative_int,
    ensure_positive,
    ensure_utc,
)


class TestEnsureNonEmpty:
    def test_空字串被擋(self) -> None:
        with pytest.raises(ValueError, match="不可為空字串"):
            ensure_non_empty("tenant_id", "")

    def test_非空通過(self) -> None:
        ensure_non_empty("tenant_id", "stanley")  # 不拋即通過


class TestEnsureDecimal:
    def test_float_冒充被擋(self) -> None:
        # 0.1 + 0.2 = 0.30000000000000004，正是用 Decimal 要避免的浮點誤差
        with pytest.raises(ValueError, match="必須是 Decimal"):
            ensure_decimal("quantity", 0.1 + 0.2)  # type: ignore[arg-type]

    def test_int_被擋(self) -> None:
        with pytest.raises(ValueError, match="必須是 Decimal"):
            ensure_decimal("quantity", 100)  # type: ignore[arg-type]

    def test_nan_被擋(self) -> None:
        with pytest.raises(ValueError, match="NaN / Infinity"):
            ensure_decimal("quantity", Decimal("NaN"))

    def test_infinity_被擋(self) -> None:
        with pytest.raises(ValueError, match="NaN / Infinity"):
            ensure_decimal("quantity", Decimal("Infinity"))

    def test_合法_decimal_通過(self) -> None:
        ensure_decimal("quantity", Decimal("100.5"))


class TestEnsureFinite:
    def test_允許負與零(self) -> None:
        ensure_finite("pnl", Decimal("-5000"))
        ensure_finite("pnl", Decimal("0"))

    def test_nan_仍被擋(self) -> None:
        with pytest.raises(ValueError, match="NaN / Infinity"):
            ensure_finite("pnl", Decimal("NaN"))


class TestEnsurePositive:
    def test_零被擋(self) -> None:
        with pytest.raises(ValueError, match="必須 > 0"):
            ensure_positive("price", Decimal("0"))

    def test_負被擋(self) -> None:
        with pytest.raises(ValueError, match="必須 > 0"):
            ensure_positive("price", Decimal("-1"))

    def test_正數通過(self) -> None:
        ensure_positive("price", Decimal("700"))


class TestEnsureNonNegative:
    def test_負被擋(self) -> None:
        with pytest.raises(ValueError, match="不可為負"):
            ensure_non_negative("commission", Decimal("-0.01"))

    def test_零與正通過(self) -> None:
        ensure_non_negative("commission", Decimal("0"))
        ensure_non_negative("commission", Decimal("5"))


class TestEnsureNonNegativeInt:
    def test_bool_被擋(self) -> None:
        with pytest.raises(ValueError, match="必須是非負整數"):
            ensure_non_negative_int("duration_ms", True)  # type: ignore[arg-type]

    def test_float_被擋(self) -> None:
        with pytest.raises(ValueError, match="必須是非負整數"):
            ensure_non_negative_int("duration_ms", 1.5)  # type: ignore[arg-type]

    def test_負被擋(self) -> None:
        with pytest.raises(ValueError, match="不可為負"):
            ensure_non_negative_int("duration_ms", -1)

    def test_零與正通過(self) -> None:
        ensure_non_negative_int("duration_ms", 0)
        ensure_non_negative_int("duration_ms", 86_400_000)


class TestEnsureUtc:
    def test_非_datetime_被擋(self) -> None:
        with pytest.raises(ValueError, match="必須是 datetime"):
            ensure_utc("timestamp", "2026-06-18")  # type: ignore[arg-type]

    def test_naive_被擋(self) -> None:
        with pytest.raises(ValueError, match="帶時區"):
            ensure_utc("timestamp", datetime(2026, 6, 18, 12, 0, 0))

    def test_aware_通過(self) -> None:
        ensure_utc("timestamp", datetime(2026, 6, 18, 12, 0, 0, tzinfo=UTC))


class TestEnsureConfidence:
    def test_非數值被擋(self) -> None:
        with pytest.raises(ValueError, match="必須是數值"):
            ensure_confidence("confidence", "high")  # type: ignore[arg-type]

    def test_bool_被擋(self) -> None:
        with pytest.raises(ValueError, match="必須是數值"):
            ensure_confidence("confidence", True)  # type: ignore[arg-type]

    def test_nan_被擋(self) -> None:
        with pytest.raises(ValueError, match="NaN / Infinity"):
            ensure_confidence("confidence", float("nan"))

    def test_infinity_被擋(self) -> None:
        with pytest.raises(ValueError, match="NaN / Infinity"):
            ensure_confidence("confidence", float("inf"))

    def test_超出範圍被擋(self) -> None:
        with pytest.raises(ValueError, match=r"\[0.0, 1.0\]"):
            ensure_confidence("confidence", 1.1)
        with pytest.raises(ValueError, match=r"\[0.0, 1.0\]"):
            ensure_confidence("confidence", -0.1)

    def test_邊界與中間值通過(self) -> None:
        ensure_confidence("confidence", 0.0)
        ensure_confidence("confidence", 1.0)
        ensure_confidence("confidence", 0.5)
