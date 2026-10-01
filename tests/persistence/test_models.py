"""models 自訂欄位型別單元測試 · PreciseDecimal 與 UTCDateTime 的跨方言行為。"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal

import pytest
from sqlalchemy import Numeric, String
from sqlalchemy.dialects.postgresql.asyncpg import PGDialect_asyncpg
from sqlalchemy.dialects.sqlite.aiosqlite import SQLiteDialect_aiosqlite
from src.persistence.models import PreciseDecimal, UTCDateTime, _to_db_decimal

# SQLAlchemy 官方 stub 沒幫 asyncpg 方言建構式標型別，僅此一行豁免
PG = PGDialect_asyncpg()  # type: ignore[no-untyped-call]
SQLITE = SQLiteDialect_aiosqlite()


class TestPreciseDecimal:
    def test_sqlite_存字串避免浮點失真(self) -> None:
        t = PreciseDecimal()
        assert t.process_bind_param(Decimal("612.50000001"), SQLITE) == "612.50000001"

    def test_postgresql_quantize到8位(self) -> None:
        # quantize 後是新 Decimal(8 位小數)，數值相等但補足尾零(不再回傳原物件)
        t = PreciseDecimal()
        result = t.process_bind_param(Decimal("612.5"), PG)
        assert result == Decimal("612.50000000")
        assert str(result) == "612.50000000"

    def test_bind_none(self) -> None:
        assert PreciseDecimal().process_bind_param(None, SQLITE) is None

    def test_讀出一律是_decimal(self) -> None:
        t = PreciseDecimal()
        assert t.process_result_value("612.50000001", SQLITE) == Decimal("612.50000001")
        assert t.process_result_value(Decimal("612.5"), PG) == Decimal("612.5")

    def test_result_none(self) -> None:
        assert PreciseDecimal().process_result_value(None, SQLITE) is None

    def test_dialect_impl_sqlite用字串_pg用numeric(self) -> None:
        t = PreciseDecimal()
        assert isinstance(t.load_dialect_impl(SQLITE), String)
        assert isinstance(t.load_dialect_impl(PG), Numeric)


class TestUTCDateTime:
    def test_naive時間直接擋下(self) -> None:
        with pytest.raises(ValueError, match="tz-aware"):
            UTCDateTime().process_bind_param(datetime(2026, 6, 10, 12, 0, 0), SQLITE)

    def test_非UTC時區寫入前轉UTC(self) -> None:
        taipei = timezone(timedelta(hours=8))
        bound = UTCDateTime().process_bind_param(
            datetime(2026, 6, 10, 20, 0, 0, tzinfo=taipei), SQLITE
        )
        assert bound == datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC)

    def test_bind_none(self) -> None:
        assert UTCDateTime().process_bind_param(None, SQLITE) is None

    def test_讀出naive補回UTC(self) -> None:
        # SQLite 存取會丟失時區，讀出 naive 必須補回 UTC
        result = UTCDateTime().process_result_value(datetime(2026, 6, 10, 12, 0, 0), SQLITE)
        assert result == datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC)

    def test_讀出aware轉成UTC(self) -> None:
        taipei = timezone(timedelta(hours=8))
        result = UTCDateTime().process_result_value(
            datetime(2026, 6, 10, 20, 0, 0, tzinfo=taipei), PG
        )
        assert result is not None
        assert result.tzinfo == UTC
        assert result == datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC)

    def test_result_none(self) -> None:
        assert UTCDateTime().process_result_value(None, SQLITE) is None


class TestToDbDecimal:
    """NUMERIC(20,8) 寫入契約 · 捨入到 8 位 + 整數溢位 fail-closed + 只在真捨入時留痕。"""

    def test_八位以內補尾零_數值不變(self) -> None:
        assert _to_db_decimal(Decimal("612.12345678")) == Decimal("612.12345678")
        assert _to_db_decimal(Decimal("612.5")) == Decimal("612.50000000")

    def test_超過八位_HALF_UP捨入(self) -> None:
        # 第 9 位為 5：ROUND_HALF_UP 進位(對齊 PostgreSQL 的捨入方式)
        assert _to_db_decimal(Decimal("1.123456785")) == Decimal("1.12345679")

    def test_真捨入會發warning(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="src.persistence.models"):
            _to_db_decimal(Decimal("1.123456789"))
        assert len(caplog.records) == 1

    def test_補尾零不發warning_零噪音(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="src.persistence.models"):
            _to_db_decimal(Decimal("612.5"))  # 數值相等只是補尾零，不算改動
        assert caplog.records == []

    def test_整數溢位_直接擋下(self) -> None:
        with pytest.raises(ValueError, match="NUMERIC"):
            _to_db_decimal(Decimal("1000000000000"))  # = 10^12，整數已 13 位

    def test_捨入進位後溢位_也擋下(self) -> None:
        # 原值 < 10^12 通過前置檢查，但 HALF_UP 進位後頂破上限 → 後置檢查擋下
        with pytest.raises(ValueError, match="進位"):
            _to_db_decimal(Decimal("999999999999.999999995"))
