"""src/data/types.py 單元測試 · enum 釘住 / 六組欄位不變式 / frozen+slots。

測試準則(S04 套路)：
- enum 成員名值用完整 dict 相等釘住(防未來改名破壞 serialization)
- 錯誤訊息用 startswith 斷言(mutation-killer：match 子字串殺不掉訊息變異)
- frozen 用賦值必炸、slots 用 not hasattr __dict__
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

import pytest
from src.core.types import OrderSide
from src.data.types import (
    PAYLOAD_KIND_MAP,
    AssetClass,
    BookLevel,
    CorporateAction,
    DataQualityFlag,
    FundamentalReport,
    FundingRate,
    InstrumentLink,
    InstrumentRef,
    InstrumentSpec,
    MacroRelease,
    MarketDataRecord,
    NewsSentiment,
    OnChainMetric,
    OpenInterest,
    OrderBookSnapshot,
    PredictionMarketMetadata,
    QuoteTick,
    RecordKind,
    TradeTick,
)

T0 = datetime(2026, 7, 3, 1, 0, 0, tzinfo=UTC)
T1 = T0 + timedelta(seconds=1)


# ============================================================================
# 工廠：各型別的合法樣本(供參數化 frozen/slots 與 record 測試共用)
# ============================================================================


def make_ref() -> InstrumentRef:
    return InstrumentRef.build(
        asset_class=AssetClass.TW_STOCK,
        venue="twse",
        provider_id="replay",
        symbol="2330",
        currency="TWD",
    )


def make_spec() -> InstrumentSpec:
    return InstrumentSpec(
        tick_size=Decimal("0.5"),
        lot_size=Decimal("1000"),
        contract_multiplier=Decimal("1"),
        timezone="Asia/Taipei",
        session="regular",
    )


def make_quote() -> QuoteTick:
    return QuoteTick(
        bid=Decimal("999"),
        ask=Decimal("1000"),
        bid_size=Decimal("5"),
        ask_size=Decimal("3"),
    )


def make_trade() -> TradeTick:
    return TradeTick(price=Decimal("1000"), volume=Decimal("2"), aggressor_side=OrderSide.BUY)


def make_book() -> OrderBookSnapshot:
    return OrderBookSnapshot(
        bids=(
            BookLevel(price=Decimal("999"), size=Decimal("5")),
            BookLevel(price=Decimal("998"), size=Decimal("7")),
        ),
        asks=(
            BookLevel(price=Decimal("1000"), size=Decimal("3")),
            BookLevel(price=Decimal("1001"), size=Decimal("9")),
        ),
    )


def make_open_interest() -> OpenInterest:
    return OpenInterest(open_interest=Decimal("12345"))


def make_funding_rate() -> FundingRate:
    return FundingRate(funding_rate=Decimal("-0.0001"), next_funding_at=T1)


def make_corporate_action() -> CorporateAction:
    return CorporateAction(
        action_type="cash_dividend", ex_date=date(2026, 7, 15), ratio=Decimal("3.5")
    )


def make_macro_release() -> MacroRelease:
    return MacroRelease(
        indicator_id="fred:CPIAUCSL",
        period="2026-06",
        actual=Decimal("321.5"),
        consensus=Decimal("321.0"),
    )


def make_fundamental_report() -> FundamentalReport:
    return FundamentalReport(
        report_type="10-K",
        fiscal_period="2026Q2",
        filing_url="https://mops.twse.com.tw/filing/2330",
    )


def make_news_sentiment() -> NewsSentiment:
    return NewsSentiment(
        event_id="gdelt:20260703-0001",
        source_url="https://example.com/news/1",
        source_domain="example.com",
        published_at=T0,
        themes=("ECON_INFLATION",),
        tone=-2.5,
        attribution_notice="Data provided by GDELT (https://www.gdeltproject.org/)",
    )


def make_on_chain_metric() -> OnChainMetric:
    return OnChainMetric(metric_id="glassnode:sopr", chain="bitcoin", value=Decimal("1.02"))


def make_prediction_market_metadata() -> PredictionMarketMetadata:
    return PredictionMarketMetadata(
        market_id="pm:example-2026",
        outcome="YES",
        probability=0.63,
        resolution_source="https://example.com/rules",
        close_time=T1,
        region_restrictions=("US", "UK"),
    )


PAYLOAD_FACTORIES = {
    RecordKind.QUOTE: make_quote,
    RecordKind.TRADE: make_trade,
    RecordKind.ORDER_BOOK: make_book,
    RecordKind.OPEN_INTEREST: make_open_interest,
    RecordKind.FUNDING_RATE: make_funding_rate,
    RecordKind.CORPORATE_ACTION: make_corporate_action,
    RecordKind.MACRO_RELEASE: make_macro_release,
    RecordKind.FUNDAMENTAL_REPORT: make_fundamental_report,
    RecordKind.NEWS_SENTIMENT: make_news_sentiment,
    RecordKind.ON_CHAIN_METRIC: make_on_chain_metric,
    RecordKind.PREDICTION_MARKET_METADATA: make_prediction_market_metadata,
}


def make_record(kind: RecordKind = RecordKind.TRADE, **overrides: object) -> MarketDataRecord:
    values: dict[str, object] = {
        "instrument": make_ref(),
        "spec": make_spec(),
        "source_timestamp": T0,
        "ingest_timestamp": T1,
        "sequence": 42,
        "payload": PAYLOAD_FACTORIES[kind](),
        "data_quality_flags": frozenset(),
        "license_tag": "replay-internal",
        "tenant_id": "acme",
    }
    values.update(overrides)
    return MarketDataRecord(**values)  # type: ignore[arg-type]


# ============================================================================
# Enum 釘住(完整 dict 相等，防改名/增刪)
# ============================================================================


class TestEnums:
    def test_asset_class_members_pinned(self) -> None:
        assert {m.name: m.value for m in AssetClass} == {
            "TW_STOCK": "tw_stock",
            "US_STOCK": "us_stock",
            "CRYPTO_SPOT": "crypto_spot",
            "FUTURES": "futures",
            "OPTIONS": "options",
            "MACRO": "macro",
            "FUNDAMENTAL": "fundamental",
            "NEWS": "news",
            "SENTIMENT": "sentiment",
            "ON_CHAIN": "on_chain",
            "PREDICTION_MARKET": "prediction_market",
        }

    def test_asset_class_has_exactly_11_members(self) -> None:
        assert len(AssetClass) == 11

    def test_data_quality_flag_members_pinned(self) -> None:
        assert {m.name: m.value for m in DataQualityFlag} == {
            "MISSING": "missing",
            "OUT_OF_ORDER": "out_of_order",
            "LATE": "late",
            "SUSPECT": "suspect",
            "GAP_DETECTED": "gap_detected",
            "REPLAYED": "replayed",
        }

    def test_record_kind_members_pinned(self) -> None:
        assert {m.name: m.value for m in RecordKind} == {
            "QUOTE": "quote",
            "TRADE": "trade",
            "ORDER_BOOK": "order_book",
            "OPEN_INTEREST": "open_interest",
            "FUNDING_RATE": "funding_rate",
            "CORPORATE_ACTION": "corporate_action",
            "MACRO_RELEASE": "macro_release",
            "FUNDAMENTAL_REPORT": "fundamental_report",
            "NEWS_SENTIMENT": "news_sentiment",
            "ON_CHAIN_METRIC": "on_chain_metric",
            "PREDICTION_MARKET_METADATA": "prediction_market_metadata",
        }

    def test_payload_kind_map_is_bijection_over_all_kinds(self) -> None:
        # 每個 RecordKind 恰有一個 payload 型別對應(雙射；漏一個都是 schema 缺口)
        assert set(PAYLOAD_KIND_MAP.values()) == set(RecordKind)
        assert len(PAYLOAD_KIND_MAP) == len(RecordKind) == 11


# ============================================================================
# frozen + slots(參數化全部值物件)
# ============================================================================

ALL_FACTORIES = [
    make_ref,
    make_spec,
    make_quote,
    make_trade,
    make_book,
    make_open_interest,
    make_funding_rate,
    make_corporate_action,
    make_macro_release,
    make_fundamental_report,
    make_news_sentiment,
    make_on_chain_metric,
    make_prediction_market_metadata,
    make_record,
    lambda: InstrumentLink(link_type="adr_of", target_instrument_id="us_stock:nyse:TSM"),
    lambda: BookLevel(price=Decimal("1"), size=Decimal("1")),
]


class TestImmutability:
    @pytest.mark.parametrize("factory", ALL_FACTORIES)
    def test_frozen(self, factory) -> None:
        obj = factory()
        first_field = dataclasses.fields(obj)[0].name
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(obj, first_field, "x")

    @pytest.mark.parametrize("factory", ALL_FACTORIES)
    def test_slots(self, factory) -> None:
        assert not hasattr(factory(), "__dict__")


# ============================================================================
# InstrumentLink
# ============================================================================


class TestInstrumentLink:
    def test_valid(self) -> None:
        link = InstrumentLink(link_type="future_of", target_instrument_id="futures:taifex:TXF")
        assert link.target_instrument_id == "futures:taifex:TXF"

    def test_empty_link_type_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            InstrumentLink(link_type="", target_instrument_id="tw_stock:twse:2330")
        assert str(exc.value) == "link_type 不可為空字串"

    def test_target_must_have_three_segments(self) -> None:
        with pytest.raises(ValueError) as exc:
            InstrumentLink(link_type="adr_of", target_instrument_id="twse:2330")
        assert str(exc.value).startswith(
            "target_instrument_id 必須是三段制 asset_class:venue:symbol"
        )

    def test_target_asset_class_must_be_valid(self) -> None:
        with pytest.raises(ValueError) as exc:
            InstrumentLink(link_type="adr_of", target_instrument_id="stock:twse:2330")
        assert str(exc.value).startswith(
            "target_instrument_id 的 asset_class 段不是合法 AssetClass"
        )

    def test_target_venue_charset_enforced(self) -> None:
        with pytest.raises(ValueError) as exc:
            InstrumentLink(link_type="adr_of", target_instrument_id="tw_stock:TWSE:2330")
        assert "venue 段 只允許小寫英數、底線、連字號" in str(exc.value)

    def test_target_symbol_charset_enforced(self) -> None:
        with pytest.raises(ValueError) as exc:
            InstrumentLink(link_type="adr_of", target_instrument_id="tw_stock:twse:23 30")
        assert "symbol 段 不可含空白或冒號" in str(exc.value)


# ============================================================================
# InstrumentRef
# ============================================================================


class TestInstrumentRef:
    def test_build_composes_instrument_id(self) -> None:
        ref = make_ref()
        assert ref.instrument_id == "tw_stock:twse:2330"
        assert ref.links == ()

    def test_mismatched_instrument_id_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            InstrumentRef(
                asset_class=AssetClass.TW_STOCK,
                venue="twse",
                provider_id="replay",
                instrument_id="tw_stock:twse:0050",
                symbol="2330",
                currency="TWD",
            )
        assert str(exc.value).startswith("instrument_id 必須等於 'tw_stock:twse:2330'")

    def test_empty_venue_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            InstrumentRef.build(
                asset_class=AssetClass.TW_STOCK,
                venue="",
                provider_id="replay",
                symbol="2330",
                currency="TWD",
            )
        assert str(exc.value) == "venue 不可為空字串"

    def test_uppercase_venue_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            InstrumentRef.build(
                asset_class=AssetClass.TW_STOCK,
                venue="TWSE",
                provider_id="replay",
                symbol="2330",
                currency="TWD",
            )
        assert str(exc.value).startswith("venue 只允許小寫英數、底線、連字號")

    def test_empty_provider_id_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            InstrumentRef.build(
                asset_class=AssetClass.TW_STOCK,
                venue="twse",
                provider_id="",
                symbol="2330",
                currency="TWD",
            )
        assert str(exc.value) == "provider_id 不可為空字串"

    @pytest.mark.parametrize("bad_symbol", ["", "23:30", "23 30"])
    def test_bad_symbol_rejected(self, bad_symbol: str) -> None:
        with pytest.raises(ValueError):
            InstrumentRef.build(
                asset_class=AssetClass.TW_STOCK,
                venue="twse",
                provider_id="replay",
                symbol=bad_symbol,
                currency="TWD",
            )

    def test_symbol_with_dot_allowed(self) -> None:
        # BRK.B 類美股代碼必須可用(場所原生代碼)
        ref = InstrumentRef.build(
            asset_class=AssetClass.US_STOCK,
            venue="nyse",
            provider_id="replay",
            symbol="BRK.B",
            currency="USD",
        )
        assert ref.instrument_id == "us_stock:nyse:BRK.B"

    @pytest.mark.parametrize("bad_currency", ["", "twd", "TW", "T" * 11, "1WD"])
    def test_bad_currency_rejected(self, bad_currency: str) -> None:
        with pytest.raises(ValueError):
            InstrumentRef.build(
                asset_class=AssetClass.TW_STOCK,
                venue="twse",
                provider_id="replay",
                symbol="2330",
                currency=bad_currency,
            )

    @pytest.mark.parametrize("good_currency", ["TWD", "USD", "USDT", "USDC1"])
    def test_good_currency_accepted(self, good_currency: str) -> None:
        ref = InstrumentRef.build(
            asset_class=AssetClass.CRYPTO_SPOT,
            venue="binance",
            provider_id="replay",
            symbol="BTCUSDT",
            currency=good_currency,
        )
        assert ref.currency == good_currency

    def test_links_carried(self) -> None:
        link = InstrumentLink(link_type="adr_of", target_instrument_id="us_stock:nyse:TSM")
        ref = InstrumentRef.build(
            asset_class=AssetClass.TW_STOCK,
            venue="twse",
            provider_id="replay",
            symbol="2330",
            currency="TWD",
            links=(link,),
        )
        assert ref.links == (link,)


# ============================================================================
# InstrumentSpec
# ============================================================================


class TestInstrumentSpec:
    def test_valid(self) -> None:
        spec = make_spec()
        assert spec.timezone == "Asia/Taipei"

    @pytest.mark.parametrize(
        ("field_name", "value"),
        [
            ("tick_size", Decimal("0")),
            ("lot_size", Decimal("-1")),
            ("contract_multiplier", Decimal("0")),
        ],
    )
    def test_non_positive_decimal_rejected(self, field_name: str, value: Decimal) -> None:
        kwargs: dict[str, object] = {
            "tick_size": Decimal("0.5"),
            "lot_size": Decimal("1000"),
            "contract_multiplier": Decimal("1"),
            "timezone": "Asia/Taipei",
            "session": "regular",
        }
        kwargs[field_name] = value
        with pytest.raises(ValueError) as exc:
            InstrumentSpec(**kwargs)  # type: ignore[arg-type]
        assert str(exc.value) == f"{field_name} 必須 > 0：{value}"

    def test_invalid_timezone_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            InstrumentSpec(
                tick_size=Decimal("0.5"),
                lot_size=Decimal("1000"),
                contract_multiplier=Decimal("1"),
                timezone="Not/AZone",
                session="regular",
            )
        assert str(exc.value).startswith("timezone 必須是有效 IANA 時區名稱")

    def test_empty_session_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            InstrumentSpec(
                tick_size=Decimal("0.5"),
                lot_size=Decimal("1000"),
                contract_multiplier=Decimal("1"),
                timezone="Asia/Taipei",
                session="",
            )
        assert str(exc.value) == "session 不可為空字串"


# ============================================================================
# 行情 payload(第 4 組)
# ============================================================================


class TestQuoteTick:
    def test_valid(self) -> None:
        quote = make_quote()
        assert quote.bid < quote.ask

    def test_crossed_quote_allowed(self) -> None:
        # crossed quote 是真實市場現象，型別層不擋(由 provider 標 SUSPECT)
        quote = QuoteTick(
            bid=Decimal("1001"), ask=Decimal("1000"), bid_size=Decimal("1"), ask_size=Decimal("1")
        )
        assert quote.bid > quote.ask

    @pytest.mark.parametrize(
        ("field_name", "value", "message"),
        [
            ("bid", Decimal("0"), "bid 必須 > 0：0"),
            ("ask", Decimal("-1"), "ask 必須 > 0：-1"),
            ("bid_size", Decimal("-1"), "bid_size 不可為負：-1"),
            ("ask_size", Decimal("-2"), "ask_size 不可為負：-2"),
        ],
    )
    def test_invalid_field_rejected(self, field_name: str, value: Decimal, message: str) -> None:
        kwargs: dict[str, object] = {
            "bid": Decimal("999"),
            "ask": Decimal("1000"),
            "bid_size": Decimal("5"),
            "ask_size": Decimal("3"),
        }
        kwargs[field_name] = value
        with pytest.raises(ValueError) as exc:
            QuoteTick(**kwargs)  # type: ignore[arg-type]
        assert str(exc.value) == message

    def test_zero_size_allowed(self) -> None:
        quote = QuoteTick(
            bid=Decimal("999"), ask=Decimal("1000"), bid_size=Decimal("0"), ask_size=Decimal("0")
        )
        assert quote.bid_size == 0


class TestTradeTick:
    def test_valid_with_side_and_without(self) -> None:
        assert make_trade().aggressor_side is OrderSide.BUY
        anonymous = TradeTick(price=Decimal("1"), volume=Decimal("1"), aggressor_side=None)
        assert anonymous.aggressor_side is None

    def test_zero_price_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            TradeTick(price=Decimal("0"), volume=Decimal("1"), aggressor_side=None)
        assert str(exc.value) == "price 必須 > 0：0"

    def test_zero_volume_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            TradeTick(price=Decimal("1"), volume=Decimal("0"), aggressor_side=None)
        assert str(exc.value) == "volume 必須 > 0：0"


class TestOrderBookSnapshot:
    def test_valid_and_properties(self) -> None:
        book = make_book()
        assert book.best_bid == BookLevel(price=Decimal("999"), size=Decimal("5"))
        assert book.best_ask == BookLevel(price=Decimal("1000"), size=Decimal("3"))
        assert book.depth == 2

    def test_empty_sides_allowed(self) -> None:
        book = OrderBookSnapshot(bids=(), asks=())
        assert book.best_bid is None
        assert book.best_ask is None
        assert book.depth == 0

    def test_depth_takes_deeper_side(self) -> None:
        book = OrderBookSnapshot(
            bids=(BookLevel(price=Decimal("9"), size=Decimal("1")),),
            asks=(
                BookLevel(price=Decimal("10"), size=Decimal("1")),
                BookLevel(price=Decimal("11"), size=Decimal("1")),
                BookLevel(price=Decimal("12"), size=Decimal("1")),
            ),
        )
        assert book.depth == 3

    def test_bids_must_be_strictly_descending(self) -> None:
        with pytest.raises(ValueError) as exc:
            OrderBookSnapshot(
                bids=(
                    BookLevel(price=Decimal("999"), size=Decimal("1")),
                    BookLevel(price=Decimal("999"), size=Decimal("2")),
                ),
                asks=(),
            )
        assert str(exc.value).startswith("bids 檔位價格必須嚴格遞減")

    def test_asks_must_be_strictly_ascending(self) -> None:
        with pytest.raises(ValueError) as exc:
            OrderBookSnapshot(
                bids=(),
                asks=(
                    BookLevel(price=Decimal("1001"), size=Decimal("1")),
                    BookLevel(price=Decimal("1000"), size=Decimal("2")),
                ),
            )
        assert str(exc.value).startswith("asks 檔位價格必須嚴格遞增")

    def test_book_level_invariants(self) -> None:
        with pytest.raises(ValueError):
            BookLevel(price=Decimal("0"), size=Decimal("1"))
        with pytest.raises(ValueError):
            BookLevel(price=Decimal("1"), size=Decimal("0"))


class TestOpenInterest:
    def test_zero_allowed_negative_rejected(self) -> None:
        assert OpenInterest(open_interest=Decimal("0")).open_interest == 0
        with pytest.raises(ValueError) as exc:
            OpenInterest(open_interest=Decimal("-1"))
        assert str(exc.value) == "open_interest 不可為負：-1"


class TestFundingRate:
    def test_negative_rate_allowed(self) -> None:
        assert make_funding_rate().funding_rate < 0

    def test_nan_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            FundingRate(funding_rate=Decimal("NaN"), next_funding_at=None)
        assert str(exc.value) == "funding_rate 不可為 NaN / Infinity：NaN"

    def test_none_next_funding_allowed(self) -> None:
        assert FundingRate(funding_rate=Decimal("0"), next_funding_at=None).next_funding_at is None

    def test_naive_next_funding_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            FundingRate(funding_rate=Decimal("0"), next_funding_at=datetime(2026, 7, 3))
        assert str(exc.value).startswith("next_funding_at 必須是帶時區的 datetime")


# ============================================================================
# 事件研究 payload(第 5 組)
# ============================================================================


class TestCorporateAction:
    def test_valid(self) -> None:
        assert make_corporate_action().ex_date == date(2026, 7, 15)

    def test_empty_action_type_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            CorporateAction(action_type="", ex_date=date(2026, 7, 15), ratio=Decimal("1"))
        assert str(exc.value) == "action_type 不可為空字串"

    def test_datetime_as_ex_date_rejected(self) -> None:
        # datetime 是 date 子類，但除權日是日曆日概念，帶時分秒＝時區歧義
        with pytest.raises(ValueError) as exc:
            CorporateAction(
                action_type="cash_dividend",
                ex_date=datetime(2026, 7, 15, tzinfo=UTC),  # type: ignore[arg-type]
                ratio=Decimal("1"),
            )
        assert str(exc.value) == "ex_date 必須是 date(不可為 datetime)"

    def test_zero_ratio_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            CorporateAction(action_type="split", ex_date=date(2026, 7, 15), ratio=Decimal("0"))
        assert str(exc.value) == "ratio 必須 > 0：0"


class TestMacroRelease:
    def test_valid_and_consensus_optional(self) -> None:
        assert make_macro_release().consensus == Decimal("321.0")
        no_consensus = MacroRelease(
            indicator_id="fred:GDP", period="2026Q1", actual=Decimal("1"), consensus=None
        )
        assert no_consensus.consensus is None

    @pytest.mark.parametrize("field_name", ["indicator_id", "period"])
    def test_empty_identity_rejected(self, field_name: str) -> None:
        kwargs: dict[str, object] = {
            "indicator_id": "fred:GDP",
            "period": "2026Q1",
            "actual": Decimal("1"),
            "consensus": None,
        }
        kwargs[field_name] = ""
        with pytest.raises(ValueError) as exc:
            MacroRelease(**kwargs)  # type: ignore[arg-type]
        assert str(exc.value) == f"{field_name} 不可為空字串"

    def test_nan_actual_rejected(self) -> None:
        with pytest.raises(ValueError):
            MacroRelease(
                indicator_id="fred:GDP", period="2026Q1", actual=Decimal("NaN"), consensus=None
            )

    def test_nan_consensus_rejected(self) -> None:
        with pytest.raises(ValueError):
            MacroRelease(
                indicator_id="fred:GDP",
                period="2026Q1",
                actual=Decimal("1"),
                consensus=Decimal("Infinity"),
            )


class TestFundamentalReport:
    def test_valid(self) -> None:
        assert make_fundamental_report().report_type == "10-K"

    @pytest.mark.parametrize("field_name", ["report_type", "fiscal_period"])
    def test_empty_identity_rejected(self, field_name: str) -> None:
        kwargs: dict[str, object] = {
            "report_type": "10-K",
            "fiscal_period": "2026Q2",
            "filing_url": "https://example.com/f",
        }
        kwargs[field_name] = ""
        with pytest.raises(ValueError) as exc:
            FundamentalReport(**kwargs)  # type: ignore[arg-type]
        assert str(exc.value) == f"{field_name} 不可為空字串"

    def test_non_http_url_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            FundamentalReport(
                report_type="10-K", fiscal_period="2026Q2", filing_url="ftp://example.com/f"
            )
        assert str(exc.value).startswith("filing_url 必須以 http:// 或 https:// 開頭")

    def test_plain_http_allowed(self) -> None:
        report = FundamentalReport(
            report_type="10-K", fiscal_period="2026Q2", filing_url="http://example.com/f"
        )
        assert report.filing_url.startswith("http://")


class TestNewsSentiment:
    def test_schema_has_no_fulltext_field(self) -> None:
        # D10 禁令做進型別：schema 裡「不存在」全文欄位(釘住欄位全集)
        assert {f.name for f in dataclasses.fields(NewsSentiment)} == {
            "event_id",
            "source_url",
            "source_domain",
            "published_at",
            "themes",
            "tone",
            "attribution_notice",
        }

    def test_valid(self) -> None:
        assert make_news_sentiment().tone == -2.5

    def test_bad_source_url_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            NewsSentiment(
                event_id="e1",
                source_url="example.com/news",
                source_domain="example.com",
                published_at=T0,
                themes=(),
                tone=0.0,
                attribution_notice="GDELT",
            )
        assert str(exc.value).startswith("source_url 必須以 http:// 或 https:// 開頭")

    def test_naive_published_at_rejected(self) -> None:
        with pytest.raises(ValueError):
            NewsSentiment(
                event_id="e1",
                source_url="https://example.com",
                source_domain="example.com",
                published_at=datetime(2026, 7, 3),
                themes=(),
                tone=0.0,
                attribution_notice="GDELT",
            )

    def test_empty_theme_element_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            NewsSentiment(
                event_id="e1",
                source_url="https://example.com",
                source_domain="example.com",
                published_at=T0,
                themes=("",),
                tone=0.0,
                attribution_notice="GDELT",
            )
        assert str(exc.value) == "themes 元素 不可為空字串"

    @pytest.mark.parametrize("bad_tone", [100.5, -100.5, float("nan"), float("inf")])
    def test_out_of_range_tone_rejected(self, bad_tone: float) -> None:
        with pytest.raises(ValueError):
            NewsSentiment(
                event_id="e1",
                source_url="https://example.com",
                source_domain="example.com",
                published_at=T0,
                themes=(),
                tone=bad_tone,
                attribution_notice="GDELT",
            )

    @pytest.mark.parametrize("boundary_tone", [-100.0, 100.0, 0])
    def test_boundary_tone_accepted(self, boundary_tone: float) -> None:
        sentiment = NewsSentiment(
            event_id="e1",
            source_url="https://example.com",
            source_domain="example.com",
            published_at=T0,
            themes=(),
            tone=boundary_tone,
            attribution_notice="GDELT",
        )
        assert sentiment.tone == boundary_tone

    def test_bool_tone_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            NewsSentiment(
                event_id="e1",
                source_url="https://example.com",
                source_domain="example.com",
                published_at=T0,
                themes=(),
                tone=True,
                attribution_notice="GDELT",
            )
        assert str(exc.value) == "tone 必須是數值，不可為 bool"

    def test_empty_attribution_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            NewsSentiment(
                event_id="e1",
                source_url="https://example.com",
                source_domain="example.com",
                published_at=T0,
                themes=(),
                tone=0.0,
                attribution_notice="",
            )
        assert str(exc.value) == "attribution_notice 不可為空字串"

    @pytest.mark.parametrize("field_name", ["event_id", "source_domain"])
    def test_empty_identity_rejected(self, field_name: str) -> None:
        kwargs: dict[str, object] = {
            "event_id": "e1",
            "source_url": "https://example.com",
            "source_domain": "example.com",
            "published_at": T0,
            "themes": (),
            "tone": 0.0,
            "attribution_notice": "GDELT",
        }
        kwargs[field_name] = ""
        with pytest.raises(ValueError) as exc:
            NewsSentiment(**kwargs)  # type: ignore[arg-type]
        assert str(exc.value) == f"{field_name} 不可為空字串"


class TestOnChainMetric:
    def test_valid(self) -> None:
        assert make_on_chain_metric().chain == "bitcoin"

    @pytest.mark.parametrize("field_name", ["metric_id", "chain"])
    def test_empty_identity_rejected(self, field_name: str) -> None:
        kwargs: dict[str, object] = {
            "metric_id": "glassnode:sopr",
            "chain": "bitcoin",
            "value": Decimal("1"),
        }
        kwargs[field_name] = ""
        with pytest.raises(ValueError) as exc:
            OnChainMetric(**kwargs)  # type: ignore[arg-type]
        assert str(exc.value) == f"{field_name} 不可為空字串"

    def test_nan_value_rejected(self) -> None:
        with pytest.raises(ValueError):
            OnChainMetric(metric_id="m", chain="c", value=Decimal("NaN"))


class TestPredictionMarketMetadata:
    def test_valid(self) -> None:
        assert make_prediction_market_metadata().probability == 0.63

    @pytest.mark.parametrize("boundary", [0.0, 1.0])
    def test_probability_boundaries_accepted(self, boundary: float) -> None:
        meta = PredictionMarketMetadata(
            market_id="pm:x",
            outcome="YES",
            probability=boundary,
            resolution_source="src",
            close_time=T1,
            region_restrictions=(),
        )
        assert meta.probability == boundary

    def test_out_of_range_probability_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            PredictionMarketMetadata(
                market_id="pm:x",
                outcome="YES",
                probability=1.1,
                resolution_source="src",
                close_time=T1,
                region_restrictions=(),
            )
        assert str(exc.value) == "probability 必須落在 [0.0, 1.0]：1.1"

    def test_naive_close_time_rejected(self) -> None:
        with pytest.raises(ValueError):
            PredictionMarketMetadata(
                market_id="pm:x",
                outcome="YES",
                probability=0.5,
                resolution_source="src",
                close_time=datetime(2026, 7, 3),
                region_restrictions=(),
            )

    def test_empty_region_element_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            PredictionMarketMetadata(
                market_id="pm:x",
                outcome="YES",
                probability=0.5,
                resolution_source="src",
                close_time=T1,
                region_restrictions=("",),
            )
        assert str(exc.value) == "region_restrictions 元素 不可為空字串"

    @pytest.mark.parametrize("field_name", ["market_id", "outcome", "resolution_source"])
    def test_empty_identity_rejected(self, field_name: str) -> None:
        kwargs: dict[str, object] = {
            "market_id": "pm:x",
            "outcome": "YES",
            "probability": 0.5,
            "resolution_source": "src",
            "close_time": T1,
            "region_restrictions": (),
        }
        kwargs[field_name] = ""
        with pytest.raises(ValueError) as exc:
            PredictionMarketMetadata(**kwargs)  # type: ignore[arg-type]
        assert str(exc.value) == f"{field_name} 不可為空字串"


# ============================================================================
# MarketDataRecord
# ============================================================================


class TestMarketDataRecord:
    def test_schema_fields_pinned(self) -> None:
        # 六組欄位全集釘住(規格 §6.2)；動任何欄位前先 rg 構造點(§8.4)
        assert [f.name for f in dataclasses.fields(MarketDataRecord)] == [
            "instrument",
            "spec",
            "source_timestamp",
            "ingest_timestamp",
            "sequence",
            "payload",
            "data_quality_flags",
            "license_tag",
            "tenant_id",
        ]

    @pytest.mark.parametrize("kind", list(RecordKind))
    def test_record_kind_derived_from_payload(self, kind: RecordKind) -> None:
        assert make_record(kind).record_kind is kind

    def test_unknown_payload_type_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            make_record(payload="not-a-payload")
        assert str(exc.value).startswith("payload 型別不在允許清單：str")

    def test_payload_subclass_rejected(self) -> None:
        # 精確型別檢查：子類不算(防偷渡帶額外欄位的變種 payload)
        class SneakyTrade(TradeTick):
            pass

        sneaky = SneakyTrade(price=Decimal("1"), volume=Decimal("1"), aggressor_side=None)
        with pytest.raises(ValueError) as exc:
            make_record(payload=sneaky)
        assert str(exc.value).startswith("payload 型別不在允許清單：SneakyTrade")

    def test_spec_may_be_none(self) -> None:
        assert make_record(spec=None).spec is None

    def test_naive_source_timestamp_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            make_record(source_timestamp=datetime(2026, 7, 3))
        assert str(exc.value).startswith("source_timestamp 必須是帶時區的 datetime")

    def test_naive_ingest_timestamp_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            make_record(ingest_timestamp=datetime(2026, 7, 3))
        assert str(exc.value).startswith("ingest_timestamp 必須是帶時區的 datetime")

    def test_source_after_ingest_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            make_record(source_timestamp=T1, ingest_timestamp=T0)
        assert str(exc.value).startswith("source_timestamp(")

    def test_source_equal_ingest_allowed(self) -> None:
        record = make_record(source_timestamp=T0, ingest_timestamp=T0)
        assert record.source_timestamp == record.ingest_timestamp

    def test_sequence_none_and_zero_allowed(self) -> None:
        assert make_record(sequence=None).sequence is None
        assert make_record(sequence=0).sequence == 0

    def test_negative_sequence_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            make_record(sequence=-1)
        assert str(exc.value) == "sequence 不可為負：-1"

    def test_bool_sequence_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            make_record(sequence=True)
        assert str(exc.value) == "sequence 必須是非負整數，不可為 bool"

    def test_flags_normalized_to_frozenset(self) -> None:
        record = make_record(data_quality_flags={DataQualityFlag.REPLAYED})
        assert isinstance(record.data_quality_flags, frozenset)
        assert record.data_quality_flags == frozenset({DataQualityFlag.REPLAYED})

    def test_non_flag_element_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            make_record(data_quality_flags={"replayed"})
        assert str(exc.value).startswith("data_quality_flags 元素必須是 DataQualityFlag")

    def test_empty_license_tag_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            make_record(license_tag="")
        assert str(exc.value) == "license_tag 不可為空字串"

    def test_empty_tenant_id_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            make_record(tenant_id="")
        assert str(exc.value) == "tenant_id 不可為空字串"

    def test_record_is_hashable(self) -> None:
        # 全欄位皆不可變 → record 可進 set / dict(去重與快取的地基)
        record = make_record()
        assert record in {record}
