"""L2 行情資料型別 · AssetClass / InstrumentRef / payload / MarketDataRecord。

設計準則(沿用 L4 core 套路)：
- 全部 enum 繼承 StrEnum，字串值對應方便序列化
- 全部 dataclass 用 frozen=True + slots=True(不可變 + 省記憶體)
- 價量一律 Decimal、時間一律 tz-aware(拒絕 naive)
- 不變式在 __post_init__ fail-closed 驗證，違反一律 raise ValueError
- MarketDataRecord 是所有 provider 的統一輸出；MarketEvent(L4)是它的降維摘要，
  只能由 bridge 單向轉換，永遠不反向(見規格 §8.3)

與 L4 MarketEvent 的關係：Record 是源頭、Event 是摘要。本模組不 import 任何
供應商名稱(紅線：供應商字樣只准出現在 src/data/providers/ 對應子目錄)。
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from enum import StrEnum
from itertools import pairwise
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from src.core.types import OrderSide
from src.core.validation import (
    ensure_confidence,
    ensure_finite,
    ensure_non_empty,
    ensure_non_negative,
    ensure_positive,
    ensure_utc,
)

# ============================================================================
# Enum · 3 個
# ============================================================================


class AssetClass(StrEnum):
    """資產類別 · 11 個成員第一天全數預留(D2)。

    enum 是 schema，動它成本最高：成員名與值由測試釘住，未來只增不改。
    v0 只有 TW_STOCK 有真 adapter 路徑；未實作的類別由 ProviderCapabilities
    宣告排除，consumer 請求不支援的類別時 fail-closed 拋錯。
    """

    TW_STOCK = "tw_stock"  # 台股
    US_STOCK = "us_stock"  # 美股
    CRYPTO_SPOT = "crypto_spot"  # 加密貨幣現貨
    FUTURES = "futures"  # 期貨
    OPTIONS = "options"  # 選擇權
    MACRO = "macro"  # 宏觀指標(FRED 類)
    FUNDAMENTAL = "fundamental"  # 基本面(財報/EDGAR/MOPS)
    NEWS = "news"  # 新聞事件
    SENTIMENT = "sentiment"  # 輿情
    ON_CHAIN = "on_chain"  # 鏈上指標
    PREDICTION_MARKET = "prediction_market"  # 預測市場(paper-only，B-116)


class DataQualityFlag(StrEnum):
    """資料品質旗標 · 下游(S15 DataQualityGate)依此分級處理。"""

    MISSING = "missing"  # 欄位缺漏(來源未提供必要資訊)
    OUT_OF_ORDER = "out_of_order"  # 亂序(source_timestamp 倒退)
    LATE = "late"  # 遲到(ingest 與 source 差距過大)
    SUSPECT = "suspect"  # 可疑(解碼異常/時鐘漂移/crossed quote)
    GAP_DETECTED = "gap_detected"  # 序號斷號＝資料缺口(Lean Synchronizer 模式)
    REPLAYED = "replayed"  # 重放資料(非即時，回測/測試用)


class RecordKind(StrEnum):
    """行情記錄種類 · 與 payload 型別一一對應(見 PAYLOAD_KIND_MAP)。

    ProviderCapabilities 用它宣告支援範圍；SubscriptionRequest 用它指定訂閱內容。
    """

    QUOTE = "quote"  # 最優買賣報價
    TRADE = "trade"  # 成交
    ORDER_BOOK = "order_book"  # 委託簿快照
    OPEN_INTEREST = "open_interest"  # 未平倉量
    FUNDING_RATE = "funding_rate"  # 資金費率
    CORPORATE_ACTION = "corporate_action"  # 公司行動
    MACRO_RELEASE = "macro_release"  # 宏觀數據發布
    FUNDAMENTAL_REPORT = "fundamental_report"  # 財報/申報
    NEWS_SENTIMENT = "news_sentiment"  # 新聞情緒(禁存全文，D10)
    ON_CHAIN_METRIC = "on_chain_metric"  # 鏈上指標
    PREDICTION_MARKET_METADATA = "prediction_market_metadata"  # 預測市場(paper-only，D12)


# ============================================================================
# 私有驗證(本模組專用；通用驗證沿用 src.core.validation)
# ============================================================================

# venue 對齊 EventBus topic 段的字元規範(小寫英數/底線/連字號)
_VENUE_RE = re.compile(r"^[a-z0-9_-]+$")
# symbol 保留場所原生代碼(如 2330、BRK.B)；禁冒號(instrument_id 分隔符)與空白
_SYMBOL_RE = re.compile(r"^[^\s:]+$")
# currency：ISO 4217 三碼為主；放寬到 3-10 碼大寫英數以承接 crypto 計價幣(USDT 類)。
# 規格 §6.2 寫 ISO 4217，此處為避免未來 CRYPTO_SPOT 實接時改 schema 而放寬(見使用說明)。
_CURRENCY_RE = re.compile(r"^[A-Z][A-Z0-9]{2,9}$")


def _ensure_venue(name: str, value: str) -> None:
    """venue 只允許 [a-z0-9_-](對齊 topic 段規範，可安全進 topic / 路徑)。"""
    ensure_non_empty(name, value)
    if not _VENUE_RE.fullmatch(value):
        raise ValueError(f"{name} 只允許小寫英數、底線、連字號：{value!r}")


def _ensure_symbol(name: str, value: str) -> None:
    """symbol 保留原生代碼，但禁空白與冒號(冒號是 instrument_id 的分隔符)。"""
    ensure_non_empty(name, value)
    if not _SYMBOL_RE.fullmatch(value):
        raise ValueError(f"{name} 不可含空白或冒號：{value!r}")


def _ensure_currency(name: str, value: str) -> None:
    """計價幣別：ISO 4217(TWD/USD)或交易所原生代碼(USDT)，3-10 碼大寫。"""
    ensure_non_empty(name, value)
    if not _CURRENCY_RE.fullmatch(value):
        raise ValueError(f"{name} 必須是 3-10 碼大寫英數(首碼為字母)：{value!r}")


def _ensure_timezone(name: str, value: str) -> None:
    """必須是有效 IANA 時區名稱(如 Asia/Taipei)；查無此區直接 fail-closed。"""
    ensure_non_empty(name, value)
    try:
        ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(f"{name} 必須是有效 IANA 時區名稱：{value!r}") from exc


def _ensure_http_url(name: str, value: str) -> None:
    """必須是 http(s) URL(擋相對路徑 / file: / javascript: 類垃圾值)。"""
    ensure_non_empty(name, value)
    if not (value.startswith("https://") or value.startswith("http://")):
        raise ValueError(f"{name} 必須以 http:// 或 https:// 開頭：{value!r}")


def _ensure_instrument_id_format(name: str, value: str) -> None:
    """instrument_id 全域命名規範 {asset_class}:{venue}:{symbol}(D13 圖節點 ID)。"""
    ensure_non_empty(name, value)
    parts = value.split(":")
    if len(parts) != 3:
        raise ValueError(f"{name} 必須是三段制 asset_class:venue:symbol，收到：{value!r}")
    asset_class, venue, symbol = parts
    valid_values = {member.value for member in AssetClass}
    if asset_class not in valid_values:
        raise ValueError(f"{name} 的 asset_class 段不是合法 AssetClass：{asset_class!r}")
    _ensure_venue(f"{name} 的 venue 段", venue)
    _ensure_symbol(f"{name} 的 symbol 段", symbol)


def _ensure_range(name: str, value: float, low: float, high: float) -> None:
    """數值必須落在 [low, high](且非 NaN/Infinity；bool 不算數值)。"""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} 必須是數值，不可為 {type(value).__name__}")
    if math.isnan(value) or math.isinf(value):
        raise ValueError(f"{name} 不可為 NaN / Infinity：{value}")
    if not low <= value <= high:
        raise ValueError(f"{name} 必須落在 [{low}, {high}]：{value}")


# ============================================================================
# 第 1-2 組 · 識別與商品規格
# ============================================================================


@dataclass(frozen=True, slots=True)
class InstrumentLink:
    """跨商品關聯邊(D13 擴充點)：如台積電 ↔ TSM ADR、期貨 ↔ 現貨。

    v0 只定 schema 供 S30 CrossAssetInfluenceGraph 建圖，無人填值。
    """

    link_type: str  # 如 "adr_of" / "future_of"(v0 不設 enum，S30 建圖時收斂)
    target_instrument_id: str  # 對端商品，須符合全域命名規範

    def __post_init__(self) -> None:
        ensure_non_empty("link_type", self.link_type)
        _ensure_instrument_id_format("target_instrument_id", self.target_instrument_id)


@dataclass(frozen=True, slots=True)
class InstrumentRef:
    """第 1 組 · 識別欄位(必填)。

    instrument_id 是全域唯一命名 {asset_class}:{venue}:{symbol}(D13)，
    與其餘欄位的一致性由不變式強制——不一致的識別是最危險的髒資料。
    links 是唯一允許預設值的欄位：空 tuple 是「無關聯」的真實語義(D13)，
    與 tenant_id 禁預設不衝突。
    """

    asset_class: AssetClass
    venue: str  # 交易/資料場所，如 twse、tpex、taifex
    provider_id: str  # 產出本筆的 provider，全域唯一
    instrument_id: str  # {asset_class}:{venue}:{symbol}
    symbol: str  # 場所原生代碼，如 2330
    currency: str  # ISO 4217 或交易所原生代碼
    links: tuple[InstrumentLink, ...] = ()

    def __post_init__(self) -> None:
        _ensure_venue("venue", self.venue)
        ensure_non_empty("provider_id", self.provider_id)
        _ensure_symbol("symbol", self.symbol)
        _ensure_currency("currency", self.currency)
        expected = f"{self.asset_class.value}:{self.venue}:{self.symbol}"
        if self.instrument_id != expected:
            raise ValueError(
                f"instrument_id 必須等於 {expected!r}(asset_class:venue:symbol)，"
                f"收到：{self.instrument_id!r}"
            )

    @classmethod
    def build(
        cls,
        *,
        asset_class: AssetClass,
        venue: str,
        provider_id: str,
        symbol: str,
        currency: str,
        links: tuple[InstrumentLink, ...] = (),
    ) -> InstrumentRef:
        """依命名規範自動組出 instrument_id，避免呼叫端手拼出錯。"""
        return cls(
            asset_class=asset_class,
            venue=venue,
            provider_id=provider_id,
            instrument_id=f"{asset_class.value}:{venue}:{symbol}",
            symbol=symbol,
            currency=currency,
            links=links,
        )


@dataclass(frozen=True, slots=True)
class InstrumentSpec:
    """第 2 組 · 商品規格欄位(可為 None——部分來源不提供)。"""

    tick_size: Decimal  # 最小跳動單位
    lot_size: Decimal  # 最小交易單位
    contract_multiplier: Decimal  # 合約乘數(現貨為 1)
    timezone: str  # IANA 名稱，如 Asia/Taipei
    session: str  # 交易時段標記，如 regular / after_hours

    def __post_init__(self) -> None:
        ensure_positive("tick_size", self.tick_size)
        ensure_positive("lot_size", self.lot_size)
        ensure_positive("contract_multiplier", self.contract_multiplier)
        _ensure_timezone("timezone", self.timezone)
        ensure_non_empty("session", self.session)


# ============================================================================
# 第 4 組 · 行情 payload(依 record kind 擇一)
# ============================================================================


@dataclass(frozen=True, slots=True)
class QuoteTick:
    """最優買賣報價。crossed quote(bid >= ask)是真實市場現象，
    型別層不擋，由 provider 標 SUSPECT flag。"""

    bid: Decimal
    ask: Decimal
    bid_size: Decimal
    ask_size: Decimal

    def __post_init__(self) -> None:
        ensure_positive("bid", self.bid)
        ensure_positive("ask", self.ask)
        ensure_non_negative("bid_size", self.bid_size)
        ensure_non_negative("ask_size", self.ask_size)


@dataclass(frozen=True, slots=True)
class TradeTick:
    """成交。aggressor_side 部分來源不提供，可為 None。"""

    price: Decimal
    volume: Decimal
    aggressor_side: OrderSide | None

    def __post_init__(self) -> None:
        ensure_positive("price", self.price)
        ensure_positive("volume", self.volume)


@dataclass(frozen=True, slots=True)
class BookLevel:
    """委託簿單一檔位(價格 + 數量)。"""

    price: Decimal
    size: Decimal

    def __post_init__(self) -> None:
        ensure_positive("price", self.price)
        ensure_positive("size", self.size)


def _ensure_strictly_sorted(name: str, levels: tuple[BookLevel, ...], *, descending: bool) -> None:
    """檔位價格必須嚴格排序(重複價格＝來源髒資料，fail-closed)。"""
    for left, right in pairwise(levels):
        ordered = left.price > right.price if descending else left.price < right.price
        if not ordered:
            direction = "嚴格遞減" if descending else "嚴格遞增"
            raise ValueError(f"{name} 檔位價格必須{direction}：{left.price} 之後接 {right.price}")


@dataclass(frozen=True, slots=True)
class OrderBookSnapshot:
    """委託簿快照(真 tick，不做假 LOB——Archive 教訓)。

    bids 由高到低、asks 由低到高；空側允許(單邊市場)。
    """

    bids: tuple[BookLevel, ...]
    asks: tuple[BookLevel, ...]

    def __post_init__(self) -> None:
        _ensure_strictly_sorted("bids", self.bids, descending=True)
        _ensure_strictly_sorted("asks", self.asks, descending=False)

    @property
    def best_bid(self) -> BookLevel | None:
        """最優買價檔(bridge 降維取用)；空側回 None。"""
        return self.bids[0] if self.bids else None

    @property
    def best_ask(self) -> BookLevel | None:
        """最優賣價檔(bridge 降維取用)；空側回 None。"""
        return self.asks[0] if self.asks else None

    @property
    def depth(self) -> int:
        """快照檔數(取兩側較深者)。"""
        return max(len(self.bids), len(self.asks))


@dataclass(frozen=True, slots=True)
class OpenInterest:
    """未平倉量(期貨/選擇權)。"""

    open_interest: Decimal

    def __post_init__(self) -> None:
        ensure_non_negative("open_interest", self.open_interest)


@dataclass(frozen=True, slots=True)
class FundingRate:
    """資金費率一等欄位(Archive Bybit funding 教訓)。費率可為負。"""

    funding_rate: Decimal
    next_funding_at: datetime | None

    def __post_init__(self) -> None:
        ensure_finite("funding_rate", self.funding_rate)
        if self.next_funding_at is not None:
            ensure_utc("next_funding_at", self.next_funding_at)


# ============================================================================
# 第 5 組 · 事件研究 payload(v0 只定 schema、不實接來源；D1/D10/D12)
# ============================================================================


@dataclass(frozen=True, slots=True)
class CorporateAction:
    """公司行動(除權息/分割/合併)。"""

    action_type: str  # 如 cash_dividend / stock_split
    ex_date: date
    ratio: Decimal  # 配息額或分割比

    def __post_init__(self) -> None:
        ensure_non_empty("action_type", self.action_type)
        # datetime 是 date 的子類；除權日是「日曆日」概念，混入時分秒＝時區歧義來源
        if type(self.ex_date) is not date:
            raise ValueError(f"ex_date 必須是 date(不可為 {type(self.ex_date).__name__})")
        ensure_positive("ratio", self.ratio)


@dataclass(frozen=True, slots=True)
class MacroRelease:
    """宏觀數據發布(FRED/官方統計)。"""

    indicator_id: str  # 如 fred:CPIAUCSL
    period: str  # 數據所屬期間，如 2026-06
    actual: Decimal
    consensus: Decimal | None  # 市場預期，部分指標無

    def __post_init__(self) -> None:
        ensure_non_empty("indicator_id", self.indicator_id)
        ensure_non_empty("period", self.period)
        ensure_finite("actual", self.actual)
        if self.consensus is not None:
            ensure_finite("consensus", self.consensus)


@dataclass(frozen=True, slots=True)
class FundamentalReport:
    """財報/申報事件(MOPS/EDGAR)。"""

    report_type: str  # 如 10-K / 月營收
    fiscal_period: str  # 如 2026Q2
    filing_url: str

    def __post_init__(self) -> None:
        ensure_non_empty("report_type", self.report_type)
        ensure_non_empty("fiscal_period", self.fiscal_period)
        _ensure_http_url("filing_url", self.filing_url)


@dataclass(frozen=True, slots=True)
class NewsSentiment:
    """新聞情緒(GDELT 類，D10)。

    禁令做進型別：本 schema 沒有全文欄位＝存不了全文；
    attribution_notice 是必填欄位不是註解(GDELT 要求 attribution)。
    """

    event_id: str
    source_url: str
    source_domain: str
    published_at: datetime
    themes: tuple[str, ...]
    tone: float  # GDELT tone 文件範圍 [-100, 100]
    attribution_notice: str

    def __post_init__(self) -> None:
        ensure_non_empty("event_id", self.event_id)
        _ensure_http_url("source_url", self.source_url)
        ensure_non_empty("source_domain", self.source_domain)
        ensure_utc("published_at", self.published_at)
        for theme in self.themes:
            ensure_non_empty("themes 元素", theme)
        _ensure_range("tone", self.tone, -100.0, 100.0)
        ensure_non_empty("attribution_notice", self.attribution_notice)


@dataclass(frozen=True, slots=True)
class OnChainMetric:
    """鏈上指標(Glassnode/Dune 類)。"""

    metric_id: str  # 如 glassnode:sopr
    chain: str  # 如 bitcoin / ethereum
    value: Decimal

    def __post_init__(self) -> None:
        ensure_non_empty("metric_id", self.metric_id)
        ensure_non_empty("chain", self.chain)
        ensure_finite("value", self.value)


@dataclass(frozen=True, slots=True)
class PredictionMarketMetadata:
    """預測市場中繼資料(paper-only，D12/B-116)。

    只承載研究用中繼資料；真錢連線路徑在程式碼庫不存在，
    profile 層由 compliance gate 強制 PAPER_ONLY。
    """

    market_id: str
    outcome: str
    probability: float  # [0, 1]
    resolution_source: str
    close_time: datetime
    region_restrictions: tuple[str, ...]

    def __post_init__(self) -> None:
        ensure_non_empty("market_id", self.market_id)
        ensure_non_empty("outcome", self.outcome)
        ensure_confidence("probability", self.probability)
        ensure_non_empty("resolution_source", self.resolution_source)
        ensure_utc("close_time", self.close_time)
        for region in self.region_restrictions:
            ensure_non_empty("region_restrictions 元素", region)


# ============================================================================
# MarketDataRecord · 統一輸出
# ============================================================================

# payload 具體型別 ↔ RecordKind 的唯一對照(用精確型別，不認子類——防偷渡)
PAYLOAD_KIND_MAP: dict[type, RecordKind] = {
    QuoteTick: RecordKind.QUOTE,
    TradeTick: RecordKind.TRADE,
    OrderBookSnapshot: RecordKind.ORDER_BOOK,
    OpenInterest: RecordKind.OPEN_INTEREST,
    FundingRate: RecordKind.FUNDING_RATE,
    CorporateAction: RecordKind.CORPORATE_ACTION,
    MacroRelease: RecordKind.MACRO_RELEASE,
    FundamentalReport: RecordKind.FUNDAMENTAL_REPORT,
    NewsSentiment: RecordKind.NEWS_SENTIMENT,
    OnChainMetric: RecordKind.ON_CHAIN_METRIC,
    PredictionMarketMetadata: RecordKind.PREDICTION_MARKET_METADATA,
}

type MarketDataPayload = (
    QuoteTick
    | TradeTick
    | OrderBookSnapshot
    | OpenInterest
    | FundingRate
    | CorporateAction
    | MacroRelease
    | FundamentalReport
    | NewsSentiment
    | OnChainMetric
    | PredictionMarketMetadata
)


@dataclass(frozen=True, slots=True)
class MarketDataRecord:
    """所有 provider 的統一輸出 · 六組欄位(規格 §6.2)。

    欄位全必填(可空者以明確 None 表示)——不給預設值，杜絕「忘了帶」的髒資料；
    tenant_id 尤其禁止預設(對齊 S10 D7 與 BaseEvent 既有不變式)。
    """

    instrument: InstrumentRef  # 第 1 組 · 識別
    spec: InstrumentSpec | None  # 第 2 組 · 商品規格(部分來源不提供)
    source_timestamp: datetime  # 第 3 組 · 來源宣稱的事件時間
    ingest_timestamp: datetime  # 第 3 組 · 本系統收到時間(本機 NTP，不信任來源時鐘)
    sequence: int | None  # 第 3 組 · 來源序號；斷號＝缺口
    payload: MarketDataPayload  # 第 4/5 組 · 依 record kind 擇一
    data_quality_flags: frozenset[DataQualityFlag]  # 第 6 組 · 品質旗標
    license_tag: str  # 第 6 組 · 指向 compliance profile 的授權標記
    tenant_id: str  # 第 6 組 · 必填、無預設(§8.2)

    def __post_init__(self) -> None:
        if type(self.payload) not in PAYLOAD_KIND_MAP:
            raise ValueError(
                f"payload 型別不在允許清單：{type(self.payload).__name__}"
                "(只接受 PAYLOAD_KIND_MAP 登記的精確型別)"
            )
        ensure_utc("source_timestamp", self.source_timestamp)
        ensure_utc("ingest_timestamp", self.ingest_timestamp)
        # 不信任來源時鐘：宣稱時間晚於接收時間＝時鐘漂移，provider 必須先夾制並標
        # SUSPECT 再構造(raw capture 留原值可對帳)，型別層一律 fail-closed
        if self.source_timestamp > self.ingest_timestamp:
            raise ValueError(
                f"source_timestamp({self.source_timestamp.isoformat()}) 不可晚於 "
                f"ingest_timestamp({self.ingest_timestamp.isoformat()})"
            )
        if self.sequence is not None:
            if isinstance(self.sequence, bool) or not isinstance(self.sequence, int):
                raise ValueError(f"sequence 必須是非負整數，不可為 {type(self.sequence).__name__}")
            if self.sequence < 0:
                raise ValueError(f"sequence 不可為負：{self.sequence}")
        for flag in self.data_quality_flags:
            if not isinstance(flag, DataQualityFlag):
                raise ValueError(
                    f"data_quality_flags 元素必須是 DataQualityFlag，不可為 {type(flag).__name__}"
                )
        # 呼叫端可能傳 set；統一正規化為 frozenset，維持值物件不可變語意
        object.__setattr__(self, "data_quality_flags", frozenset(self.data_quality_flags))
        ensure_non_empty("license_tag", self.license_tag)
        ensure_non_empty("tenant_id", self.tenant_id)

    @property
    def record_kind(self) -> RecordKind:
        """由 payload 精確型別導出(單一事實來源，杜絕欄位與 payload 漂移)。"""
        return PAYLOAD_KIND_MAP[type(self.payload)]
