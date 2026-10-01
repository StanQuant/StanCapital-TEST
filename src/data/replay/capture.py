"""raw capture 寫入器 + MarketDataRecord JSONL 序列化(D5、規格 §14)。

設計鐵律：
- append-only：capture 檔一旦存在不得重開改寫；修正只能產生新版本 capture。
- 每個 capture 附 manifest(記錄數 / 時間範圍 / license_tag / 內容 SHA-256)，
  verify_capture 可偵測內容竄改；未簽章前不宣稱不可竄改或不可抵賴。
- 正規化軌是回測可重現性的凍結點：decoder 改版不影響已寫入的正規化資料；
  爭議時用 raw 軌對帳。
- v0 不壓縮(D5 的「零新依賴」裁決優先於 zstd 字樣：Python 3.12 無 stdlib
  zstd，壓縮輪轉留給 S15 儲存體系，見使用說明)。
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from ulid import ULID

from src.core.types import OrderSide
from src.core.validation import ensure_non_empty, ensure_non_negative_int, ensure_utc
from src.data.sinks import (
    MarketDataLifecycleAction,
    MarketDataLifecycleEvent,
    MarketDataLifecycleSink,
    NoopMarketDataLifecycleSink,
)
from src.data.types import (
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

# capture 格式版本：欄位變動時遞增，讀取端嚴格比對(fail-closed)
CAPTURE_SCHEMA_VERSION = 1

# manifest 檔名 = capture 檔名 + 此後綴
MANIFEST_SUFFIX = ".manifest.json"


class CaptureError(Exception):
    """capture 寫入 / 讀取 / 對帳失敗。"""


# ============================================================================
# 序列化 · MarketDataRecord ↔ JSON dict
# ============================================================================


def _json_default(value: object) -> object:
    """json.dumps 的型別轉換：Decimal→str(不失真)、時間→ISO、集合→排序清單。"""
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (frozenset, set)):
        return sorted(str(item) for item in value)
    raise CaptureError(f"無法序列化的型別：{type(value).__name__}")


def record_to_json_line(record: MarketDataRecord) -> str:
    """正規化一筆 record 為單行 JSON(鍵排序，位元組級可重現)。"""
    data = dataclasses.asdict(record)
    data["schema_version"] = CAPTURE_SCHEMA_VERSION
    data["record_kind"] = record.record_kind.value
    return json.dumps(
        data, default=_json_default, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def _parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _parse_optional_decimal(value: str | None) -> Decimal | None:
    return None if value is None else Decimal(value)


def _instrument_from(data: dict[str, Any]) -> InstrumentRef:
    return InstrumentRef(
        asset_class=AssetClass(data["asset_class"]),
        venue=data["venue"],
        provider_id=data["provider_id"],
        instrument_id=data["instrument_id"],
        symbol=data["symbol"],
        currency=data["currency"],
        links=tuple(
            InstrumentLink(
                link_type=link["link_type"],
                target_instrument_id=link["target_instrument_id"],
            )
            for link in data["links"]
        ),
    )


def _spec_from(data: dict[str, Any] | None) -> InstrumentSpec | None:
    if data is None:
        return None
    return InstrumentSpec(
        tick_size=Decimal(data["tick_size"]),
        lot_size=Decimal(data["lot_size"]),
        contract_multiplier=Decimal(data["contract_multiplier"]),
        timezone=data["timezone"],
        session=data["session"],
    )


def _quote_from(data: dict[str, Any]) -> QuoteTick:
    return QuoteTick(
        bid=Decimal(data["bid"]),
        ask=Decimal(data["ask"]),
        bid_size=Decimal(data["bid_size"]),
        ask_size=Decimal(data["ask_size"]),
    )


def _trade_from(data: dict[str, Any]) -> TradeTick:
    side = data["aggressor_side"]
    return TradeTick(
        price=Decimal(data["price"]),
        volume=Decimal(data["volume"]),
        aggressor_side=None if side is None else OrderSide(side),
    )


def _book_from(data: dict[str, Any]) -> OrderBookSnapshot:
    return OrderBookSnapshot(
        bids=tuple(
            BookLevel(price=Decimal(lv["price"]), size=Decimal(lv["size"])) for lv in data["bids"]
        ),
        asks=tuple(
            BookLevel(price=Decimal(lv["price"]), size=Decimal(lv["size"])) for lv in data["asks"]
        ),
    )


def _open_interest_from(data: dict[str, Any]) -> OpenInterest:
    return OpenInterest(open_interest=Decimal(data["open_interest"]))


def _funding_rate_from(data: dict[str, Any]) -> FundingRate:
    next_at = data["next_funding_at"]
    return FundingRate(
        funding_rate=Decimal(data["funding_rate"]),
        next_funding_at=None if next_at is None else _parse_datetime(next_at),
    )


def _corporate_action_from(data: dict[str, Any]) -> CorporateAction:
    return CorporateAction(
        action_type=data["action_type"],
        ex_date=date.fromisoformat(data["ex_date"]),
        ratio=Decimal(data["ratio"]),
    )


def _macro_release_from(data: dict[str, Any]) -> MacroRelease:
    return MacroRelease(
        indicator_id=data["indicator_id"],
        period=data["period"],
        actual=Decimal(data["actual"]),
        consensus=_parse_optional_decimal(data["consensus"]),
    )


def _fundamental_report_from(data: dict[str, Any]) -> FundamentalReport:
    return FundamentalReport(
        report_type=data["report_type"],
        fiscal_period=data["fiscal_period"],
        filing_url=data["filing_url"],
    )


def _news_sentiment_from(data: dict[str, Any]) -> NewsSentiment:
    return NewsSentiment(
        event_id=data["event_id"],
        source_url=data["source_url"],
        source_domain=data["source_domain"],
        published_at=_parse_datetime(data["published_at"]),
        themes=tuple(data["themes"]),
        tone=data["tone"],
        attribution_notice=data["attribution_notice"],
    )


def _on_chain_metric_from(data: dict[str, Any]) -> OnChainMetric:
    return OnChainMetric(
        metric_id=data["metric_id"], chain=data["chain"], value=Decimal(data["value"])
    )


def _prediction_market_from(data: dict[str, Any]) -> PredictionMarketMetadata:
    return PredictionMarketMetadata(
        market_id=data["market_id"],
        outcome=data["outcome"],
        probability=data["probability"],
        resolution_source=data["resolution_source"],
        close_time=_parse_datetime(data["close_time"]),
        region_restrictions=tuple(data["region_restrictions"]),
    )


# RecordKind → payload 解析器(11 種全覆蓋，與 PAYLOAD_KIND_MAP 成鏡像)
_PAYLOAD_PARSERS: dict[RecordKind, Any] = {
    RecordKind.QUOTE: _quote_from,
    RecordKind.TRADE: _trade_from,
    RecordKind.ORDER_BOOK: _book_from,
    RecordKind.OPEN_INTEREST: _open_interest_from,
    RecordKind.FUNDING_RATE: _funding_rate_from,
    RecordKind.CORPORATE_ACTION: _corporate_action_from,
    RecordKind.MACRO_RELEASE: _macro_release_from,
    RecordKind.FUNDAMENTAL_REPORT: _fundamental_report_from,
    RecordKind.NEWS_SENTIMENT: _news_sentiment_from,
    RecordKind.ON_CHAIN_METRIC: _on_chain_metric_from,
    RecordKind.PREDICTION_MARKET_METADATA: _prediction_market_from,
}


def record_from_json_line(line: str) -> MarketDataRecord:
    """單行 JSON 還原為 MarketDataRecord(schema 版本不符直接 fail-closed)。"""
    data = json.loads(line)
    version = data["schema_version"]
    if version != CAPTURE_SCHEMA_VERSION:
        raise CaptureError(
            f"capture schema 版本不符：檔案為 v{version}，本程式支援 v{CAPTURE_SCHEMA_VERSION}"
        )
    kind = RecordKind(data["record_kind"])
    sequence = data["sequence"]
    return MarketDataRecord(
        instrument=_instrument_from(data["instrument"]),
        spec=_spec_from(data["spec"]),
        source_timestamp=_parse_datetime(data["source_timestamp"]),
        ingest_timestamp=_parse_datetime(data["ingest_timestamp"]),
        sequence=sequence,
        payload=_PAYLOAD_PARSERS[kind](data["payload"]),
        data_quality_flags=frozenset(DataQualityFlag(flag) for flag in data["data_quality_flags"]),
        license_tag=data["license_tag"],
        tenant_id=data["tenant_id"],
    )


def read_normalized_records(path: Path) -> tuple[MarketDataRecord, ...]:
    """讀取正規化 capture 檔，回傳全部 records(重放 / 回測入口)。"""
    lines = path.read_text(encoding="utf-8").splitlines()
    return tuple(record_from_json_line(line) for line in lines if line)


# ============================================================================
# raw capture 條目
# ============================================================================


@dataclass(frozen=True, slots=True)
class RawCaptureEntry:
    """raw 軌單行：{capture_ts, provider_id, tenant_id, channel, raw_payload,
    transport_meta}(規格 §14.1)。raw_payload 保留來源原文，不做任何解讀。"""

    capture_ts: datetime
    provider_id: str
    tenant_id: str
    channel: str  # 如 ws:/TASP/XCPXWS 訂閱頻道
    raw_payload: str
    transport_meta: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        ensure_utc("capture_ts", self.capture_ts)
        ensure_non_empty("provider_id", self.provider_id)
        ensure_non_empty("tenant_id", self.tenant_id)
        ensure_non_empty("channel", self.channel)
        ensure_non_empty("raw_payload", self.raw_payload)
        for pair in self.transport_meta:
            key, value = pair
            ensure_non_empty("transport_meta 鍵", key)
            if not isinstance(value, str):
                raise ValueError(f"transport_meta 值必須是 str，不可為 {type(value).__name__}")


def _raw_entry_to_json_line(entry: RawCaptureEntry) -> str:
    data = dataclasses.asdict(entry)
    data["schema_version"] = CAPTURE_SCHEMA_VERSION
    return json.dumps(
        data, default=_json_default, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


# ============================================================================
# manifest 與寫入器
# ============================================================================


@dataclass(frozen=True, slots=True)
class CaptureManifest:
    """capture session 對帳單(tamper-evident；未進 S15 Registry 前不得作研究證據)。"""

    schema_version: int
    provider_id: str
    tenant_id: str
    license_tag: str
    record_count: int
    started_at: datetime | None  # 空 capture 為 None
    ended_at: datetime | None
    content_sha256: str

    def __post_init__(self) -> None:
        if isinstance(self.schema_version, bool) or not isinstance(self.schema_version, int):
            raise ValueError("schema_version 必須是整數")
        if self.schema_version != CAPTURE_SCHEMA_VERSION:
            raise ValueError(
                f"manifest schema 版本不符：檔案為 v{self.schema_version}，"
                f"本程式支援 v{CAPTURE_SCHEMA_VERSION}"
            )
        ensure_non_empty("provider_id", self.provider_id)
        ensure_non_empty("tenant_id", self.tenant_id)
        ensure_non_empty("license_tag", self.license_tag)
        ensure_non_negative_int("record_count", self.record_count)
        ensure_non_empty("content_sha256", self.content_sha256)
        if len(self.content_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.content_sha256
        ):
            raise ValueError("content_sha256 必須是 64 碼小寫十六進位 SHA-256")
        if self.started_at is not None:
            ensure_utc("started_at", self.started_at)
        if self.ended_at is not None:
            ensure_utc("ended_at", self.ended_at)
        if (self.started_at is None) != (self.ended_at is None):
            raise ValueError("started_at 與 ended_at 必須同時存在或同時為 None")
        if self.record_count == 0 and self.started_at is not None:
            raise ValueError("空 capture 的 started_at / ended_at 必須為 None")
        if self.record_count > 0 and self.started_at is None:
            raise ValueError("非空 capture 必須有 started_at / ended_at")
        if (
            self.started_at is not None
            and self.ended_at is not None
            and self.started_at > self.ended_at
        ):
            raise ValueError("started_at 不可晚於 ended_at")


def manifest_path_for(capture_path: Path) -> Path:
    """capture 檔對應的 manifest 路徑(同目錄、同名 + .manifest.json)。"""
    return capture_path.with_name(capture_path.name + MANIFEST_SUFFIX)


class _JsonlCaptureWriter:
    """append-only JSONL 寫入器共用底座(邊寫邊算 SHA-256，finalize 出 manifest)。"""

    def __init__(
        self,
        path: Path,
        *,
        provider_id: str,
        tenant_id: str,
        license_tag: str,
        lifecycle_sink: MarketDataLifecycleSink | None = None,
        actor_id: str = "market-data-capture",
        trace_id: str | None = None,
    ) -> None:
        ensure_non_empty("provider_id", provider_id)
        ensure_non_empty("tenant_id", tenant_id)
        ensure_non_empty("license_tag", license_tag)
        ensure_non_empty("actor_id", actor_id)
        if path.exists():
            raise CaptureError(
                f"capture 檔已存在：{path}(append-only 鐵律：不可回頭改寫，"
                "修正請產生新版本 capture)"
            )
        manifest_path = manifest_path_for(path)
        if manifest_path.exists():
            raise CaptureError(f"manifest 已存在：{manifest_path}(不可覆寫既有 capture session)")
        self._path = path
        self._manifest_path = manifest_path
        self._provider_id = provider_id
        self._tenant_id = tenant_id
        self._license_tag = license_tag
        self._file = path.open("x", encoding="utf-8")
        self._hasher = hashlib.sha256()
        self._count = 0
        self._started_at: datetime | None = None
        self._ended_at: datetime | None = None
        self._finalized = False
        self._lifecycle_sink = lifecycle_sink or NoopMarketDataLifecycleSink()
        self._actor_id = actor_id
        self._trace_id = trace_id or str(ULID())
        self._lifecycle_sink.emit(
            MarketDataLifecycleEvent(
                action=MarketDataLifecycleAction.CAPTURE_START,
                provider_id=self._provider_id,
                tenant_id=self._tenant_id,
                actor_id=self._actor_id,
                trace_id=self._trace_id,
                result="success",
                license_tag=self._license_tag,
                record_count=0,
            )
        )

    def _append_line(self, line: str, entry_ts: datetime) -> None:
        if self._finalized:
            raise CaptureError("capture 已 finalize，不可再追加(append-only 生命週期已結束)")
        payload = line + "\n"
        self._file.write(payload)
        self._hasher.update(payload.encode("utf-8"))
        self._count += 1
        if self._started_at is None or entry_ts < self._started_at:
            self._started_at = entry_ts
        if self._ended_at is None or entry_ts > self._ended_at:
            self._ended_at = entry_ts

    def finalize(self) -> CaptureManifest:
        """關檔並寫出 manifest。一個 session 只能 finalize 一次。"""
        if self._finalized:
            raise CaptureError("capture 已 finalize，不可重複 finalize")
        self._finalized = True
        self._file.close()
        manifest = CaptureManifest(
            schema_version=CAPTURE_SCHEMA_VERSION,
            provider_id=self._provider_id,
            tenant_id=self._tenant_id,
            license_tag=self._license_tag,
            record_count=self._count,
            started_at=self._started_at,
            ended_at=self._ended_at,
            content_sha256=self._hasher.hexdigest(),
        )
        data = dataclasses.asdict(manifest)
        with self._manifest_path.open("x", encoding="utf-8") as handle:
            json.dump(data, handle, default=_json_default, ensure_ascii=False, sort_keys=True)
        self._lifecycle_sink.emit(
            MarketDataLifecycleEvent(
                action=MarketDataLifecycleAction.CAPTURE_END,
                provider_id=self._provider_id,
                tenant_id=self._tenant_id,
                actor_id=self._actor_id,
                trace_id=self._trace_id,
                result="success",
                license_tag=self._license_tag,
                manifest_sha256=manifest.content_sha256,
                record_count=manifest.record_count,
                started_at=manifest.started_at,
                ended_at=manifest.ended_at,
            )
        )
        return manifest


class RawCaptureWriter(_JsonlCaptureWriter):
    """raw 軌寫入器：一個 session 綁定單一 provider / tenant / license_tag。"""

    def append(self, entry: RawCaptureEntry) -> None:
        if entry.provider_id != self._provider_id:
            raise CaptureError(
                f"entry.provider_id({entry.provider_id!r}) 與本 session"
                f"({self._provider_id!r}) 不符——一個 capture 只收單一來源"
            )
        if entry.tenant_id != self._tenant_id:
            raise CaptureError(
                f"entry.tenant_id({entry.tenant_id!r}) 與本 session"
                f"({self._tenant_id!r}) 不符——禁止跨租戶混寫"
            )
        self._append_line(_raw_entry_to_json_line(entry), entry.capture_ts)


class NormalizedCaptureWriter(_JsonlCaptureWriter):
    """正規化軌寫入器：重放與回測吃這份(decoder 結果的凍結點)。"""

    def append(self, record: MarketDataRecord) -> None:
        if record.instrument.provider_id != self._provider_id:
            raise CaptureError(
                f"record.instrument.provider_id({record.instrument.provider_id!r}) 與本 session"
                f"({self._provider_id!r}) 不符——一個 capture 只收單一來源"
            )
        if record.tenant_id != self._tenant_id:
            raise CaptureError(
                f"record.tenant_id({record.tenant_id!r}) 與本 session"
                f"({self._tenant_id!r}) 不符——禁止跨租戶混寫"
            )
        if record.license_tag != self._license_tag:
            raise CaptureError(
                f"record.license_tag({record.license_tag!r}) 與本 session"
                f"({self._license_tag!r}) 不符——禁止授權來源標記漂移"
            )
        self._append_line(record_to_json_line(record), record.source_timestamp)


def read_manifest(capture_path: Path) -> CaptureManifest:
    """讀取 capture 對應的 manifest。"""
    manifest_path = manifest_path_for(capture_path)
    if not manifest_path.exists():
        raise CaptureError(f"找不到 manifest：{manifest_path}(無對帳單的 capture 不可信)")
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        return CaptureManifest(
            schema_version=data["schema_version"],
            provider_id=data["provider_id"],
            tenant_id=data["tenant_id"],
            license_tag=data["license_tag"],
            record_count=data["record_count"],
            started_at=(
                None if data["started_at"] is None else _parse_datetime(data["started_at"])
            ),
            ended_at=None if data["ended_at"] is None else _parse_datetime(data["ended_at"]),
            content_sha256=data["content_sha256"],
        )
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise CaptureError(f"manifest 格式無效：{manifest_path}({exc})") from exc


def verify_capture(capture_path: Path) -> CaptureManifest:
    """對帳：串流重算檔案 SHA-256 與行數，與 manifest 比對(偵測竄改)。

    通過回傳 manifest；不符一律 CaptureError(fail-closed)。
    """
    manifest = read_manifest(capture_path)
    hasher = hashlib.sha256()
    actual_count = 0
    try:
        with capture_path.open("rb") as handle:
            for raw_line in handle:
                hasher.update(raw_line)
                if raw_line.rstrip(b"\r\n"):
                    actual_count += 1
    except OSError as exc:
        raise CaptureError(f"無法讀取 capture：{capture_path}({exc})") from exc
    actual_sha = hasher.hexdigest()
    if actual_sha != manifest.content_sha256:
        raise CaptureError(
            f"capture 內容雜湊不符：manifest={manifest.content_sha256} 實際={actual_sha}"
            "(檔案已被改動，違反 append-only 鐵律)"
        )
    if actual_count != manifest.record_count:
        raise CaptureError(
            f"capture 記錄數不符：manifest={manifest.record_count} 實際={actual_count}"
        )
    return manifest
