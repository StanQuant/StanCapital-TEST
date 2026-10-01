"""L2 行情供應者統一介面 · MarketDataProvider Protocol + 值物件。

定位鐵律：本 Protocol 是第一公民，任何供應商(含券商)只以 adapter 身分實作它；
本檔 grep 不到任何供應商名稱。

fail-closed 設計：
- capabilities 宣告外的 asset class / record kind 請求 → UnsupportedCapabilityError
- tenant_id 建構時必填注入、無預設(§8.2)
- 未 connect 就 subscribe、未過 actual-connect gate 就 connect → 一律拋錯
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from src.core.validation import ensure_non_negative_int, ensure_utc
from src.data.compliance import ProviderComplianceProfile
from src.data.types import (
    AssetClass,
    DataQualityFlag,
    InstrumentRef,
    MarketDataRecord,
    RecordKind,
)


class UnsupportedCapabilityError(Exception):
    """consumer 請求了 capabilities 宣告外的能力(fail-closed，不靜默回空資料)。"""


class ProviderStateError(Exception):
    """provider 生命週期狀態錯誤(如未 connect 就 subscribe)。"""


class ProviderState(StrEnum):
    """provider 連線狀態 · ProviderHealth 與 S09 遙測共用。"""

    DISCONNECTED = "disconnected"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    CIRCUIT_OPEN = "circuit_open"  # 熔斷開路：停止重擊，降頻探測(D7)


@dataclass(frozen=True, slots=True)
class ProviderCapabilities:
    """能力宣告 · 「定義 vs 實作」的可測試界線(D2)。

    enum 11 類全定義，但 provider 只宣告自己真的支援的子集；
    宣告外的請求由 ensure_supported 統一 fail-closed。
    """

    asset_classes: frozenset[AssetClass]
    record_kinds: frozenset[RecordKind]
    supports_replay: bool
    supports_snapshot: bool
    max_subscriptions: int

    def __post_init__(self) -> None:
        if not self.asset_classes:
            raise ValueError("asset_classes 不可為空(不支援任何資產的 provider 沒有存在意義)")
        for asset_class in self.asset_classes:
            if not isinstance(asset_class, AssetClass):
                raise ValueError(
                    f"asset_classes 元素必須是 AssetClass，不可為 {type(asset_class).__name__}"
                )
        if not self.record_kinds:
            raise ValueError("record_kinds 不可為空")
        for kind in self.record_kinds:
            if not isinstance(kind, RecordKind):
                raise ValueError(
                    f"record_kinds 元素必須是 RecordKind，不可為 {type(kind).__name__}"
                )
        if isinstance(self.max_subscriptions, bool) or not isinstance(self.max_subscriptions, int):
            raise ValueError(
                f"max_subscriptions 必須是正整數，不可為 {type(self.max_subscriptions).__name__}"
            )
        if self.max_subscriptions < 1:
            raise ValueError(f"max_subscriptions 必須 >= 1：{self.max_subscriptions}")
        # 呼叫端可能傳 set；統一正規化為 frozenset
        object.__setattr__(self, "asset_classes", frozenset(self.asset_classes))
        object.__setattr__(self, "record_kinds", frozenset(self.record_kinds))

    def ensure_supported(self, request: SubscriptionRequest) -> None:
        """訂閱請求必須完全落在宣告能力內，否則 fail-closed 拋錯(不靜默回空)。"""
        asset_class = request.instrument.asset_class
        if asset_class not in self.asset_classes:
            raise UnsupportedCapabilityError(
                f"asset_class {asset_class.value!r} 不在本 provider 宣告能力內"
                f"(支援：{sorted(m.value for m in self.asset_classes)})"
            )
        unsupported = request.record_kinds - self.record_kinds
        if unsupported:
            raise UnsupportedCapabilityError(
                f"record_kinds {sorted(m.value for m in unsupported)} 不在本 provider 宣告能力內"
                f"(支援：{sorted(m.value for m in self.record_kinds)})"
            )


@dataclass(frozen=True, slots=True)
class SubscriptionRequest:
    """訂閱請求 · instrument + 要哪些 record kinds(+ 委託簿檔數)。"""

    instrument: InstrumentRef
    record_kinds: frozenset[RecordKind]
    depth_levels: int | None = None  # 僅訂 ORDER_BOOK 時有意義

    def __post_init__(self) -> None:
        if not self.record_kinds:
            raise ValueError("record_kinds 不可為空(不知道要訂什麼)")
        for kind in self.record_kinds:
            if not isinstance(kind, RecordKind):
                raise ValueError(
                    f"record_kinds 元素必須是 RecordKind，不可為 {type(kind).__name__}"
                )
        object.__setattr__(self, "record_kinds", frozenset(self.record_kinds))
        if self.depth_levels is not None:
            if isinstance(self.depth_levels, bool) or not isinstance(self.depth_levels, int):
                raise ValueError(
                    f"depth_levels 必須是正整數，不可為 {type(self.depth_levels).__name__}"
                )
            if self.depth_levels < 1:
                raise ValueError(f"depth_levels 必須 >= 1：{self.depth_levels}")
            if RecordKind.ORDER_BOOK not in self.record_kinds:
                raise ValueError("depth_levels 只在訂閱 ORDER_BOOK 時有意義(請移除或加訂)")


@dataclass(frozen=True, slots=True)
class ProviderHealth:
    """健康快照 · 連線 / 重連 / gap 統計(§15 長跑報告與 S09 遙測的資料來源)。"""

    state: ProviderState
    reconnect_count: int
    sequence_gap_count: int
    last_record_at: datetime | None

    def __post_init__(self) -> None:
        if not isinstance(self.state, ProviderState):
            raise ValueError(f"state 必須是 ProviderState，不可為 {type(self.state).__name__}")
        ensure_non_negative_int("reconnect_count", self.reconnect_count)
        ensure_non_negative_int("sequence_gap_count", self.sequence_gap_count)
        if self.last_record_at is not None:
            ensure_utc("last_record_at", self.last_record_at)


class SequenceQualityTracker:
    """斷號 / 亂序偵測(per instrument)· Lean Synchronizer 模式。

    provider 實作(adapter / replay)共用。序號語義由來源「宣告」：
    - sequence_contiguous=True(預設)：序號應連續，跳號 → GAP_DETECTED。
    - sequence_contiguous=False：序號只保證遞增不保證連續(如場所級流水號，
      單一商品訂閱天然跳號——2026-07-17 sandbox 兩輪實測定案)，
      跳號不是缺口；仍偵測序號倒退/重複與時序倒退 → OUT_OF_ORDER。
    只標旗不修正(下游 S15 分級處理)。
    """

    def __init__(self, *, sequence_contiguous: bool = True) -> None:
        self._sequence_contiguous = sequence_contiguous
        self._last_sequence: dict[str, int] = {}
        self._last_source_ts: dict[str, datetime] = {}
        self._gap_count = 0

    @property
    def gap_count(self) -> int:
        """偵測到的缺口總數(進 ProviderHealth.sequence_gap_count)。"""
        return self._gap_count

    def observe(self, record: MarketDataRecord) -> set[DataQualityFlag]:
        """觀察一筆 record，回傳應追加的品質旗標。"""
        flags: set[DataQualityFlag] = set()
        key = record.instrument.instrument_id
        if record.sequence is not None:
            last = self._last_sequence.get(key)
            if last is not None:
                if self._sequence_contiguous and record.sequence > last + 1:
                    flags.add(DataQualityFlag.GAP_DETECTED)  # 斷號＝資料缺口
                    self._gap_count += 1
                elif record.sequence <= last:
                    flags.add(DataQualityFlag.OUT_OF_ORDER)  # 序號倒退/重複
            self._last_sequence[key] = (
                max(last, record.sequence) if last is not None else record.sequence
            )
        last_ts = self._last_source_ts.get(key)
        if last_ts is not None and record.source_timestamp < last_ts:
            flags.add(DataQualityFlag.OUT_OF_ORDER)  # 時序倒退
        else:
            self._last_source_ts[key] = record.source_timestamp
        return flags


class MarketDataProvider(Protocol):
    """L2 行情供應者統一介面 · 任何供應商 adapter 與 replay 皆實作本 Protocol。

    生命週期：connect → subscribe → stream → unsubscribe → disconnect；
    contract test(tests/data/contract/)對每個實作驗證同一套行為契約。
    """

    @property
    def provider_id(self) -> str:
        """全域唯一 provider 識別，如 "replay"。"""

    @property
    def tenant_id(self) -> str:
        """建構時必填注入，無預設(§8.2)。"""

    def capabilities(self) -> ProviderCapabilities:
        """能力宣告；宣告外請求 fail-closed。"""

    def compliance_profile(self) -> ProviderComplianceProfile:
        """合規側寫；無側寫的 provider 不得註冊進 Registry。"""

    async def connect(self) -> None:
        """建立連線。未過 actual-connect gate 直接拋 ComplianceGateError。"""

    async def disconnect(self) -> None:
        """關閉連線並釋放資源(冪等：重複呼叫不炸)。"""

    async def subscribe(self, request: SubscriptionRequest) -> str:
        """訂閱，回傳訂閱 handle。未 connect 就呼叫 → ProviderStateError。"""

    async def unsubscribe(self, handle: str) -> None:
        """退訂。無效 handle → ProviderStateError(fail fast，不靜默吞)。"""

    def stream(self) -> AsyncIterator[MarketDataRecord]:
        """統一出口：正規化後的 MarketDataRecord 流。"""

    async def health(self) -> ProviderHealth:
        """連線 / 延遲 / gap 統計快照。"""
