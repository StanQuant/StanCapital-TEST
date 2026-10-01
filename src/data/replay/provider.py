"""ReplayMarketDataProvider · 歷史/錄製資料重放(規格 §10、D5)。

角色：第二個 MarketDataProvider 實作——證明 Protocol 不綁任何供應商；
回測與測試共用(Charter 紅線「backtest = live 同碼」的地基)。

行為鐵律：
- 重放資料一律帶 REPLAYED flag，下游能區分「重放」與「即時」。
- ingest_timestamp 用重放時刻(不冒充原始接收時間)；tenant_id 換成本
  provider 注入的租戶；license_tag 原樣保留(授權隨 capture 走)。
- 斷號 → GAP_DETECTED、時序倒退 → OUT_OF_ORDER：壞資料場景可重放可驗證
  (Lean 亂序 fixture 模式)，不靜默修正。
- 只重放真 capture 或明確標示的合成 fixture，不製造假 LOB(Archive 教訓)。
"""

from __future__ import annotations

import asyncio
import dataclasses
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from datetime import UTC, date, datetime
from enum import StrEnum

from ulid import ULID

from src.core.validation import ensure_non_empty
from src.data.compliance import (
    ActualConnectGate,
    ProviderComplianceProfile,
    RateLimitPolicy,
    RateLimitSource,
    ensure_may_actual_connect,
)
from src.data.provider import (
    ProviderCapabilities,
    ProviderHealth,
    ProviderState,
    ProviderStateError,
    SequenceQualityTracker,
    SubscriptionRequest,
)
from src.data.sinks import (
    MarketDataLifecycleAction,
    MarketDataLifecycleEvent,
    MarketDataLifecycleSink,
    NoopMarketDataLifecycleSink,
)
from src.data.types import AssetClass, DataQualityFlag, MarketDataRecord, RecordKind

REPLAY_PROVIDER_ID = "replay"

# 重放屬本地資源，上限只防呆(訂閱本身無外部成本)
REPLAY_MAX_SUBSCRIPTIONS = 256

# 本地資料的「條款」指向專案內文件；實際授權隨每筆 record 的 license_tag 走
_REPLAY_TERMS_URL = "https://stanquant.internal/data-licenses/replay"
_REPLAY_TERMS_CHECKED = date(2026, 7, 3)


class ReplayMode(StrEnum):
    """重放時間模式(規格 §10)。"""

    AS_FAST_AS_POSSIBLE = "as_fast_as_possible"  # 測試 / 回測：不等待
    PACED = "paced"  # demo：照 source_timestamp 間隔重放


def replay_capabilities() -> ProviderCapabilities:
    """重放能力：依 capture 資料可承載任何 AssetClass / RecordKind(D2)。"""
    return ProviderCapabilities(
        asset_classes=frozenset(AssetClass),
        record_kinds=frozenset(RecordKind),
        supports_replay=True,
        supports_snapshot=True,
        max_subscriptions=REPLAY_MAX_SUBSCRIPTIONS,
    )


def replay_compliance_profile() -> ProviderComplianceProfile:
    """重放側寫：本地資料無外部連線 → READY_FOR_SANDBOX(規格 §12.3)。

    backoff_on_limit=False 僅本地來源允許(不存在「打爆對方」的問題)。
    """
    return ProviderComplianceProfile(
        terms_url=_REPLAY_TERMS_URL,
        terms_last_checked=_REPLAY_TERMS_CHECKED,
        commercial_use_allowed=True,  # 內部使用；對外散布仍看各 record 的 license_tag
        redistribution_allowed=False,  # 保守預設：capture 內容不得轉發
        attribution_required=False,
        third_party_terms_required=False,
        rate_limit_source=RateLimitSource.OFFICIAL,
        internal_safe_rate_limit=RateLimitPolicy(
            max_concurrency=64,
            min_interval_ms=0,
            max_requests_per_window=None,
            window_seconds=None,
            backoff_on_limit=False,
        ),
        sandbox_available=False,
        sandbox_scope=None,
        testnet_endpoint_rest=None,
        testnet_endpoint_ws=None,
        production_endpoint_rest=None,
        production_endpoint_ws=None,
        credentials_required=False,
        secret_provider_required=True,  # 恆為 True(validator 強制)
        actual_connect_gate=ActualConnectGate.READY_FOR_SANDBOX,
        region_restrictions=(),
    )


class ReplayMarketDataProvider:
    """把正規化 capture 重放為 MarketDataRecord 流。

    now_fn / sleep_fn 可注入(測試決定性)；tenant_id 必填無預設(§8.2)。
    """

    def __init__(
        self,
        records: Sequence[MarketDataRecord],
        *,
        tenant_id: str,
        mode: ReplayMode = ReplayMode.AS_FAST_AS_POSSIBLE,
        now_fn: Callable[[], datetime] | None = None,
        sleep_fn: Callable[[float], Awaitable[None]] | None = None,
        lifecycle_sink: MarketDataLifecycleSink | None = None,
        actor_id: str = "market-data-replay",
        monotonic_fn: Callable[[], float] | None = None,
    ) -> None:
        ensure_non_empty("tenant_id", tenant_id)
        ensure_non_empty("actor_id", actor_id)
        if not isinstance(mode, ReplayMode):
            raise ValueError(f"mode 必須是 ReplayMode，不可為 {type(mode).__name__}")
        for record in records:
            if not isinstance(record, MarketDataRecord):
                raise ValueError(
                    f"records 元素必須是 MarketDataRecord，不可為 {type(record).__name__}"
                )
        self._records = tuple(records)
        self._tenant_id = tenant_id
        self._mode = mode
        self._now_fn = now_fn if now_fn is not None else _utc_now
        self._sleep_fn = sleep_fn if sleep_fn is not None else asyncio.sleep
        self._lifecycle_sink = lifecycle_sink or NoopMarketDataLifecycleSink()
        self._actor_id = actor_id
        self._trace_id = str(ULID())
        self._monotonic_fn = monotonic_fn if monotonic_fn is not None else time.perf_counter
        self._connected = False
        self._subscriptions: dict[str, SubscriptionRequest] = {}
        self._quality = SequenceQualityTracker()  # 斷號 / 亂序偵測(與 adapter 共用套路)
        self._last_record_at: datetime | None = None

    @property
    def provider_id(self) -> str:
        return REPLAY_PROVIDER_ID

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    def capabilities(self) -> ProviderCapabilities:
        return replay_capabilities()

    def compliance_profile(self) -> ProviderComplianceProfile:
        return replay_compliance_profile()

    async def connect(self) -> None:
        """gate 檢查後開啟(READY_FOR_SANDBOX 必過；檢查本身不可省——契約一致性)。"""
        ensure_may_actual_connect(self.compliance_profile(), self.provider_id)
        self._connected = True
        self._lifecycle_sink.emit(
            MarketDataLifecycleEvent(
                action=MarketDataLifecycleAction.PROVIDER_CONNECT,
                provider_id=self.provider_id,
                tenant_id=self._tenant_id,
                actor_id=self._actor_id,
                trace_id=self._trace_id,
                result="success",
            )
        )

    async def disconnect(self) -> None:
        """冪等關閉；進行中的 stream 會在下一筆前停止。"""
        self._connected = False
        self._lifecycle_sink.emit(
            MarketDataLifecycleEvent(
                action=MarketDataLifecycleAction.PROVIDER_DISCONNECT,
                provider_id=self.provider_id,
                tenant_id=self._tenant_id,
                actor_id=self._actor_id,
                trace_id=self._trace_id,
                result="success",
            )
        )

    async def subscribe(self, request: SubscriptionRequest) -> str:
        if not self._connected:
            raise ProviderStateError("尚未 connect，不可 subscribe(fail-closed)")
        self.capabilities().ensure_supported(request)
        if len(self._subscriptions) >= REPLAY_MAX_SUBSCRIPTIONS:
            raise ProviderStateError(f"訂閱數已達上限 {REPLAY_MAX_SUBSCRIPTIONS}，拒絕新訂閱")
        handle = str(ULID())
        self._subscriptions[handle] = request
        return handle

    async def unsubscribe(self, handle: str) -> None:
        if handle not in self._subscriptions:
            raise ProviderStateError(f"未知的訂閱 handle：{handle!r}(fail fast，不靜默吞)")
        del self._subscriptions[handle]

    def stream(self) -> AsyncIterator[MarketDataRecord]:
        return self._generate()

    async def health(self) -> ProviderHealth:
        return ProviderHealth(
            state=ProviderState.CONNECTED if self._connected else ProviderState.DISCONNECTED,
            reconnect_count=0,  # 本地重放不存在重連
            sequence_gap_count=self._quality.gap_count,
            last_record_at=self._last_record_at,
        )

    # ------------------------------------------------------------------
    # 內部
    # ------------------------------------------------------------------

    def _matches_subscription(self, record: MarketDataRecord) -> bool:
        return any(
            request.instrument.instrument_id == record.instrument.instrument_id
            and record.record_kind in request.record_kinds
            for request in self._subscriptions.values()
        )

    def _quality_flags(self, record: MarketDataRecord) -> set[DataQualityFlag]:
        """重放品質旗標：REPLAYED 恆帶 + 斷號/亂序偵測(不靜默修正)。"""
        flags = set(record.data_quality_flags)
        flags.add(DataQualityFlag.REPLAYED)
        flags |= self._quality.observe(record)
        return flags

    async def _generate(self) -> AsyncIterator[MarketDataRecord]:
        trace_id = str(ULID())
        operation_started = self._monotonic_fn()
        emitted_count = 0
        initial_gap_count = self._quality.gap_count
        source_times: list[datetime] = []
        license_tags: set[str] = set()
        result = "success"
        self._lifecycle_sink.emit(
            MarketDataLifecycleEvent(
                action=MarketDataLifecycleAction.REPLAY_START,
                provider_id=self.provider_id,
                tenant_id=self._tenant_id,
                actor_id=self._actor_id,
                trace_id=trace_id,
                result="success",
                record_count=0,
            )
        )
        previous_source_ts: datetime | None = None
        try:
            for record in self._records:
                if not self._connected:
                    return  # disconnect 後停止產出
                if not self._matches_subscription(record):
                    continue
                if self._mode is ReplayMode.PACED and previous_source_ts is not None:
                    delta = (record.source_timestamp - previous_source_ts).total_seconds()
                    if delta > 0:
                        await self._sleep_fn(delta)
                previous_source_ts = record.source_timestamp
                flags = self._quality_flags(record)
                ingest = self._now_fn()
                if record.source_timestamp > ingest:
                    # 不信任時鐘：capture 宣稱時間晚於現在＝異常，夾制並標 SUSPECT
                    ingest = record.source_timestamp
                    flags.add(DataQualityFlag.SUSPECT)
                replayed = dataclasses.replace(
                    record,
                    instrument=dataclasses.replace(
                        record.instrument, provider_id=REPLAY_PROVIDER_ID
                    ),
                    ingest_timestamp=ingest,
                    data_quality_flags=frozenset(flags),
                    tenant_id=self._tenant_id,  # 重放進「本」租戶的流(§8.2)
                )
                self._last_record_at = ingest
                emitted_count += 1
                source_times.append(record.source_timestamp)
                license_tags.add(record.license_tag)
                yield replayed
        except Exception:
            result = "failed"
            raise
        finally:
            duration_ms = max(0.0, (self._monotonic_fn() - operation_started) * 1000)
            license_tag = next(iter(license_tags)) if len(license_tags) == 1 else None
            if len(license_tags) > 1:
                license_tag = "mixed"
            self._lifecycle_sink.emit(
                MarketDataLifecycleEvent(
                    action=MarketDataLifecycleAction.REPLAY_END,
                    provider_id=self.provider_id,
                    tenant_id=self._tenant_id,
                    actor_id=self._actor_id,
                    trace_id=trace_id,
                    result=result,
                    license_tag=license_tag,
                    record_count=emitted_count,
                    started_at=min(source_times) if source_times else None,
                    ended_at=max(source_times) if source_times else None,
                    duration_ms=duration_ms,
                    sequence_gap_count=self._quality.gap_count - initial_gap_count,
                )
            )


def _utc_now() -> datetime:
    return datetime.now(UTC)
