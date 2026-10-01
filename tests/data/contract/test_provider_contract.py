"""provider 行為契約(規格 §11)· 同一套測試 × 所有 providers。

每一條測試都以 harness fixture 參數化：每個 provider 都必須
表現出完全相同的契約行為——這是「Protocol 不綁供應商」的證明。
"""

from __future__ import annotations

import pytest
from src.core.events import MarketEvent
from src.core.types import EventType
from src.data.bridge import MarketDataBridge
from src.data.compliance import ActualConnectGate, ProviderComplianceProfile
from src.data.provider import (
    MarketDataProvider,
    ProviderCapabilities,
    ProviderHealth,
    ProviderStateError,
    UnsupportedCapabilityError,
)
from src.data.registry import ProviderRegistry
from src.data.types import DataQualityFlag, MarketDataRecord

from tests.data.contract.conftest import ReplayHarness, TradeEvent
from tests.data.test_bridge import RecordingBus

Harness = ReplayHarness

CLEAN_SCENARIO = [TradeEvent(1, 0), TradeEvent(2, 1), TradeEvent(3, 2)]
GAP_SCENARIO = [TradeEvent(1, 0), TradeEvent(2, 1), TradeEvent(9, 2)]
OUT_OF_ORDER_SCENARIO = [TradeEvent(1, 0), TradeEvent(3, 1), TradeEvent(2, 2)]


async def connect_and_subscribe(harness: Harness, scenario: list[TradeEvent]) -> MarketDataProvider:
    provider = harness.make(scenario)
    await provider.connect()
    await provider.subscribe(harness.trade_request())
    return provider


async def collect(provider: MarketDataProvider) -> list[MarketDataRecord]:
    return [record async for record in provider.stream()]


class TestComplianceContract:
    async def test_profile_exists_and_consistent(self, harness: Harness) -> None:
        # 契約：compliance profile 存在、secret_provider_required 恆真、
        # gate 是合法成員(§11 第 8 條)
        provider = harness.make(CLEAN_SCENARIO)
        profile = provider.compliance_profile()
        assert isinstance(profile, ProviderComplianceProfile)
        assert profile.secret_provider_required is True
        assert isinstance(profile.actual_connect_gate, ActualConnectGate)

    async def test_identity_contract(self, harness: Harness) -> None:
        provider = harness.make(CLEAN_SCENARIO)
        assert isinstance(provider.provider_id, str) and provider.provider_id
        assert provider.tenant_id == "acme"  # 建構時注入，無預設(§8.2)


class TestCapabilitiesContract:
    async def test_capabilities_declared(self, harness: Harness) -> None:
        caps = harness.make(CLEAN_SCENARIO).capabilities()
        assert isinstance(caps, ProviderCapabilities)

    async def test_out_of_declaration_request_fails_closed(self, harness: Harness) -> None:
        # 宣告外請求 → 拋錯，不靜默回空資料(D2)
        provider = harness.make(CLEAN_SCENARIO)
        await provider.connect()
        unsupported = harness.unsupported_request()
        if unsupported is None:
            # 此 provider 宣告承載一切：宣告必須真的完整(否則就是假宣告)
            caps = provider.capabilities()
            assert len(caps.asset_classes) == 11
            return
        with pytest.raises(UnsupportedCapabilityError):
            await provider.subscribe(unsupported)


class TestLifecycleContract:
    async def test_subscribe_before_connect_raises(self, harness: Harness) -> None:
        provider = harness.make(CLEAN_SCENARIO)
        with pytest.raises(ProviderStateError):
            await provider.subscribe(harness.trade_request())

    async def test_stream_before_subscribe_yields_nothing(self, harness: Harness) -> None:
        provider = harness.make(CLEAN_SCENARIO)
        await provider.connect()
        assert await collect(provider) == []

    async def test_unsubscribe_stops_output(self, harness: Harness) -> None:
        provider = harness.make(CLEAN_SCENARIO)
        await provider.connect()
        handle = await provider.subscribe(harness.trade_request())
        stream = provider.stream()
        first = await anext(stream)
        assert first.sequence == 1
        await provider.unsubscribe(handle)
        assert [record async for record in stream] == []

    async def test_unsubscribe_unknown_handle_raises(self, harness: Harness) -> None:
        provider = harness.make(CLEAN_SCENARIO)
        await provider.connect()
        with pytest.raises(ProviderStateError):
            await provider.unsubscribe("no-such-handle")


class TestRecordInvariantsContract:
    async def test_records_satisfy_six_group_invariants(self, harness: Harness) -> None:
        # §11 第 2-3 條：每筆 record 六組欄位不變式 + tenant 一致 + 時序不倒掛
        provider = await connect_and_subscribe(harness, CLEAN_SCENARIO)
        records = await collect(provider)
        assert len(records) == 3
        for record in records:
            assert isinstance(record, MarketDataRecord)  # 構造即驗證(fail-closed)
            assert record.tenant_id == provider.tenant_id
            assert record.instrument.provider_id == provider.provider_id
            assert record.source_timestamp <= record.ingest_timestamp
            assert record.source_timestamp.tzinfo is not None
            assert record.license_tag

    async def test_gap_semantics_follow_declaration(self, harness: Harness) -> None:
        # §11 第 4 條(2026-07-17 修訂)：斷號偵測跟隨來源的序號語義宣告——
        # 宣告連續：跳號 → GAP_DETECTED；宣告非連續：跳號不得誤報
        provider = await connect_and_subscribe(harness, GAP_SCENARIO)
        records = await collect(provider)
        health = await provider.health()
        if harness.sequence_contiguous:
            assert DataQualityFlag.GAP_DETECTED in records[2].data_quality_flags
            assert health.sequence_gap_count == 1
        else:
            assert DataQualityFlag.GAP_DETECTED not in records[2].data_quality_flags
            assert health.sequence_gap_count == 0  # 非連續來源：跳號不誤報

    async def test_out_of_order_flagged_not_dropped(self, harness: Harness) -> None:
        # §11 第 5 條：亂序 → OUT_OF_ORDER，且不靜默丟棄
        provider = await connect_and_subscribe(harness, OUT_OF_ORDER_SCENARIO)
        records = await collect(provider)
        assert len(records) == 3  # 一筆都沒少
        assert DataQualityFlag.OUT_OF_ORDER in records[2].data_quality_flags

    async def test_health_snapshot_valid(self, harness: Harness) -> None:
        provider = await connect_and_subscribe(harness, CLEAN_SCENARIO)
        await collect(provider)
        health = await provider.health()
        assert isinstance(health, ProviderHealth)
        assert health.last_record_at is not None


class TestBridgeContract:
    async def test_bridge_output_passes_l4_invariants(self, harness: Harness) -> None:
        # §11 第 9 條：降維後的 MarketEvent 全部通過 L4 既有不變式
        provider = await connect_and_subscribe(harness, CLEAN_SCENARIO)
        registry = ProviderRegistry()
        registry.register(provider)
        bus = RecordingBus()
        bridge = MarketDataBridge(bus, registry)  # type: ignore[arg-type]
        published = await bridge.pump(provider)
        assert published == 3
        for topic, event in bus.published:
            assert topic == "acme.l2.market"
            assert isinstance(event, MarketEvent)  # 構造即通過 __post_init__
            assert event.event_type is EventType.MARKET
            assert event.tenant_id == "acme"
            assert event.symbol == "2330"
