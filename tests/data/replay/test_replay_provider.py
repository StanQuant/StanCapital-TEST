"""ReplayMarketDataProvider 單元測試 · 生命週期 / REPLAYED flag / gap 偵測 / 兩種時間模式。"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from src.data.compliance import ActualConnectGate
from src.data.provider import ProviderState, ProviderStateError, SubscriptionRequest
from src.data.replay.provider import (
    REPLAY_MAX_SUBSCRIPTIONS,
    REPLAY_PROVIDER_ID,
    ReplayMarketDataProvider,
    ReplayMode,
    replay_capabilities,
    replay_compliance_profile,
)
from src.data.sinks import (
    InMemoryMarketDataLifecycleSink,
    MarketDataLifecycleAction,
    MarketDataLifecycleSink,
)
from src.data.types import (
    AssetClass,
    DataQualityFlag,
    MarketDataRecord,
    RecordKind,
    TradeTick,
)

from tests.data.test_types import T0, make_record, make_ref

NOW = datetime(2026, 7, 3, 6, 0, 0, tzinfo=UTC)


def make_provider(
    records: list[MarketDataRecord] | None = None,
    *,
    mode: ReplayMode = ReplayMode.AS_FAST_AS_POSSIBLE,
    sleeps: list[float] | None = None,
    now: datetime = NOW,
    lifecycle_sink: MarketDataLifecycleSink | None = None,
    monotonic_fn: object | None = None,
) -> ReplayMarketDataProvider:
    async def fake_sleep(seconds: float) -> None:
        if sleeps is not None:
            sleeps.append(seconds)

    return ReplayMarketDataProvider(
        records if records is not None else [make_record(RecordKind.TRADE)],
        tenant_id="acme",
        mode=mode,
        now_fn=lambda: now,
        sleep_fn=fake_sleep,
        lifecycle_sink=lifecycle_sink,
        monotonic_fn=monotonic_fn,  # type: ignore[arg-type]
    )


def trade_request() -> SubscriptionRequest:
    return SubscriptionRequest(instrument=make_ref(), record_kinds=frozenset({RecordKind.TRADE}))


async def collect(provider: ReplayMarketDataProvider) -> list[MarketDataRecord]:
    return [record async for record in provider.stream()]


class TestDeclarations:
    def test_capabilities_cover_all_asset_classes_and_kinds(self) -> None:
        caps = replay_capabilities()
        assert caps.asset_classes == frozenset(AssetClass)
        assert caps.record_kinds == frozenset(RecordKind)
        assert caps.supports_replay is True
        assert caps.supports_snapshot is True
        assert caps.max_subscriptions == REPLAY_MAX_SUBSCRIPTIONS

    def test_profile_gate_is_ready_for_sandbox(self) -> None:
        profile = replay_compliance_profile()
        assert profile.actual_connect_gate is ActualConnectGate.READY_FOR_SANDBOX
        assert profile.secret_provider_required is True
        assert profile.credentials_required is False
        assert profile.redistribution_allowed is False

    def test_provider_identity(self) -> None:
        provider = make_provider()
        assert provider.provider_id == REPLAY_PROVIDER_ID == "replay"
        assert provider.tenant_id == "acme"


class TestConstructorValidation:
    def test_empty_tenant_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            ReplayMarketDataProvider([], tenant_id="")
        assert str(exc.value) == "tenant_id 不可為空字串"

    def test_empty_actor_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            ReplayMarketDataProvider([], tenant_id="acme", actor_id="")
        assert str(exc.value) == "actor_id 不可為空字串"

    def test_bad_mode_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            ReplayMarketDataProvider([], tenant_id="acme", mode="paced")  # type: ignore[arg-type]
        assert str(exc.value) == "mode 必須是 ReplayMode，不可為 str"

    def test_non_record_element_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            ReplayMarketDataProvider(["nope"], tenant_id="acme")  # type: ignore[list-item]
        assert str(exc.value) == "records 元素必須是 MarketDataRecord，不可為 str"

    def test_replay_mode_members_pinned(self) -> None:
        assert {m.name: m.value for m in ReplayMode} == {
            "AS_FAST_AS_POSSIBLE": "as_fast_as_possible",
            "PACED": "paced",
        }


class TestLifecycle:
    async def test_subscribe_before_connect_rejected(self) -> None:
        provider = make_provider()
        with pytest.raises(ProviderStateError) as exc:
            await provider.subscribe(trade_request())
        assert str(exc.value) == "尚未 connect，不可 subscribe(fail-closed)"

    async def test_stream_before_subscribe_yields_nothing(self) -> None:
        provider = make_provider()
        await provider.connect()
        assert await collect(provider) == []

    async def test_subscribe_then_stream_yields(self) -> None:
        provider = make_provider()
        await provider.connect()
        await provider.subscribe(trade_request())
        records = await collect(provider)
        assert len(records) == 1

    async def test_lifecycle_sink_connects_replay_to_s05_and_s09_port(self) -> None:
        sink = InMemoryMarketDataLifecycleSink()
        times = iter([1.0, 1.25])
        records = [
            make_record(RecordKind.TRADE, license_tag="license-a"),
            make_record(RecordKind.TRADE, license_tag="license-b"),
        ]
        provider = make_provider(
            records,
            lifecycle_sink=sink,
            monotonic_fn=lambda: next(times),
        )
        await provider.connect()
        await provider.subscribe(trade_request())
        assert len(await collect(provider)) == 2
        await provider.disconnect()

        assert [event.action for event in sink.events] == [
            MarketDataLifecycleAction.PROVIDER_CONNECT,
            MarketDataLifecycleAction.REPLAY_START,
            MarketDataLifecycleAction.REPLAY_END,
            MarketDataLifecycleAction.PROVIDER_DISCONNECT,
        ]
        assert [record.action for record in sink.audit_records] == [
            "market_data.replay_start",
            "market_data.replay_end",
        ]
        connect, start, end, disconnect = sink.events
        assert connect.actor_id == "market-data-replay"
        assert connect.result == "success"
        assert start.result == "success"
        assert start.record_count == 0
        assert end.result == "success"
        assert disconnect.result == "success"
        assert end.license_tag == "mixed"
        assert end.record_count == 2
        assert end.duration_ms == 250.0

    async def test_replay_end_single_license_and_incremental_gap_count(self) -> None:
        sink = InMemoryMarketDataLifecycleSink()
        provider = make_provider(
            [seq_record(1), seq_record(3)],
            lifecycle_sink=sink,
        )
        await provider.connect()
        await provider.subscribe(trade_request())

        assert len(await collect(provider)) == 2
        assert len(await collect(provider)) == 2
        replay_ends = [
            event for event in sink.events if event.action is MarketDataLifecycleAction.REPLAY_END
        ]
        assert [event.license_tag for event in replay_ends] == [
            "replay-internal",
            "replay-internal",
        ]
        assert [event.sequence_gap_count for event in replay_ends] == [1, 0]

    async def test_replay_failure_is_audited_before_error_propagates(self) -> None:
        sink = InMemoryMarketDataLifecycleSink()

        def broken_now() -> datetime:
            raise RuntimeError("clock failed")

        provider = ReplayMarketDataProvider(
            [make_record(RecordKind.TRADE)],
            tenant_id="acme",
            now_fn=broken_now,
            lifecycle_sink=sink,
        )
        await provider.connect()
        await provider.subscribe(trade_request())

        with pytest.raises(RuntimeError, match="clock failed"):
            await collect(provider)
        assert sink.events[-1].action is MarketDataLifecycleAction.REPLAY_END
        assert sink.events[-1].result == "failed"
        assert sink.audit_records[-1].response_status == "failed"

    async def test_unsubscribe_stops_stream(self) -> None:
        provider = make_provider([make_record(RecordKind.TRADE), make_record(RecordKind.TRADE)])
        await provider.connect()
        handle = await provider.subscribe(trade_request())
        stream = provider.stream()
        first = await anext(stream)
        assert first.record_kind is RecordKind.TRADE
        await provider.unsubscribe(handle)
        remaining = [record async for record in stream]
        assert remaining == []

    async def test_unsubscribe_unknown_handle_rejected(self) -> None:
        provider = make_provider()
        await provider.connect()
        with pytest.raises(ProviderStateError) as exc:
            await provider.unsubscribe("ghost")
        assert str(exc.value).startswith("未知的訂閱 handle：'ghost'")

    async def test_disconnect_mid_stream_stops(self) -> None:
        provider = make_provider([make_record(RecordKind.TRADE), make_record(RecordKind.TRADE)])
        await provider.connect()
        await provider.subscribe(trade_request())
        stream = provider.stream()
        await anext(stream)
        await provider.disconnect()
        assert [record async for record in stream] == []

    async def test_disconnect_is_idempotent(self) -> None:
        provider = make_provider()
        await provider.disconnect()
        await provider.disconnect()  # 重複呼叫不炸

    async def test_subscription_cap_enforced(self) -> None:
        provider = make_provider()
        await provider.connect()
        for _ in range(REPLAY_MAX_SUBSCRIPTIONS):
            await provider.subscribe(trade_request())
        with pytest.raises(ProviderStateError) as exc:
            await provider.subscribe(trade_request())
        assert str(exc.value).startswith(f"訂閱數已達上限 {REPLAY_MAX_SUBSCRIPTIONS}")

    async def test_kind_filter_applies(self) -> None:
        # 訂 TRADE 就只收 TRADE(QUOTE 被過濾)
        provider = make_provider([make_record(RecordKind.QUOTE), make_record(RecordKind.TRADE)])
        await provider.connect()
        await provider.subscribe(trade_request())
        records = await collect(provider)
        assert [r.record_kind for r in records] == [RecordKind.TRADE]


class TestReplaySemantics:
    async def test_replayed_flag_tenant_and_provider_rewritten(self) -> None:
        source = make_record(RecordKind.TRADE, tenant_id="original-tenant")
        provider = make_provider([source])
        await provider.connect()
        await provider.subscribe(trade_request())
        (record,) = await collect(provider)
        assert DataQualityFlag.REPLAYED in record.data_quality_flags  # 重放必標
        assert record.tenant_id == "acme"  # 換成注入租戶(§8.2)
        assert record.instrument.provider_id == "replay"  # 產出者是 replay
        assert record.license_tag == source.license_tag  # 授權隨 capture 走
        assert record.ingest_timestamp == NOW  # 重放時刻當 ingest
        assert record.source_timestamp == source.source_timestamp

    async def test_existing_flags_preserved(self) -> None:
        source = make_record(RecordKind.TRADE, data_quality_flags=frozenset({DataQualityFlag.LATE}))
        provider = make_provider([source])
        await provider.connect()
        await provider.subscribe(trade_request())
        (record,) = await collect(provider)
        assert DataQualityFlag.LATE in record.data_quality_flags

    async def test_future_source_clamped_and_suspect(self) -> None:
        # capture 宣稱時間晚於「現在」＝時鐘異常：夾制 + SUSPECT，不靜默
        past_now = T0  # 假時鐘撥回 record 的 source_timestamp 之前
        source = make_record(RecordKind.TRADE, source_timestamp=T0 + timedelta(seconds=1))
        provider = make_provider([source], now=past_now)
        await provider.connect()
        await provider.subscribe(trade_request())
        (record,) = await collect(provider)
        assert record.ingest_timestamp == record.source_timestamp
        assert DataQualityFlag.SUSPECT in record.data_quality_flags


def seq_record(sequence: int, *, offset_seconds: int = 0) -> MarketDataRecord:
    return make_record(
        RecordKind.TRADE,
        sequence=sequence,
        source_timestamp=T0 + timedelta(seconds=offset_seconds),
        ingest_timestamp=T0 + timedelta(seconds=offset_seconds + 1),
    )


class TestGapDetection:
    async def test_sequence_gap_flagged_and_counted(self) -> None:
        # 序號 1,2,5：第三筆斷號 → GAP_DETECTED，health 統計 +1(Lean 模式)
        provider = make_provider([seq_record(1), seq_record(2), seq_record(5)])
        await provider.connect()
        await provider.subscribe(trade_request())
        records = await collect(provider)
        assert DataQualityFlag.GAP_DETECTED not in records[0].data_quality_flags
        assert DataQualityFlag.GAP_DETECTED not in records[1].data_quality_flags
        assert DataQualityFlag.GAP_DETECTED in records[2].data_quality_flags
        health = await provider.health()
        assert health.sequence_gap_count == 1

    async def test_sequence_regress_flagged_out_of_order(self) -> None:
        # 序號 1,3,2：3 斷號(GAP)、2 倒退(OUT_OF_ORDER)
        provider = make_provider([seq_record(1), seq_record(3), seq_record(2)])
        await provider.connect()
        await provider.subscribe(trade_request())
        records = await collect(provider)
        assert DataQualityFlag.GAP_DETECTED in records[1].data_quality_flags
        assert DataQualityFlag.OUT_OF_ORDER in records[2].data_quality_flags

    async def test_timestamp_regress_flagged_out_of_order(self) -> None:
        # source_timestamp 倒退(無序號輔助)也要抓到
        early = make_record(RecordKind.TRADE, sequence=None)
        late = make_record(
            RecordKind.TRADE,
            sequence=None,
            source_timestamp=T0 - timedelta(seconds=5),
        )
        provider = make_provider([early, late])
        await provider.connect()
        await provider.subscribe(trade_request())
        records = await collect(provider)
        assert DataQualityFlag.OUT_OF_ORDER not in records[0].data_quality_flags
        assert DataQualityFlag.OUT_OF_ORDER in records[1].data_quality_flags

    async def test_contiguous_sequences_clean(self) -> None:
        provider = make_provider([seq_record(1), seq_record(2), seq_record(3)])
        await provider.connect()
        await provider.subscribe(trade_request())
        records = await collect(provider)
        for record in records:
            # 連號 + 相同時間戳：除 REPLAYED 外不得有任何品質旗標(殺邊界變異)
            assert record.data_quality_flags == frozenset({DataQualityFlag.REPLAYED})
        assert (await provider.health()).sequence_gap_count == 0


class TestPacing:
    async def test_paced_mode_sleeps_source_deltas(self) -> None:
        # T0、T0+1ms、T0+3ms → sleep [1ms, 2ms](第一筆不等)
        sleeps: list[float] = []
        records = [
            seq_record(1),
            make_record(
                RecordKind.TRADE,
                sequence=2,
                source_timestamp=T0 + timedelta(milliseconds=1),
                ingest_timestamp=T0 + timedelta(milliseconds=2),
            ),
            make_record(
                RecordKind.TRADE,
                sequence=3,
                source_timestamp=T0 + timedelta(milliseconds=3),
                ingest_timestamp=T0 + timedelta(milliseconds=4),
            ),
        ]
        provider = make_provider(records, mode=ReplayMode.PACED, sleeps=sleeps)
        await provider.connect()
        await provider.subscribe(trade_request())
        await collect(provider)
        assert sleeps == pytest.approx([0.001, 0.002])

    async def test_paced_mode_zero_delta_does_not_sleep(self) -> None:
        # 同一時間戳的兩筆(如同 tick 內多筆成交)：delta=0 不呼叫 sleep
        sleeps: list[float] = []
        records = [seq_record(1, offset_seconds=0), seq_record(2, offset_seconds=0)]
        provider = make_provider(records, mode=ReplayMode.PACED, sleeps=sleeps)
        await provider.connect()
        await provider.subscribe(trade_request())
        await collect(provider)
        assert sleeps == []

    async def test_as_fast_as_possible_never_sleeps(self) -> None:
        sleeps: list[float] = []
        records = [seq_record(1, offset_seconds=0), seq_record(2, offset_seconds=10)]
        provider = make_provider(records, sleeps=sleeps)
        await provider.connect()
        await provider.subscribe(trade_request())
        await collect(provider)
        assert sleeps == []


class TestHealth:
    async def test_initial_health(self) -> None:
        provider = make_provider()
        health = await provider.health()
        assert health.state is ProviderState.DISCONNECTED
        assert health.reconnect_count == 0
        assert health.sequence_gap_count == 0
        assert health.last_record_at is None

    async def test_health_after_stream(self) -> None:
        provider = make_provider()
        await provider.connect()
        await provider.subscribe(trade_request())
        await collect(provider)
        health = await provider.health()
        assert health.state is ProviderState.CONNECTED
        assert health.last_record_at == NOW

    async def test_default_now_and_sleep(self) -> None:
        # 預設 now_fn / sleep_fn 路徑：真時鐘下 ingest 一定 >= source(歷史資料)
        provider = ReplayMarketDataProvider(
            [
                make_record(
                    RecordKind.TRADE,
                    payload=TradeTick(price=Decimal("1"), volume=Decimal("1"), aggressor_side=None),
                )
            ],
            tenant_id="acme",
        )
        await provider.connect()
        await provider.subscribe(trade_request())
        (record,) = await collect(provider)
        assert record.ingest_timestamp >= record.source_timestamp
        assert DataQualityFlag.REPLAYED in record.data_quality_flags
