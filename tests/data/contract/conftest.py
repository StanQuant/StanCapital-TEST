"""contract test 共用 harness · 所有 provider 同一套腳本語義。

「新增第三個 provider 時，只加一個 harness，同套測試直接生效」——
這就是 Protocol 不綁供應商的可驗證證明(規格 §11)。

腳本語義：TradeEvent(sequence, offset_seconds) 描述「第幾號、何時」的成交；
- ReplayHarness 把它變成 capture records；
harness 注入固定時鐘(NOW)與零等待 sleep，測試決定性。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from src.data.provider import MarketDataProvider, SubscriptionRequest
from src.data.replay.provider import ReplayMarketDataProvider
from src.data.types import AssetClass, InstrumentRef, RecordKind

from tests.data.test_types import make_record

# 對齊官方範例 time=1685338200000000(2023-05-29 05:30 UTC)
BASE_TS = datetime(2023, 5, 29, 5, 30, tzinfo=UTC)
NOW = datetime(2026, 7, 3, 6, 0, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class TradeEvent:
    """provider 中立的腳本事件：一筆 2330 成交。"""

    sequence: int | None
    offset_seconds: int = 0


class ReplayHarness:
    """腳本 → capture records → ReplayMarketDataProvider。"""

    name = "replay"
    sequence_contiguous = True  # capture 序號沿用來源語義；fixture 為連號

    def make(self, scenario: list[TradeEvent]) -> MarketDataProvider:
        records = [
            make_record(
                RecordKind.TRADE,
                sequence=event.sequence,
                source_timestamp=BASE_TS + timedelta(seconds=event.offset_seconds),
                ingest_timestamp=BASE_TS + timedelta(seconds=event.offset_seconds + 1),
            )
            for event in scenario
        ]
        return ReplayMarketDataProvider(records, tenant_id="acme", now_fn=lambda: NOW)

    def trade_request(self) -> SubscriptionRequest:
        return SubscriptionRequest(
            instrument=InstrumentRef.build(
                asset_class=AssetClass.TW_STOCK,
                venue="twse",
                provider_id="replay",
                symbol="2330",
                currency="TWD",
            ),
            record_kinds=frozenset({RecordKind.TRADE}),
        )

    def unsupported_request(self) -> SubscriptionRequest | None:
        return None  # replay 宣告承載全部 asset class / kind(D2)，無「宣告外」


_HARNESSES = {harness.name: harness for harness in (ReplayHarness(),)}


@pytest.fixture(params=sorted(_HARNESSES))
def harness(request: pytest.FixtureRequest) -> ReplayHarness:
    """參數化 harness：每個 contract 測試自動對所有 providers 各跑一次。"""
    return _HARNESSES[request.param]
