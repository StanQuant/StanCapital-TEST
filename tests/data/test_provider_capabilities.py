"""src/data/provider.py 單元測試 · 能力宣告 fail-closed / 訂閱請求 / 健康快照。"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest
from src.data.provider import (
    ProviderCapabilities,
    ProviderHealth,
    ProviderState,
    SubscriptionRequest,
    UnsupportedCapabilityError,
)
from src.data.types import AssetClass, RecordKind

from tests.data.test_types import make_ref


def make_capabilities(**overrides: object) -> ProviderCapabilities:
    values: dict[str, object] = {
        "asset_classes": frozenset({AssetClass.TW_STOCK}),
        "record_kinds": frozenset({RecordKind.QUOTE, RecordKind.TRADE, RecordKind.ORDER_BOOK}),
        "supports_replay": False,
        "supports_snapshot": True,
        "max_subscriptions": 100,
    }
    values.update(overrides)
    return ProviderCapabilities(**values)  # type: ignore[arg-type]


def make_request(**overrides: object) -> SubscriptionRequest:
    values: dict[str, object] = {
        "instrument": make_ref(),
        "record_kinds": frozenset({RecordKind.TRADE}),
    }
    values.update(overrides)
    return SubscriptionRequest(**values)  # type: ignore[arg-type]


class TestProviderState:
    def test_members_pinned(self) -> None:
        assert {m.name: m.value for m in ProviderState} == {
            "DISCONNECTED": "disconnected",
            "CONNECTED": "connected",
            "RECONNECTING": "reconnecting",
            "CIRCUIT_OPEN": "circuit_open",
        }


class TestProviderCapabilities:
    def test_valid(self) -> None:
        caps = make_capabilities()
        assert AssetClass.TW_STOCK in caps.asset_classes

    def test_empty_asset_classes_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            make_capabilities(asset_classes=frozenset())
        assert str(exc.value).startswith("asset_classes 不可為空")

    def test_empty_record_kinds_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            make_capabilities(record_kinds=frozenset())
        assert str(exc.value) == "record_kinds 不可為空"

    def test_wrong_asset_class_element_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            make_capabilities(asset_classes=frozenset({"tw_stock"}))
        assert str(exc.value).startswith("asset_classes 元素必須是 AssetClass")

    def test_wrong_record_kind_element_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            make_capabilities(record_kinds=frozenset({"trade"}))
        assert str(exc.value).startswith("record_kinds 元素必須是 RecordKind")

    @pytest.mark.parametrize("bad", [0, -1])
    def test_non_positive_max_subscriptions_rejected(self, bad: int) -> None:
        with pytest.raises(ValueError) as exc:
            make_capabilities(max_subscriptions=bad)
        assert str(exc.value) == f"max_subscriptions 必須 >= 1：{bad}"

    def test_bool_max_subscriptions_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            make_capabilities(max_subscriptions=True)
        assert str(exc.value) == "max_subscriptions 必須是正整數，不可為 bool"

    def test_sets_normalized_to_frozenset(self) -> None:
        caps = make_capabilities(
            asset_classes={AssetClass.TW_STOCK}, record_kinds={RecordKind.TRADE}
        )
        assert isinstance(caps.asset_classes, frozenset)
        assert isinstance(caps.record_kinds, frozenset)


class TestEnsureSupported:
    def test_supported_request_passes(self) -> None:
        make_capabilities().ensure_supported(make_request())  # 不拋錯即通過

    def test_unsupported_asset_class_rejected(self) -> None:
        # D2 驗收核心：未實作的 asset class 請求 fail-closed 拋錯，不靜默回空資料
        us_ref = make_ref()
        us_ref = dataclasses.replace(
            us_ref,
            asset_class=AssetClass.US_STOCK,
            venue="nyse",
            symbol="TSM",
            instrument_id="us_stock:nyse:TSM",
        )
        with pytest.raises(UnsupportedCapabilityError) as exc:
            make_capabilities().ensure_supported(make_request(instrument=us_ref))
        assert str(exc.value).startswith("asset_class 'us_stock' 不在本 provider 宣告能力內")

    def test_unsupported_record_kind_rejected(self) -> None:
        request = make_request(record_kinds=frozenset({RecordKind.TRADE, RecordKind.FUNDING_RATE}))
        with pytest.raises(UnsupportedCapabilityError) as exc:
            make_capabilities().ensure_supported(request)
        assert str(exc.value).startswith("record_kinds ['funding_rate'] 不在本 provider 宣告能力內")

    def test_subset_of_kinds_passes(self) -> None:
        request = make_request(record_kinds=frozenset({RecordKind.QUOTE, RecordKind.TRADE}))
        make_capabilities().ensure_supported(request)


class TestSubscriptionRequest:
    def test_valid_defaults(self) -> None:
        request = make_request()
        assert request.depth_levels is None

    def test_empty_record_kinds_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            make_request(record_kinds=frozenset())
        assert str(exc.value).startswith("record_kinds 不可為空")

    def test_wrong_kind_element_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            make_request(record_kinds=frozenset({"trade"}))
        assert str(exc.value).startswith("record_kinds 元素必須是 RecordKind")

    def test_set_normalized_to_frozenset(self) -> None:
        request = make_request(record_kinds={RecordKind.TRADE})
        assert isinstance(request.record_kinds, frozenset)

    def test_depth_levels_with_order_book_allowed(self) -> None:
        request = make_request(record_kinds=frozenset({RecordKind.ORDER_BOOK}), depth_levels=5)
        assert request.depth_levels == 5

    @pytest.mark.parametrize("bad", [0, -3])
    def test_non_positive_depth_rejected(self, bad: int) -> None:
        with pytest.raises(ValueError) as exc:
            make_request(record_kinds=frozenset({RecordKind.ORDER_BOOK}), depth_levels=bad)
        assert str(exc.value) == f"depth_levels 必須 >= 1：{bad}"

    def test_bool_depth_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            make_request(record_kinds=frozenset({RecordKind.ORDER_BOOK}), depth_levels=True)
        assert str(exc.value) == "depth_levels 必須是正整數，不可為 bool"

    def test_depth_without_order_book_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            make_request(depth_levels=5)
        assert str(exc.value).startswith("depth_levels 只在訂閱 ORDER_BOOK 時有意義")


class TestProviderHealth:
    def test_valid(self) -> None:
        health = ProviderHealth(
            state=ProviderState.CONNECTED,
            reconnect_count=0,
            sequence_gap_count=0,
            last_record_at=datetime(2026, 7, 3, tzinfo=UTC),
        )
        assert health.state is ProviderState.CONNECTED

    def test_none_last_record_allowed(self) -> None:
        health = ProviderHealth(
            state=ProviderState.DISCONNECTED,
            reconnect_count=0,
            sequence_gap_count=0,
            last_record_at=None,
        )
        assert health.last_record_at is None

    def test_wrong_state_type_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            ProviderHealth(
                state="connected",  # type: ignore[arg-type]
                reconnect_count=0,
                sequence_gap_count=0,
                last_record_at=None,
            )
        assert str(exc.value) == "state 必須是 ProviderState，不可為 str"

    @pytest.mark.parametrize("field_name", ["reconnect_count", "sequence_gap_count"])
    def test_negative_counts_rejected(self, field_name: str) -> None:
        kwargs: dict[str, object] = {
            "state": ProviderState.CONNECTED,
            "reconnect_count": 0,
            "sequence_gap_count": 0,
            "last_record_at": None,
        }
        kwargs[field_name] = -1
        with pytest.raises(ValueError) as exc:
            ProviderHealth(**kwargs)  # type: ignore[arg-type]
        assert str(exc.value) == f"{field_name} 不可為負：-1"

    def test_naive_last_record_rejected(self) -> None:
        with pytest.raises(ValueError):
            ProviderHealth(
                state=ProviderState.CONNECTED,
                reconnect_count=0,
                sequence_gap_count=0,
                last_record_at=datetime(2026, 7, 3),
            )


class TestImmutability:
    @pytest.mark.parametrize(
        "factory",
        [
            make_capabilities,
            make_request,
            lambda: ProviderHealth(
                state=ProviderState.CONNECTED,
                reconnect_count=0,
                sequence_gap_count=0,
                last_record_at=None,
            ),
        ],
    )
    def test_frozen_and_slots(self, factory) -> None:
        obj = factory()
        first_field = dataclasses.fields(obj)[0].name
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(obj, first_field, "x")
        assert not hasattr(obj, "__dict__")
