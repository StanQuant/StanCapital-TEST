"""序列化測試 · 4 事件型別 round-trip + 精度保真 + 邊界。"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal

import pytest
from src.messaging.serializers import JsonEventSerializer, _json_default

from tests.messaging.conftest import (
    make_fill_event,
    make_market_event,
    make_order_event,
    make_signal_event,
)


@pytest.fixture
def serializer() -> JsonEventSerializer:
    return JsonEventSerializer()


class TestRoundTrip:
    """round-trip 後逐欄位相等(frozen dataclass 的 == 比較全部欄位)。"""

    def test_market_event(self, serializer):
        event = make_market_event()
        assert serializer.deserialize(serializer.serialize(event)) == event

    def test_signal_event(self, serializer):
        event = make_signal_event()
        assert serializer.deserialize(serializer.serialize(event)) == event

    def test_order_event_含巢狀_order(self, serializer):
        event = make_order_event()
        restored = serializer.deserialize(serializer.serialize(event))
        assert restored == event
        assert restored.order == event.order  # 巢狀 dataclass 完整重建

    def test_fill_event_含巢狀_fill(self, serializer):
        event = make_fill_event()
        restored = serializer.deserialize(serializer.serialize(event))
        assert restored == event
        assert restored.fill == event.fill


class TestPrecision:
    def test_decimal_多位小數不失真(self, serializer):
        event = make_market_event(price=Decimal("0.00000001"))
        restored = serializer.deserialize(serializer.serialize(event))
        assert restored.price == Decimal("0.00000001")
        assert isinstance(restored.price, Decimal)

    def test_decimal_不經過_float(self, serializer):
        # float 無法精確表示的數字，字串編碼必須原樣保留
        event = make_market_event(price=Decimal("1085.12345678"))
        payload = json.loads(serializer.serialize(event))
        assert payload["price"] == "1085.12345678"

    def test_datetime_含時區與微秒(self, serializer):
        ts = datetime(2026, 6, 11, 9, 30, 0, 123456, tzinfo=UTC)
        event = make_market_event(timestamp=ts)
        restored = serializer.deserialize(serializer.serialize(event))
        assert restored.timestamp == ts
        assert restored.timestamp.tzinfo is not None

    def test_enum_重建為同一成員(self, serializer):
        event = make_signal_event()
        restored = serializer.deserialize(serializer.serialize(event))
        assert restored.strategy_kind is event.strategy_kind
        assert restored.direction is event.direction


class TestNullFields:
    def test_optional_欄位為_none_不失真(self, serializer):
        event = make_market_event(bid=None, ask=None)
        restored = serializer.deserialize(serializer.serialize(event))
        assert restored.bid is None
        assert restored.ask is None

    def test_trace_id_none(self, serializer):
        event = make_signal_event(trace_id=None)
        assert serializer.deserialize(serializer.serialize(event)).trace_id is None

    def test_target_quantity_none(self, serializer):
        event = make_signal_event(target_quantity=None)
        assert serializer.deserialize(serializer.serialize(event)).target_quantity is None


class TestEdgeCases:
    def test_輸出為_utf8_bytes(self, serializer):
        data = serializer.serialize(make_signal_event())
        assert isinstance(data, bytes)
        json.loads(data.decode("utf-8"))  # 合法 JSON

    def test_metadata_字典完整保留(self, serializer):
        event = make_signal_event(metadata={"a": "1", "b": "中文值"})
        restored = serializer.deserialize(serializer.serialize(event))
        assert restored.metadata == {"a": "1", "b": "中文值"}

    def test_未知_event_type_拋錯(self, serializer):
        payload = json.loads(serializer.serialize(make_signal_event()))
        payload["event_type"] = "unknown_type"
        with pytest.raises(ValueError):
            serializer.deserialize(json.dumps(payload).encode("utf-8"))

    def test_json_default_拒絕未知型別(self):
        with pytest.raises(TypeError, match="無法序列化的型別: set"):
            _json_default(set())
