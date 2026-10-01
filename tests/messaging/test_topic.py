"""topic 規範測試 · split_topic / validate_pattern / topic_matches / dlq_topic / 防呆。"""

from __future__ import annotations

import pytest
from src.core.event_bus import (
    dlq_topic,
    ensure_topic_for_event,
    split_topic,
    topic_matches,
    validate_pattern,
)
from src.core.types import EventType

from tests.messaging.conftest import make_signal_event


class TestSplitTopic:
    def test_合法三段制拆解(self):
        assert split_topic("acme.l6.signal") == ("acme", "l6", "signal")

    def test_layer_全範圍_l0_到_l15(self):
        for i in range(16):
            assert split_topic(f"acme.l{i}.signal")[1] == f"l{i}"

    @pytest.mark.parametrize("bad", ["acme.l6", "acme.l6.signal.extra", "acme", ""])
    def test_段數不對拋錯(self, bad):
        with pytest.raises(ValueError, match="三段制"):
            split_topic(bad)

    @pytest.mark.parametrize(
        "bad",
        ["Acme.l6.signal", "acme.l6.SIGNAL", "ac me.l6.signal", "acme..signal", "acme.l6.sig nal"],
    )
    def test_非法字元拋錯(self, bad):
        with pytest.raises(ValueError, match="非法段"):
            split_topic(bad)

    @pytest.mark.parametrize("bad_layer", ["l16", "l99", "x6", "layer6", "dlq"])
    def test_layer_段不在_l0_l15_拋錯(self, bad_layer):
        with pytest.raises(ValueError, match="l0-l15"):
            split_topic(f"acme.{bad_layer}.signal")


class TestValidatePattern:
    def test_精確_pattern_合法(self):
        assert validate_pattern("acme.l6.signal") == ("acme", "l6", "signal")

    def test_layer_萬用字元合法(self):
        assert validate_pattern("acme.*.signal") == ("acme", "*", "signal")

    def test_event_type_萬用字元合法(self):
        assert validate_pattern("acme.l6.*") == ("acme", "l6", "*")

    def test_雙萬用字元合法(self):
        assert validate_pattern("acme.*.*") == ("acme", "*", "*")

    def test_tenant_段萬用字元被拒(self):
        with pytest.raises(ValueError, match="防跨租戶監聽"):
            validate_pattern("*.l6.signal")

    def test_tenant_段非法字元被拒(self):
        with pytest.raises(ValueError, match="tenant 段"):
            validate_pattern("Acme.l6.signal")

    def test_段數不對拋錯(self):
        with pytest.raises(ValueError, match="三段制"):
            validate_pattern("acme.l6")

    def test_layer_段非法值被拒(self):
        with pytest.raises(ValueError, match="l0-l15"):
            validate_pattern("acme.l16.signal")

    def test_event_type_段非法字元被拒(self):
        with pytest.raises(ValueError, match="event_type 段"):
            validate_pattern("acme.l6.SIGNAL")


class TestTopicMatches:
    @pytest.mark.parametrize(
        ("pattern", "topic", "expected"),
        [
            ("acme.l6.signal", "acme.l6.signal", True),
            ("acme.l6.*", "acme.l6.signal", True),
            ("acme.*.signal", "acme.l6.signal", True),
            ("acme.*.*", "acme.l2.market", True),
            ("acme.l6.*", "acme.l2.market", False),
            ("acme.*.signal", "acme.l2.market", False),
            ("acme.l6.signal", "other.l6.signal", False),
            ("acme.l6.signal", "acme.l6.market", False),
        ],
    )
    def test_匹配矩陣(self, pattern, topic, expected):
        assert topic_matches(pattern, topic) is expected


class TestDlqTopic:
    def test_由原_topic_導出(self):
        assert dlq_topic("acme.l6.signal") == "acme.dlq.l6_signal"

    def test_原_topic_不合法時拋錯(self):
        with pytest.raises(ValueError, match="三段制"):
            dlq_topic("acme.l6")


class TestEnsureTopicForEvent:
    def test_一致時通過(self):
        event = make_signal_event()
        ensure_topic_for_event("acme.l6.signal", event)  # 不拋錯即通過

    def test_tenant_不一致拋錯(self):
        event = make_signal_event(tenant_id="acme")
        with pytest.raises(ValueError, match="tenant"):
            ensure_topic_for_event("other.l6.signal", event)

    def test_event_type_不一致拋錯(self):
        event = make_signal_event()
        assert event.event_type is EventType.SIGNAL
        with pytest.raises(ValueError, match="event_type"):
            ensure_topic_for_event("acme.l6.market", event)
