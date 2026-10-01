"""mutation 釘住測試 · 錯誤/日誌訊息完全相等 + dataclass 行為 + 邊界值。

S02 教訓:「包含」式斷言(match= 子字串)殺不掉「前後加料」的字串變異，
錯誤訊息與日誌是維運排障依賴、屬對外行為，必須用完全相等釘住。
"""

from __future__ import annotations

import dataclasses
import logging
from collections.abc import Awaitable, Callable

import pytest
from src.core.event_bus import (
    DeadLetter,
    EventHandler,
    ensure_topic_for_event,
    split_topic,
    topic_matches,
    validate_pattern,
)
from src.core.events import BaseEvent
from src.messaging.in_memory import InMemoryEventBus
from src.messaging.serializers import JsonEventSerializer, _json_default

from tests.messaging.conftest import FIXED_TS, make_signal_event

MESSAGE_CASES = [
    (
        lambda: split_topic("acme.l6"),
        "topic 必須是三段制 {tenant_id}.{layer}.{event_type}，收到: 'acme.l6'",
    ),
    (
        lambda: split_topic("Acme.l6.signal"),
        "topic 段只允許 [a-z0-9_-]，收到非法段: 'Acme' (topic='Acme.l6.signal')",
    ),
    (
        lambda: split_topic("acme.l16.signal"),
        "layer 段必須是 l0-l15，收到: 'l16' (topic='acme.l16.signal')",
    ),
    (lambda: validate_pattern("acme.l6"), "pattern 必須是三段制，收到: 'acme.l6'"),
    (lambda: validate_pattern("*.l6.signal"), "tenant 段禁止萬用字元(防跨租戶監聽): '*.l6.signal'"),
    (lambda: validate_pattern("Acme.l6.signal"), "tenant 段只允許 [a-z0-9_-]，收到: 'Acme'"),
    (lambda: validate_pattern("acme.l16.signal"), "layer 段必須是 l0-l15 或 *，收到: 'l16'"),
    (lambda: validate_pattern("acme.l6.SIG"), "event_type 段只允許 [a-z0-9_-] 或 *，收到: 'SIG'"),
    (
        lambda: ensure_topic_for_event("other.l6.signal", make_signal_event()),
        "topic 的 tenant 段 'other' 與事件 tenant_id 'acme' 不一致",
    ),
    (
        lambda: ensure_topic_for_event("acme.l6.market", make_signal_event()),
        "topic 的 event_type 段 'market' 與事件 event_type 'signal' 不一致",
    ),
    (lambda: InMemoryEventBus(max_attempts=0), "max_attempts 至少 1，收到: 0"),
    (lambda: InMemoryEventBus(base_delay=-0.1), "base_delay 不可為負，收到: -0.1"),
    (lambda: _json_default(set()), "無法序列化的型別: set"),
]


@pytest.mark.parametrize(("func", "expected"), MESSAGE_CASES)
def test_訊息完全相等(func, expected):
    with pytest.raises((ValueError, TypeError)) as excinfo:
        func()
    assert str(excinfo.value) == expected


def test_eventhandler_型別別名正確():
    assert EventHandler == Callable[[BaseEvent], Awaitable[None]]


def _make_letter() -> DeadLetter:
    return DeadLetter(
        event=make_signal_event(),
        original_topic="acme.l6.signal",
        failure_count=3,
        last_error="RuntimeError: boom",
        dead_at=FIXED_TS,
    )


def test_deadletter_不可變():
    letter = _make_letter()
    with pytest.raises(dataclasses.FrozenInstanceError):
        letter.failure_count = 4  # type: ignore[misc]


def test_deadletter_使用_slots():
    assert hasattr(DeadLetter, "__slots__")
    assert not hasattr(_make_letter(), "__dict__")


def test_topic_matches_段數不一致防呆():
    # zip strict=True 是防禦線: 未驗證的輸入長度不符要炸、不能靜默
    with pytest.raises(ValueError):
        topic_matches("acme.l6.signal", "acme.l6")


async def test_max_attempts_邊界值_1_合法且一次失敗即進_dlq():
    calls = 0

    async def failing(event: BaseEvent) -> None:
        nonlocal calls
        calls += 1
        msg = "boom"
        raise RuntimeError(msg)

    bus = InMemoryEventBus(max_attempts=1, base_delay=0)  # 邊界: 1 必須合法
    await bus.subscribe("acme.l6.signal", failing)
    await bus.publish("acme.l6.signal", make_signal_event())
    assert calls == 1  # 不重試
    letters = await bus.read_dlq("acme")
    assert len(letters) == 1
    assert letters[0].failure_count == 1


async def test_訂閱與退訂日誌完全相等(caplog):
    async def noop(event: BaseEvent) -> None:
        return

    bus = InMemoryEventBus(base_delay=0)
    with caplog.at_level(logging.INFO, logger="src.messaging.in_memory"):
        sub_id = await bus.subscribe("acme.l6.signal", noop)
        await bus.unsubscribe(sub_id)
    messages = [r.getMessage() for r in caplog.records]
    assert "新訂閱 pattern=acme.l6.signal subscription_id=sub-1" in messages
    assert "退訂 subscription_id=sub-1 成功=True" in messages


def test_序列化保留非_ascii_原文():
    # ensure_ascii=False 是行為: DLQ 落地後要人類可讀，中文不得變 \uXXXX 逃脫碼
    data = JsonEventSerializer().serialize(make_signal_event(metadata={"k": "中文值"}))
    assert "中文值" in data.decode("utf-8")
