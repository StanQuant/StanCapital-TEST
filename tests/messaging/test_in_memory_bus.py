"""InMemoryEventBus 行為測試 · pub/sub / 租戶隔離 / 重試 / DLQ / 退訂。

行為設計成與 RedisEventBus 一致，這套測試的案例之後會在整合測試對 Redis 重跑。
"""

from __future__ import annotations

import asyncio
import logging

import pytest
from src.core.events import BaseEvent
from src.messaging.in_memory import InMemoryEventBus

from tests.messaging.conftest import make_market_event, make_signal_event


@pytest.fixture
def bus() -> InMemoryEventBus:
    # base_delay=0：單元測試不等真實退避(退避數值另測)
    return InMemoryEventBus(base_delay=0)


class Recorder:
    """記錄收到的事件；可設定前 N 次呼叫故意失敗。"""

    def __init__(self, fail_times: int = 0) -> None:
        self.received: list[BaseEvent] = []
        self.calls = 0
        self._fail_times = fail_times

    async def __call__(self, event: BaseEvent) -> None:
        self.calls += 1
        if self.calls <= self._fail_times:
            msg = "boom"
            raise RuntimeError(msg)
        self.received.append(event)


class TestPubSub:
    async def test_發布訂閱_round_trip(self, bus):
        rec = Recorder()
        await bus.subscribe("acme.l6.signal", rec)
        event = make_signal_event()
        await bus.publish("acme.l6.signal", event)
        assert rec.received == [event]

    async def test_萬用字元訂閱收得到(self, bus):
        rec = Recorder()
        await bus.subscribe("acme.l6.*", rec)
        event = make_signal_event()
        await bus.publish("acme.l6.signal", event)
        assert rec.received == [event]

    async def test_萬用字元不跨層(self, bus):
        rec = Recorder()
        await bus.subscribe("acme.l6.*", rec)
        await bus.publish("acme.l2.market", make_market_event())
        assert rec.received == []

    async def test_多訂閱者都收到(self, bus):
        rec1, rec2 = Recorder(), Recorder()
        await bus.subscribe("acme.l6.signal", rec1)
        await bus.subscribe("acme.*.*", rec2)
        event = make_signal_event()
        await bus.publish("acme.l6.signal", event)
        assert rec1.received == [event]
        assert rec2.received == [event]

    async def test_一個_handler_壞掉不影響其他訂閱者(self, bus):
        broken, healthy = Recorder(fail_times=99), Recorder()
        await bus.subscribe("acme.l6.signal", broken)
        await bus.subscribe("acme.l6.signal", healthy)
        event = make_signal_event()
        await bus.publish("acme.l6.signal", event)
        assert healthy.received == [event]

    async def test_無訂閱者時發布不報錯(self, bus):
        await bus.publish("acme.l6.signal", make_signal_event())


class TestTenantIsolation:
    async def test_別租戶的訂閱者收不到(self, bus):
        rec = Recorder()
        await bus.subscribe("other.l6.signal", rec)
        await bus.publish("acme.l6.signal", make_signal_event(tenant_id="acme"))
        assert rec.received == []

    async def test_topic_與事件租戶不一致拒發(self, bus):
        with pytest.raises(ValueError, match="tenant"):
            await bus.publish("other.l6.signal", make_signal_event(tenant_id="acme"))

    async def test_topic_與事件型別不一致拒發(self, bus):
        with pytest.raises(ValueError, match="event_type"):
            await bus.publish("acme.l6.market", make_signal_event())


class TestValidation:
    async def test_非法_topic_拒發(self, bus):
        with pytest.raises(ValueError, match="三段制"):
            await bus.publish("acme.l6", make_signal_event())

    async def test_非法_pattern_拒訂(self, bus):
        rec = Recorder()
        with pytest.raises(ValueError, match="防跨租戶監聽"):
            await bus.subscribe("*.l6.signal", rec)

    def test_max_attempts_至少_1(self):
        with pytest.raises(ValueError, match="max_attempts 至少 1"):
            InMemoryEventBus(max_attempts=0)

    def test_base_delay_不可為負(self):
        with pytest.raises(ValueError, match="base_delay 不可為負"):
            InMemoryEventBus(base_delay=-0.1)


class TestRetryAndDlq:
    async def test_失敗兩次第三次成功_不進_dlq(self, bus):
        rec = Recorder(fail_times=2)
        await bus.subscribe("acme.l6.signal", rec)
        event = make_signal_event()
        await bus.publish("acme.l6.signal", event)
        # 證據數字(S02 教訓)：總共呼叫 3 次、最終收到、DLQ 空
        assert rec.calls == 3
        assert rec.received == [event]
        assert await bus.read_dlq("acme") == []

    async def test_重試耗盡進_dlq(self, bus):
        rec = Recorder(fail_times=99)
        await bus.subscribe("acme.l6.signal", rec)
        event = make_signal_event()
        await bus.publish("acme.l6.signal", event)
        assert rec.calls == 3  # 預設 max_attempts=3
        letters = await bus.read_dlq("acme")
        assert len(letters) == 1
        letter = letters[0]
        assert letter.event == event
        assert letter.original_topic == "acme.l6.signal"
        assert letter.failure_count == 3
        assert letter.last_error == "RuntimeError: boom"
        assert letter.dead_at.tzinfo is not None

    async def test_退避延遲序列為指數退避(self, monkeypatch):
        delays: list[float] = []

        async def fake_sleep(seconds: float) -> None:
            delays.append(seconds)

        monkeypatch.setattr(asyncio, "sleep", fake_sleep)
        bus = InMemoryEventBus()  # 預設 base_delay=0.1
        rec = Recorder(fail_times=99)
        await bus.subscribe("acme.l6.signal", rec)
        await bus.publish("acme.l6.signal", make_signal_event())
        # D5 裁決：0.1 / 0.2(最後一次失敗後直接進 DLQ，不再等)
        assert delays == [0.1, 0.2]

    async def test_read_dlq_依租戶過濾(self, bus):
        rec = Recorder(fail_times=99)
        await bus.subscribe("acme.l6.signal", rec)
        await bus.publish("acme.l6.signal", make_signal_event(tenant_id="acme"))
        assert await bus.read_dlq("other") == []

    async def test_read_dlq_依_topic_過濾(self, bus):
        rec = Recorder(fail_times=99)
        await bus.subscribe("acme.*.*", rec)
        await bus.publish("acme.l6.signal", make_signal_event())
        await bus.publish("acme.l2.market", make_market_event())
        assert len(await bus.read_dlq("acme")) == 2
        only_signal = await bus.read_dlq("acme", topic="acme.l6.signal")
        assert len(only_signal) == 1
        assert only_signal[0].original_topic == "acme.l6.signal"


class TestUnsubscribe:
    async def test_退訂後不再收到(self, bus):
        rec = Recorder()
        sub_id = await bus.subscribe("acme.l6.signal", rec)
        assert await bus.unsubscribe(sub_id) is True
        await bus.publish("acme.l6.signal", make_signal_event())
        assert rec.received == []

    async def test_無效_id_回_false(self, bus):
        assert await bus.unsubscribe("sub-999") is False

    async def test_subscription_id_遞增不重複(self, bus):
        rec = Recorder()
        id1 = await bus.subscribe("acme.l6.signal", rec)
        id2 = await bus.subscribe("acme.l6.signal", rec)
        assert id1 == "sub-1"
        assert id2 == "sub-2"


class TestLogging:
    """日誌訊息是維運排障依賴，用測試釘住(S02 教訓)。"""

    async def test_發布日誌含訂閱者數(self, bus, caplog):
        rec = Recorder()
        await bus.subscribe("acme.l6.signal", rec)
        with caplog.at_level(logging.INFO, logger="src.messaging.in_memory"):
            await bus.publish("acme.l6.signal", make_signal_event())
        assert "發布事件 topic=acme.l6.signal event_id=evt-sig-1 訂閱者=1" in [
            r.getMessage() for r in caplog.records
        ]

    async def test_進_dlq_日誌(self, bus, caplog):
        rec = Recorder(fail_times=99)
        await bus.subscribe("acme.l6.signal", rec)
        with caplog.at_level(logging.WARNING, logger="src.messaging.in_memory"):
            await bus.publish("acme.l6.signal", make_signal_event())
        messages = [r.getMessage() for r in caplog.records]
        assert (
            "事件進 DLQ topic=acme.l6.signal event_id=evt-sig-1 錯誤=RuntimeError: boom" in messages
        )
        assert (
            "handler 失敗 topic=acme.l6.signal subscription_id=sub-1 第1/3次 錯誤=RuntimeError: boom"
            in messages
        )


class TestPublishMany:
    async def test_批次發布全數送達且保序(self, bus):
        rec = Recorder()
        await bus.subscribe("acme.l6.signal", rec)
        events = [make_signal_event(event_id=f"evt-{i}") for i in range(3)]
        await bus.publish_many("acme.l6.signal", events)
        assert rec.received == events

    async def test_空批次為無操作(self, bus):
        await bus.publish_many("acme.l6.signal", [])

    async def test_批次中租戶不一致一樣拒發(self, bus):
        with pytest.raises(ValueError, match="tenant"):
            await bus.publish_many("acme.l6.signal", [make_signal_event(tenant_id="other")])
