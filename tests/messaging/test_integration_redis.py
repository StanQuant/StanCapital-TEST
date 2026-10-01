"""RedisEventBus 整合測試 · 需要真 Redis(docker compose 的 stanquant-redis，port 6380)。

行為案例與 InMemoryEventBus 對齊(規格 §6.2「行為一致性」)。
啟動: docker compose -f infra/db/docker-compose.yml up -d redis --wait
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable

import pytest
from src.core.events import BaseEvent
from src.messaging.redis_bus import RedisEventBus

from tests.messaging.conftest import make_market_event, make_signal_event

pytestmark = pytest.mark.integration

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6380/0")


async def wait_until(predicate: Callable[[], bool], max_wait: float = 5.0) -> None:
    """輪詢等待條件成立(跨任務投遞是異步的，不能 assert 立即狀態)。"""
    deadline = asyncio.get_running_loop().time() + max_wait
    while asyncio.get_running_loop().time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.02)
    msg = f"等待 {max_wait}s 後條件仍未成立"
    raise AssertionError(msg)


class Recorder:
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


@pytest.fixture
async def bus():
    b = RedisEventBus(REDIS_URL, base_delay=0)
    await b._redis.flushdb()  # 測試庫隔離：每個測試從乾淨狀態開始
    yield b
    await b.aclose()


@pytest.fixture
async def second_bus():
    """模擬另一個進程(獨立連線與訂閱任務)。"""
    b = RedisEventBus(REDIS_URL, base_delay=0)
    yield b
    await b.aclose()


class TestPubSub:
    async def test_發布訂閱_round_trip_精度保真(self, bus):
        rec = Recorder()
        await bus.subscribe("acme.l6.signal", rec)
        event = make_signal_event()
        await bus.publish("acme.l6.signal", event)
        await wait_until(lambda: len(rec.received) == 1)
        assert rec.received == [event]  # 逐欄位相等(Decimal / datetime / enum)

    async def test_跨進程_pub_sub(self, bus, second_bus):
        rec = Recorder()
        await second_bus.subscribe("acme.l6.signal", rec)
        event = make_signal_event()
        await bus.publish("acme.l6.signal", event)  # A 進程發、B 進程收
        await wait_until(lambda: len(rec.received) == 1)
        assert rec.received == [event]

    async def test_萬用字元收到訂閱後才出現的_topic(self, bus):
        rec = Recorder()
        await bus.subscribe("acme.*.*", rec)
        event = make_market_event()  # acme.l2.market 的 stream 在訂閱當下不存在
        await bus.publish("acme.l2.market", event)
        await wait_until(lambda: len(rec.received) == 1)
        assert rec.received == [event]

    async def test_只收訂閱之後的事件(self, bus):
        before = make_signal_event(event_id="evt-before")
        await bus.publish("acme.l6.signal", before)
        rec = Recorder()
        await bus.subscribe("acme.l6.signal", rec)
        after = make_signal_event(event_id="evt-after")
        await bus.publish("acme.l6.signal", after)
        await wait_until(lambda: len(rec.received) == 1)
        assert [e.event_id for e in rec.received] == ["evt-after"]

    async def test_多訂閱者都收到(self, bus):
        rec1, rec2 = Recorder(), Recorder()
        await bus.subscribe("acme.l6.signal", rec1)
        await bus.subscribe("acme.*.*", rec2)
        event = make_signal_event()
        await bus.publish("acme.l6.signal", event)
        await wait_until(lambda: rec1.received == [event] and rec2.received == [event])


class TestTenantIsolation:
    async def test_別租戶的訂閱者收不到(self, bus):
        rec = Recorder()
        await bus.subscribe("other.l6.signal", rec)
        await bus.publish("acme.l6.signal", make_signal_event(tenant_id="acme"))
        await asyncio.sleep(0.5)  # 給足投遞時間後確認真的沒收到
        assert rec.received == []

    async def test_topic_與事件租戶不一致拒發(self, bus):
        with pytest.raises(ValueError, match="tenant"):
            await bus.publish("other.l6.signal", make_signal_event(tenant_id="acme"))


class TestRetryAndDlq:
    async def test_失敗兩次第三次成功_不進_dlq(self, bus):
        rec = Recorder(fail_times=2)
        await bus.subscribe("acme.l6.signal", rec)
        event = make_signal_event()
        await bus.publish("acme.l6.signal", event)
        await wait_until(lambda: rec.received == [event])
        assert rec.calls == 3  # 證據數字(S02 教訓)
        assert await bus.read_dlq("acme") == []

    async def test_重試耗盡進_dlq_且死信跨進程可讀(self, bus, second_bus):
        rec = Recorder(fail_times=99)
        await bus.subscribe("acme.l6.signal", rec)
        event = make_signal_event()
        await bus.publish("acme.l6.signal", event)
        await wait_until(lambda: rec.calls >= 3)
        letters = []

        async def dlq_ready() -> bool:
            nonlocal letters
            letters = await second_bus.read_dlq("acme")  # 另一進程讀 DLQ(持久化驗證)
            return len(letters) == 1

        deadline = asyncio.get_running_loop().time() + 5
        while not await dlq_ready():
            if asyncio.get_running_loop().time() > deadline:
                msg = "等不到 DLQ 死信"
                raise AssertionError(msg)
            await asyncio.sleep(0.05)
        letter = letters[0]
        assert letter.event == event
        assert letter.original_topic == "acme.l6.signal"
        assert letter.failure_count == 3
        assert letter.last_error == "RuntimeError: boom"
        assert letter.dead_at.tzinfo is not None
        assert rec.calls == 3  # ack 後不重複投遞

    async def test_read_dlq_依_topic_過濾(self, bus):
        rec = Recorder(fail_times=99)
        await bus.subscribe("acme.*.*", rec)
        await bus.publish("acme.l6.signal", make_signal_event())
        await bus.publish("acme.l2.market", make_market_event())

        async def two_letters() -> bool:
            return len(await bus.read_dlq("acme")) == 2

        deadline = asyncio.get_running_loop().time() + 5
        while not await two_letters():
            if asyncio.get_running_loop().time() > deadline:
                msg = "等不到 2 筆死信"
                raise AssertionError(msg)
            await asyncio.sleep(0.05)
        only_signal = await bus.read_dlq("acme", topic="acme.l6.signal")
        assert len(only_signal) == 1
        assert only_signal[0].original_topic == "acme.l6.signal"


class TestUnsubscribe:
    async def test_退訂後不再收到(self, bus):
        rec = Recorder()
        sub_id = await bus.subscribe("acme.l6.signal", rec)
        assert await bus.unsubscribe(sub_id) is True
        await bus.publish("acme.l6.signal", make_signal_event())
        await asyncio.sleep(0.5)
        assert rec.received == []

    async def test_無效_id_回_false(self, bus):
        assert await bus.unsubscribe("sub-NOTEXIST") is False


class TestPublishMany:
    async def test_批次發布全數送達(self, bus):
        rec = Recorder()
        await bus.subscribe("acme.l6.signal", rec)
        events = [make_signal_event(event_id=f"evt-{i}") for i in range(200)]
        await bus.publish_many("acme.l6.signal", events)
        await wait_until(lambda: len(rec.received) == 200)
        assert rec.received == events  # 保序且逐欄位相等

    async def test_空批次為無操作(self, bus):
        await bus.publish_many("acme.l6.signal", [])

    async def test_批次中任一筆租戶不一致_整批拒發(self, bus):
        rec = Recorder()
        await bus.subscribe("acme.l6.signal", rec)
        good = make_signal_event()
        bad = make_signal_event(tenant_id="other")
        with pytest.raises(ValueError, match="tenant"):
            await bus.publish_many("acme.l6.signal", [good, bad])
        await asyncio.sleep(0.3)
        assert rec.received == []  # 先全部驗證再送，壞一筆整批不出門


class TestInternals:
    """打到防禦分支：group 容錯 / 空批次 / 斷線重連(覆蓋率收尾)。"""

    async def test_ensure_group_重複建立不報錯(self, bus):
        await bus._redis.xadd("acme.l6.signal", {b"data": b"x"})
        await bus._ensure_group("acme.l6.signal", "g1", start_id="$")
        await bus._ensure_group("acme.l6.signal", "g1", start_id="$")  # BUSYGROUP 被吞掉

    async def test_ensure_group_其他錯誤照拋(self, bus):
        from redis import exceptions as redis_exc

        await bus._redis.sadd("notastream", "x")  # 故意做一個非 stream 的 key
        with pytest.raises(redis_exc.ResponseError):
            await bus._ensure_group("notastream", "g1", start_id="$")

    async def test_空批次讀取不_ack(self, bus, monkeypatch):
        real = bus._redis.xreadgroup
        injected = False

        async def fake(group, consumer, streams, count, block):
            nonlocal injected
            if not injected:
                injected = True
                return [(b"acme.l6.signal", [])]  # 模擬空批次
            return await real(group, consumer, streams, count=count, block=block)

        monkeypatch.setattr(bus._redis, "xreadgroup", fake)
        rec = Recorder()
        await bus.subscribe("acme.l6.signal", rec)
        event = make_signal_event()
        await bus.publish("acme.l6.signal", event)
        await wait_until(lambda: rec.received == [event])

    async def test_消費迴圈斷線自動重連(self, bus, monkeypatch):
        real = bus._redis.xreadgroup
        fail_once = True

        async def flaky(*args, **kwargs):
            nonlocal fail_once
            if fail_once:
                fail_once = False
                raise ConnectionError("connection lost")
            return await real(*args, **kwargs)

        monkeypatch.setattr(bus._redis, "xreadgroup", flaky)
        rec = Recorder()
        await bus.subscribe("acme.l6.signal", rec)
        event = make_signal_event()
        await bus.publish("acme.l6.signal", event)
        await wait_until(lambda: rec.received == [event])  # 斷一次線仍送達
