"""RedisEventBus 單元測試 · 不需要真 Redis(連線重試邏輯 / 建構防呆 / read_dlq 防呆)。"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest
from src.messaging.redis_bus import RedisEventBus, _ConsumeState

URL = "redis://localhost:6380/0"


class _FakeRedis:
    """最小 Redis 替身：只記錄 xadd / xack 呼叫，xreadgroup 回固定結果。"""

    def __init__(self, xreadgroup_result: list[Any]) -> None:
        self._result = xreadgroup_result
        self.xadd_calls: list[tuple[str, dict[Any, Any]]] = []
        self.xack_calls: list[tuple[Any, ...]] = []

    async def xreadgroup(self, *_args: Any, **_kwargs: Any) -> list[Any]:
        return self._result

    async def xadd(self, key: str, fields: dict[Any, Any], **_kwargs: Any) -> bytes:
        self.xadd_calls.append((key, fields))
        return b"0-0"

    async def xack(self, *args: Any) -> int:
        self.xack_calls.append(args)
        return 1


class _BoomSerializer:
    """deserialize 一律拋指定例外（模擬毒丸訊息 / 連線錯誤）。"""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def serialize(self, _event: Any) -> bytes:
        return b"x"

    def deserialize(self, _data: bytes) -> Any:
        raise self._exc


class TestConstruction:
    def test_未給_url_且無環境變數時拋錯(self, monkeypatch):
        monkeypatch.delenv("REDIS_URL", raising=False)
        with pytest.raises(ValueError, match="REDIS_URL"):
            RedisEventBus()

    def test_環境變數可當預設(self, monkeypatch):
        monkeypatch.setenv("REDIS_URL", URL)
        RedisEventBus()  # 不拋錯即通過(lazy 連線，不會真的連)

    def test_max_attempts_至少_1(self):
        with pytest.raises(ValueError, match="max_attempts 至少 1"):
            RedisEventBus(URL, max_attempts=0)

    def test_base_delay_不可為負(self):
        with pytest.raises(ValueError, match="base_delay 不可為負"):
            RedisEventBus(URL, base_delay=-1)

    def test_stream_maxlen_至少_1(self):
        # 審查 H6：Streams ack 後仍永久留存，maxlen 必須有效避免 OOM
        with pytest.raises(ValueError, match="stream_maxlen 至少 1"):
            RedisEventBus(URL, stream_maxlen=0)


class TestConsumeResilience:
    """審查 C2：消費迴圈永不靜默死亡（毒丸隔離 + 非預期錯誤保持存活 + 任務結束可觀測）。"""

    async def test_毒丸訊息被隔離而不毒死訂閱(self, caplog):
        fake = _FakeRedis([(b"acme.l6.signal", [(b"5-0", {b"data": b"garbage"})])])
        bus = RedisEventBus(URL, base_delay=0)
        bus._redis = fake  # type: ignore[assignment]
        bus._serializer = _BoomSerializer(ValueError("bad payload"))  # type: ignore[assignment]

        async def handler(_e: object) -> None:
            raise AssertionError("毒丸不該抵達 handler")

        state = _ConsumeState(next_refresh=float("inf"))  # 跳過 topic 重掃
        with caplog.at_level(logging.CRITICAL, logger="src.messaging.redis_bus"):
            await bus._consume_once("acme", "acme.*.*", "g", {"acme.l6.signal"}, handler, state)
        # 毒丸進獨立 poison 流、且仍被 ack（不卡住 PEL）、且 CRITICAL 告警
        assert any(key == "sq:poison:acme.l6.signal" for key, _ in fake.xadd_calls)
        assert fake.xack_calls and b"5-0" in fake.xack_calls[0]
        assert any("毒丸訊息隔離" in r.getMessage() for r in caplog.records)

    async def test_連線類錯誤往外傳由外層重連(self):
        fake = _FakeRedis([(b"acme.l6.signal", [(b"6-0", {b"data": b"x"})])])
        bus = RedisEventBus(URL, base_delay=0)
        bus._redis = fake  # type: ignore[assignment]
        # 內建 ConnectionError 是 OSError 子類 → 屬可重試，應往外拋而非當毒丸
        bus._serializer = _BoomSerializer(ConnectionError("redis down"))  # type: ignore[assignment]

        async def handler(_e: object) -> None: ...

        state = _ConsumeState(next_refresh=float("inf"))
        with pytest.raises(ConnectionError):
            await bus._consume_once("acme", "acme.*.*", "g", {"acme.l6.signal"}, handler, state)

    async def test_非預期錯誤不靜默死亡_大聲記錄後保持存活(self, monkeypatch, caplog):
        bus = RedisEventBus(URL, base_delay=0)
        calls = 0

        async def fake_once(*_a: object, **_k: object) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise ValueError("unexpected boom")  # 非連線類、非取消
            raise asyncio.CancelledError  # 第二圈退出迴圈

        monkeypatch.setattr(bus, "_consume_once", fake_once)

        async def handler(_e: object) -> None: ...

        with caplog.at_level(logging.CRITICAL, logger="src.messaging.redis_bus"):
            with pytest.raises(asyncio.CancelledError):
                await bus._consume_loop("acme", "acme.*.*", "g", set(), handler)
        assert calls == 2  # 證據：第一圈炸了沒死，第二圈才被 cancel
        assert any("非預期錯誤" in r.getMessage() for r in caplog.records)

    async def test_訂閱任務非預期結束會被記錄(self, caplog):
        bus = RedisEventBus(URL)

        async def boom() -> None:
            raise RuntimeError("dead")

        task: asyncio.Task[None] = asyncio.ensure_future(boom())
        await asyncio.gather(task, return_exceptions=True)  # 讓它以例外結束
        with caplog.at_level(logging.CRITICAL, logger="src.messaging.redis_bus"):
            bus._on_subscription_done(task)
        assert any("訂閱背景任務非預期結束" in r.getMessage() for r in caplog.records)

    async def test_訂閱任務正常結束不告警(self, caplog):
        bus = RedisEventBus(URL)

        async def done() -> None:
            return None

        task: asyncio.Task[None] = asyncio.ensure_future(done())
        await asyncio.gather(task, return_exceptions=True)  # 正常結束（無例外）
        with caplog.at_level(logging.CRITICAL, logger="src.messaging.redis_bus"):
            bus._on_subscription_done(task)
        assert not any("非預期結束" in r.getMessage() for r in caplog.records)


class TestWithRetry:
    """連線類錯誤重試 · 證據數字看呼叫次數與退避序列(S02 教訓)。"""

    @pytest.fixture
    def bus(self) -> RedisEventBus:
        return RedisEventBus(URL, base_delay=0)

    async def test_成功時直接回傳(self, bus):
        async def ok() -> str:
            return "value"

        assert await bus._with_retry("op", ok) == "value"

    async def test_連線錯誤兩次後成功(self, bus):
        calls = 0

        async def flaky() -> str:
            nonlocal calls
            calls += 1
            if calls <= 2:
                raise ConnectionError("redis down")
            return "ok"

        assert await bus._with_retry("op", flaky) == "ok"
        assert calls == 3

    async def test_oserror_整類可重試(self, bus):
        # S02 教訓：整台斷線拋 OS 層錯誤，必須在重試清單內
        calls = 0

        async def os_flaky() -> str:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("network unreachable")
            return "ok"

        assert await bus._with_retry("op", os_flaky) == "ok"
        assert calls == 2

    async def test_重試耗盡拋最後一次錯誤(self, bus, caplog):
        async def always_fail() -> None:
            raise ConnectionError("still down")

        with caplog.at_level(logging.ERROR, logger="src.messaging.redis_bus"):
            with pytest.raises(ConnectionError, match="still down"):
                await bus._with_retry("publish", always_fail)
        assert "Redis publish 重試耗盡，明確失敗" in [r.getMessage() for r in caplog.records]

    async def test_資料類錯誤不重試直接拋(self, bus):
        calls = 0

        async def bad_data() -> None:
            nonlocal calls
            calls += 1
            raise ValueError("not retryable")

        with pytest.raises(ValueError, match="not retryable"):
            await bus._with_retry("op", bad_data)
        assert calls == 1  # 證據：只呼叫一次，沒有重試

    async def test_退避序列為指數退避(self, monkeypatch):
        delays: list[float] = []

        async def fake_sleep(seconds: float) -> None:
            delays.append(seconds)

        monkeypatch.setattr(asyncio, "sleep", fake_sleep)
        bus = RedisEventBus(URL)  # 預設 base_delay=0.1

        async def always_fail() -> None:
            raise ConnectionError("down")

        with pytest.raises(ConnectionError):
            await bus._with_retry("op", always_fail)
        assert delays == [0.1, 0.2]


class TestReadDlqValidation:
    async def test_topic_與租戶不一致拋錯(self):
        bus = RedisEventBus(URL)
        with pytest.raises(ValueError, match="不屬於租戶"):
            await bus.read_dlq("other", topic="acme.l6.signal")
