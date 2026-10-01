"""RedisEventBus · 生產 / 跨進程實作(Redis Streams，D1 裁決)。

設計：
- 每個 topic 一條 stream(stream key = topic)；租戶 topic 目錄記在 set sq:topics:{tenant}
- 每個訂閱一個 consumer group(ULID 命名，跨進程不撞名)，一個背景任務輪詢
- 訂閱語義與 InMemory 一致：只收「訂閱之後」發布的事件
  - subscribe 當下已存在的 topic → group 從 "$" 起讀(只收新)
  - 訂閱後才出現的 topic → group 從 "0" 起讀(整條 stream 都是訂閱後的事件)
- handler 重試耗盡 → 死信寫進 DLQ stream({tenant}.dlq.{layer}_{event_type})後才 ack
- 連線層重試含 OSError 整類(S02 教訓：整台斷線拋的是 OS 層錯誤)
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

import redis.asyncio as aioredis
from redis import exceptions as redis_exc
from ulid import ULID

from src.core.event_bus import (
    DeadLetter,
    EventHandler,
    dlq_topic,
    ensure_topic_for_event,
    split_topic,
    topic_matches,
    validate_pattern,
)
from src.core.events import BaseEvent
from src.messaging.delivery import deliver_with_retry
from src.messaging.serializers import EventSerializer, JsonEventSerializer

logger = logging.getLogger(__name__)

# 連線類錯誤(可重試)；資料類錯誤(如序列化失敗)不在此列、直接拋
_RETRYABLE = (OSError, redis_exc.ConnectionError, redis_exc.TimeoutError)


def _topics_set_key(tenant_id: str) -> str:
    """租戶的 topic 目錄 set(冒號前綴避免與 topic 名撞名)。"""
    return f"sq:topics:{tenant_id}"


def _dlq_set_key(tenant_id: str) -> str:
    return f"sq:dlq:{tenant_id}"


@dataclass
class _ConsumeState:
    """消費迴圈跨迭代的可變狀態（topic 目錄下次重掃時點）。"""

    next_refresh: float = 0.0


class RedisEventBus:
    """Redis Streams 版事件匯流排(實作 src.core.event_bus.EventBus Protocol)。"""

    def __init__(
        self,
        url: str | None = None,
        *,
        serializer: EventSerializer | None = None,
        max_attempts: int = 3,
        base_delay: float = 0.1,
        block_ms: int = 100,
        batch_size: int = 64,
        stream_maxlen: int = 100_000,
    ) -> None:
        resolved = url or os.environ.get("REDIS_URL")
        if not resolved:
            msg = "缺少 Redis 連線字串: 請傳入 url 或設定環境變數 REDIS_URL"
            raise ValueError(msg)
        if max_attempts < 1:
            msg = f"max_attempts 至少 1，收到: {max_attempts}"
            raise ValueError(msg)
        if base_delay < 0:
            msg = f"base_delay 不可為負，收到: {base_delay}"
            raise ValueError(msg)
        if stream_maxlen < 1:
            # 2026-06-18 修(審查 H6)：Streams ack 後仍永久留存，不修剪會 OOM
            msg = f"stream_maxlen 至少 1，收到: {stream_maxlen}"
            raise ValueError(msg)
        self._redis = aioredis.from_url(resolved)
        self._serializer = serializer or JsonEventSerializer()
        self._max_attempts = max_attempts
        self._base_delay = base_delay
        self._block_ms = block_ms
        self._batch_size = batch_size
        # 主 stream / DLQ 的近似修剪上限：xadd 帶 maxlen，避免高吞吐下 Redis 記憶體無上限成長
        self._stream_maxlen = stream_maxlen
        # 本實例已登記過目錄的 topic：發布熱路徑省一次 SADD 往返(效能基準實測必要)
        self._announced_topics: set[str] = set()
        # 消費迴圈的 topic 目錄重掃間隔(秒)：不必每圈掃，新 topic 最晚此延遲內被發現
        self._refresh_s = 0.5
        # subscription_id(= consumer group 名) → 背景消費任務
        self._tasks: dict[str, asyncio.Task[None]] = {}

    # ------------------------------------------------------------------
    # EventBus Protocol
    # ------------------------------------------------------------------

    async def publish(self, topic: str, event: BaseEvent) -> None:
        ensure_topic_for_event(topic, event)
        data = self._serializer.serialize(event)

        async def _do() -> None:
            if topic in self._announced_topics:
                # 熱路徑：topic 已登記過目錄，單一 XADD 即可
                await self._redis.xadd(
                    topic, {"data": data}, maxlen=self._stream_maxlen, approximate=True
                )
                return
            pipe = self._redis.pipeline()
            pipe.xadd(topic, {"data": data}, maxlen=self._stream_maxlen, approximate=True)
            pipe.sadd(_topics_set_key(event.tenant_id), topic)
            await pipe.execute()
            self._announced_topics.add(topic)

        await self._with_retry("publish", _do)
        logger.info("發布事件 topic=%s event_id=%s", topic, event.event_id)

    async def publish_many(self, topic: str, events: Sequence[BaseEvent]) -> None:
        """微批次發布：逐筆驗證後一次往返送整批(吞吐量約為單筆發布的 5-10 倍)。"""
        if not events:
            return
        payloads = []
        for event in events:
            ensure_topic_for_event(topic, event)
            payloads.append(self._serializer.serialize(event))

        async def _do() -> None:
            pipe = self._redis.pipeline()
            for data in payloads:
                pipe.xadd(topic, {"data": data}, maxlen=self._stream_maxlen, approximate=True)
            pipe.sadd(_topics_set_key(events[0].tenant_id), topic)
            await pipe.execute()
            self._announced_topics.add(topic)

        await self._with_retry("publish_many", _do)
        logger.info("批次發布 topic=%s 筆數=%d", topic, len(events))

    async def subscribe(self, topic_pattern: str, handler: EventHandler) -> str:
        validate_pattern(topic_pattern)
        tenant_id = topic_pattern.split(".")[0]
        group = f"sub-{ULID()}"
        # 訂閱當下已存在的 topic：group 從 "$" 起讀，只收訂閱後的新事件
        known = await self._matching_topics(tenant_id, topic_pattern)
        for topic in known:
            await self._ensure_group(topic, group, start_id="$")
        task = asyncio.create_task(
            self._consume_loop(tenant_id, topic_pattern, group, set(known), handler)
        )
        # 2026-06-18 修(審查 C2)：訂閱任務若非預期結束要被看見，不可靜默失聰
        task.add_done_callback(self._on_subscription_done)
        self._tasks[group] = task
        logger.info("新訂閱 pattern=%s subscription_id=%s", topic_pattern, group)
        return group

    async def unsubscribe(self, subscription_id: str) -> bool:
        task = self._tasks.pop(subscription_id, None)
        removed = task is not None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        logger.info("退訂 subscription_id=%s 成功=%s", subscription_id, removed)
        return removed

    async def read_dlq(self, tenant_id: str, topic: str | None = None) -> list[DeadLetter]:
        if topic is not None:
            if split_topic(topic)[0] != tenant_id:
                msg = f"topic {topic!r} 不屬於租戶 {tenant_id!r}"
                raise ValueError(msg)
            keys = [dlq_topic(topic)]
        else:
            # redis-py 型別宣告寬鬆(bytes | str)；decode_responses=False 下實際固定回 bytes
            members = cast("set[bytes]", await self._redis.smembers(_dlq_set_key(tenant_id)))
            keys = sorted(m.decode("utf-8") for m in members)
        letters: list[DeadLetter] = []
        for key in keys:
            entries = cast("list[tuple[bytes, dict[bytes, bytes]]]", await self._redis.xrange(key))
            for _message_id, fields in entries:
                letters.append(
                    DeadLetter(
                        event=self._serializer.deserialize(fields[b"data"]),
                        original_topic=fields[b"original_topic"].decode("utf-8"),
                        failure_count=int(fields[b"failure_count"]),
                        last_error=fields[b"last_error"].decode("utf-8"),
                        dead_at=datetime.fromisoformat(fields[b"dead_at"].decode("utf-8")),
                    )
                )
        return letters

    async def aclose(self) -> None:
        """關閉匯流排：停掉所有訂閱任務並釋放連線。"""
        for sub_id in list(self._tasks):
            await self.unsubscribe(sub_id)
        await self._redis.aclose()

    # ------------------------------------------------------------------
    # 內部
    # ------------------------------------------------------------------

    async def _with_retry(self, op: str, func: Callable[[], Awaitable[Any]]) -> Any:
        """連線類錯誤重試(指數退避)；耗盡後明確失敗、不卡死。"""
        last: Exception | None = None
        for attempt in range(1, self._max_attempts + 1):
            try:
                return await func()
            except _RETRYABLE as exc:
                last = exc
                logger.warning(
                    "Redis %s 連線失敗 第%d/%d次 錯誤=%s: %s",
                    op,
                    attempt,
                    self._max_attempts,
                    type(exc).__name__,
                    exc,
                )
                if attempt < self._max_attempts:
                    await asyncio.sleep(self._base_delay * 2 ** (attempt - 1))
        logger.error("Redis %s 重試耗盡，明確失敗", op)
        assert last is not None  # 迴圈至少跑一次且只有失敗會走到這
        raise last

    async def _matching_topics(self, tenant_id: str, pattern: str) -> list[str]:
        members = await self._with_retry(
            "smembers", lambda: self._redis.smembers(_topics_set_key(tenant_id))
        )
        topics = sorted(m.decode("utf-8") for m in members)
        return [t for t in topics if topic_matches(pattern, t)]

    async def _ensure_group(self, topic: str, group: str, start_id: str) -> None:
        try:
            await self._redis.xgroup_create(topic, group, id=start_id, mkstream=True)
        except redis_exc.ResponseError as exc:
            # group 已存在(BUSYGROUP)是正常情況，其他錯誤照拋
            if "BUSYGROUP" not in str(exc):
                raise

    async def _consume_loop(
        self,
        tenant_id: str,
        pattern: str,
        group: str,
        known: set[str],
        handler: EventHandler,
    ) -> None:
        """訂閱背景任務：永不靜默死亡（審查 C2）。

        連線類錯誤 → 退避重連；非預期錯誤 → CRITICAL 記錄後保持存活重試；
        毒丸訊息在 _consume_once 內被隔離，不會傳到這層。只有被 cancel（退訂）才結束。
        """
        state = _ConsumeState()
        while True:
            try:
                await self._consume_once(tenant_id, pattern, group, known, handler, state)
            except asyncio.CancelledError:
                raise
            except _RETRYABLE as exc:
                logger.warning("Redis 消費迴圈連線失敗，%.1fs 後重連: %s", self._base_delay, exc)
                await asyncio.sleep(self._base_delay)
            except Exception:
                # fail-closed 觀測導向：絕不靜默死亡，大聲記錄後訂閱保持存活、退避重試
                logger.critical(
                    "Redis 消費迴圈非預期錯誤（訂閱保持存活，%.1fs 後重試）",
                    self._base_delay,
                    exc_info=True,
                )
                await asyncio.sleep(self._base_delay)

    async def _consume_once(
        self,
        tenant_id: str,
        pattern: str,
        group: str,
        known: set[str],
        handler: EventHandler,
        state: _ConsumeState,
    ) -> None:
        """單次消費迭代：發現新 topic → 批次讀取 → 逐筆投遞（毒丸隔離）→ 整批 ack。"""
        consumer = "c-1"  # 一個訂閱一個 group 一個任務，固定單一 consumer
        now = asyncio.get_running_loop().time()
        if now >= state.next_refresh:
            for topic in await self._matching_topics(tenant_id, pattern):
                if topic not in known:
                    # 訂閱後才出現的 stream，整條都是訂閱後的事件 → 從頭收
                    await self._ensure_group(topic, group, start_id="0")
                    known.add(topic)
            state.next_refresh = now + self._refresh_s
        if not known:
            await asyncio.sleep(self._block_ms / 1000)
            return
        # redis-py 型別宣告寬鬆；decode_responses=False 下實際固定回 bytes
        result = cast(
            "list[tuple[bytes, list[tuple[bytes, dict[bytes, bytes]]]]]",
            await self._redis.xreadgroup(
                group,
                consumer,
                dict.fromkeys(sorted(known), ">"),
                count=self._batch_size,
                block=self._block_ms,
            ),
        )
        for stream_key, messages in result or []:
            topic = stream_key.decode("utf-8")
            done_ids: list[bytes] = []
            for message_id, fields in messages:
                try:
                    await self._handle_message(topic, group, fields, handler)
                except _RETRYABLE:
                    raise  # 連線類 → 交外層重連（本筆不 ack，留 PEL 下次處理）
                except Exception as exc:
                    # 毒丸訊息（如反序列化失敗）：隔離後 ack，不毒死整個訂閱
                    await self._poison_letter(topic, fields, exc)
                done_ids.append(message_id)
            if done_ids:
                # 整批 ack：每筆單獨 ack 會多付 N 次網路往返(效能基準實測必要)
                await self._redis.xack(topic, group, *done_ids)

    async def _poison_letter(self, topic: str, fields: dict[bytes, bytes], exc: Exception) -> None:
        """毒丸訊息隔離（審查 C2）：連反序列化都失敗的原始 bytes 進獨立 poison 流供鑑識。

        與 DLQ 不同：DLQ 存「能反序列化但 handler 失敗」的事件；poison 存「無法反序列化」
        的原始 bytes，read_dlq 不會去解析它（避免再次爆炸）。同時 CRITICAL 告警。
        """
        poison_key = f"sq:poison:{topic}"
        await self._redis.xadd(
            poison_key,
            {
                "raw_data": fields.get(b"data", b""),
                "original_topic": topic,
                "error": f"{type(exc).__name__}: {exc}",
                "dead_at": datetime.now(UTC).isoformat(),
            },
            maxlen=self._stream_maxlen,
            approximate=True,
        )
        logger.critical("毒丸訊息隔離 topic=%s 錯誤=%s: %s", topic, type(exc).__name__, exc)

    def _on_subscription_done(self, task: asyncio.Task[None]) -> None:
        """訂閱任務結束的觀測點（審查 C2）：正常退訂取消不告警；非預期例外結束則 CRITICAL。"""
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            logger.critical("訂閱背景任務非預期結束（訂閱已失效）: %r", exc)

    async def _handle_message(
        self,
        topic: str,
        group: str,
        fields: dict[bytes, bytes],
        handler: EventHandler,
    ) -> None:
        """單筆投遞：重試耗盡先寫 DLQ(死信落地前不 ack，不丟事件；ack 由呼叫端整批做)。"""
        event = self._serializer.deserialize(fields[b"data"])
        last_error = await deliver_with_retry(
            topic=topic,
            event=event,
            sub_id=group,
            handler=handler,
            max_attempts=self._max_attempts,
            base_delay=self._base_delay,
        )
        if last_error is not None:
            await self._dead_letter(topic, event, last_error)

    async def _dead_letter(self, topic: str, event: BaseEvent, last_error: str) -> None:
        dlq_key = dlq_topic(topic)
        pipe = self._redis.pipeline()
        pipe.xadd(
            dlq_key,
            {
                "data": self._serializer.serialize(event),
                "original_topic": topic,
                "failure_count": str(self._max_attempts),
                "last_error": last_error,
                "dead_at": datetime.now(UTC).isoformat(),
            },
            maxlen=self._stream_maxlen,
            approximate=True,
        )
        pipe.sadd(_dlq_set_key(event.tenant_id), dlq_key)
        await pipe.execute()
        logger.error("事件進 DLQ topic=%s event_id=%s 錯誤=%s", topic, event.event_id, last_error)
