"""InMemoryEventBus · 單機 / 測試用實作。

行為與 RedisEventBus 完全一致(同一套行為測試跑兩遍)：
- handler 失敗重試 max_attempts 次(D5 裁決：預設 3，指數退避 0.1/0.2/0.4s)
- 重試耗盡 → 事件進 DLQ 留底，不靜默丟棄
- 一個 handler 壞掉不影響其他訂閱者
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from itertools import count

from src.core.event_bus import (
    DeadLetter,
    EventHandler,
    ensure_topic_for_event,
    topic_matches,
    validate_pattern,
)
from src.core.events import BaseEvent
from src.messaging.delivery import deliver_with_retry

logger = logging.getLogger(__name__)


class InMemoryEventBus:
    """記憶體版事件匯流排(實作 src.core.event_bus.EventBus Protocol)。"""

    def __init__(self, max_attempts: int = 3, base_delay: float = 0.1) -> None:
        if max_attempts < 1:
            msg = f"max_attempts 至少 1，收到: {max_attempts}"
            raise ValueError(msg)
        if base_delay < 0:
            msg = f"base_delay 不可為負，收到: {base_delay}"
            raise ValueError(msg)
        self._max_attempts = max_attempts
        self._base_delay = base_delay
        # subscription_id → (pattern, handler)
        self._subscriptions: dict[str, tuple[str, EventHandler]] = {}
        self._dlq: list[DeadLetter] = []
        self._id_counter = count(1)

    async def publish(self, topic: str, event: BaseEvent) -> None:
        ensure_topic_for_event(topic, event)
        matched = [
            (sub_id, handler)
            for sub_id, (pattern, handler) in self._subscriptions.items()
            if topic_matches(pattern, topic)
        ]
        logger.info("發布事件 topic=%s event_id=%s 訂閱者=%d", topic, event.event_id, len(matched))
        for sub_id, handler in matched:
            await self._deliver(topic, event, sub_id, handler)

    async def publish_many(self, topic: str, events: Sequence[BaseEvent]) -> None:
        """微批次發布：InMemory 無網路往返，逐筆發布即可(與 Redis 版介面一致)。"""
        for event in events:
            await self.publish(topic, event)

    async def subscribe(self, topic_pattern: str, handler: EventHandler) -> str:
        validate_pattern(topic_pattern)
        subscription_id = f"sub-{next(self._id_counter)}"
        self._subscriptions[subscription_id] = (topic_pattern, handler)
        logger.info("新訂閱 pattern=%s subscription_id=%s", topic_pattern, subscription_id)
        return subscription_id

    async def unsubscribe(self, subscription_id: str) -> bool:
        removed = self._subscriptions.pop(subscription_id, None) is not None
        logger.info("退訂 subscription_id=%s 成功=%s", subscription_id, removed)
        return removed

    async def read_dlq(self, tenant_id: str, topic: str | None = None) -> list[DeadLetter]:
        return [
            letter
            for letter in self._dlq
            if letter.event.tenant_id == tenant_id
            and (topic is None or letter.original_topic == topic)
        ]

    async def _deliver(
        self, topic: str, event: BaseEvent, sub_id: str, handler: EventHandler
    ) -> None:
        """單一訂閱者投遞：重試耗盡進 DLQ，例外不外洩(保護其他訂閱者)。"""
        last_error = await deliver_with_retry(
            topic=topic,
            event=event,
            sub_id=sub_id,
            handler=handler,
            max_attempts=self._max_attempts,
            base_delay=self._base_delay,
        )
        if last_error is None:
            return
        self._dlq.append(
            DeadLetter(
                event=event,
                original_topic=topic,
                failure_count=self._max_attempts,
                last_error=last_error,
                dead_at=datetime.now(UTC),
            )
        )
        logger.error("事件進 DLQ topic=%s event_id=%s 錯誤=%s", topic, event.event_id, last_error)
