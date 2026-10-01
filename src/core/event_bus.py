"""L4 事件匯流排 · Protocol 介面 + topic 規範 + 死信型別。

依賴限制：零第三方套件(import-linter 強制)。
實作不在這裡(D4 裁決)：InMemoryEventBus / RedisEventBus 在 src/messaging/。

topic 三段制(RoadMap 硬規定)：{tenant_id}.{layer}.{event_type}
範例：acme.l6.signal
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from src.core.events import BaseEvent

# 每段只允許小寫英數與底線、連字號
_SEGMENT_RE = re.compile(r"^[a-z0-9_-]+$")

# layer 段限定 Charter 16 層
_VALID_LAYERS = frozenset(f"l{i}" for i in range(16))

# DLQ topic 的第二段固定值：{tenant_id}.dlq.{layer}_{event_type}
DLQ_SEGMENT = "dlq"

# 訂閱處理函式：收一個事件、async 處理、不回傳
EventHandler = Callable[[BaseEvent], Awaitable[None]]


def split_topic(topic: str) -> tuple[str, str, str]:
    """驗證並拆解 topic。格式不符直接拋 ValueError(fail fast，不靜默修正)。"""
    parts = topic.split(".")
    if len(parts) != 3:
        msg = f"topic 必須是三段制 {{tenant_id}}.{{layer}}.{{event_type}}，收到: {topic!r}"
        raise ValueError(msg)
    tenant_id, layer, event_type = parts
    for segment in parts:
        if not _SEGMENT_RE.match(segment):
            msg = f"topic 段只允許 [a-z0-9_-]，收到非法段: {segment!r} (topic={topic!r})"
            raise ValueError(msg)
    if layer not in _VALID_LAYERS:
        msg = f"layer 段必須是 l0-l15，收到: {layer!r} (topic={topic!r})"
        raise ValueError(msg)
    return tenant_id, layer, event_type


def validate_pattern(pattern: str) -> tuple[str, str, str]:
    """驗證訂閱 pattern。layer / event_type 段允許萬用字元 *，tenant 段禁止(防跨租戶監聽)。"""
    parts = pattern.split(".")
    if len(parts) != 3:
        msg = f"pattern 必須是三段制，收到: {pattern!r}"
        raise ValueError(msg)
    tenant_id, layer, event_type = parts
    if tenant_id == "*":
        msg = f"tenant 段禁止萬用字元(防跨租戶監聽): {pattern!r}"
        raise ValueError(msg)
    if not _SEGMENT_RE.match(tenant_id):
        msg = f"tenant 段只允許 [a-z0-9_-]，收到: {tenant_id!r}"
        raise ValueError(msg)
    if layer != "*" and layer not in _VALID_LAYERS:
        msg = f"layer 段必須是 l0-l15 或 *，收到: {layer!r}"
        raise ValueError(msg)
    if event_type != "*" and not _SEGMENT_RE.match(event_type):
        msg = f"event_type 段只允許 [a-z0-9_-] 或 *，收到: {event_type!r}"
        raise ValueError(msg)
    return tenant_id, layer, event_type


def topic_matches(pattern: str, topic: str) -> bool:
    """判斷 topic 是否落在 pattern 範圍內。兩者都須已通過驗證。"""
    pattern_parts = pattern.split(".")
    topic_parts = topic.split(".")
    return all(p == "*" or p == t for p, t in zip(pattern_parts, topic_parts, strict=True))


def ensure_topic_for_event(topic: str, event: BaseEvent) -> None:
    """發布前防呆：topic 的 tenant 段與 event_type 段必須與事件本身一致。

    杜絕「事件是 A 租戶、topic 是 B 租戶」的跨租戶投遞。
    """
    tenant_id, _, event_type = split_topic(topic)
    if tenant_id != event.tenant_id:
        msg = f"topic 的 tenant 段 {tenant_id!r} 與事件 tenant_id {event.tenant_id!r} 不一致"
        raise ValueError(msg)
    if event_type != event.event_type.value:
        msg = (
            f"topic 的 event_type 段 {event_type!r}"
            f" 與事件 event_type {event.event_type.value!r} 不一致"
        )
        raise ValueError(msg)


def dlq_topic(original_topic: str) -> str:
    """由原 topic 導出 DLQ topic：{tenant_id}.dlq.{layer}_{event_type}。"""
    tenant_id, layer, event_type = split_topic(original_topic)
    return f"{tenant_id}.{DLQ_SEGMENT}.{layer}_{event_type}"


@dataclass(frozen=True, slots=True)
class DeadLetter:
    """死信 · handler 重試耗盡後的事件留底(維運排障 / S09 observability 用)。"""

    event: BaseEvent
    original_topic: str
    failure_count: int
    last_error: str
    dead_at: datetime


class EventBus(Protocol):
    """L4 內部事件匯流排介面(async 版，D3 裁決)。

    InMemory 與 Redis 兩實作行為必須一致(同一套行為測試跑兩遍)。
    """

    async def publish(self, topic: str, event: BaseEvent) -> None:
        """發布事件到 topic。topic 與事件的 tenant / event_type 不一致即拋 ValueError。"""

    async def publish_many(self, topic: str, events: Sequence[BaseEvent]) -> None:
        """微批次發布(高吞吐路徑)：逐筆驗證、一次往返。行情資料本來就成批進來。"""

    async def subscribe(self, topic_pattern: str, handler: EventHandler) -> str:
        """訂閱符合 pattern 的事件，回傳 subscription_id 供退訂。"""

    async def unsubscribe(self, subscription_id: str) -> bool:
        """退訂。回傳是否真的退掉了(無效 id 回 False)。"""

    async def read_dlq(self, tenant_id: str, topic: str | None = None) -> list[DeadLetter]:
        """讀取某租戶的死信，可再依原 topic 過濾。"""
