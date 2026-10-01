"""共用投遞邏輯 · handler 重試(InMemory 與 Redis 共用)。

兩實作共用同一套重試規則，行為一致是「程式碼上的必然」而非測試巧合。
D5 裁決：預設 3 次，指數退避 base_delay * 2^(attempt-1)。
"""

from __future__ import annotations

import asyncio
import logging

from src.core.event_bus import EventHandler
from src.core.events import BaseEvent

logger = logging.getLogger(__name__)


async def deliver_with_retry(
    *,
    topic: str,
    event: BaseEvent,
    sub_id: str,
    handler: EventHandler,
    max_attempts: int,
    base_delay: float,
) -> str | None:
    """重試投遞單一事件。成功回 None；重試耗盡回 last_error 字串(呼叫端負責寫 DLQ)。"""
    last_error = ""
    for attempt in range(1, max_attempts + 1):
        try:
            await handler(event)
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            logger.warning(
                "handler 失敗 topic=%s subscription_id=%s 第%d/%d次 錯誤=%s",
                topic,
                sub_id,
                attempt,
                max_attempts,
                last_error,
            )
            if attempt < max_attempts:
                await asyncio.sleep(base_delay * 2 ** (attempt - 1))
        else:
            return None
    return last_error
