"""結構化日誌（D1：structlog + OTEL log bridge）。

特性：
- JSON 輸出（或本機 console 美化）。
- 每筆 log 自動帶當前 span 的 trace_id / span_id（log ↔ trace 互跳）。
- 套用 redaction，禁止外漏 key / secret / PII。
- 橋接既有 stdlib logging：所有 `logging.getLogger(__name__)` 呼叫點不必改，
  也走同一條 JSON 管線。
- 請求情境（tenant_id…）以 contextvars 綁定；tenant_id 無預設。
"""

from __future__ import annotations

import logging
from typing import Any, cast

import structlog
from opentelemetry import trace

from src.observability.config import ObservabilityConfig
from src.observability.redaction import Redactor

_REDACTOR = Redactor()


def add_otel_context(_logger: Any, _method_name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """把當前 OTEL span 的 trace_id / span_id 注入 log（無有效 span 時略過）。"""
    ctx = trace.get_current_span().get_span_context()
    if ctx.is_valid:
        event_dict["trace_id"] = format(ctx.trace_id, "032x")
        event_dict["span_id"] = format(ctx.span_id, "016x")
    return event_dict


def redact_event(_logger: Any, _method_name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """序列化前遮蔽敏感欄位 / 值。"""
    return cast(dict[str, Any], _REDACTOR.redact(event_dict))


def _shared_processors() -> list[Any]:
    return [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        add_otel_context,
        redact_event,
    ]


def configure_logging(config: ObservabilityConfig) -> None:
    """設定 structlog + stdlib 統一 JSON 管線（冪等：重設 root handler）。"""
    shared = _shared_processors()
    structlog.configure(
        processors=[*shared, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )
    renderer: Any = (
        structlog.dev.ConsoleRenderer()
        if config.console_logs
        else structlog.processors.JSONRenderer()
    )
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(config.log_level)


def get_logger(name: str | None = None) -> Any:
    """取得 structlog logger。"""
    return structlog.get_logger(name)


def bind_request_context(tenant_id: str, **fields: Any) -> None:
    """綁定請求情境到 contextvars。tenant_id 必填、無預設（多租戶 Day-1）。"""
    if not tenant_id:
        raise ValueError("tenant_id 不可為空")
    structlog.contextvars.bind_contextvars(tenant_id=tenant_id, **fields)


def clear_request_context() -> None:
    """清掉請求情境（請求結束時呼叫，避免汙染下一筆）。"""
    structlog.contextvars.clear_contextvars()
