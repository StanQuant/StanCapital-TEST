"""W3C Trace Context 跨進程傳遞（D4：工具函式 + 邊界自動掛載）。

- inject_context：把當前 trace context 寫進 carrier（傳給下游 / 外部呼叫）。
- extract_context：從上游 carrier 還原 context。
- attached_context：在邊界（event consumer / 未來 HTTP middleware）自動掛上還原的
  context，讓其下開的 span 自動接上游 trace。
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager

from opentelemetry import context as otel_context
from opentelemetry.context import Context
from opentelemetry.propagate import extract, inject


def inject_context(carrier: dict[str, str] | None = None) -> dict[str, str]:
    """把當前 trace context 注入 carrier（None 則新建）。回傳同一個 carrier。"""
    target = {} if carrier is None else carrier
    inject(target)
    return target


def extract_context(carrier: Mapping[str, str]) -> Context:
    """從 carrier 還原 trace context。"""
    return extract(carrier)


@contextmanager
def attached_context(carrier: Mapping[str, str]) -> Iterator[None]:
    """邊界自動掛載：還原 carrier 的 context 並設為當前，離開時還原。"""
    token = otel_context.attach(extract(carrier))
    try:
        yield
    finally:
        otel_context.detach(token)
