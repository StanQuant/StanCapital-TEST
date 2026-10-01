"""分散式追蹤（OTEL Tracer 封裝）。

- build_tracer_provider：依設定建 TracerProvider；有 OTLP endpoint 才掛匯出器，
  否則 span 照建但不外送（D2 no-op fallback）。
- Tracer：span context manager，自動記錄例外、設 ERROR 狀態、遮蔽屬性。
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import Span, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased
from opentelemetry.trace import Status, StatusCode

from src.observability.config import ObservabilityConfig
from src.observability.redaction import safe_attributes


def build_tracer_provider(config: ObservabilityConfig) -> TracerProvider:
    """建 TracerProvider；有 endpoint 才掛 OTLP 匯出（no-op fallback）。"""
    resource = Resource.create(config.resource_attributes())
    sampler = ParentBased(TraceIdRatioBased(config.trace_sample_ratio))
    provider = TracerProvider(resource=resource, sampler=sampler)
    if config.exporters_enabled:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )

        exporter = OTLPSpanExporter(endpoint=f"{config.otlp_endpoint}/v1/traces")
        provider.add_span_processor(BatchSpanProcessor(exporter))
    return provider


class Tracer:
    """OTEL tracer 薄封裝，提供安全的 span 輔助。"""

    __slots__ = ("_tracer",)

    def __init__(self, otel_tracer: Any) -> None:
        self._tracer = otel_tracer

    @contextmanager
    def span(
        self,
        name: str,
        attributes: Mapping[str, Any] | None = None,
        tenant_id: str | None = None,
    ) -> Iterator[Span]:
        """開一個 child span：記時由 SDK 負責；例外自動記錄並設 ERROR 後重拋。"""
        with self._tracer.start_as_current_span(name) as current:
            if tenant_id is not None:
                current.set_attribute("tenant_id", tenant_id)
            if attributes:
                for key, value in safe_attributes(attributes).items():
                    current.set_attribute(key, value)
            try:
                yield current
            except Exception as exc:
                current.set_status(Status(StatusCode.ERROR, str(exc)))
                current.record_exception(exc)
                raise

    def add_event(self, span: Span, name: str, attributes: Mapping[str, Any] | None = None) -> None:
        """在 span 掛事件（安全事件如 ATR/Policy 決策走這裡），屬性先遮蔽。"""
        span.add_event(name, attributes=safe_attributes(attributes or {}))
