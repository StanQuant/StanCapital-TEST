"""分散式追蹤測試。"""

from __future__ import annotations

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
from opentelemetry.trace import StatusCode
from src.observability.config import Environment, ObservabilityConfig
from src.observability.redaction import safe_attributes
from src.observability.tracing import Tracer, build_tracer_provider


def _cfg(*, endpoint: str | None = None) -> ObservabilityConfig:
    return ObservabilityConfig(
        service_name="svc",
        service_version="1.0",
        environment=Environment.LOCAL,
        otlp_endpoint=endpoint,
    )


def _tracer_with_capture() -> tuple[Tracer, InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return Tracer(provider.get_tracer("test")), exporter


def test_safe_attributes_redacts_key() -> None:
    assert safe_attributes({"api_key": "x"}) == {"api_key": "***REDACTED***"}


def test_safe_attributes_redacts_value() -> None:
    out = safe_attributes({"note": "mail me a@b.com"})
    assert out["note"] == "mail me ***REDACTED***"


def test_safe_attributes_passthrough_non_str() -> None:
    assert safe_attributes({"count": 5, "flag": True}) == {"count": 5, "flag": True}


def test_build_provider_no_exporter() -> None:
    provider = build_tracer_provider(_cfg())
    assert isinstance(provider, TracerProvider)
    provider.shutdown()


def test_build_provider_with_exporter() -> None:
    provider = build_tracer_provider(_cfg(endpoint="http://collector:4318"))
    assert isinstance(provider, TracerProvider)
    provider.shutdown()


def test_span_records_attributes() -> None:
    tracer, exporter = _tracer_with_capture()
    with tracer.span("op", attributes={"symbol": "2330"}, tenant_id="stanley"):
        pass
    (span,) = exporter.get_finished_spans()
    assert span.name == "op"
    assert span.attributes is not None
    assert span.attributes["symbol"] == "2330"
    assert span.attributes["tenant_id"] == "stanley"


def test_span_redacts_attribute() -> None:
    tracer, exporter = _tracer_with_capture()
    with tracer.span("op", attributes={"password": "x"}):
        pass
    (span,) = exporter.get_finished_spans()
    assert span.attributes is not None
    assert span.attributes["password"] == "***REDACTED***"


def test_span_no_optional_args() -> None:
    tracer, exporter = _tracer_with_capture()
    with tracer.span("bare"):
        pass
    (span,) = exporter.get_finished_spans()
    assert span.attributes is not None
    assert "tenant_id" not in span.attributes


def test_span_records_exception() -> None:
    tracer, exporter = _tracer_with_capture()
    with pytest.raises(ValueError, match="boom"):
        with tracer.span("op"):
            raise ValueError("boom")
    (span,) = exporter.get_finished_spans()
    assert span.status.status_code is StatusCode.ERROR
    assert span.events  # 例外被記錄成 event


def test_add_event() -> None:
    tracer, exporter = _tracer_with_capture()
    with tracer.span("op") as span:
        tracer.add_event(span, "atr_decision", {"level": "high"})
    (finished,) = exporter.get_finished_spans()
    names = [e.name for e in finished.events]
    assert "atr_decision" in names


def test_add_event_no_attributes() -> None:
    tracer, exporter = _tracer_with_capture()
    with tracer.span("op") as span:
        tracer.add_event(span, "plain")
    (finished,) = exporter.get_finished_spans()
    assert "plain" in [e.name for e in finished.events]


def test_tracer_slots_no_dict() -> None:
    tracer, _ = _tracer_with_capture()
    assert not hasattr(tracer, "__dict__")


# ---- mutation killers ----


def test_build_provider_resource_attributes() -> None:
    # 殺 resource=None 變異
    provider = build_tracer_provider(_cfg())
    assert provider.resource.attributes["service.name"] == "svc"
    provider.shutdown()


def test_build_provider_sampler_reflects_ratio() -> None:
    # 殺 sampler=None 變異（None → 預設 AlwaysOn，描述不含 TraceIdRatioBased）
    cfg = ObservabilityConfig(
        service_name="svc",
        service_version="1.0",
        environment=Environment.LOCAL,
        trace_sample_ratio=0.5,
    )
    provider = build_tracer_provider(cfg)
    assert "TraceIdRatioBased" in provider.sampler.get_description()
    provider.shutdown()
