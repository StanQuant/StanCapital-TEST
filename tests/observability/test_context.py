"""W3C Trace Context 傳遞測試。"""

from __future__ import annotations

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from src.observability.context import (
    attached_context,
    extract_context,
    inject_context,
)


def _tracer() -> trace.Tracer:
    return TracerProvider().get_tracer("test")


def test_inject_creates_carrier_with_traceparent() -> None:
    tracer = _tracer()
    with tracer.start_as_current_span("s"):
        carrier = inject_context()
    assert "traceparent" in carrier


def test_inject_preserves_existing_keys() -> None:
    tracer = _tracer()
    with tracer.start_as_current_span("s"):
        carrier = inject_context({"x-custom": "v"})
    assert carrier["x-custom"] == "v"
    assert "traceparent" in carrier


def test_no_traceparent_outside_span() -> None:
    # 無有效 span 時不會注入 traceparent
    assert "traceparent" not in inject_context()


def test_extract_returns_context() -> None:
    carrier = {"traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"}
    ctx = extract_context(carrier)
    span_ctx = trace.get_current_span(ctx).get_span_context()
    assert format(span_ctx.trace_id, "032x") == "0af7651916cd43dd8448eb211c80319c"


def test_round_trip_propagation() -> None:
    tracer = _tracer()
    # 上游開 span 並注入
    with tracer.start_as_current_span("upstream") as up:
        upstream_trace_id = up.get_span_context().trace_id
        carrier = inject_context()
    # 下游邊界掛載後開 span，應接上同一條 trace
    with attached_context(carrier):
        with tracer.start_as_current_span("downstream") as down:
            assert down.get_span_context().trace_id == upstream_trace_id


def test_attached_context_restores_after_exit() -> None:
    carrier = {"traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"}
    with attached_context(carrier):
        pass
    # 離開後當前 span 不應殘留為遠端 span
    assert not trace.get_current_span().get_span_context().is_valid
