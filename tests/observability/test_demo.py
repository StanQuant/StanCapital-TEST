"""5 層 trace demo 測試（fake exporter 整合，D9 非 docker 部分）。"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator

import pytest
import structlog
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from src.observability import demo as demo_module
from src.observability.config import Environment, ObservabilityConfig
from src.observability.demo import run_five_layer_demo
from src.observability.logging import configure_logging
from src.observability.metrics import Metrics
from src.observability.provider import ObservabilityProvider
from src.observability.tracing import Tracer


@pytest.fixture(autouse=True)
def _reset() -> Iterator[None]:
    yield
    structlog.reset_defaults()
    structlog.contextvars.clear_contextvars()
    logging.getLogger().handlers.clear()


def _capturing_provider() -> tuple[
    ObservabilityProvider, InMemorySpanExporter, InMemoryMetricReader
]:
    cfg = ObservabilityConfig(
        service_name="demo", service_version="1.0", environment=Environment.LOCAL
    )
    configure_logging(cfg)
    exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(exporter))
    reader = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=[reader])
    provider = ObservabilityProvider(
        cfg,
        Tracer(tracer_provider.get_tracer("demo")),
        Metrics(meter_provider.get_meter("demo")),
        tracer_provider,
        meter_provider,
    )
    return provider, exporter, reader


def test_demo_single_trace_across_five_layers() -> None:
    provider, exporter, _ = _capturing_provider()
    trace_id = run_five_layer_demo(provider)
    spans = exporter.get_finished_spans()
    assert len(spans) == 5
    # 全部同一條 trace
    trace_ids = {format(s.get_span_context().trace_id, "032x") for s in spans}
    assert trace_ids == {trace_id}


def test_demo_layer_names() -> None:
    provider, exporter, _ = _capturing_provider()
    run_five_layer_demo(provider)
    names = {s.name for s in exporter.get_finished_spans()}
    assert "L4.event_bus.receive_click_event" in names
    assert "L9.observability.emit_telemetry" in names


def test_demo_parent_chain() -> None:
    provider, exporter, _ = _capturing_provider()
    run_five_layer_demo(provider)
    spans = exporter.get_finished_spans()
    # 恰有一個 root（無 parent），其餘各有 parent → 巢狀鏈
    roots = [s for s in spans if s.parent is None]
    assert len(roots) == 1
    assert roots[0].name == "L4.event_bus.receive_click_event"


def test_demo_tenant_context_cleared() -> None:
    provider, _, _ = _capturing_provider()
    run_five_layer_demo(provider, tenant_id="stanley")
    # demo 結束後 contextvars 應已清除
    assert structlog.contextvars.get_contextvars() == {}


# ---- mutation killers ----


def test_demo_all_five_layer_full_names() -> None:
    # 殺每一層名與操作名的字串變異
    provider, exporter, _ = _capturing_provider()
    run_five_layer_demo(provider)
    names = {s.name for s in exporter.get_finished_spans()}
    assert names == {
        "L4.event_bus.receive_click_event",
        "L5.application.handle_submit_order",
        "L11.governance.rbac_abac_check",
        "L10.security.atr_policy_evaluate",
        "L9.observability.emit_telemetry",
    }


def test_demo_default_tenant_is_stanley() -> None:
    # 殺 tenant_id 預設值字串變異
    provider, exporter, _ = _capturing_provider()
    run_five_layer_demo(provider)
    span = exporter.get_finished_spans()[0]
    assert span.attributes is not None
    assert span.attributes["tenant_id"] == "stanley"


def test_demo_records_request_metric_value() -> None:
    # 殺 record_request_ms(4.2) 數值變異 + tenant_id 標籤變異
    provider, _, reader = _capturing_provider()
    run_five_layer_demo(provider)
    data = reader.get_metrics_data()
    assert data is not None
    point = None
    for rm in data.resource_metrics:
        for sm in rm.scope_metrics:
            for metric in sm.metrics:
                if metric.name == "request_duration_ms":
                    point = next(iter(metric.data.data_points))
    assert point is not None
    assert point.sum == 4.2
    assert point.attributes["tenant_id"] == "stanley"


def test_demo_logs_layer_enter_with_workflow(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # 殺 "layer_enter" 事件名與 workflow_id="demo_submit_order" 變異
    provider, _, _ = _capturing_provider()
    run_five_layer_demo(provider)
    lines = [json.loads(line) for line in capsys.readouterr().err.strip().splitlines() if line]
    enters = [p for p in lines if p["event"] == "layer_enter"]
    assert len(enters) == 5
    assert all(p["workflow_id"] == "demo_submit_order" for p in enters)


def test_demo_complete_log_has_tenant(capsys: pytest.CaptureFixture[str]) -> None:
    # demo_complete 在 context 清除前發出，欄位與各層一致（帶 tenant_id / workflow_id）
    provider, _, _ = _capturing_provider()
    run_five_layer_demo(provider)
    lines = [json.loads(line) for line in capsys.readouterr().err.strip().splitlines() if line]
    complete = next(p for p in lines if p["event"] == "demo_complete")
    assert complete["tenant_id"] == "stanley"
    assert complete["workflow_id"] == "demo_submit_order"
    assert len(complete["trace_id"]) == 32


def test_demo_main_runs(capsys: pytest.CaptureFixture[str]) -> None:
    # 殺 main() 內字串/wiring 變異
    demo_module.main()
    lines = [json.loads(line) for line in capsys.readouterr().err.strip().splitlines() if line]
    complete = next(p for p in lines if p["event"] == "demo_complete")
    assert len(complete["trace_id"]) == 32
