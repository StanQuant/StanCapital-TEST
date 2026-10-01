"""S07/S08 安全事件接線測試。"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest
import structlog
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from src.observability.config import Environment, ObservabilityConfig
from src.observability.logging import configure_logging
from src.observability.metrics import Metrics
from src.observability.ports import InMemorySocNotificationPort
from src.observability.provider import ObservabilityProvider
from src.observability.sinks import (
    ObservabilityAuditMetadataSink,
    ObservabilitySecurityOfficerSink,
)
from src.observability.tracing import Tracer


@pytest.fixture(autouse=True)
def _reset() -> Iterator[None]:
    yield
    structlog.reset_defaults()
    structlog.contextvars.clear_contextvars()
    logging.getLogger().handlers.clear()


def _provider() -> ObservabilityProvider:
    return ObservabilityProvider.create(
        ObservabilityConfig(
            service_name="svc",
            service_version="1.0",
            environment=Environment.LOCAL,
        )
    )


def _notification(level: str = "high", action: str = "block") -> SimpleNamespace:
    return SimpleNamespace(
        tenant_id="stanley",
        agent_id="agent1",
        decision_id="d1",
        score=80,
        level=level,
        action=action,
        triggered_rules=("T001", "T002"),
        target="orders/submit",
        trace_id="tr1",
        timestamp="2026-06-29T00:00:00+00:00",
    )


def _read_json_lines(captured: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in captured.strip().splitlines() if line]


def test_security_sink_sends_soc_alert() -> None:
    soc = InMemorySocNotificationPort()
    sink = ObservabilitySecurityOfficerSink(_provider(), soc)
    sink.notify(_notification(level="high", action="block"))
    assert len(soc.alerts) == 1
    alert = soc.alerts[0]
    assert alert.source == "atr"
    assert alert.severity == "critical"
    assert alert.tenant_id == "stanley"
    assert alert.decision_id == "d1"


@pytest.mark.parametrize(
    ("level", "severity"),
    [
        ("low", "info"),
        ("medium", "warning"),
        ("high", "critical"),
        ("critical", "critical"),
        ("unknown_level", "warning"),
    ],
)
def test_security_sink_severity_mapping(level: str, severity: str) -> None:
    soc = InMemorySocNotificationPort()
    sink = ObservabilitySecurityOfficerSink(_provider(), soc)
    sink.notify(_notification(level=level))
    assert soc.alerts[0].severity == severity


def test_security_sink_emits_log(capsys: pytest.CaptureFixture[str]) -> None:
    sink = ObservabilitySecurityOfficerSink(_provider(), InMemorySocNotificationPort())
    sink.notify(_notification(level="critical"))
    payloads = _read_json_lines(capsys.readouterr().err)
    event = next(p for p in payloads if p["event"] == "atr_security_event")
    assert event["level"] == "critical"
    assert event["tenant_id"] == "stanley"
    assert event["score"] == 80


def test_security_sink_default_noop_port() -> None:
    # 不給 SOC port 也不應出錯
    sink = ObservabilitySecurityOfficerSink(_provider())
    sink.notify(_notification())


def test_security_sink_fail_closed(caplog: pytest.LogCaptureFixture) -> None:
    class _BoomMetrics:
        def record_atr_decision(self, *_: Any) -> None:
            raise RuntimeError("boom")

    broken = SimpleNamespace(metrics=_BoomMetrics())
    sink = ObservabilitySecurityOfficerSink(broken)  # type: ignore[arg-type]
    with caplog.at_level(logging.CRITICAL):
        sink.notify(_notification())  # 不應拋出
    rec = next(r for r in caplog.records if r.levelno == logging.CRITICAL)
    assert rec.message == "ObservabilitySecurityOfficerSink emit 失敗"
    assert rec.exc_info  # 真值：tuple 為真，exc_info=False/None 為假


def test_audit_sink_records_metric_and_log(
    capsys: pytest.CaptureFixture[str],
) -> None:
    sink = ObservabilityAuditMetadataSink(_provider())
    sink.record(
        {
            "effect": "deny",
            "tenant_id": "stanley",
            "decision_id": "p1",
            "matched_rule_ids": ["r1"],
        }
    )
    payloads = _read_json_lines(capsys.readouterr().err)
    event = next(p for p in payloads if p["event"] == "policy_audit_metadata")
    assert event["metadata"]["effect"] == "deny"
    assert event["metadata"]["tenant_id"] == "stanley"


def test_audit_sink_missing_fields_defaults() -> None:
    # metadata 缺欄位也不可出錯（fail-closed 觀測）；trace event 用預設值
    provider, span_exporter, _ = _capturing_provider()
    sink = ObservabilityAuditMetadataSink(provider)
    with provider.tracer.span("parent"):
        sink.record({})
    pd = next(
        e
        for s in span_exporter.get_finished_spans()
        for e in s.events
        if e.name == "policy_decision"
    )
    assert pd.attributes is not None
    assert pd.attributes["effect"] == "unknown"
    assert pd.attributes["decision_id"] == ""


def test_audit_sink_fail_closed(caplog: pytest.LogCaptureFixture) -> None:
    class _BoomMetrics:
        def record_policy_decision(self, *_: Any) -> None:
            raise RuntimeError("boom")

    broken = SimpleNamespace(metrics=_BoomMetrics())
    sink = ObservabilityAuditMetadataSink(broken)  # type: ignore[arg-type]
    with caplog.at_level(logging.CRITICAL):
        sink.record({"effect": "allow", "tenant_id": "t"})
    rec = next(r for r in caplog.records if r.levelno == logging.CRITICAL)
    assert rec.message == "ObservabilityAuditMetadataSink emit 失敗"
    assert rec.exc_info  # 真值：tuple 為真，exc_info=False/None 為假


def test_sinks_slots_no_dict() -> None:
    provider = _provider()
    assert not hasattr(ObservabilitySecurityOfficerSink(provider), "__dict__")
    assert not hasattr(ObservabilityAuditMetadataSink(provider), "__dict__")


# ---- mutation killers ----


def _capturing_provider() -> tuple[
    ObservabilityProvider, InMemorySpanExporter, InMemoryMetricReader
]:
    cfg = ObservabilityConfig(
        service_name="svc", service_version="1.0", environment=Environment.LOCAL
    )
    configure_logging(cfg)
    span_exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(span_exporter))
    reader = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=[reader])
    provider = ObservabilityProvider(
        cfg,
        Tracer(tracer_provider.get_tracer("t")),
        Metrics(meter_provider.get_meter("t")),
        tracer_provider,
        meter_provider,
    )
    return provider, span_exporter, reader


def _metric_attrs(reader: InMemoryMetricReader, name: str) -> dict[str, object]:
    data = reader.get_metrics_data()
    assert data is not None
    for rm in data.resource_metrics:
        for sm in rm.scope_metrics:
            for metric in sm.metrics:
                if metric.name == name:
                    return dict(next(iter(metric.data.data_points)).attributes or {})
    raise AssertionError(f"metric {name} not found")


def test_security_sink_log_full_fields(capsys: pytest.CaptureFixture[str]) -> None:
    sink = ObservabilitySecurityOfficerSink(_provider(), InMemorySocNotificationPort())
    sink.notify(_notification(level="high", action="block"))
    event = next(
        p for p in _read_json_lines(capsys.readouterr().err) if p["event"] == "atr_security_event"
    )
    assert event["agent_id"] == "agent1"
    assert event["action"] == "block"
    assert event["target"] == "orders/submit"
    assert event["decision_id"] == "d1"
    assert event["triggered_rules"] == ["T001", "T002"]
    assert event["trace_id"] == "tr1"
    # threat_level 與 structlog 的 log level（severity=critical）不同名，須各自存在
    assert event["threat_level"] == "high"
    assert event["level"] == "critical"


def test_security_sink_alert_fields() -> None:
    soc = InMemorySocNotificationPort()
    ObservabilitySecurityOfficerSink(_provider(), soc).notify(
        _notification(level="high", action="block")
    )
    alert = soc.alerts[0]
    assert alert.source == "atr"
    assert alert.title == "ATR high · block"
    assert alert.attributes["agent_id"] == "agent1"
    assert alert.attributes["target"] == "orders/submit"
    assert alert.timestamp == "2026-06-29T00:00:00+00:00"


def test_security_sink_emits_trace_event() -> None:
    provider, span_exporter, reader = _capturing_provider()
    sink = ObservabilitySecurityOfficerSink(provider, InMemorySocNotificationPort())
    with provider.tracer.span("parent"):
        sink.notify(_notification(level="high", action="block"))
    events = [e for s in span_exporter.get_finished_spans() for e in s.events]
    atr = next(e for e in events if e.name == "atr_decision")
    assert atr.attributes is not None
    assert atr.attributes["decision_id"] == "d1"
    assert atr.attributes["level"] == "high"
    assert atr.attributes["action"] == "block"
    assert _metric_attrs(reader, "atr_decisions_total")["tenant_id"] == "stanley"


def test_audit_sink_emits_trace_event_and_metric() -> None:
    provider, span_exporter, reader = _capturing_provider()
    sink = ObservabilityAuditMetadataSink(provider)
    with provider.tracer.span("parent"):
        sink.record({"effect": "deny", "tenant_id": "stanley", "decision_id": "p1"})
    events = [e for s in span_exporter.get_finished_spans() for e in s.events]
    pd = next(e for e in events if e.name == "policy_decision")
    assert pd.attributes is not None
    assert pd.attributes["effect"] == "deny"
    assert pd.attributes["decision_id"] == "p1"
    assert _metric_attrs(reader, "policy_decisions_total")["tenant_id"] == "stanley"
    assert _metric_attrs(reader, "policy_decisions_total")["decision"] == "deny"


def _metric_names(reader: InMemoryMetricReader) -> list[str]:
    data = reader.get_metrics_data()
    return [
        m.name
        for rm in (data.resource_metrics if data else [])
        for sm in rm.scope_metrics
        for m in sm.metrics
    ]


def test_audit_sink_missing_tenant_no_unknown_bucket() -> None:
    # 多租戶不變量：缺 tenant_id 不得建立 unknown 租戶桶（不發 per-tenant 指標）
    provider, span_exporter, reader = _capturing_provider()
    sink = ObservabilityAuditMetadataSink(provider)
    with provider.tracer.span("parent"):
        sink.record({"effect": "deny", "decision_id": "p1"})
    events = [e for s in span_exporter.get_finished_spans() for e in s.events]
    pd = next(e for e in events if e.name == "policy_decision")
    assert pd.attributes is not None
    assert pd.attributes["effect"] == "deny"
    assert pd.attributes["decision_id"] == "p1"
    assert "policy_decisions_total" not in _metric_names(reader)


def test_audit_sink_missing_tenant_logs_warning(
    capsys: pytest.CaptureFixture[str],
) -> None:
    sink = ObservabilityAuditMetadataSink(_provider())
    sink.record({"effect": "deny", "decision_id": "p1"})
    evt = next(
        p
        for p in _read_json_lines(capsys.readouterr().err)
        if p["event"] == "policy_audit_metadata_missing_tenant"
    )
    assert evt["level"] == "warning"


def test_audit_sink_empty_string_tenant_no_bucket() -> None:
    # tenant_id 為空字串同樣視為缺（falsy），不建立租戶桶
    provider, _, reader = _capturing_provider()
    sink = ObservabilityAuditMetadataSink(provider)
    sink.record({"effect": "deny", "tenant_id": "", "decision_id": "p1"})
    assert "policy_decisions_total" not in _metric_names(reader)
