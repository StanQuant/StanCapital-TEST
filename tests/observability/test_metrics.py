"""指標測試。"""

from __future__ import annotations

from typing import Any

import pytest
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from src.observability.config import Environment, ObservabilityConfig
from src.observability.metrics import Metrics, build_meter_provider, safe_labels


def _cfg(*, endpoint: str | None = None) -> ObservabilityConfig:
    return ObservabilityConfig(
        service_name="svc",
        service_version="1.0",
        environment=Environment.LOCAL,
        otlp_endpoint=endpoint,
    )


def _metrics_with_reader() -> tuple[Metrics, InMemoryMetricReader]:
    reader = InMemoryMetricReader()
    provider = MeterProvider(metric_readers=[reader])
    return Metrics(provider.get_meter("test")), reader


def _points(reader: InMemoryMetricReader, name: str) -> list[Any]:
    data = reader.get_metrics_data()
    assert data is not None
    for rm in data.resource_metrics:
        for sm in rm.scope_metrics:
            for metric in sm.metrics:
                if metric.name == name:
                    return list(metric.data.data_points)
    return []


def test_build_meter_provider_no_exporter() -> None:
    provider = build_meter_provider(_cfg())
    assert isinstance(provider, MeterProvider)
    provider.shutdown()


def test_build_meter_provider_with_exporter() -> None:
    provider = build_meter_provider(_cfg(endpoint="http://collector:4318"))
    assert isinstance(provider, MeterProvider)
    provider.shutdown()


def test_increment_counter() -> None:
    metrics, reader = _metrics_with_reader()
    metrics.increment("hits_total", 2, {"tenant_id": "stanley"})
    metrics.increment("hits_total", 3, {"tenant_id": "stanley"})
    points = _points(reader, "hits_total")
    assert points[0].value == 5
    assert points[0].attributes["tenant_id"] == "stanley"


def test_increment_default_amount() -> None:
    metrics, reader = _metrics_with_reader()
    metrics.increment("calls_total")
    assert _points(reader, "calls_total")[0].value == 1


def test_counter_instrument_cached() -> None:
    metrics, _ = _metrics_with_reader()
    metrics.increment("c")
    metrics.increment("c")
    assert len(metrics._counters) == 1


def test_histogram_instrument_cached() -> None:
    metrics, _ = _metrics_with_reader()
    metrics.record("h", 1.0)
    metrics.record("h", 2.0)
    assert len(metrics._histograms) == 1


def test_gauge_instrument_cached() -> None:
    metrics, _ = _metrics_with_reader()
    metrics.set_gauge("g", 1)
    metrics.set_gauge("g", 2)
    assert len(metrics._gauges) == 1


def test_record_histogram() -> None:
    metrics, reader = _metrics_with_reader()
    metrics.record("latency_ms", 12.5, {"tenant_id": "t"})
    points = _points(reader, "latency_ms")
    assert points[0].count == 1
    assert points[0].sum == 12.5


def test_set_gauge() -> None:
    metrics, reader = _metrics_with_reader()
    metrics.set_gauge("active", 7, {"tenant_id": "t"})
    assert _points(reader, "active")[0].value == 7


def test_labels_redacted() -> None:
    metrics, reader = _metrics_with_reader()
    metrics.increment("evt_total", 1, {"password": "x", "ok": "y"})
    attrs = _points(reader, "evt_total")[0].attributes
    assert attrs["password"] == "***REDACTED***"
    assert attrs["ok"] == "y"


def test_record_policy_decision() -> None:
    metrics, reader = _metrics_with_reader()
    metrics.record_policy_decision("deny", "stanley")
    attrs = _points(reader, "policy_decisions_total")[0].attributes
    assert attrs["decision"] == "deny"
    assert attrs["tenant_id"] == "stanley"


def test_record_atr_decision() -> None:
    metrics, reader = _metrics_with_reader()
    metrics.record_atr_decision("high", "block", "stanley")
    attrs = _points(reader, "atr_decisions_total")[0].attributes
    assert attrs["level"] == "high"
    assert attrs["action"] == "block"


def test_record_audit_write_ms() -> None:
    metrics, reader = _metrics_with_reader()
    metrics.record_audit_write_ms(8.0, "stanley")
    assert _points(reader, "audit_write_ms")[0].sum == 8.0


def test_record_request_ms() -> None:
    metrics, reader = _metrics_with_reader()
    metrics.record_request_ms(20.0, {"route": "/orders"})
    points = _points(reader, "request_duration_ms")
    assert points[0].sum == 20.0
    assert points[0].attributes["route"] == "/orders"


def test_record_request_ms_no_attributes() -> None:
    metrics, reader = _metrics_with_reader()
    metrics.record_request_ms(5.0)
    assert _points(reader, "request_duration_ms")[0].sum == 5.0


def test_metrics_slots_no_dict() -> None:
    metrics, _ = _metrics_with_reader()
    assert not hasattr(metrics, "__dict__")


# ---- mutation killers ----


def test_build_meter_provider_resource() -> None:
    # 殺 resource=None 變異
    provider = build_meter_provider(_cfg())
    assert provider._sdk_config.resource.attributes["service.name"] == "svc"
    provider.shutdown()


def test_counter_cache_stores_instrument() -> None:
    # 殺 self._counters[name] = None 變異
    metrics, _ = _metrics_with_reader()
    inst = metrics._counter("x")
    assert metrics._counters["x"] is inst


def test_histogram_cache_stores_instrument() -> None:
    metrics, _ = _metrics_with_reader()
    inst = metrics._histogram("x")
    assert metrics._histograms["x"] is inst


def test_gauge_cache_stores_instrument() -> None:
    metrics, _ = _metrics_with_reader()
    inst = metrics._gauge("x")
    assert metrics._gauges["x"] is inst


def test_atr_decision_has_tenant_label() -> None:
    metrics, reader = _metrics_with_reader()
    metrics.record_atr_decision("high", "block", "stanley")
    assert _points(reader, "atr_decisions_total")[0].attributes["tenant_id"] == "stanley"


def test_audit_write_has_tenant_label() -> None:
    metrics, reader = _metrics_with_reader()
    metrics.record_audit_write_ms(8.0, "stanley")
    assert _points(reader, "audit_write_ms")[0].attributes["tenant_id"] == "stanley"


def test_policy_decision_metric_name_and_labels() -> None:
    metrics, reader = _metrics_with_reader()
    metrics.record_policy_decision("deny", "stanley")
    pts = _points(reader, "policy_decisions_total")
    assert pts[0].attributes["tenant_id"] == "stanley"


# ---- 高基數 label 守門 ----


def test_safe_labels_keeps_tenant_drops_ids() -> None:
    out = safe_labels(
        {
            "tenant_id": "t",
            "user_id": "u",
            "order_id": "o",
            "decision_id": "d",
            "decision": "deny",
        }
    )
    assert out == {"tenant_id": "t", "decision": "deny"}


@pytest.mark.parametrize(
    ("key", "kept"),
    [
        ("tenant_id", True),
        ("account_id", False),
        ("user_id", False),
        ("email", False),
        ("ip", False),
        ("ip_address", False),
        ("user", False),
        ("username", False),
        ("decision", True),
        ("route", True),
    ],
)
def test_safe_labels_key_policy(key: str, kept: bool) -> None:
    out = safe_labels({key: "v"})
    assert (key in out) is kept


def test_increment_drops_high_cardinality_label() -> None:
    metrics, reader = _metrics_with_reader()
    metrics.increment("evt_total", 1, {"tenant_id": "t", "user_id": "u"})
    attrs = _points(reader, "evt_total")[0].attributes
    assert attrs["tenant_id"] == "t"
    assert "user_id" not in attrs


def test_record_drops_high_cardinality_label() -> None:
    metrics, reader = _metrics_with_reader()
    metrics.record("lat_ms", 1.0, {"tenant_id": "t", "order_id": "o"})
    attrs = _points(reader, "lat_ms")[0].attributes
    assert "order_id" not in attrs


def test_set_gauge_drops_high_cardinality_label() -> None:
    metrics, reader = _metrics_with_reader()
    metrics.set_gauge("g", 1, {"tenant_id": "t", "session_id": "s"})
    attrs = _points(reader, "g")[0].attributes
    assert "session_id" not in attrs
