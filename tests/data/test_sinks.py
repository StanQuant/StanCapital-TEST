"""S11 → S05 audit / S09 observability 接線測試。"""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import AbstractContextManager
from dataclasses import FrozenInstanceError, dataclass
from datetime import UTC, datetime
from typing import Any

import pytest
from src.data.sinks import (
    InMemoryMarketDataAuditSink,
    InMemoryMarketDataLifecycleSink,
    MarketDataAuditProjection,
    MarketDataLifecycleAction,
    MarketDataLifecycleEvent,
    MarketDataTelemetrySink,
    NoopMarketDataAuditSink,
    NoopMarketDataLifecycleSink,
    project_market_data_audit_event,
)

NOW = datetime(2026, 7, 16, 1, 0, tzinfo=UTC)
LATER = datetime(2026, 7, 16, 1, 5, tzinfo=UTC)
SHA256 = "a" * 64


def make_event(
    action: MarketDataLifecycleAction = MarketDataLifecycleAction.CAPTURE_END,
    **overrides: object,
) -> MarketDataLifecycleEvent:
    values: dict[str, object] = {
        "action": action,
        "provider_id": "demo-quote",
        "tenant_id": "stanley",
        "actor_id": "agent-1",
        "trace_id": "trace-1",
        "result": "success",
        "license_tag": "demo-internal",
        "manifest_sha256": SHA256,
        "record_count": 2,
        "started_at": NOW,
        "ended_at": LATER,
        "duration_ms": 3.5,
        "reconnect_count": 1,
        "sequence_gap_count": 0,
        "circuit_open": False,
    }
    values.update(overrides)
    return MarketDataLifecycleEvent(**values)  # type: ignore[arg-type]


def test_lifecycle_actions_pin_audit_boundary() -> None:
    assert {action.name: action.value for action in MarketDataLifecycleAction} == {
        "CAPTURE_START": "capture_start",
        "CAPTURE_END": "capture_end",
        "CAPTURE_DELETE": "capture_delete",
        "REPLAY_START": "replay_start",
        "REPLAY_END": "replay_end",
        "PROVIDER_CONNECT": "provider_connect",
        "PROVIDER_DISCONNECT": "provider_disconnect",
        "PROVIDER_RECONNECT": "provider_reconnect",
        "CIRCUIT_OPEN": "circuit_open",
        "DECODE": "decode",
        "QUALITY_FLAG": "quality_flag",
    }
    audit_actions = {action for action in MarketDataLifecycleAction if action.requires_audit}

    assert audit_actions == {
        MarketDataLifecycleAction.CAPTURE_START,
        MarketDataLifecycleAction.CAPTURE_END,
        MarketDataLifecycleAction.CAPTURE_DELETE,
        MarketDataLifecycleAction.REPLAY_START,
        MarketDataLifecycleAction.REPLAY_END,
    }


def test_event_metadata_is_fixed_allowlist_and_immutable() -> None:
    event = make_event()

    assert not hasattr(event, "__dict__")
    with pytest.raises(FrozenInstanceError):
        event.result = "failed"  # type: ignore[misc]
    assert event.to_metadata() == {
        "event_type": "market_data_lifecycle",
        "action": "capture_end",
        "provider_id": "demo-quote",
        "tenant_id": "stanley",
        "actor_id": "agent-1",
        "trace_id": "trace-1",
        "result": "success",
        "license_tag": "demo-internal",
        "manifest_sha256": SHA256,
        "record_count": 2,
        "started_at": NOW.isoformat(),
        "ended_at": LATER.isoformat(),
        "duration_ms": 3.5,
        "reconnect_count": 1,
        "sequence_gap_count": 0,
        "circuit_open": False,
    }


def test_event_schema_rejects_sensitive_or_arbitrary_payload_fields() -> None:
    with pytest.raises(TypeError):
        MarketDataLifecycleEvent(  # type: ignore[call-arg]
            action=MarketDataLifecycleAction.DECODE,
            provider_id="demo-quote",
            tenant_id="stanley",
            actor_id="agent-1",
            trace_id="trace-1",
            result="success",
            raw_payload="must-not-enter-audit",
        )


def test_event_rejects_non_enum_action() -> None:
    with pytest.raises(ValueError) as exc:
        make_event(action="capture_end")  # type: ignore[arg-type]
    assert str(exc.value) == "action 必須是 MarketDataLifecycleAction，不可為 str"


@pytest.mark.parametrize(
    "field_name", ["provider_id", "tenant_id", "actor_id", "trace_id", "result"]
)
def test_event_rejects_empty_identity(field_name: str) -> None:
    with pytest.raises(ValueError, match=field_name):
        make_event(**{field_name: ""})


def test_event_rejects_empty_license() -> None:
    with pytest.raises(ValueError) as exc:
        make_event(license_tag="")
    assert str(exc.value) == "license_tag 不可為空字串"


@pytest.mark.parametrize("bad_hash", ["a" * 63, "G" * 64, "X" * 64])
def test_event_rejects_bad_manifest_hash(bad_hash: str) -> None:
    with pytest.raises(ValueError) as exc:
        make_event(manifest_sha256=bad_hash)
    assert str(exc.value) == "manifest_sha256 必須是 64 碼小寫十六進位 SHA-256"


@pytest.mark.parametrize(
    ("field_name", "value"),
    [("record_count", -1), ("reconnect_count", -1), ("sequence_gap_count", -1)],
)
def test_event_rejects_negative_counts(field_name: str, value: int) -> None:
    with pytest.raises(ValueError) as exc:
        make_event(**{field_name: value})
    assert str(exc.value) == f"{field_name} 不可為負：{value}"


@pytest.mark.parametrize("bad_duration", [True, "1", float("inf"), -0.1])
def test_event_rejects_invalid_duration(bad_duration: object) -> None:
    with pytest.raises(ValueError) as exc:
        make_event(duration_ms=bad_duration)
    assert str(exc.value) == "duration_ms 必須是有限非負數"


@pytest.mark.parametrize("field_name", ["started_at", "ended_at"])
def test_event_rejects_naive_times(field_name: str) -> None:
    with pytest.raises(ValueError) as exc:
        make_event(**{field_name: datetime(2026, 7, 16, 1, 0)})
    assert str(exc.value).startswith(f"{field_name} 必須是帶時區的 datetime")


def test_event_rejects_reversed_range_and_supports_empty_optionals() -> None:
    with pytest.raises(ValueError) as exc:
        make_event(started_at=LATER, ended_at=NOW)
    assert str(exc.value) == "started_at 不可晚於 ended_at"

    assert make_event(started_at=NOW, ended_at=NOW).started_at == NOW

    metadata = make_event(
        MarketDataLifecycleAction.PROVIDER_CONNECT,
        license_tag=None,
        manifest_sha256=None,
        record_count=None,
        started_at=None,
        ended_at=None,
    ).to_metadata()
    assert metadata["started_at"] is None
    assert metadata["ended_at"] is None


def test_event_defaults_are_governed_and_serialized() -> None:
    event = MarketDataLifecycleEvent(
        action=MarketDataLifecycleAction.PROVIDER_CONNECT,
        provider_id="demo-quote",
        tenant_id="stanley",
        actor_id="agent-1",
        trace_id="trace-1",
        result="success",
    )

    metadata = event.to_metadata()
    assert metadata["license_tag"] is None
    assert metadata["manifest_sha256"] is None
    assert metadata["record_count"] is None
    assert metadata["started_at"] is None
    assert metadata["ended_at"] is None
    assert metadata["duration_ms"] == 0.0
    assert metadata["reconnect_count"] == 0
    assert metadata["sequence_gap_count"] == 0
    assert metadata["circuit_open"] is False


def test_projection_is_s05_ready_stable_and_immutable() -> None:
    event = make_event()
    first = project_market_data_audit_event(event, risk_score=25)
    second = project_market_data_audit_event(event, risk_score=25)

    assert first == second
    assert first.tenant_id == "stanley"
    assert first.action == "market_data.capture_end"
    assert first.resource == "market-data/demo-quote"
    assert first.response_status == "success"
    assert first.risk_score == 25
    assert len(first.request_payload_hash) == 64
    assert first.metadata["event_type"] == "market_data_lifecycle"
    assert not hasattr(first, "__dict__")
    with pytest.raises(FrozenInstanceError):
        first.tenant_id = "other"  # type: ignore[misc]


def test_projection_hash_changes_with_event() -> None:
    first = project_market_data_audit_event(make_event(result="success"))
    second = project_market_data_audit_event(make_event(result="failed"))
    assert first.request_payload_hash != second.request_payload_hash


def test_projection_hash_pins_canonical_unicode_json() -> None:
    projection = project_market_data_audit_event(make_event(provider_id="券商甲"))

    assert (
        projection.request_payload_hash
        == (
            "d6e4b6e07008305730ca750e6e538ab9c9f7adf27982dd6b2a7d05141ddded85"  # pragma: allowlist secret
        )
    )


@pytest.mark.parametrize(
    "field_name",
    [
        "tenant_id",
        "actor_id",
        "action",
        "resource",
        "request_payload_hash",
        "response_status",
        "trace_id",
    ],
)
def test_projection_rejects_empty_required_fields(field_name: str) -> None:
    values: dict[str, object] = {
        "tenant_id": "stanley",
        "actor_id": "agent-1",
        "action": "market_data.capture_end",
        "resource": "market-data/demo-quote",
        "request_payload_hash": SHA256,
        "response_status": "success",
        "trace_id": "trace-1",
    }
    values[field_name] = ""
    with pytest.raises(ValueError, match=field_name):
        MarketDataAuditProjection(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad_hash", ["a" * 63, "G" * 64, "X" * 64])
def test_projection_rejects_bad_hash(bad_hash: str) -> None:
    with pytest.raises(ValueError) as exc:
        MarketDataAuditProjection(
            tenant_id="stanley",
            actor_id="agent-1",
            action="market_data.capture_end",
            resource="market-data/demo-quote",
            request_payload_hash=bad_hash,
            response_status="success",
            trace_id="trace-1",
        )
    assert str(exc.value) == "request_payload_hash 必須是 64 碼小寫十六進位 SHA-256"


@pytest.mark.parametrize("risk_score", [-1, 101])
def test_projection_rejects_bad_risk_score(risk_score: int) -> None:
    with pytest.raises(ValueError) as exc:
        MarketDataAuditProjection(
            tenant_id="stanley",
            actor_id="agent-1",
            action="market_data.capture_end",
            resource="market-data/demo-quote",
            request_payload_hash=SHA256,
            response_status="success",
            trace_id="trace-1",
            risk_score=risk_score,
        )
    assert str(exc.value) == "risk_score 必須在 0-100 之間"


def test_projection_defaults_and_upper_risk_boundary() -> None:
    default_projection = project_market_data_audit_event(make_event())
    upper_boundary = project_market_data_audit_event(make_event(), risk_score=100)

    assert default_projection.risk_score == 0
    assert upper_boundary.risk_score == 100
    direct_default = MarketDataAuditProjection(
        tenant_id="stanley",
        actor_id="agent-1",
        action="market_data.capture_end",
        resource="market-data/demo-quote",
        request_payload_hash=SHA256,
        response_status="success",
        trace_id="trace-1",
    )
    assert direct_default.risk_score == 0
    assert direct_default.metadata == {}


def test_audit_and_lifecycle_sinks_keep_only_required_projections() -> None:
    audit_event = make_event()
    telemetry_event = make_event(MarketDataLifecycleAction.DECODE)

    noop_projection = NoopMarketDataAuditSink().record(audit_event)
    audit_sink = InMemoryMarketDataAuditSink()
    assert audit_sink.record(audit_event) == noop_projection
    assert audit_sink.records == [noop_projection]

    assert NoopMarketDataLifecycleSink().emit(audit_event) == noop_projection
    assert NoopMarketDataLifecycleSink().emit(telemetry_event) is None

    lifecycle_sink = InMemoryMarketDataLifecycleSink()
    assert lifecycle_sink.emit(telemetry_event) is None
    projection = lifecycle_sink.emit(audit_event)
    assert lifecycle_sink.events == [telemetry_event, audit_event]
    assert lifecycle_sink.audit_records == [projection]
    assert isinstance(projection, MarketDataAuditProjection)


@dataclass(slots=True)
class FakeSpan:
    name: str
    attributes: dict[str, Any]
    events: list[tuple[str, Mapping[str, Any]]]


class FakeSpanContext(AbstractContextManager[FakeSpan]):
    def __init__(self, tracer: FakeTracer, span: FakeSpan) -> None:
        self._tracer = tracer
        self._span = span

    def __enter__(self) -> FakeSpan:
        self._tracer.spans.append(self._span)
        return self._span

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        return False


class FakeTracer:
    def __init__(self) -> None:
        self.spans: list[FakeSpan] = []

    def span(
        self,
        name: str,
        attributes: Mapping[str, Any] | None = None,
        tenant_id: str | None = None,
    ) -> FakeSpanContext:
        safe_attributes = dict(attributes or {})
        if tenant_id is not None:
            safe_attributes["tenant_id"] = tenant_id
        return FakeSpanContext(self, FakeSpan(name, safe_attributes, []))

    def add_event(
        self,
        span: FakeSpan,
        name: str,
        attributes: Mapping[str, Any] | None = None,
    ) -> None:
        span.events.append((name, dict(attributes or {})))


class FakeMetrics:
    def __init__(self) -> None:
        self.counters: list[tuple[str, int, Mapping[str, Any]]] = []
        self.records: list[tuple[str, float, Mapping[str, Any]]] = []

    def increment(
        self,
        name: str,
        amount: int = 1,
        attributes: Mapping[str, Any] | None = None,
    ) -> None:
        self.counters.append((name, amount, dict(attributes or {})))

    def record(
        self,
        name: str,
        value: float,
        attributes: Mapping[str, Any] | None = None,
    ) -> None:
        self.records.append((name, value, dict(attributes or {})))


class FakeLogger:
    def __init__(self) -> None:
        self.entries: list[tuple[str, str, Mapping[str, Any]]] = []

    def info(self, message: str, **kwargs: Any) -> None:
        self.entries.append(("info", message, dict(kwargs)))

    def warning(self, message: str, **kwargs: Any) -> None:
        self.entries.append(("warning", message, dict(kwargs)))


class FakeObservabilityProvider:
    def __init__(self) -> None:
        self.metrics = FakeMetrics()
        self.tracer = FakeTracer()
        self._logger = FakeLogger()

    def logger(self, name: str | None = None) -> FakeLogger:
        _ = name
        return self._logger


def test_telemetry_sink_emits_s05_and_all_s09_signals() -> None:
    fake_obs = FakeObservabilityProvider()
    audit_sink = InMemoryMarketDataAuditSink()
    sink = MarketDataTelemetrySink(fake_obs, audit_sink=audit_sink)  # type: ignore[arg-type]

    capture_projection = sink.emit(make_event(duration_ms=3.5))
    assert audit_sink.records == [capture_projection]

    reconnect = make_event(
        MarketDataLifecycleAction.PROVIDER_RECONNECT,
        result="failed",
        duration_ms=25.0,
        sequence_gap_count=2,
        circuit_open=True,
    )
    assert sink.emit(reconnect) is None
    assert sink.emit(make_event(MarketDataLifecycleAction.DECODE, duration_ms=1.25)) is None

    counter_names = [name for name, _amount, _labels in fake_obs.metrics.counters]
    assert counter_names == [
        "market_data_lifecycle_total",
        "market_data_lifecycle_total",
        "market_data_reconnect_total",
        "market_data_sequence_gap_total",
        "market_data_lifecycle_total",
    ]
    assert (
        "market_data_sequence_gap_total",
        2,
        {
            "tenant_id": "stanley",
            "provider": "demo-quote",
            "action": "provider_reconnect",
            "result": "failed",
        },
    ) in fake_obs.metrics.counters
    assert [(name, value) for name, value, _labels in fake_obs.metrics.records] == [
        ("market_data_operation_duration_ms", 3.5),
        ("market_data_operation_duration_ms", 25.0),
        ("market_data_decode_latency_ms", 1.25),
    ]
    assert [level for level, _message, _payload in fake_obs._logger.entries] == [
        "info",
        "warning",
        "info",
    ]
    assert [message for _level, message, _payload in fake_obs._logger.entries] == [
        "market_data_lifecycle_event",
        "market_data_lifecycle_event",
        "market_data_lifecycle_event",
    ]
    assert all(entry[2]["metadata"] is not None for entry in fake_obs._logger.entries)
    assert fake_obs.tracer.spans[0].name == "market_data.capture_end"
    assert [span.events[0][0] for span in fake_obs.tracer.spans] == [
        "market_data_lifecycle_event",
        "market_data_lifecycle_event",
        "market_data_lifecycle_event",
    ]


def test_telemetry_zero_duration_does_not_emit_operation_histogram() -> None:
    fake_obs = FakeObservabilityProvider()
    sink = MarketDataTelemetrySink(fake_obs)  # type: ignore[arg-type]

    sink.emit(
        make_event(
            MarketDataLifecycleAction.PROVIDER_CONNECT,
            duration_ms=0.0,
        )
    )

    assert fake_obs.metrics.records == []


def test_telemetry_pins_one_unit_boundaries_and_warning_truth_table() -> None:
    fake_obs = FakeObservabilityProvider()
    sink = MarketDataTelemetrySink(fake_obs)  # type: ignore[arg-type]

    sink.emit(
        make_event(
            MarketDataLifecycleAction.PROVIDER_CONNECT,
            result="failed",
            duration_ms=1.0,
            sequence_gap_count=1,
            circuit_open=False,
        )
    )

    assert [(name, value) for name, value, _labels in fake_obs.metrics.records] == [
        ("market_data_operation_duration_ms", 1.0)
    ]
    assert (
        "market_data_sequence_gap_total",
        1,
        {
            "tenant_id": "stanley",
            "provider": "demo-quote",
            "action": "provider_connect",
            "result": "failed",
        },
    ) in fake_obs.metrics.counters
    assert fake_obs._logger.entries[0][0] == "warning"


def test_telemetry_default_noop_dependencies_are_safe() -> None:
    sink = MarketDataTelemetrySink()
    assert (
        sink.emit(
            make_event(
                MarketDataLifecycleAction.PROVIDER_CONNECT,
                license_tag=None,
                manifest_sha256=None,
                record_count=None,
                started_at=None,
                ended_at=None,
                duration_ms=0.0,
            )
        )
        is None
    )
