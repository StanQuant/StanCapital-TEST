"""S10 audit / observability sink 測試。"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import FrozenInstanceError, dataclass
from typing import Any

import pytest
from src.observability.ports import InMemorySocNotificationPort
from src.security.vault.audit import SecretAuditEvent
from src.security.vault.redaction import contains_plaintext
from src.security.vault.sinks import (
    InMemorySecretAuditSink,
    SecretAuditProjection,
    SecretObservabilitySink,
    _hash_redacted_payload,
    project_secret_audit_event,
)
from src.security.vault.types import SecretAction, SecretMetadata, SecretValue


@dataclass(slots=True)
class FakeSpan:
    name: str
    attributes: dict[str, Any]
    events: list[tuple[str, Mapping[str, Any]]]


class FakeSpanContext:
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
        safe_attrs = dict(attributes or {})
        if tenant_id is not None:
            safe_attrs["tenant_id"] = tenant_id
        return FakeSpanContext(self, FakeSpan(name, safe_attrs, []))

    def add_event(
        self,
        span: FakeSpan,
        name: str,
        attributes: Mapping[str, Any] | None = None,
    ) -> None:
        span.events.append((name, dict(attributes or {})))


class FakeMetrics:
    def __init__(self) -> None:
        self.counters: list[tuple[str, Mapping[str, Any]]] = []
        self.records: list[tuple[str, float, Mapping[str, Any]]] = []

    def increment(
        self,
        name: str,
        amount: int = 1,
        attributes: Mapping[str, Any] | None = None,
    ) -> None:
        _ = amount
        self.counters.append((name, dict(attributes or {})))

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


def _event(
    action: SecretAction, metadata: SecretMetadata, *, result: str = "success"
) -> SecretAuditEvent:
    return SecretAuditEvent(
        action=action,
        metadata=metadata,
        actor_id="agent-1",
        trace_id="trace-1",
        result=result,
        reason="commercial audit",
        failure_category=None if result == "success" else "provider_unavailable",
    )


def test_secret_audit_projection_is_s05_ready_and_redacted(
    secret_metadata: SecretMetadata,
    secret_value: SecretValue,
) -> None:
    projection = project_secret_audit_event(_event(SecretAction.READ, secret_metadata))

    assert isinstance(projection, SecretAuditProjection)
    assert projection.tenant_id == "stanley"
    assert projection.actor_id == "agent-1"
    assert projection.action == "secret.read"
    assert projection.resource == "tenant/stanley/service/audit/purpose/hmac_signing/env/local"
    assert len(projection.request_payload_hash) == 64
    assert projection.response_status == "success"
    assert projection.trace_id == "trace-1"
    assert projection.risk_score == 0
    assert projection.metadata["event_type"] == "secret_lifecycle"
    assert projection.metadata["resource"]["provider"] == "memory"
    assert projection.metadata["resource"]["status"] == "active"
    assert contains_plaintext(projection.metadata, secret_value) is False


def test_secret_audit_projection_is_immutable_and_slotted(
    secret_metadata: SecretMetadata,
) -> None:
    projection = project_secret_audit_event(_event(SecretAction.READ, secret_metadata))

    assert not hasattr(projection, "__dict__")
    with pytest.raises(FrozenInstanceError):
        projection.tenant_id = "other"  # type: ignore[misc]


def test_secret_audit_projection_supports_nonzero_risk_score(
    secret_metadata: SecretMetadata,
) -> None:
    projection = project_secret_audit_event(
        _event(SecretAction.DELETE, secret_metadata),
        risk_score=80,
    )

    assert projection.risk_score == 80
    assert projection.action == "secret.delete"
    assert projection.metadata["action"] == "delete"


def test_secret_audit_projection_hash_changes_with_payload(
    secret_metadata: SecretMetadata,
) -> None:
    read_projection = project_secret_audit_event(_event(SecretAction.READ, secret_metadata))
    delete_projection = project_secret_audit_event(_event(SecretAction.DELETE, secret_metadata))

    assert read_projection.request_payload_hash != delete_projection.request_payload_hash


def test_secret_audit_hash_is_stable_across_payload_key_order() -> None:
    first = {
        "tenant_id": "stanley",
        "action": "read",
        "secret_value": "hidden",  # pragma: allowlist secret
    }
    second = {
        "secret_value": "hidden",  # pragma: allowlist secret
        "action": "read",
        "tenant_id": "stanley",
    }

    assert _hash_redacted_payload(first) == _hash_redacted_payload(second)


def test_in_memory_secret_audit_sink_records_projection(secret_metadata: SecretMetadata) -> None:
    sink = InMemorySecretAuditSink()
    projection = sink.record(_event(SecretAction.CREATE, secret_metadata))

    assert sink.records == [projection]
    assert projection.action == "secret.create"


def test_secret_observability_sink_emits_redacted_log_metric_trace_and_soc(
    secret_metadata: SecretMetadata,
    secret_value: SecretValue,
) -> None:
    fake_obs = FakeObservabilityProvider()
    audit_sink = InMemorySecretAuditSink()
    soc = InMemorySocNotificationPort()
    sink = SecretObservabilitySink(fake_obs, audit_sink=audit_sink, soc_port=soc)  # type: ignore[arg-type]

    projection = sink.emit(_event(SecretAction.DELETE, secret_metadata), duration_ms=12.5)

    assert audit_sink.records == [projection]
    assert fake_obs.metrics.counters == [
        (
            "secret_lifecycle_total",
            {
                "tenant_id": "stanley",
                "provider": "memory",
                "action": "delete",
                "result": "success",
                "status": "active",
            },
        )
    ]
    assert fake_obs.metrics.records == [
        (
            "secret_provider_duration_ms",
            12.5,
            {
                "tenant_id": "stanley",
                "provider": "memory",
                "action": "delete",
                "result": "success",
                "status": "active",
            },
        )
    ]
    assert fake_obs._logger.entries[0][0] == "warning"
    assert fake_obs._logger.entries[0][1] == "secret_lifecycle_event"
    assert fake_obs._logger.entries[0][2]["metadata"]["resource"]["provider"] == "memory"
    assert fake_obs.tracer.spans[0].name == "vault.delete"
    assert fake_obs.tracer.spans[0].attributes == {
        "tenant_id": "stanley",
        "provider": "memory",
        "action": "delete",
        "result": "success",
        "status": "active",
    }
    assert fake_obs.tracer.spans[0].events[0][0] == "secret_lifecycle_event"
    assert soc.alerts[0].source == "vault"
    assert soc.alerts[0].severity == "warning"
    assert soc.alerts[0].title == "Secret delete success"
    assert soc.alerts[0].decision_id == projection.request_payload_hash[:16]
    assert soc.alerts[0].trace_id == "trace-1"
    assert soc.alerts[0].attributes["resource"] == projection.resource
    assert soc.alerts[0].attributes == {
        "action": "secret.delete",
        "resource": projection.resource,
        "provider": "memory",
        "status": "active",
    }
    assert contains_plaintext(fake_obs._logger.entries, secret_value) is False
    assert contains_plaintext(fake_obs.metrics.counters, secret_value) is False
    assert contains_plaintext(fake_obs.tracer.spans, secret_value) is False
    assert contains_plaintext(soc.alerts, secret_value) is False


def test_secret_observability_sink_sends_failed_read_to_soc(
    secret_metadata: SecretMetadata,
) -> None:
    fake_obs = FakeObservabilityProvider()
    soc = InMemorySocNotificationPort()
    sink = SecretObservabilitySink(fake_obs, soc_port=soc)  # type: ignore[arg-type]

    projection = sink.emit(_event(SecretAction.READ, secret_metadata, result="failed"))

    assert projection.response_status == "failed"
    assert fake_obs._logger.entries[0][0] == "warning"
    assert soc.alerts[0].severity == "critical"
    assert soc.alerts[0].title == "Secret read failed"
    assert soc.alerts[0].attributes["action"] == "secret.read"


def test_secret_observability_sink_escalates_partial_failure_signals(
    secret_metadata: SecretMetadata,
) -> None:
    fake_obs = FakeObservabilityProvider()
    soc = InMemorySocNotificationPort()
    sink = SecretObservabilitySink(fake_obs, soc_port=soc)  # type: ignore[arg-type]
    failed_without_category = SecretAuditEvent(
        action=SecretAction.READ,
        metadata=secret_metadata,
        actor_id="agent-1",
        trace_id="trace-1",
        result="failed",
        reason="provider failed without category",
    )
    success_with_category = SecretAuditEvent(
        action=SecretAction.READ,
        metadata=secret_metadata,
        actor_id="agent-1",
        trace_id="trace-2",
        result="success",
        reason="provider reported category",
        failure_category="provider_warning",
    )

    sink.emit(failed_without_category)
    sink.emit(success_with_category)

    assert [alert.severity for alert in soc.alerts] == ["critical", "critical"]


def test_secret_observability_sink_info_event_does_not_send_soc_or_latency(
    secret_metadata: SecretMetadata,
) -> None:
    fake_obs = FakeObservabilityProvider()
    soc = InMemorySocNotificationPort()
    sink = SecretObservabilitySink(fake_obs, soc_port=soc)  # type: ignore[arg-type]

    projection = sink.emit(_event(SecretAction.READ, secret_metadata))

    assert projection.action == "secret.read"
    assert fake_obs._logger.entries[0][0] == "info"
    assert fake_obs.tracer.spans[0].name == "vault.read"
    assert fake_obs.tracer.spans[0].events[0][1]["action"] == "read"
    assert fake_obs.metrics.records == []
    assert soc.alerts == []


def test_secret_observability_sink_records_sub_millisecond_latency(
    secret_metadata: SecretMetadata,
) -> None:
    fake_obs = FakeObservabilityProvider()
    sink = SecretObservabilitySink(fake_obs)  # type: ignore[arg-type]

    sink.emit(_event(SecretAction.READ, secret_metadata), duration_ms=0.5)

    assert fake_obs.metrics.records == [
        (
            "secret_provider_duration_ms",
            0.5,
            {
                "tenant_id": "stanley",
                "provider": "memory",
                "action": "read",
                "result": "success",
                "status": "active",
            },
        )
    ]


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
def test_secret_audit_projection_rejects_empty_required_fields(field_name: str) -> None:
    kwargs = {
        "tenant_id": "stanley",
        "actor_id": "agent-1",
        "action": "secret.read",
        "resource": "tenant/stanley/service/audit/purpose/hmac_signing/env/local",
        "request_payload_hash": "a" * 64,
        "response_status": "success",
        "trace_id": "trace-1",
    }
    kwargs[field_name] = ""
    with pytest.raises(ValueError, match=field_name):
        SecretAuditProjection(**kwargs)


@pytest.mark.parametrize("risk_score", [-1, 101])
def test_secret_audit_projection_rejects_invalid_risk_score(risk_score: int) -> None:
    with pytest.raises(ValueError, match="risk_score"):
        SecretAuditProjection(
            tenant_id="stanley",
            actor_id="agent-1",
            action="secret.read",
            resource="tenant/stanley/service/audit/purpose/hmac_signing/env/local",
            request_payload_hash="a" * 64,
            response_status="success",
            trace_id="trace-1",
            risk_score=risk_score,
        )


def test_secret_audit_projection_rejects_bad_hash() -> None:
    with pytest.raises(ValueError, match="SHA256"):
        SecretAuditProjection(
            tenant_id="stanley",
            actor_id="agent-1",
            action="secret.read",
            resource="tenant/stanley/service/audit/purpose/hmac_signing/env/local",
            request_payload_hash="bad",
            response_status="success",
            trace_id="trace-1",
        )
