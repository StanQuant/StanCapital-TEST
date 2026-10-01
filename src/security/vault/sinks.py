"""S10 secret lifecycle sinks。

本檔只定義 port 與 S09 observability adapter；不直接寫 S05 audit repository，
避免 S10 反向耦合治理層與不可變證據鏈。
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, cast

from src.observability.ports import NoopSocNotificationPort, SocAlert, SocNotificationPort
from src.observability.provider import ObservabilityProvider
from src.security.vault.audit import SecretAuditEvent
from src.security.vault.redaction import redact_secret_payload
from src.security.vault.types import SecretAction


@dataclass(frozen=True, slots=True)
class SecretAuditProjection:
    """給 S05 上層編排寫入不可變 audit log 的 redacted 投影。"""

    tenant_id: str
    actor_id: str
    action: str
    resource: str
    request_payload_hash: str
    response_status: str
    trace_id: str
    risk_score: int = 0
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in (
            "tenant_id",
            "actor_id",
            "action",
            "resource",
            "request_payload_hash",
            "response_status",
            "trace_id",
        ):
            if not getattr(self, field_name):
                raise ValueError(f"{field_name} 不可為空")
        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score 必須在 0-100 之間")
        if len(self.request_payload_hash) != 64:
            raise ValueError("request_payload_hash 必須是 SHA256 hex")


class SecretAuditSink(Protocol):
    """S10 → S05 的 audit port。"""

    def record(self, event: SecretAuditEvent) -> SecretAuditProjection:
        """記錄 secret lifecycle event，回傳 redacted audit projection。"""


class NoopSecretAuditSink:
    """本機預設：不寫外部 audit，但仍產生 redacted projection。"""

    def record(self, event: SecretAuditEvent) -> SecretAuditProjection:
        return project_secret_audit_event(event)


class InMemorySecretAuditSink:
    """測試 / demo 用 audit sink。"""

    def __init__(self) -> None:
        self.records: list[SecretAuditProjection] = []

    def record(self, event: SecretAuditEvent) -> SecretAuditProjection:
        projection = project_secret_audit_event(event)
        self.records.append(projection)
        return projection


def project_secret_audit_event(
    event: SecretAuditEvent, *, risk_score: int = 0
) -> SecretAuditProjection:
    """把 S10 event 轉成 S05 可寫入的 redacted 投影。"""

    payload = event.to_metadata()
    resource = cast(dict[str, Any], payload["resource"])
    name = cast(dict[str, str], resource["name"])
    return SecretAuditProjection(
        tenant_id=name["tenant_id"],
        actor_id=event.actor_id,
        action=f"secret.{event.action.value}",
        resource=name["path"],
        request_payload_hash=_hash_redacted_payload(payload),
        response_status=event.result,
        trace_id=event.trace_id,
        risk_score=risk_score,
        metadata=payload,
    )


class SecretObservabilitySink:
    """S10 → S09：redacted log + metric + trace event + SOC port。"""

    __slots__ = ("_audit_sink", "_obs", "_soc")

    def __init__(
        self,
        observability: ObservabilityProvider | None = None,
        *,
        audit_sink: SecretAuditSink | None = None,
        soc_port: SocNotificationPort | None = None,
    ) -> None:
        self._obs = observability or ObservabilityProvider.noop()
        self._audit_sink = audit_sink or NoopSecretAuditSink()
        self._soc = soc_port or NoopSocNotificationPort()

    def emit(self, event: SecretAuditEvent, *, duration_ms: float = 0.0) -> SecretAuditProjection:
        """發送 S10 lifecycle event；所有輸出均先 redacted。"""

        projection = self._audit_sink.record(event)
        payload = redact_secret_payload(dict(projection.metadata))
        labels = _metric_labels(event)
        self._obs.metrics.increment("secret_lifecycle_total", attributes=labels)
        if duration_ms > 0:
            self._obs.metrics.record("secret_provider_duration_ms", duration_ms, attributes=labels)
        log = self._obs.logger(__name__)
        severity = _severity(event)
        log_method = getattr(log, "warning" if severity != "info" else "info")
        log_method("secret_lifecycle_event", metadata=payload)
        with self._obs.tracer.span(
            f"vault.{event.action.value}",
            attributes=labels,
            tenant_id=event.metadata.name.tenant_id,
        ) as span:
            self._obs.tracer.add_event(span, "secret_lifecycle_event", payload)
        if severity != "info":
            self._soc.send(_soc_alert(event, severity, projection))
        return projection


def _hash_redacted_payload(payload: Mapping[str, Any]) -> str:
    clean = redact_secret_payload(payload)
    encoded = json.dumps(clean, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _metric_labels(event: SecretAuditEvent) -> dict[str, str]:
    return {
        "tenant_id": event.metadata.name.tenant_id,
        "provider": event.metadata.provider.value,
        "action": event.action.value,
        "result": event.result,
        "status": event.metadata.status.value,
    }


def _severity(event: SecretAuditEvent) -> str:
    if event.result != "success" or event.failure_category:
        return "critical"
    if event.action in {SecretAction.DELETE, SecretAction.ROTATE}:
        return "warning"
    return "info"


def _soc_alert(
    event: SecretAuditEvent,
    severity: str,
    projection: SecretAuditProjection,
) -> SocAlert:
    return SocAlert(
        tenant_id=projection.tenant_id,
        source="vault",
        severity=severity,
        title=f"Secret {event.action.value} {event.result}",
        decision_id=projection.request_payload_hash[:16],
        trace_id=event.trace_id,
        timestamp=event.timestamp.isoformat(),
        attributes={
            "action": projection.action,
            "resource": projection.resource,
            "provider": event.metadata.provider.value,
            "status": event.metadata.status.value,
        },
    )
