"""S07 ATR / S08 Policy 安全事件接線（D5）。

把安全事件變成可觀測訊號：log + metric + trace event + SOC port。
- 結構化 duck typing：不 import security，observability 保持零 app 依賴（最底層）。
- fail-closed for telemetry：sink 內部 emit 失敗時自己吞錯 + 記 CRITICAL，
  絕不把例外往上丟害死決策路徑（遙測不得反害業務）。
"""

from __future__ import annotations

import logging as _stdlib_logging
from collections.abc import Mapping
from typing import Any, Protocol

from opentelemetry import trace

from src.observability.ports import (
    NoopSocNotificationPort,
    SocAlert,
    SocNotificationPort,
)
from src.observability.provider import ObservabilityProvider
from src.observability.redaction import safe_attributes

_logger = _stdlib_logging.getLogger(__name__)

# ATR 風險級別 → SOC severity / log 方法名。
_LEVEL_SEVERITY: dict[str, str] = {
    "low": "info",
    "medium": "warning",
    "high": "critical",
    "critical": "critical",
}


class SecurityNotificationLike(Protocol):
    """S07 SecurityNotification 的結構化介面（duck typing，不直接 import security）。"""

    tenant_id: str
    agent_id: str
    decision_id: str
    score: int
    level: str
    action: str
    triggered_rules: tuple[str, ...]
    target: str
    trace_id: str
    timestamp: str


def _emit_trace_event(name: str, attributes: Mapping[str, Any]) -> None:
    """掛 trace event 到當前 span（無 span 時自動 no-op）。"""
    trace.get_current_span().add_event(name, attributes=safe_attributes(attributes))


class ObservabilitySecurityOfficerSink:
    """S07 SecurityOfficerSink 實作：log + metric + trace event + SOC port。"""

    __slots__ = ("_obs", "_soc")

    def __init__(
        self,
        provider: ObservabilityProvider,
        soc_port: SocNotificationPort | None = None,
    ) -> None:
        self._obs = provider
        self._soc = soc_port or NoopSocNotificationPort()

    def notify(self, notification: SecurityNotificationLike) -> None:
        try:
            self._obs.metrics.record_atr_decision(
                notification.level, notification.action, notification.tenant_id
            )
            severity = _LEVEL_SEVERITY.get(notification.level, "warning")
            fields = safe_attributes(
                {
                    "tenant_id": notification.tenant_id,
                    "agent_id": notification.agent_id,
                    "decision_id": notification.decision_id,
                    "score": notification.score,
                    "threat_level": notification.level,
                    "action": notification.action,
                    "target": notification.target,
                    "triggered_rules": list(notification.triggered_rules),
                    "trace_id": notification.trace_id,
                }
            )
            getattr(self._obs.logger(__name__), severity)("atr_security_event", **fields)
            _emit_trace_event(
                "atr_decision",
                {
                    "decision_id": notification.decision_id,
                    "level": notification.level,
                    "action": notification.action,
                },
            )
            self._soc.send(
                SocAlert(
                    tenant_id=notification.tenant_id,
                    source="atr",
                    severity=severity,
                    title=f"ATR {notification.level} · {notification.action}",
                    decision_id=notification.decision_id,
                    trace_id=notification.trace_id,
                    timestamp=notification.timestamp,
                    attributes=safe_attributes(
                        {
                            "agent_id": notification.agent_id,
                            "target": notification.target,
                        }
                    ),
                )
            )
        except Exception:  # 遙測不得反害業務
            _logger.critical("ObservabilitySecurityOfficerSink emit 失敗", exc_info=True)


class ObservabilityAuditMetadataSink:
    """S08 AuditMetadataSink 實作：log + metric + trace event。

    注意：這是維運觀測，不是 S05 不可變證據鏈（兩平面分離，D8）。
    """

    __slots__ = ("_obs",)

    def __init__(self, provider: ObservabilityProvider) -> None:
        self._obs = provider

    def record(self, metadata: Mapping[str, Any]) -> None:
        try:
            effect = str(metadata.get("effect", "unknown"))
            tenant_id = metadata.get("tenant_id")
            log = self._obs.logger(__name__)
            safe_meta = safe_attributes(dict(metadata))
            if tenant_id:
                # 多租戶不變量：有 tenant_id 才發 per-tenant 指標，不建立 unknown 租戶桶。
                self._obs.metrics.record_policy_decision(effect, str(tenant_id))
                log.info("policy_audit_metadata", metadata=safe_meta)
            else:
                # 缺 tenant_id 的安全事件本身即異常：記 WARNING，但不污染指標基數。
                log.warning("policy_audit_metadata_missing_tenant", metadata=safe_meta)
            _emit_trace_event(
                "policy_decision",
                {"decision_id": str(metadata.get("decision_id", "")), "effect": effect},
            )
        except Exception:  # 遙測不得反害業務
            _logger.critical("ObservabilityAuditMetadataSink emit 失敗", exc_info=True)
