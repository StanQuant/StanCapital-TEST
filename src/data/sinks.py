"""S11 → S05 / S09 lifecycle ports 與 adapters。

依賴方向採 Hexagonal Architecture：
- `MarketDataLifecycleSink` 是 L2 data 擁有的 driven port。
- `MarketDataTelemetrySink` 是 S09 observability adapter，輸出 log / metric / trace。
- `MarketDataAuditSink` 只接收 redacted domain event，產生 S05 可寫入的 projection；
  不直接 import S05 repository，避免 L2 反向依賴 L11。

任何 payload 都只含 provider / tenant / license / manifest hash / 計數與時間範圍，
不接受 credential、raw payload 或任意 metadata，從型別邊界防止秘密進稽核與遙測。
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol

from src.core.validation import ensure_non_empty, ensure_non_negative_int, ensure_utc
from src.observability.provider import ObservabilityProvider


class MarketDataLifecycleAction(StrEnum):
    """S11 生命週期事件；capture / replay 動作必須同時產生 S05 projection。"""

    CAPTURE_START = "capture_start"
    CAPTURE_END = "capture_end"
    CAPTURE_DELETE = "capture_delete"
    REPLAY_START = "replay_start"
    REPLAY_END = "replay_end"
    PROVIDER_CONNECT = "provider_connect"
    PROVIDER_DISCONNECT = "provider_disconnect"
    PROVIDER_RECONNECT = "provider_reconnect"
    CIRCUIT_OPEN = "circuit_open"
    DECODE = "decode"
    QUALITY_FLAG = "quality_flag"

    @property
    def requires_audit(self) -> bool:
        """規格 §14.3：capture / replay 動作必須產生 S05 audit metadata。"""

        return self in {
            MarketDataLifecycleAction.CAPTURE_START,
            MarketDataLifecycleAction.CAPTURE_END,
            MarketDataLifecycleAction.CAPTURE_DELETE,
            MarketDataLifecycleAction.REPLAY_START,
            MarketDataLifecycleAction.REPLAY_END,
        }


@dataclass(frozen=True, slots=True)
class MarketDataLifecycleEvent:
    """不含 secret / raw payload 的 S11 稽核與遙測事件。"""

    action: MarketDataLifecycleAction
    provider_id: str
    tenant_id: str
    actor_id: str
    trace_id: str
    result: str
    license_tag: str | None = None
    manifest_sha256: str | None = None
    record_count: int | None = None
    started_at: datetime | None = None
    ended_at: datetime | None = None
    duration_ms: float = 0.0
    reconnect_count: int = 0
    sequence_gap_count: int = 0
    circuit_open: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.action, MarketDataLifecycleAction):
            raise ValueError(
                f"action 必須是 MarketDataLifecycleAction，不可為 {type(self.action).__name__}"
            )
        for field_name in ("provider_id", "tenant_id", "actor_id", "trace_id", "result"):
            ensure_non_empty(field_name, getattr(self, field_name))
        if self.license_tag is not None:
            ensure_non_empty("license_tag", self.license_tag)
        if self.manifest_sha256 is not None and (
            len(self.manifest_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.manifest_sha256)
        ):
            raise ValueError("manifest_sha256 必須是 64 碼小寫十六進位 SHA-256")
        if self.record_count is not None:
            ensure_non_negative_int("record_count", self.record_count)
        ensure_non_negative_int("reconnect_count", self.reconnect_count)
        ensure_non_negative_int("sequence_gap_count", self.sequence_gap_count)
        if not isinstance(self.duration_ms, (int, float)) or isinstance(self.duration_ms, bool):
            raise ValueError("duration_ms 必須是有限非負數")
        if not math.isfinite(self.duration_ms) or self.duration_ms < 0:
            raise ValueError("duration_ms 必須是有限非負數")
        if self.started_at is not None:
            ensure_utc("started_at", self.started_at)
        if self.ended_at is not None:
            ensure_utc("ended_at", self.ended_at)
        if (
            self.started_at is not None
            and self.ended_at is not None
            and self.started_at > self.ended_at
        ):
            raise ValueError("started_at 不可晚於 ended_at")

    def to_metadata(self) -> dict[str, Any]:
        """輸出固定 allowlist metadata；型別上沒有 credential / raw payload 欄位。"""

        return {
            "event_type": "market_data_lifecycle",
            "action": self.action.value,
            "provider_id": self.provider_id,
            "tenant_id": self.tenant_id,
            "actor_id": self.actor_id,
            "trace_id": self.trace_id,
            "result": self.result,
            "license_tag": self.license_tag,
            "manifest_sha256": self.manifest_sha256,
            "record_count": self.record_count,
            "started_at": None if self.started_at is None else self.started_at.isoformat(),
            "ended_at": None if self.ended_at is None else self.ended_at.isoformat(),
            "duration_ms": float(self.duration_ms),
            "reconnect_count": self.reconnect_count,
            "sequence_gap_count": self.sequence_gap_count,
            "circuit_open": self.circuit_open,
        }


@dataclass(frozen=True, slots=True)
class MarketDataAuditProjection:
    """與 S10 projection 同形，可由上層 composition root 轉入 S05 AuditRecordInput。"""

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
            ensure_non_empty(field_name, getattr(self, field_name))
        if len(self.request_payload_hash) != 64 or any(
            character not in "0123456789abcdef" for character in self.request_payload_hash
        ):
            raise ValueError("request_payload_hash 必須是 64 碼小寫十六進位 SHA-256")
        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score 必須在 0-100 之間")


class MarketDataAuditSink(Protocol):
    """S11 → S05 audit port。"""

    def record(self, event: MarketDataLifecycleEvent) -> MarketDataAuditProjection:
        """記錄一筆 redacted lifecycle event。"""


class NoopMarketDataAuditSink:
    """預設不寫外部儲存，但仍可產生可驗證 projection。"""

    def record(self, event: MarketDataLifecycleEvent) -> MarketDataAuditProjection:
        return project_market_data_audit_event(event)


class InMemoryMarketDataAuditSink:
    """測試 / demo adapter。"""

    def __init__(self) -> None:
        self.records: list[MarketDataAuditProjection] = []

    def record(self, event: MarketDataLifecycleEvent) -> MarketDataAuditProjection:
        projection = project_market_data_audit_event(event)
        self.records.append(projection)
        return projection


def project_market_data_audit_event(
    event: MarketDataLifecycleEvent, *, risk_score: int = 0
) -> MarketDataAuditProjection:
    """把 S11 lifecycle event 轉成 S05-ready projection。"""

    payload = event.to_metadata()
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return MarketDataAuditProjection(
        tenant_id=event.tenant_id,
        actor_id=event.actor_id,
        action=f"market_data.{event.action.value}",
        resource=f"market-data/{event.provider_id}",
        request_payload_hash=hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
        response_status=event.result,
        trace_id=event.trace_id,
        risk_score=risk_score,
        metadata=payload,
    )


class MarketDataLifecycleSink(Protocol):
    """capture / replay / provider 呼叫的統一 port。"""

    def emit(self, event: MarketDataLifecycleEvent) -> MarketDataAuditProjection | None:
        """輸出事件；audit-required 動作回傳 S05 projection。"""


class NoopMarketDataLifecycleSink:
    """預設 adapter：無外部 I/O；audit-required 動作仍產生 projection。"""

    def emit(self, event: MarketDataLifecycleEvent) -> MarketDataAuditProjection | None:
        if event.action.requires_audit:
            return project_market_data_audit_event(event)
        return None


class InMemoryMarketDataLifecycleSink:
    """測試 / demo adapter：同時保留 lifecycle event 與 S05-ready projection。"""

    def __init__(self) -> None:
        self.events: list[MarketDataLifecycleEvent] = []
        self.audit_records: list[MarketDataAuditProjection] = []

    def emit(self, event: MarketDataLifecycleEvent) -> MarketDataAuditProjection | None:
        self.events.append(event)
        if not event.action.requires_audit:
            return None
        projection = project_market_data_audit_event(event)
        self.audit_records.append(projection)
        return projection


class MarketDataTelemetrySink:
    """S11 → S09 log / metric / trace，並把規定動作送往 S05 audit port。"""

    def __init__(
        self,
        observability: ObservabilityProvider | None = None,
        *,
        audit_sink: MarketDataAuditSink | None = None,
    ) -> None:
        self._obs = observability or ObservabilityProvider.noop()
        self._audit_sink = audit_sink or NoopMarketDataAuditSink()

    def emit(self, event: MarketDataLifecycleEvent) -> MarketDataAuditProjection | None:
        projection = self._audit_sink.record(event) if event.action.requires_audit else None
        labels = {
            "tenant_id": event.tenant_id,
            "provider": event.provider_id,
            "action": event.action.value,
            "result": event.result,
        }
        self._obs.metrics.increment("market_data_lifecycle_total", attributes=labels)
        if event.action is MarketDataLifecycleAction.DECODE:
            self._obs.metrics.record(
                "market_data_decode_latency_ms", event.duration_ms, attributes=labels
            )
        elif event.duration_ms > 0:
            self._obs.metrics.record(
                "market_data_operation_duration_ms", event.duration_ms, attributes=labels
            )
        if event.action is MarketDataLifecycleAction.PROVIDER_RECONNECT:
            self._obs.metrics.increment("market_data_reconnect_total", attributes=labels)
        if event.sequence_gap_count > 0:
            self._obs.metrics.increment(
                "market_data_sequence_gap_total",
                amount=event.sequence_gap_count,
                attributes=labels,
            )
        payload = event.to_metadata()
        log = self._obs.logger(__name__)
        log_method = (
            log.info if event.result == "success" and not event.circuit_open else log.warning
        )
        log_method("market_data_lifecycle_event", metadata=payload)
        with self._obs.tracer.span(
            f"market_data.{event.action.value}",
            attributes=labels,
            tenant_id=event.tenant_id,
        ) as span:
            self._obs.tracer.add_event(span, "market_data_lifecycle_event", payload)
        return projection
