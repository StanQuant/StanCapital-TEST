"""L10 ATR 領域型別。

設計紀律:
- frozen=True + slots=True，避免執行中被改寫
- tenant_id 必填無預設值
- 分數、風險等級、回應動作在建構期驗證
- L10 型別不放進 L4 Core，避免污染核心交易型別
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from ulid import ULID


def _new_id() -> str:
    return str(ULID())


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ThreatCode(StrEnum):
    """ATR 八類威脅代碼。"""

    T001 = "T001"
    T002 = "T002"
    T003 = "T003"
    T004 = "T004"
    T005 = "T005"
    T006 = "T006"
    T007 = "T007"
    T008 = "T008"


class ThreatLevel(StrEnum):
    """分數對應的五級風險。"""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AtrAction(StrEnum):
    """ATR 回應動作。"""

    ALLOW = "allow"
    LOG = "log"
    ENCRYPT = "encrypt"
    SUSPEND = "suspend"
    TERMINATE = "terminate"


def level_for_score(score: int) -> ThreatLevel:
    """把 0-100 分映射到 Architecture §6.3 五級。"""
    if not 0 <= score <= 100:
        raise ValueError(f"score 必須在 0-100 之間: {score}")
    if score <= 20:
        return ThreatLevel.SAFE
    if score <= 40:
        return ThreatLevel.LOW
    if score <= 60:
        return ThreatLevel.MEDIUM
    if score <= 80:
        return ThreatLevel.HIGH
    return ThreatLevel.CRITICAL


@dataclass(frozen=True, slots=True)
class AgentIdentity:
    """Agent 身分與上下文風險。risk_level 依 Charter Agent 表採 1-10。"""

    tenant_id: str
    agent_id: str
    risk_level: int

    def __post_init__(self) -> None:
        if not self.tenant_id:
            raise ValueError("tenant_id 不可為空")
        if not self.agent_id:
            raise ValueError("agent_id 不可為空")
        if not 1 <= self.risk_level <= 10:
            raise ValueError(f"risk_level 必須在 1-10 之間: {self.risk_level}")


MetadataValue = str | int | float | bool | None


@dataclass(frozen=True, slots=True)
class AgentBehavior:
    """一次 Agent 行為，作為 ATR 評分輸入。"""

    agent: AgentIdentity
    tool_name: str
    action: str
    target: str
    payload_summary: str
    external_destination: str | None = None
    metadata: dict[str, MetadataValue] = field(default_factory=dict)
    trace_id: str = field(default_factory=_new_id)
    target_event_id: str | None = None

    def __post_init__(self) -> None:
        if not self.tool_name:
            raise ValueError("tool_name 不可為空")
        if not self.action:
            raise ValueError("action 不可為空")
        if not self.trace_id:
            raise ValueError("trace_id 不可為空")
        for key, value in self.metadata.items():
            if not key:
                raise ValueError("metadata key 不可為空")
            if not isinstance(value, str | int | float | bool | None):
                raise ValueError(f"metadata 值型別不支援: {key}={value!r}")


@dataclass(frozen=True, slots=True)
class AtrRuleDefinition:
    """Rulebook 裡的一條規則設定。matcher 本體仍在 rules.py。"""

    code: ThreatCode
    category: str
    weight: int
    risk_category: str
    description: str
    enabled: bool = True
    version: int = 1

    def __post_init__(self) -> None:
        if not self.category:
            raise ValueError("category 不可為空")
        if not 0 <= self.weight <= 100:
            raise ValueError(f"weight 必須在 0-100 之間: {self.weight}")
        if not self.risk_category:
            raise ValueError("risk_category 不可為空")
        if not self.description:
            raise ValueError("description 不可為空")
        if self.version < 1:
            raise ValueError(f"version 必須 >= 1: {self.version}")


@dataclass(frozen=True, slots=True)
class TriggeredRule:
    """一次命中的威脅規則。"""

    code: ThreatCode
    category: str
    weight: int
    risk_category: str


@dataclass(frozen=True, slots=True)
class ThreatScore:
    """ATR 評分結果。"""

    value: int
    level: ThreatLevel
    triggered_rules: tuple[TriggeredRule, ...]
    context_multiplier: float
    agent_id: str
    tenant_id: str
    risk_category: str
    trace_id: str
    timestamp: datetime = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        if not 0 <= self.value <= 100:
            raise ValueError(f"value 必須在 0-100 之間: {self.value}")
        if self.level is not level_for_score(self.value):
            raise ValueError(f"level 與 value 不一致: {self.level} / {self.value}")
        if self.context_multiplier < 1.0:
            raise ValueError(f"context_multiplier 必須 >= 1.0: {self.context_multiplier}")
        if not self.agent_id:
            raise ValueError("agent_id 不可為空")
        if not self.tenant_id:
            raise ValueError("tenant_id 不可為空")
        if not self.risk_category:
            raise ValueError("risk_category 不可為空")
        if not self.trace_id:
            raise ValueError("trace_id 不可為空")
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp 必須是 tz-aware 時間")

    @property
    def triggered_codes(self) -> tuple[ThreatCode, ...]:
        """測試與上層常用的精簡代碼清單。"""
        return tuple(rule.code for rule in self.triggered_rules)


@dataclass(frozen=True, slots=True)
class SuppressionRule:
    """受控抑制規則(D6)。

    抑制規則只能最多降低一級，不能把 high / critical 直接洗成 safe。
    未來 S09/S26 可把此模型接到管理介面與租戶覆寫。
    """

    suppression_id: str
    tenant_id: str
    threat_code: ThreatCode
    reason: str
    approved_by: str
    max_level_reduction: int = 1

    def __post_init__(self) -> None:
        if not self.suppression_id:
            raise ValueError("suppression_id 不可為空")
        if not self.tenant_id:
            raise ValueError("tenant_id 不可為空")
        if not self.reason:
            raise ValueError("reason 不可為空")
        if not self.approved_by:
            raise ValueError("approved_by 不可為空")
        if not 0 <= self.max_level_reduction <= 1:
            raise ValueError(f"max_level_reduction 必須為 0 或 1: {self.max_level_reduction}")


@dataclass(frozen=True, slots=True)
class AtrDecision:
    """ATR 最終決策，供 gateway / audit / notification 使用。"""

    score: ThreatScore
    action: AtrAction
    audit_required: bool
    encrypt_trace: bool
    suspend_agent: bool
    terminate_session: bool
    notify_security_officer: bool
    requires_human_approval: bool
    suppression_applied: tuple[SuppressionRule, ...] = ()
    decision_id: str = field(default_factory=_new_id)

    def __post_init__(self) -> None:
        if not self.decision_id:
            raise ValueError("decision_id 不可為空")
        if self.action is AtrAction.ALLOW:
            if self.encrypt_trace or self.suspend_agent or self.terminate_session:
                raise ValueError("ALLOW 不可同時要求加密/暫停/終止")
        if self.action is AtrAction.SUSPEND and not self.suspend_agent:
            raise ValueError("SUSPEND 決策必須 suspend_agent=True")
        if self.action is AtrAction.TERMINATE and not self.terminate_session:
            raise ValueError("TERMINATE 決策必須 terminate_session=True")
        if self.terminate_session and not self.requires_human_approval:
            raise ValueError("終止 Session 必須要求人類審批")

    def to_audit_metadata(self) -> dict[str, Any]:
        """給 S05/S22 使用的稽核 metadata。"""
        return {
            "decision_id": self.decision_id,
            "risk_score": self.score.value,
            "risk_category": self.score.risk_category,
            "threat_level": self.score.level.value,
            "atr_action": self.action.value,
            "triggered_rules": [code.value for code in self.score.triggered_codes],
            "trace_id": self.score.trace_id,
        }
