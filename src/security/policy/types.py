"""L10 Policy Engine 領域型別。"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from ulid import ULID

from src.security.policy.expressions import PolicyExpression

type MetadataValue = str | int | float | bool | None


def _new_id() -> str:
    return str(ULID())


def _utc_now() -> datetime:
    return datetime.now(UTC)


class PolicyEffect(StrEnum):
    """Policy Engine 三態決策。"""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class PolicyScopeLevel(StrEnum):
    """政策層級。越細層只能加嚴，不能放寬上層 deny。"""

    TENANT = "tenant"
    DEPARTMENT = "department"
    PROJECT = "project"
    AGENT = "agent"


@dataclass(frozen=True, slots=True)
class PolicyScope:
    """一組政策的適用範圍。tenant_id 必填，不給預設。"""

    tenant_id: str
    level: PolicyScopeLevel
    department: str | None = None
    project: str | None = None
    agent_id: str | None = None

    def __post_init__(self) -> None:
        if not self.tenant_id:
            raise ValueError("tenant_id 不可為空")
        if self.level is PolicyScopeLevel.DEPARTMENT and not self.department:
            raise ValueError("department scope 必須提供 department")
        if self.level is PolicyScopeLevel.PROJECT and not self.project:
            raise ValueError("project scope 必須提供 project")
        if self.level is PolicyScopeLevel.AGENT and not self.agent_id:
            raise ValueError("agent scope 必須提供 agent_id")

    def matches(self, request: PolicyRequest) -> bool:
        """政策 scope 是否適用於這次請求。"""
        if self.tenant_id != request.tenant_id:
            return False
        if self.level is PolicyScopeLevel.TENANT:
            return True
        if self.level is PolicyScopeLevel.DEPARTMENT:
            return self.department == request.department
        if self.level is PolicyScopeLevel.PROJECT:
            return self.project == request.project
        return self.agent_id == request.agent_id


@dataclass(frozen=True, slots=True)
class ApprovalRequirement:
    """政策要求審批時的最小商業化 metadata。"""

    approver_role: str
    timeout_seconds: int
    escalation_role: str | None = None

    def __post_init__(self) -> None:
        if not self.approver_role:
            raise ValueError("approver_role 不可為空")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds 必須大於 0")
        if self.escalation_role == "":
            raise ValueError("escalation_role 不可為空字串")


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """一條 policy rule。all_expressions 與 any_expressions 至少一組非空。"""

    rule_id: str
    effect: PolicyEffect
    description: str
    all_expressions: tuple[PolicyExpression, ...] = ()
    any_expressions: tuple[PolicyExpression, ...] = ()
    approval: ApprovalRequirement | None = None
    limits: Mapping[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.rule_id:
            raise ValueError("rule_id 不可為空")
        if not self.description:
            raise ValueError("description 不可為空")
        if not self.all_expressions and not self.any_expressions:
            raise ValueError("policy rule 至少需要 all 或 any expression")
        if self.effect is PolicyEffect.REQUIRE_APPROVAL and self.approval is None:
            raise ValueError("require_approval rule 必須提供 approval 設定")
        if self.effect is not PolicyEffect.REQUIRE_APPROVAL and self.approval is not None:
            raise ValueError("只有 require_approval rule 可提供 approval 設定")
        for key, value in self.limits.items():
            if not key:
                raise ValueError("limit key 不可為空")
            if value < 0:
                raise ValueError(f"limit value 不可小於 0: {key}")
        object.__setattr__(self, "limits", MappingProxyType(dict(self.limits)))


@dataclass(frozen=True, slots=True)
class PolicySet:
    """一份已解析且可版本化的 policy set。"""

    schema_version: int
    policy_set_id: str
    version: str
    scope: PolicyScope
    rules: tuple[PolicyRule, ...]
    content_hash: str

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError(f"schema_version 目前只支援 1: {self.schema_version}")
        if not self.policy_set_id:
            raise ValueError("policy_set_id 不可為空")
        if not self.version:
            raise ValueError("version 不可為空")
        if not self.rules:
            raise ValueError("policy set 至少需要一條 rule")
        if len({rule.rule_id for rule in self.rules}) != len(self.rules):
            raise ValueError("policy set 內 rule_id 不可重複")
        if not self.content_hash:
            raise ValueError("content_hash 不可為空")


@dataclass(frozen=True, slots=True)
class PolicyRequest:
    """一次 Policy 評估輸入。tenant_id 必填，不給預設。"""

    tenant_id: str
    subject_id: str
    subject_type: str
    department: str
    project: str
    action: str
    resource_type: str
    resource_id: str
    sensitivity_level: int
    risk_category: str
    trace_id: str
    agent_id: str | None = None
    atr_risk_score: int | None = None
    atr_risk_category: str | None = None

    def __post_init__(self) -> None:
        for field_name in (
            "tenant_id",
            "subject_id",
            "subject_type",
            "department",
            "project",
            "action",
            "resource_type",
            "resource_id",
            "risk_category",
            "trace_id",
        ):
            if not getattr(self, field_name):
                raise ValueError(f"{field_name} 不可為空")
        if not 1 <= self.sensitivity_level <= 5:
            raise ValueError(f"sensitivity_level 必須在 1-5 之間: {self.sensitivity_level}")
        if self.atr_risk_score is not None and not 0 <= self.atr_risk_score <= 100:
            raise ValueError(f"atr_risk_score 必須在 0-100 之間: {self.atr_risk_score}")
        if self.atr_risk_category == "":
            raise ValueError("atr_risk_category 不可為空字串")

    def with_atr(self, *, risk_score: int, risk_category: str) -> PolicyRequest:
        """由 guard 編排層把 ATR 結果餵入，不讓 evaluator 直接依賴 AtrEngine。"""
        return PolicyRequest(
            tenant_id=self.tenant_id,
            subject_id=self.subject_id,
            subject_type=self.subject_type,
            department=self.department,
            project=self.project,
            action=self.action,
            resource_type=self.resource_type,
            resource_id=self.resource_id,
            sensitivity_level=self.sensitivity_level,
            risk_category=self.risk_category,
            trace_id=self.trace_id,
            agent_id=self.agent_id,
            atr_risk_score=risk_score,
            atr_risk_category=risk_category,
        )


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Policy Engine 最終決策。所有 decision 都可轉成 audit metadata。"""

    tenant_id: str
    effect: PolicyEffect
    matched_rule_ids: tuple[str, ...]
    policy_set_ids: tuple[str, ...]
    policy_versions: tuple[str, ...]
    reason: str
    trace_id: str
    requires_approval: bool
    audit_required: bool
    audit_mandatory: bool
    approval: ApprovalRequirement | None = None
    decision_id: str = field(default_factory=_new_id)
    timestamp: datetime = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        if not self.tenant_id:
            raise ValueError("tenant_id 不可為空")
        if not self.reason:
            raise ValueError("reason 不可為空")
        if not self.trace_id:
            raise ValueError("trace_id 不可為空")
        if not self.decision_id:
            raise ValueError("decision_id 不可為空")
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp 必須是 tz-aware 時間")
        if self.effect is PolicyEffect.REQUIRE_APPROVAL and not self.requires_approval:
            raise ValueError("require_approval effect 必須 requires_approval=True")
        if self.requires_approval and self.approval is None:
            raise ValueError("requires_approval=True 必須提供 approval")
        if not self.audit_required:
            raise ValueError("S08 所有 policy decision 都必須產生 audit metadata")

    def to_audit_metadata(self) -> dict[str, Any]:
        """給 S05/S09/S28 使用的不可變稽核資料。"""
        return {
            "decision_id": self.decision_id,
            "tenant_id": self.tenant_id,
            "effect": self.effect.value,
            "matched_rule_ids": list(self.matched_rule_ids),
            "policy_set_ids": list(self.policy_set_ids),
            "policy_versions": list(self.policy_versions),
            "reason": self.reason,
            "requires_approval": self.requires_approval,
            "audit_mandatory": self.audit_mandatory,
            "trace_id": self.trace_id,
            "timestamp": self.timestamp.isoformat(),
        }
