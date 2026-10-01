"""S08 Policy 型別測試。"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest
from src.security.policy.expressions import compile_expression
from src.security.policy.types import (
    ApprovalRequirement,
    PolicyDecision,
    PolicyEffect,
    PolicyRequest,
    PolicyRule,
    PolicyScope,
    PolicyScopeLevel,
    PolicySet,
)

from .conftest import base_request, raises_starting


def test_public_enum_values_are_stable_contracts() -> None:
    assert {effect.name: effect.value for effect in PolicyEffect} == {
        "ALLOW": "allow",
        "DENY": "deny",
        "REQUIRE_APPROVAL": "require_approval",
    }
    assert {level.name: level.value for level in PolicyScopeLevel} == {
        "TENANT": "tenant",
        "DEPARTMENT": "department",
        "PROJECT": "project",
        "AGENT": "agent",
    }


def test_policy_scope_validates_and_matches_request() -> None:
    request = base_request()
    tenant_scope = PolicyScope("stanley", PolicyScopeLevel.TENANT)
    assert tenant_scope.matches(request)
    assert not PolicyScope("other", PolicyScopeLevel.TENANT).matches(request)
    assert PolicyScope("stanley", PolicyScopeLevel.DEPARTMENT, department="research").matches(
        request
    )
    assert not PolicyScope("stanley", PolicyScopeLevel.DEPARTMENT, department="trading").matches(
        request
    )
    assert PolicyScope("stanley", PolicyScopeLevel.PROJECT, project="alpha").matches(request)
    assert not PolicyScope("stanley", PolicyScopeLevel.PROJECT, project="beta").matches(request)
    assert PolicyScope("stanley", PolicyScopeLevel.AGENT, agent_id="agent-1").matches(request)
    assert not PolicyScope("stanley", PolicyScopeLevel.AGENT, agent_id="agent-2").matches(request)
    with raises_starting(ValueError, "tenant_id 不可為空"):
        PolicyScope("", PolicyScopeLevel.TENANT)
    with raises_starting(ValueError, "department scope 必須提供 department"):
        PolicyScope("stanley", PolicyScopeLevel.DEPARTMENT)
    with raises_starting(ValueError, "project scope 必須提供 project"):
        PolicyScope("stanley", PolicyScopeLevel.PROJECT)
    with raises_starting(ValueError, "agent scope 必須提供 agent_id"):
        PolicyScope("stanley", PolicyScopeLevel.AGENT)


def test_policy_scope_defaults_and_is_frozen_slotted() -> None:
    scope = PolicyScope("stanley", PolicyScopeLevel.TENANT)
    assert not hasattr(scope, "__dict__")
    assert scope.department is None
    assert scope.project is None
    assert scope.agent_id is None
    with pytest.raises(FrozenInstanceError):
        scope.tenant_id = "x"  # type: ignore[misc]


def test_approval_requirement_validation() -> None:
    requirement = ApprovalRequirement("security_officer", 60, "compliance_officer")
    assert not hasattr(requirement, "__dict__")
    assert requirement.escalation_role == "compliance_officer"
    assert ApprovalRequirement("security_officer", 60).escalation_role is None
    assert ApprovalRequirement("security_officer", 1).timeout_seconds == 1  # 邊界下限
    with pytest.raises(FrozenInstanceError):
        requirement.timeout_seconds = 1  # type: ignore[misc]
    with raises_starting(ValueError, "approver_role 不可為空"):
        ApprovalRequirement("", 60)
    with raises_starting(ValueError, "timeout_seconds 必須大於 0"):
        ApprovalRequirement("security_officer", 0)
    with raises_starting(ValueError, "escalation_role 不可為空字串"):
        ApprovalRequirement("security_officer", 60, "")


def test_policy_rule_validation_and_limits_are_read_only() -> None:
    expression = compile_expression('action == "read_documents"')
    approval = ApprovalRequirement("security_officer", 60)
    rule = PolicyRule(
        "approval",
        PolicyEffect.REQUIRE_APPROVAL,
        "需要審批",
        all_expressions=(expression,),
        approval=approval,
        limits={"quota": 1},
    )
    assert rule.limits["quota"] == 1
    with pytest.raises(TypeError):
        rule.limits["quota"] = 2  # type: ignore[index]
    with raises_starting(ValueError, "rule_id 不可為空"):
        PolicyRule("", PolicyEffect.ALLOW, "desc", all_expressions=(expression,))
    with raises_starting(ValueError, "description 不可為空"):
        PolicyRule("id", PolicyEffect.ALLOW, "", all_expressions=(expression,))
    with raises_starting(ValueError, "policy rule 至少需要 all 或 any expression"):
        PolicyRule("id", PolicyEffect.ALLOW, "desc")
    with raises_starting(ValueError, "require_approval rule 必須提供 approval 設定"):
        PolicyRule("id", PolicyEffect.REQUIRE_APPROVAL, "desc", all_expressions=(expression,))
    with raises_starting(ValueError, "只有 require_approval rule 可提供 approval 設定"):
        PolicyRule(
            "id", PolicyEffect.ALLOW, "desc", all_expressions=(expression,), approval=approval
        )
    with raises_starting(ValueError, "limit key 不可為空"):
        PolicyRule("id", PolicyEffect.ALLOW, "desc", all_expressions=(expression,), limits={"": 1})
    with raises_starting(ValueError, "limit value 不可小於 0"):
        PolicyRule(
            "id",
            PolicyEffect.ALLOW,
            "desc",
            all_expressions=(expression,),
            limits={"quota": -1},
        )


def test_policy_rule_defaults_frozen_and_limit_zero_boundary() -> None:
    expression = compile_expression('action == "read_documents"')
    only_any = PolicyRule("id", PolicyEffect.ALLOW, "desc", any_expressions=(expression,))
    assert only_any.all_expressions == ()
    only_all = PolicyRule("id", PolicyEffect.ALLOW, "desc", all_expressions=(expression,))
    assert only_all.any_expressions == ()
    assert only_all.approval is None
    assert not hasattr(only_all, "__dict__")
    with pytest.raises(FrozenInstanceError):
        only_all.rule_id = "x"  # type: ignore[misc]
    # limit value 0 仍合法(殺 < 0 → <= 0 / < 1 邊界變異)
    zero_limit = PolicyRule(
        "id", PolicyEffect.ALLOW, "desc", all_expressions=(expression,), limits={"quota": 0}
    )
    assert zero_limit.limits["quota"] == 0


def test_policy_set_validation() -> None:
    expression = compile_expression('action == "read_documents"')
    rule = PolicyRule("allow", PolicyEffect.ALLOW, "允許", all_expressions=(expression,))
    scope = PolicyScope("stanley", PolicyScopeLevel.TENANT)
    policy_set = PolicySet(1, "base", "v1", scope, (rule,), "hash")
    assert not hasattr(policy_set, "__dict__")
    with pytest.raises(FrozenInstanceError):
        policy_set.version = "v2"  # type: ignore[misc]
    with raises_starting(ValueError, "schema_version 目前只支援 1"):
        PolicySet(2, "base", "v1", scope, (rule,), "hash")
    with raises_starting(ValueError, "policy_set_id 不可為空"):
        PolicySet(1, "", "v1", scope, (rule,), "hash")
    with raises_starting(ValueError, "version 不可為空"):
        PolicySet(1, "base", "", scope, (rule,), "hash")
    with raises_starting(ValueError, "policy set 至少需要一條 rule"):
        PolicySet(1, "base", "v1", scope, (), "hash")
    with raises_starting(ValueError, "policy set 內 rule_id 不可重複"):
        PolicySet(1, "base", "v1", scope, (rule, rule), "hash")
    with raises_starting(ValueError, "content_hash 不可為空"):
        PolicySet(1, "base", "v1", scope, (rule,), "")


def test_policy_request_validation_and_with_atr() -> None:
    request = base_request(atr_risk_score=None, atr_risk_category=None)
    with_atr = request.with_atr(risk_score=75, risk_category="sensitive_file_access")
    assert with_atr.atr_risk_score == 75
    assert with_atr.atr_risk_category == "sensitive_file_access"
    assert not hasattr(with_atr, "__dict__")
    with pytest.raises(FrozenInstanceError):
        with_atr.action = "write"  # type: ignore[misc]
    with raises_starting(ValueError, "tenant_id 不可為空"):
        base_request(tenant_id="")
    with raises_starting(ValueError, "sensitivity_level 必須在 1-5 之間"):
        base_request(sensitivity_level=6)
    with raises_starting(ValueError, "atr_risk_score 必須在 0-100 之間"):
        base_request(atr_risk_score=101)
    with raises_starting(ValueError, "atr_risk_category 不可為空字串"):
        base_request(atr_risk_category="")


def test_policy_request_optional_defaults_and_range_boundaries() -> None:
    minimal = PolicyRequest(
        tenant_id="stanley",
        subject_id="user-1",
        subject_type="agent",
        department="research",
        project="alpha",
        action="read_documents",
        resource_type="document",
        resource_id="doc-1",
        sensitivity_level=1,
        risk_category="normal",
        trace_id="trace-1",
    )
    assert minimal.agent_id is None
    assert minimal.atr_risk_score is None
    assert minimal.atr_risk_category is None
    assert minimal.sensitivity_level == 1  # 敏感度下限
    assert base_request(sensitivity_level=5).sensitivity_level == 5  # 敏感度上限
    assert base_request(atr_risk_score=0).atr_risk_score == 0  # ATR 下限
    assert base_request(atr_risk_score=100).atr_risk_score == 100  # ATR 上限


def test_policy_decision_validation_and_audit_metadata() -> None:
    approval = ApprovalRequirement("security_officer", 60)
    decision = PolicyDecision(
        tenant_id="stanley",
        effect=PolicyEffect.REQUIRE_APPROVAL,
        matched_rule_ids=("rule-1",),
        policy_set_ids=("base",),
        policy_versions=("v1",),
        reason="需要審批",
        trace_id="trace-1",
        requires_approval=True,
        audit_required=True,
        audit_mandatory=True,
        approval=approval,
        timestamp=datetime(2026, 6, 23, tzinfo=UTC),
        decision_id="decision-1",
    )
    assert decision.to_audit_metadata() == {
        "decision_id": "decision-1",
        "tenant_id": "stanley",
        "effect": "require_approval",
        "matched_rule_ids": ["rule-1"],
        "policy_set_ids": ["base"],
        "policy_versions": ["v1"],
        "reason": "需要審批",
        "requires_approval": True,
        "audit_mandatory": True,
        "trace_id": "trace-1",
        "timestamp": "2026-06-23T00:00:00+00:00",
    }
    assert not hasattr(decision, "__dict__")
    with pytest.raises(FrozenInstanceError):
        decision.reason = "x"  # type: ignore[misc]
    allow_decision = PolicyDecision(
        "stanley", PolicyEffect.ALLOW, (), (), (), "ok", "trace", False, True, False
    )
    assert allow_decision.approval is None
    with raises_starting(ValueError, "tenant_id 不可為空"):
        PolicyDecision("", PolicyEffect.ALLOW, (), (), (), "ok", "trace", False, True, False)
    with raises_starting(ValueError, "reason 不可為空"):
        PolicyDecision("stanley", PolicyEffect.ALLOW, (), (), (), "", "trace", False, True, False)
    with raises_starting(ValueError, "trace_id 不可為空"):
        PolicyDecision("stanley", PolicyEffect.ALLOW, (), (), (), "ok", "", False, True, False)
    with raises_starting(ValueError, "decision_id 不可為空"):
        PolicyDecision(
            "stanley",
            PolicyEffect.ALLOW,
            (),
            (),
            (),
            "ok",
            "trace",
            False,
            True,
            False,
            decision_id="",
        )
    with raises_starting(ValueError, "timestamp 必須是 tz-aware 時間"):
        PolicyDecision(
            "stanley",
            PolicyEffect.ALLOW,
            (),
            (),
            (),
            "ok",
            "trace",
            False,
            True,
            False,
            timestamp=datetime(2026, 6, 23),
        )
    with raises_starting(ValueError, "requires_approval=True 必須提供 approval"):
        PolicyDecision(
            "stanley",
            PolicyEffect.ALLOW,
            (),
            (),
            (),
            "ok",
            "trace",
            True,
            True,
            True,
        )
    with raises_starting(ValueError, "require_approval effect 必須 requires_approval=True"):
        PolicyDecision(
            "stanley",
            PolicyEffect.REQUIRE_APPROVAL,
            (),
            (),
            (),
            "ok",
            "trace",
            False,
            True,
            True,
        )
    with raises_starting(ValueError, "S08 所有 policy decision 都必須產生 audit metadata"):
        PolicyDecision(
            "stanley", PolicyEffect.ALLOW, (), (), (), "ok", "trace", False, False, False
        )
