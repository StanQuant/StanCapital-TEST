"""PolicyEvaluator 測試。"""

from __future__ import annotations

from src.security.policy.dsl import parse_policy_set
from src.security.policy.evaluator import PolicyEvaluator
from src.security.policy.types import PolicyEffect

from .conftest import base_policy_set, base_request, policy_text


def test_evaluator_allows_matching_allow_rule() -> None:
    decision = PolicyEvaluator((base_policy_set(),)).evaluate(base_request())
    assert decision.effect is PolicyEffect.ALLOW
    assert decision.matched_rule_ids == ("allow-research-read",)
    assert not decision.audit_mandatory
    assert decision.audit_required


def test_evaluator_requires_approval_for_high_risk_real_order() -> None:
    decision = PolicyEvaluator((base_policy_set(),)).evaluate(
        base_request(action="submit_real_order", atr_risk_score=75, atr_risk_category="high")
    )
    assert decision.effect is PolicyEffect.REQUIRE_APPROVAL
    assert decision.requires_approval
    assert decision.approval is not None
    assert decision.approval.escalation_role == "compliance_officer"
    assert decision.audit_mandatory


def test_evaluator_denies_and_deny_overrides_allow() -> None:
    text = (
        policy_text()
        + """
  - id: allow-external-upload
    effect: allow
    description: 惡意放寬應被 deny 壓過
    when:
      all:
        - expr: action == "external_upload"
"""
    )
    decision = PolicyEvaluator((parse_policy_set(text),)).evaluate(
        base_request(action="external_upload", sensitivity_level=5)
    )
    assert decision.effect is PolicyEffect.DENY
    assert decision.matched_rule_ids == ("deny-external-upload", "allow-external-upload")


def test_evaluator_denies_no_match_scope_mismatch_and_expression_error() -> None:
    evaluator = PolicyEvaluator((base_policy_set(),))
    no_match = evaluator.evaluate(base_request(department="trading", action="read_documents"))
    assert no_match.effect is PolicyEffect.DENY
    assert no_match.reason == "無政策命中 → deny-by-default"

    other_tenant = evaluator.evaluate(base_request(tenant_id="other"))
    assert other_tenant.effect is PolicyEffect.DENY
    assert other_tenant.matched_rule_ids == ()

    missing_atr = evaluator.evaluate(
        base_request(action="submit_real_order", atr_risk_score=None, atr_risk_category=None)
    )
    assert missing_atr.effect is PolicyEffect.DENY
    assert missing_atr.reason.startswith("政策評估失敗 → fail-closed")


def test_evaluator_supports_department_project_and_agent_scopes() -> None:
    department = parse_policy_set(
        policy_text(scope_extra="  department: research\n")
        .replace("level: tenant", "level: department")
        .replace("version: 2026.06.23-001", "version: department")
    )
    project = parse_policy_set(
        policy_text(scope_extra="  project: alpha\n")
        .replace("level: tenant", "level: project")
        .replace("version: 2026.06.23-001", "version: project")
    )
    agent = parse_policy_set(
        policy_text(scope_extra="  agent_id: agent-1\n")
        .replace("level: tenant", "level: agent")
        .replace("version: 2026.06.23-001", "version: agent")
    )
    decision = PolicyEvaluator((department, project, agent)).evaluate(base_request())
    assert decision.effect is PolicyEffect.ALLOW
    assert decision.policy_versions == ("department", "project", "agent")


def test_audit_mandatory_for_sensitive_or_regulated_allow() -> None:
    text = """
schema_version: 1
policy_set_id: allow-sensitive
version: v1
scope:
  tenant_id: stanley
  level: tenant
rules:
  - id: allow-any
    effect: allow
    description: 測試高風險 allow 稽核強制
    when:
      all:
        - expr: tenant_id == "stanley"
"""
    evaluator = PolicyEvaluator((parse_policy_set(text),))
    assert evaluator.evaluate(base_request(sensitivity_level=4)).audit_mandatory
    assert evaluator.evaluate(base_request(atr_risk_score=61)).audit_mandatory
    assert evaluator.evaluate(base_request(action="submit_real_order")).audit_mandatory
    assert evaluator.evaluate(base_request(action="external_upload")).audit_mandatory
    assert not evaluator.evaluate(base_request(action="read_documents")).audit_mandatory


def test_evaluator_skips_non_matching_scope_and_continues_to_later_policy() -> None:
    # 前面的部門政策 scope 不命中(department=trading)，後面的租戶政策仍必須被評估到。
    # 若把 continue 改成 break，後面的租戶政策會被跳過 → 此測試會失敗。
    trading = parse_policy_set(
        policy_text(scope_extra="  department: trading\n")
        .replace("level: tenant", "level: department")
        .replace("version: 2026.06.23-001", "version: trading-dept")
    )
    decision = PolicyEvaluator((trading, base_policy_set())).evaluate(base_request())
    assert decision.effect is PolicyEffect.ALLOW
    assert decision.matched_rule_ids == ("allow-research-read",)
    assert decision.policy_versions == ("2026.06.23-001",)


def test_evaluator_supports_any_expressions() -> None:
    text = """
schema_version: 1
policy_set_id: any-policy
version: v1
scope:
  tenant_id: stanley
  level: tenant
rules:
  - id: allow-any
    effect: allow
    description: any 條件任一命中即可
    when:
      any:
        - expr: department == "trading"
        - expr: action == "read_documents"
"""
    decision = PolicyEvaluator((parse_policy_set(text),)).evaluate(base_request())
    assert decision.effect is PolicyEffect.ALLOW
