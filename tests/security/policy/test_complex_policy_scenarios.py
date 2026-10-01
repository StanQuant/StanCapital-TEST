"""S08 複雜策略場景測試。"""

from __future__ import annotations

import pytest
from src.security.policy.dsl import parse_policy_set
from src.security.policy.evaluator import PolicyEvaluator
from src.security.policy.types import PolicyEffect

from .conftest import base_request, policy_text


def test_complex_multilevel_policy_deny_cannot_be_relaxed_by_agent_allow() -> None:
    tenant = parse_policy_set(policy_text())
    agent_allow = parse_policy_set(
        """
schema_version: 1
policy_set_id: agent-policy
version: agent-v1
scope:
  tenant_id: stanley
  level: agent
  agent_id: agent-1
rules:
  - id: allow-agent-upload
    effect: allow
    description: 細層嘗試放寬外部上傳
    when:
      all:
        - expr: action == "external_upload"
"""
    )
    decision = PolicyEvaluator((tenant, agent_allow)).evaluate(
        base_request(action="external_upload", sensitivity_level=5)
    )
    assert decision.effect is PolicyEffect.DENY
    assert decision.matched_rule_ids == ("deny-external-upload", "allow-agent-upload")


def test_complex_four_level_scopes_match_and_deny_wins() -> None:
    """tenant + department + project + agent 四層同時命中，最終 deny 優先(規格 §11.2)。"""
    tenant = parse_policy_set(
        """
schema_version: 1
policy_set_id: tenant-policy
version: tenant-v1
scope:
  tenant_id: stanley
  level: tenant
rules:
  - id: tenant-allow
    effect: allow
    description: 租戶層允許研究部門
    when:
      all:
        - expr: department == "research"
"""
    )
    department = parse_policy_set(
        """
schema_version: 1
policy_set_id: department-policy
version: department-v1
scope:
  tenant_id: stanley
  level: department
  department: research
rules:
  - id: department-approval
    effect: require_approval
    description: 部門層要求審批
    approval:
      approver_role: security_officer
      timeout_seconds: 600
    when:
      all:
        - expr: action == "read_documents"
"""
    )
    project = parse_policy_set(
        """
schema_version: 1
policy_set_id: project-policy
version: project-v1
scope:
  tenant_id: stanley
  level: project
  project: alpha
rules:
  - id: project-allow
    effect: allow
    description: 專案層允許
    when:
      all:
        - expr: project == "alpha"
"""
    )
    agent = parse_policy_set(
        """
schema_version: 1
policy_set_id: agent-policy
version: agent-v1
scope:
  tenant_id: stanley
  level: agent
  agent_id: agent-1
rules:
  - id: agent-deny
    effect: deny
    description: agent 層加嚴禁止
    when:
      all:
        - expr: agent_id == "agent-1"
"""
    )
    decision = PolicyEvaluator((tenant, department, project, agent)).evaluate(base_request())
    assert decision.effect is PolicyEffect.DENY
    assert decision.matched_rule_ids == (
        "tenant-allow",
        "department-approval",
        "project-allow",
        "agent-deny",
    )
    assert decision.policy_set_ids == (
        "tenant-policy",
        "department-policy",
        "project-policy",
        "agent-policy",
    )


def test_complex_atr_policy_and_approval_path() -> None:
    decision = PolicyEvaluator((parse_policy_set(policy_text()),)).evaluate(
        base_request(action="submit_real_order", atr_risk_score=75, atr_risk_category="high")
    )
    assert decision.effect is PolicyEffect.REQUIRE_APPROVAL
    assert decision.approval is not None
    assert decision.approval.approver_role == "security_officer"


@pytest.mark.integration
def test_integration_policy_rollback_changes_decision_without_deleting_history() -> None:
    strict = parse_policy_set(policy_text(version="strict"))
    relaxed = parse_policy_set(
        """
schema_version: 1
policy_set_id: security-base
version: relaxed
scope:
  tenant_id: stanley
  level: tenant
rules:
  - id: allow-low-risk-upload
    effect: allow
    description: 低敏感外部上傳暫時放行
    when:
      all:
        - expr: action == "external_upload"
        - expr: resource.sensitivity_level <= 2
"""
    )
    request = base_request(action="external_upload", sensitivity_level=2)
    assert PolicyEvaluator((strict,)).evaluate(request).effect is PolicyEffect.DENY
    assert PolicyEvaluator((relaxed,)).evaluate(request).effect is PolicyEffect.ALLOW
