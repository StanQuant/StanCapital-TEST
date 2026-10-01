"""Policy DSL 測試。"""

from __future__ import annotations

from pathlib import Path

import pytest
from src.security.policy.dsl import load_policy_set, parse_policy_set
from src.security.policy.errors import PolicyLoadError
from src.security.policy.types import PolicyEffect, PolicyScopeLevel

from .conftest import policy_text, raises_starting


def test_parse_policy_set_success_and_load_file(tmp_path: Path) -> None:
    text = policy_text()
    policy_set = parse_policy_set(text)
    assert policy_set.schema_version == 1
    assert policy_set.policy_set_id == "security-base"
    assert policy_set.scope.level is PolicyScopeLevel.TENANT
    assert policy_set.rules[0].effect is PolicyEffect.DENY
    assert policy_set.rules[1].approval is not None
    assert policy_set.rules[1].approval.approver_role == "security_officer"
    assert policy_set.rules[1].approval.escalation_role == "compliance_officer"
    assert policy_set.rules[2].limits["output_tokens_per_day"] == 1000
    assert len(policy_set.content_hash) == 64
    path = tmp_path / "policy.yaml"
    path.write_text(text, encoding="utf-8")
    assert load_policy_set(path).content_hash == policy_set.content_hash


def test_scope_specific_yaml_is_supported() -> None:
    department = policy_text(scope_extra="  department: research\n").replace(
        "level: tenant", "level: department"
    )
    assert parse_policy_set(department).scope.department == "research"
    project = policy_text(scope_extra="  project: alpha\n").replace(
        "level: tenant", "level: project"
    )
    assert parse_policy_set(project).scope.project == "alpha"
    agent = policy_text(scope_extra="  agent_id: agent-1\n").replace(
        "level: tenant", "level: agent"
    )
    assert parse_policy_set(agent).scope.agent_id == "agent-1"


def test_any_clause_is_supported() -> None:
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
    description: any 任一命中
    when:
      any:
        - expr: department == "research"
        - expr: action == "read_documents"
"""
    rule = parse_policy_set(text).rules[0]
    assert len(rule.any_expressions) == 2
    assert rule.all_expressions == ()


@pytest.mark.parametrize(
    ("text", "prefix"),
    [
        ("[]", "policy set 頂層必須是 YAML mapping"),
        (
            policy_text().replace("schema_version: 1", "schema_version: true"),
            "schema_version 必須是整數",
        ),
        (
            policy_text().replace("schema_version: 1", "schema_version: 2"),
            "schema_version 目前只支援 1",
        ),
        (
            policy_text().replace("policy_set_id: security-base", "policy_set_id: ''"),
            "policy_set_id 必須是非空字串",
        ),
        (policy_text().replace("scope:", "unknown: true\nscope:"), "policy set 含未知欄位"),
        (policy_text().replace("level: tenant", "level: unknown"), "未知 scope level: 'unknown'"),
        (policy_text().replace("level: tenant", "level: ''"), "scope.level 必須是非空字串"),
        (
            policy_text().replace("  level: tenant", "  level: tenant\n  bogus: 1"),
            "scope 含未知欄位",
        ),
        (policy_text(scope_extra="  project: ''\n"), "scope.project 必須是非空字串或 null"),
        (policy_text(scope_extra="  agent_id: ''\n"), "scope.agent_id 必須是非空字串或 null"),
        (policy_text().replace("version: 2026.06.23-001", "version: ''"), "version 必須是非空字串"),
        (
            policy_text().replace("tenant_id: stanley", "tenant_id: ''"),
            "scope.tenant_id 必須是非空字串",
        ),
        (policy_text().replace("rules:", "rules: []"), "policy set YAML 語法錯誤"),
        (
            policy_text().replace("id: deny-external-upload", "id: approval-real-order"),
            "rule id 不可重複",
        ),
        (policy_text().replace("id: deny-external-upload", "id: ''"), "rule.id 必須是非空字串"),
        (
            policy_text().replace(
                "    description: 禁止外部上傳高敏感資料",
                "    description: 禁止外部上傳高敏感資料\n    bogus: 1",
            ),
            "rule 含未知欄位",
        ),
        (
            policy_text().replace("effect: deny", "effect: block", 1),
            "rule deny-external-upload 使用未知 effect: 'block'",
        ),
        (
            policy_text().replace("effect: deny", "effect: 123", 1),
            "rule deny-external-upload.effect 必須是非空字串",
        ),
        (
            policy_text().replace(
                "      approver_role: security_officer",
                "      approver_role: security_officer\n      bogus: 1",
            ),
            "rule approval-real-order.approval 含未知欄位",
        ),
        (
            policy_text().replace("escalation_role: compliance_officer", "escalation_role: ''"),
            "approval.escalation_role 必須是非空字串或 null",
        ),
        (
            policy_text().replace("description: 禁止外部上傳高敏感資料", "description: 1"),
            "rule deny-external-upload.description 必須是非空字串",
        ),
        (policy_text().replace("when:", "when: []", 1), "policy set YAML 語法錯誤"),
        (policy_text().replace("all:", "none:", 1), "rule deny-external-upload.when 含未知欄位"),
        (
            policy_text().replace('- expr: action == "external_upload"', "- bad: action", 1),
            "rule deny-external-upload.when.all 項目必須只含 expr",
        ),
        (
            policy_text().replace('expr: action == "external_upload"', "expr: ''", 1),
            "expr 必須是非空字串",
        ),
        (policy_text().replace("approval:", "approval: []", 1), "policy set YAML 語法錯誤"),
        (
            policy_text().replace("approver_role: security_officer", "approver_role: ''"),
            "approval.approver_role 必須是非空字串",
        ),
        (
            policy_text().replace("timeout_seconds: 900", "timeout_seconds: true"),
            "approval.timeout_seconds 必須是整數",
        ),
        (policy_text().replace("limits:", "limits: []"), "policy set YAML 語法錯誤"),
        (
            policy_text().replace("output_tokens_per_day: 1000", "'': 1000"),
            "rule allow-research-read.limits key 必須是非空字串",
        ),
        (
            policy_text().replace("output_tokens_per_day: 1000", "output_tokens_per_day: true"),
            "rule allow-research-read.limits.output_tokens_per_day 必須是整數",
        ),
    ],
)
def test_parse_policy_set_rejects_invalid_policy(text: str, prefix: str) -> None:
    with raises_starting(PolicyLoadError, prefix):
        parse_policy_set(text)


_SCOPE_NOT_MAPPING = """
schema_version: 1
policy_set_id: security-base
version: v1
scope: []
rules:
  - id: allow
    effect: allow
    description: allow
    when:
      all:
        - expr: tenant_id == "stanley"
"""

_RULE_NOT_MAPPING = """
schema_version: 1
policy_set_id: security-base
version: v1
scope:
  tenant_id: stanley
  level: tenant
rules:
  - bad
"""

_WHEN_ALL_EMPTY = """
schema_version: 1
policy_set_id: security-base
version: v1
scope:
  tenant_id: stanley
  level: tenant
rules:
  - id: allow
    effect: allow
    description: allow
    when:
      all: []
"""

_WHEN_ALL_NOT_LIST = """
schema_version: 1
policy_set_id: security-base
version: v1
scope:
  tenant_id: stanley
  level: tenant
rules:
  - id: allow
    effect: allow
    description: allow
    when:
      all: wrong
"""

_WHEN_ANY_NOT_LIST = """
schema_version: 1
policy_set_id: security-base
version: v1
scope:
  tenant_id: stanley
  level: tenant
rules:
  - id: allow
    effect: allow
    description: allow
    when:
      any: wrong
"""

_APPROVAL_NOT_MAPPING = """
schema_version: 1
policy_set_id: security-base
version: v1
scope:
  tenant_id: stanley
  level: tenant
rules:
  - id: approval
    effect: require_approval
    description: approval
    approval: []
    when:
      all:
        - expr: tenant_id == "stanley"
"""

_LIMITS_NOT_MAPPING = """
schema_version: 1
policy_set_id: security-base
version: v1
scope:
  tenant_id: stanley
  level: tenant
rules:
  - id: allow
    effect: allow
    description: allow
    limits: []
    when:
      all:
        - expr: tenant_id == "stanley"
"""

_LIMITS_EMPTY_KEY = """
schema_version: 1
policy_set_id: security-base
version: v1
scope:
  tenant_id: stanley
  level: tenant
rules:
  - id: allow
    effect: allow
    description: allow
    limits:
      "": 1
    when:
      all:
        - expr: tenant_id == "stanley"
"""

_EXPR_NOT_STRING = """
schema_version: 1
policy_set_id: security-base
version: v1
scope:
  tenant_id: stanley
  level: tenant
rules:
  - id: allow
    effect: allow
    description: allow
    when:
      all:
        - expr: true
"""

_RULES_EMPTY = """
schema_version: 1
policy_set_id: security-base
version: v1
scope:
  tenant_id: stanley
  level: tenant
rules: []
"""

_WHEN_NOT_MAPPING = """
schema_version: 1
policy_set_id: security-base
version: v1
scope:
  tenant_id: stanley
  level: tenant
rules:
  - id: allow
    effect: allow
    description: allow
    when: []
"""

_DEPARTMENT_EMPTY = """
schema_version: 1
policy_set_id: security-base
version: v1
scope:
  tenant_id: stanley
  level: department
  department: ""
rules:
  - id: allow
    effect: allow
    description: allow
    when:
      all:
        - expr: tenant_id == "stanley"
"""


@pytest.mark.parametrize(
    ("text", "prefix"),
    [
        (_SCOPE_NOT_MAPPING, "scope 必須是 mapping"),
        (_RULE_NOT_MAPPING, "rule 必須是 mapping"),
        (_WHEN_ALL_EMPTY, "rule allow.when 至少需要 all 或 any"),
        (_WHEN_ALL_NOT_LIST, "rule allow.when.all 必須是非空清單"),
        (_WHEN_ANY_NOT_LIST, "rule allow.when.any 必須是非空清單"),
        (_APPROVAL_NOT_MAPPING, "rule approval.approval 必須是 mapping"),
        (_LIMITS_NOT_MAPPING, "rule allow.limits 必須是 mapping"),
        (_LIMITS_EMPTY_KEY, "rule allow.limits key 必須是非空字串"),
        (_EXPR_NOT_STRING, "expr 必須是非空字串"),
        (_RULES_EMPTY, "rules 必須是非空清單"),
        (_WHEN_NOT_MAPPING, "rule allow.when 必須是 mapping"),
        (_DEPARTMENT_EMPTY, "scope.department 必須是非空字串或 null"),
    ],
)
def test_parse_policy_set_rejects_targeted_invalid_yaml(text: str, prefix: str) -> None:
    with raises_starting(PolicyLoadError, prefix):
        parse_policy_set(text)
