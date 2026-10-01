"""L10 Policy DSL · YAML 結構 + 安全 expression AST。"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml
from yaml import YAMLError

from src.security.policy.errors import PolicyLoadError
from src.security.policy.expressions import compile_expression
from src.security.policy.types import (
    ApprovalRequirement,
    PolicyEffect,
    PolicyRule,
    PolicyScope,
    PolicyScopeLevel,
    PolicySet,
)

_TOP_LEVEL_KEYS = frozenset({"schema_version", "policy_set_id", "version", "scope", "rules"})
_SCOPE_KEYS = frozenset({"tenant_id", "level", "department", "project", "agent_id"})
_RULE_KEYS = frozenset({"id", "effect", "description", "when", "approval", "limits"})
_WHEN_KEYS = frozenset({"all", "any"})
_APPROVAL_KEYS = frozenset({"approver_role", "timeout_seconds", "escalation_role"})


def parse_policy_set(text: str) -> PolicySet:
    """解析 YAML 文字成 PolicySet。任何不合法欄位都 fail-closed。"""
    try:
        raw = yaml.safe_load(text)
    except YAMLError as exc:
        raise PolicyLoadError(f"policy set YAML 語法錯誤: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyLoadError("policy set 頂層必須是 YAML mapping")
    _reject_unknown_keys(raw, _TOP_LEVEL_KEYS, "policy set")
    scope = _parse_scope(raw.get("scope"))
    rules = _parse_rules(raw.get("rules"))
    try:
        return PolicySet(
            schema_version=_require_int(raw.get("schema_version"), "schema_version"),
            policy_set_id=_require_str(raw.get("policy_set_id"), "policy_set_id"),
            version=_require_str(raw.get("version"), "version"),
            scope=scope,
            rules=rules,
            content_hash=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        )
    except ValueError as exc:
        raise PolicyLoadError(str(exc)) from exc


def load_policy_set(path: Path | str) -> PolicySet:
    """從檔案載入 policy set。"""
    return parse_policy_set(Path(path).read_text(encoding="utf-8"))


def _parse_scope(raw: Any) -> PolicyScope:
    if not isinstance(raw, dict):
        raise PolicyLoadError("scope 必須是 mapping")
    _reject_unknown_keys(raw, _SCOPE_KEYS, "scope")
    try:
        level = PolicyScopeLevel(_require_str(raw.get("level"), "scope.level"))
    except ValueError:
        raise PolicyLoadError(f"未知 scope level: {raw.get('level')!r}") from None
    return PolicyScope(
        tenant_id=_require_str(raw.get("tenant_id"), "scope.tenant_id"),
        level=level,
        department=_optional_str(raw.get("department"), "scope.department"),
        project=_optional_str(raw.get("project"), "scope.project"),
        agent_id=_optional_str(raw.get("agent_id"), "scope.agent_id"),
    )


def _parse_rules(raw: Any) -> tuple[PolicyRule, ...]:
    if not isinstance(raw, list) or not raw:
        raise PolicyLoadError("rules 必須是非空清單")
    rules = tuple(_parse_rule(item) for item in raw)
    if len({rule.rule_id for rule in rules}) != len(rules):
        raise PolicyLoadError("rule id 不可重複")
    return rules


def _parse_rule(raw: Any) -> PolicyRule:
    if not isinstance(raw, dict):
        raise PolicyLoadError(f"rule 必須是 mapping: {raw!r}")
    _reject_unknown_keys(raw, _RULE_KEYS, "rule")
    rule_id = _require_str(raw.get("id"), "rule.id")
    try:
        effect = PolicyEffect(_require_str(raw.get("effect"), f"rule {rule_id}.effect"))
    except ValueError:
        raise PolicyLoadError(f"rule {rule_id} 使用未知 effect: {raw.get('effect')!r}") from None
    all_expressions, any_expressions = _parse_when(raw.get("when"), rule_id)
    return PolicyRule(
        rule_id=rule_id,
        effect=effect,
        description=_require_str(raw.get("description"), f"rule {rule_id}.description"),
        all_expressions=all_expressions,
        any_expressions=any_expressions,
        approval=_parse_approval(raw.get("approval"), rule_id),
        limits=_parse_limits(raw.get("limits"), rule_id),
    )


def _parse_when(raw: Any, rule_id: str) -> tuple[tuple[Any, ...], tuple[Any, ...]]:
    if not isinstance(raw, dict):
        raise PolicyLoadError(f"rule {rule_id}.when 必須是 mapping")
    _reject_unknown_keys(raw, _WHEN_KEYS, f"rule {rule_id}.when")
    all_raw = raw.get("all", [])
    any_raw = raw.get("any", [])
    if not all_raw and not any_raw:
        raise PolicyLoadError(f"rule {rule_id}.when 至少需要 all 或 any")
    return _parse_expr_list(all_raw, rule_id, "all"), _parse_expr_list(any_raw, rule_id, "any")


def _parse_expr_list(raw: Any, rule_id: str, key: str) -> tuple[Any, ...]:
    if raw == []:
        return ()
    if not isinstance(raw, list) or not raw:
        raise PolicyLoadError(f"rule {rule_id}.when.{key} 必須是非空清單")
    expressions = []
    for item in raw:
        if not isinstance(item, dict) or set(item) != {"expr"}:
            raise PolicyLoadError(f"rule {rule_id}.when.{key} 項目必須只含 expr")
        expressions.append(compile_expression(_require_str(item.get("expr"), "expr")))
    return tuple(expressions)


def _parse_approval(raw: Any, rule_id: str) -> ApprovalRequirement | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise PolicyLoadError(f"rule {rule_id}.approval 必須是 mapping")
    _reject_unknown_keys(raw, _APPROVAL_KEYS, f"rule {rule_id}.approval")
    return ApprovalRequirement(
        approver_role=_require_str(raw.get("approver_role"), "approval.approver_role"),
        timeout_seconds=_require_int(raw.get("timeout_seconds"), "approval.timeout_seconds"),
        escalation_role=_optional_str(raw.get("escalation_role"), "approval.escalation_role"),
    )


def _parse_limits(raw: Any, rule_id: str) -> dict[str, int]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise PolicyLoadError(f"rule {rule_id}.limits 必須是 mapping")
    limits: dict[str, int] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not key:
            raise PolicyLoadError(f"rule {rule_id}.limits key 必須是非空字串")
        limits[key] = _require_int(value, f"rule {rule_id}.limits.{key}")
    return limits


def _reject_unknown_keys(raw: dict[Any, Any], allowed: frozenset[str], label: str) -> None:
    unknown = set(raw) - allowed
    if unknown:
        raise PolicyLoadError(f"{label} 含未知欄位: {sorted(unknown)}")


def _require_str(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise PolicyLoadError(f"{label} 必須是非空字串")
    return value


def _optional_str(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise PolicyLoadError(f"{label} 必須是非空字串或 null")
    return value


def _require_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyLoadError(f"{label} 必須是整數")
    return value
