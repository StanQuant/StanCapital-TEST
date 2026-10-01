"""ABAC 測試共用工廠 · 預設值合理，可用 overrides 覆寫任一欄位。"""

from __future__ import annotations

from typing import Any

from src.governance.abac.attributes import AccessRequest
from src.governance.abac.decisions import AbacEffect
from src.governance.abac.policy import Condition, Operator, PolicyRule
from src.governance.rbac.permissions import Action, Resource
from src.governance.rbac.roles import Role


def make_request(**overrides: Any) -> AccessRequest:
    """組一個「正常經理寫一般訂單」的請求；測試只覆寫關注的欄位。"""
    fields: dict[str, Any] = {
        "user_id": "USR-001",
        "tenant_id": "stanley",
        "role": Role.MANAGER,
        "department": "trading",
        "region": "taiwan",
        "project": "alpha",
        "sensitivity_level": 2,
        "risk_category": "normal",
        "requested_resource": Resource.ORDER,
        "requested_action": Action.WRITE,
    }
    fields.update(overrides)
    return AccessRequest(**fields)


def make_rule(**overrides: Any) -> PolicyRule:
    """組一條單條件政策；測試只覆寫關注的欄位。"""
    fields: dict[str, Any] = {
        "policy_id": "P-001",
        "effect": AbacEffect.DENY,
        "target": (Condition("department", Operator.EQ, "trading"),),
        "description": "測試政策",
    }
    fields.update(overrides)
    return PolicyRule(**fields)
