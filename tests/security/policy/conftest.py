"""S08 測試 helper。"""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from src.security.policy.dsl import parse_policy_set
from src.security.policy.types import PolicyRequest, PolicySet


@contextmanager
def raises_starting(exc_type: type[Exception], prefix: str) -> Iterator[pytest.ExceptionInfo[Any]]:
    """斷言拋出 exc_type，且訊息以 prefix 開頭。

    用 `\\A`(字串起點)錨定 + `re.escape`：mutmut 把訊息包成 `XX...XX` 時起點變成 XX，
    斷言失敗→變異被殺。比 `match=` 子字串安全(子字串在 XX 包裹後仍命中、殺不掉)。
    """
    with pytest.raises(exc_type, match=r"\A" + re.escape(prefix)) as info:
        yield info


def policy_text(*, version: str = "2026.06.23-001", scope_extra: str = "") -> str:
    return f"""
schema_version: 1
policy_set_id: security-base
version: {version}
scope:
  tenant_id: stanley
  level: tenant
{scope_extra}rules:
  - id: deny-external-upload
    effect: deny
    description: 禁止外部上傳高敏感資料
    when:
      all:
        - expr: action == "external_upload"
        - expr: resource.sensitivity_level >= 4

  - id: approval-real-order
    effect: require_approval
    description: 高風險真實下單必須審批
    approval:
      approver_role: security_officer
      timeout_seconds: 900
      escalation_role: compliance_officer
    when:
      all:
        - expr: action == "submit_real_order"
        - expr: atr.risk_score >= 61

  - id: allow-research-read
    effect: allow
    description: 研究部門可讀低敏感資料
    limits:
      output_tokens_per_day: 1000
    when:
      all:
        - expr: department == "research"
        - expr: action in ["read_documents", "perform_analysis"]
        - expr: resource.sensitivity_level <= 3
"""


def base_policy_set() -> PolicySet:
    return parse_policy_set(policy_text())


def base_request(**overrides: object) -> PolicyRequest:
    values: dict[str, object] = {
        "tenant_id": "stanley",
        "subject_id": "user-1",
        "subject_type": "agent",
        "department": "research",
        "project": "alpha",
        "action": "read_documents",
        "resource_type": "document",
        "resource_id": "doc-1",
        "sensitivity_level": 2,
        "risk_category": "normal",
        "trace_id": "trace-1",
        "agent_id": "agent-1",
        "atr_risk_score": 12,
        "atr_risk_category": "safe",
    }
    values.update(overrides)
    return PolicyRequest(**values)  # type: ignore[arg-type]
