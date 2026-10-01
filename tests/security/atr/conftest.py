"""ATR 測試工廠。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.security.atr.engine import AtrEngine
from src.security.atr.response import AtrResponseHandler
from src.security.atr.rulebook import load_rulebook
from src.security.atr.rules import build_rules
from src.security.atr.types import AgentBehavior, AgentIdentity, SuppressionRule, ThreatCode

BASE_RULEBOOK = Path("policies/atr/base.yaml")


def make_agent(**overrides: Any) -> AgentIdentity:
    fields: dict[str, Any] = {
        "tenant_id": "stanley",
        "agent_id": "research-agent",
        "risk_level": 5,
    }
    fields.update(overrides)
    return AgentIdentity(**fields)


def make_behavior(**overrides: Any) -> AgentBehavior:
    fields: dict[str, Any] = {
        "agent": make_agent(),
        "tool_name": "shell",
        "action": "read",
        "target": "/workspace/report.txt",
        "payload_summary": "read normal report",
        "trace_id": "trace-001",
    }
    fields.update(overrides)
    return AgentBehavior(**fields)


def make_engine() -> AtrEngine:
    return AtrEngine(build_rules(load_rulebook(BASE_RULEBOOK)))


def make_response_handler(*suppressions: SuppressionRule) -> AtrResponseHandler:
    return AtrResponseHandler(tuple(suppressions))


def make_suppression(**overrides: Any) -> SuppressionRule:
    fields: dict[str, Any] = {
        "suppression_id": "SUP-001",
        "tenant_id": "stanley",
        "threat_code": ThreatCode.T005,
        "reason": "已知測試 prompt，僅允許降低一級",
        "approved_by": "security-officer",
    }
    fields.update(overrides)
    return SuppressionRule(**fields)
