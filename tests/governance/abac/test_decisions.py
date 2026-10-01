"""AbacEffect / AbacDecision 型別測試。"""

from __future__ import annotations

import dataclasses

import pytest
from src.governance.abac.decisions import AbacDecision, AbacEffect


def test_effect_string_values() -> None:
    # 值同時當 DSL 字面值，golden 釘死避免改值破壞政策檔相容性
    assert AbacEffect.ALLOW.value == "allow"
    assert AbacEffect.DENY.value == "deny"
    assert AbacEffect.REQUIRE_APPROVAL.value == "require_approval"


def test_decision_holds_fields() -> None:
    decision = AbacDecision(effect=AbacEffect.DENY, matched_policy="P-9", reason="擋下")
    assert decision.effect is AbacEffect.DENY
    assert decision.matched_policy == "P-9"
    assert decision.reason == "擋下"


def test_decision_allows_none_matched_policy() -> None:
    decision = AbacDecision(effect=AbacEffect.DENY, matched_policy=None, reason="預設拒絕")
    assert decision.matched_policy is None


def test_decision_is_frozen() -> None:
    decision = AbacDecision(effect=AbacEffect.ALLOW, matched_policy=None, reason="")
    with pytest.raises(dataclasses.FrozenInstanceError):
        decision.effect = AbacEffect.DENY  # type: ignore[misc]
