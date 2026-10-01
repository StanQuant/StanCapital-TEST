"""Condition / PolicyRule / matches 純函式測試（運算子兩側邊界 + AND 語義）。"""

from __future__ import annotations

import dataclasses

import pytest
from src.governance.abac.decisions import AbacEffect
from src.governance.abac.policy import Condition, Operator, PolicyRule, matches
from src.governance.rbac.permissions import Action, Resource
from src.governance.rbac.roles import Role

from tests.governance.abac.conftest import make_request, make_rule


def _rule_with(*conditions: Condition) -> PolicyRule:
    return PolicyRule(
        policy_id="P", effect=AbacEffect.DENY, target=tuple(conditions), description=""
    )


# ---- EQ ----
def test_eq_true_and_false() -> None:
    req = make_request(department="trading")
    assert matches(_rule_with(Condition("department", Operator.EQ, "trading")), req) is True
    assert matches(_rule_with(Condition("department", Operator.EQ, "risk")), req) is False


# ---- NE ----
def test_ne_true_and_false() -> None:
    req = make_request(department="trading")
    assert matches(_rule_with(Condition("department", Operator.NE, "risk")), req) is True
    assert matches(_rule_with(Condition("department", Operator.NE, "trading")), req) is False


# ---- IN ----
def test_in_true_and_false() -> None:
    req = make_request(requested_action=Action.WRITE)
    in_set: tuple[str, ...] = ("write", "delete")
    assert matches(_rule_with(Condition("requested_action", Operator.IN, in_set)), req) is True
    miss: tuple[str, ...] = ("read", "manage")
    assert matches(_rule_with(Condition("requested_action", Operator.IN, miss)), req) is False


# ---- GTE（兩側邊界）----
@pytest.mark.parametrize(
    ("level", "threshold", "expected"),
    [(4, 4, True), (5, 4, True), (3, 4, False)],
)
def test_gte_boundaries(level: int, threshold: int, expected: bool) -> None:
    req = make_request(sensitivity_level=level)
    rule = _rule_with(Condition("sensitivity_level", Operator.GTE, threshold))
    assert matches(rule, req) is expected


# ---- LTE（兩側邊界）----
@pytest.mark.parametrize(
    ("level", "threshold", "expected"),
    [(3, 3, True), (2, 3, True), (4, 3, False)],
)
def test_lte_boundaries(level: int, threshold: int, expected: bool) -> None:
    req = make_request(sensitivity_level=level)
    rule = _rule_with(Condition("sensitivity_level", Operator.LTE, threshold))
    assert matches(rule, req) is expected


# ---- 列舉屬性（role / resource / action 皆 StrEnum）----
def test_enum_attributes_compare_by_value() -> None:
    req = make_request(role=Role.MANAGER, requested_resource=Resource.ORDER)
    assert matches(_rule_with(Condition("role", Operator.EQ, "manager")), req) is True
    assert matches(_rule_with(Condition("requested_resource", Operator.EQ, "order")), req) is True


# ---- AND 語義：全部成立才命中 ----
def test_all_conditions_must_hold() -> None:
    req = make_request(department="trading", sensitivity_level=5)
    both_true = _rule_with(
        Condition("department", Operator.EQ, "trading"),
        Condition("sensitivity_level", Operator.GTE, 5),
    )
    one_false = _rule_with(
        Condition("department", Operator.EQ, "trading"),
        Condition("sensitivity_level", Operator.GTE, 6),  # 5 >= 6 → False
    )
    assert matches(both_true, req) is True
    assert matches(one_false, req) is False


def test_rule_and_condition_are_frozen_with_slots() -> None:
    rule = make_rule()
    with pytest.raises(dataclasses.FrozenInstanceError):
        rule.policy_id = "X"  # type: ignore[misc]
    cond = rule.target[0]
    with pytest.raises(dataclasses.FrozenInstanceError):
        cond.attribute = "x"  # type: ignore[misc]
    # slots=True：殺 slots 變異(值物件紀律)
    assert not hasattr(rule, "__dict__")
    assert not hasattr(cond, "__dict__")
