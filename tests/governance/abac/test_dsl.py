"""Policy DSL 解析與嚴格驗證測試（fail-closed：壞政策一律 PolicyLoadError）。

錯誤測試一律斷言訊息「開頭」(startswith)或「完全相等」而非子字串——
子字串會被 mutmut 的 XX 包裹變異騙過(殺手測試套路，S05 教訓)。
"""

from __future__ import annotations

from pathlib import Path

import pytest
from src.governance.abac.decisions import AbacEffect
from src.governance.abac.dsl import load_policies, parse_policies
from src.governance.abac.errors import PolicyLoadError
from src.governance.abac.policy import Operator

_VALID = """
policies:
  - id: deny-secret
    effect: deny
    description: 機密刪除擋下
    target:
      - attr: sensitivity_level
        op: gte
        value: 5
      - attr: requested_action
        op: in
        value: [write, delete]
  - id: allow-read
    effect: allow
    description: 讀取放行
    target:
      - attr: requested_action
        op: eq
        value: read
"""


def _expect_load_error(text: str, prefix: str) -> None:
    """壞政策應拋 PolicyLoadError，且訊息以 prefix 開頭(startswith 殺 XX 包裹變異)。"""
    with pytest.raises(PolicyLoadError) as excinfo:
        parse_policies(text)
    assert str(excinfo.value).startswith(prefix)


def test_parse_valid_policies() -> None:
    rules = parse_policies(_VALID)
    assert len(rules) == 2
    first = rules[0]
    assert first.policy_id == "deny-secret"
    assert first.effect is AbacEffect.DENY
    assert first.description == "機密刪除擋下"
    assert len(first.target) == 2
    assert first.target[0].operator is Operator.GTE
    assert first.target[0].value == 5
    # in 的值轉成 tuple
    assert first.target[1].operator is Operator.IN
    assert first.target[1].value == ("write", "delete")
    assert rules[1].effect is AbacEffect.ALLOW


def test_parse_ne_and_lte_operators() -> None:
    """涵蓋 ne / lte 運算子的字面值(釘死 Operator 成員值，避免 DSL 相容性破壞)。"""
    text = """
policies:
  - id: p1
    effect: deny
    target:
      - attr: department
        op: ne
        value: trading
      - attr: sensitivity_level
        op: lte
        value: 3
"""
    rule = parse_policies(text)[0]
    assert rule.target[0].operator is Operator.NE
    assert rule.target[0].value == "trading"
    assert rule.target[1].operator is Operator.LTE
    assert rule.target[1].value == 3


def test_description_defaults_to_empty_when_absent() -> None:
    text = """
policies:
  - id: p1
    effect: allow
    target:
      - attr: requested_action
        op: eq
        value: read
"""
    assert parse_policies(text)[0].description == ""


def test_load_policies_from_file(tmp_path: Path) -> None:
    path = tmp_path / "p.yaml"
    path.write_text(_VALID, encoding="utf-8")
    rules = load_policies(path)
    assert len(rules) == 2


def test_load_real_base_policy_file() -> None:
    base = Path(__file__).parents[3] / "policies" / "abac" / "base.yaml"
    rules = load_policies(base)
    ids = {r.policy_id for r in rules}
    assert "deny-top-secret-mutation" in ids
    assert "allow-normal-trading" in ids
    assert len(rules) == 7


# --------------------------------------------------------------------------
# 錯誤分支（每條驗證都要被 fail-closed 攔下；訊息開頭釘死）
# --------------------------------------------------------------------------
@pytest.mark.parametrize("text", ["just-a-string", "[1, 2, 3]", "key: value"])
def test_top_level_must_have_policies_key(text: str) -> None:
    _expect_load_error(text, "政策檔頂層必須是含 'policies' 鍵的對應")


def test_policies_must_be_list() -> None:
    _expect_load_error("policies: not-a-list", "'policies' 必須是清單")


def test_duplicate_id_rejected() -> None:
    text = """
policies:
  - id: dup
    effect: allow
    target:
      - attr: requested_action
        op: eq
        value: read
  - id: dup
    effect: deny
    target:
      - attr: requested_action
        op: eq
        value: write
"""
    _expect_load_error(text, "政策 id 重複: dup")


def test_entry_must_be_mapping() -> None:
    _expect_load_error("policies: ['plain-string']", "政策項目必須是對應:")


@pytest.mark.parametrize(
    "id_line",
    ["effect: allow", "id: ''\n    effect: allow", "id: 123\n    effect: allow"],
)
def test_missing_or_invalid_id_rejected(id_line: str) -> None:
    text = f"""
policies:
  - {id_line}
    target:
      - attr: requested_action
        op: eq
        value: read
"""
    _expect_load_error(text, "政策缺少合法 id:")


def test_unknown_effect_rejected() -> None:
    text = """
policies:
  - id: p1
    effect: maybe
    target:
      - attr: requested_action
        op: eq
        value: read
"""
    _expect_load_error(text, "政策 p1 使用未知 effect: 'maybe'")


def test_non_string_description_rejected() -> None:
    text = """
policies:
  - id: p1
    effect: allow
    description: [list, not, string]
    target:
      - attr: requested_action
        op: eq
        value: read
"""
    _expect_load_error(text, "政策 p1 的 description 必須是字串")


@pytest.mark.parametrize("target_line", ["target: not-a-list", "target: []"])
def test_target_must_be_non_empty_list(target_line: str) -> None:
    text = f"""
policies:
  - id: p1
    effect: allow
    {target_line}
"""
    _expect_load_error(text, "政策 p1 的 target 必須是非空清單")


def test_condition_must_be_mapping() -> None:
    text = """
policies:
  - id: p1
    effect: allow
    target:
      - just-a-string
"""
    _expect_load_error(text, "政策 p1 的 target 條件必須是對應")


def test_unknown_attribute_rejected() -> None:
    text = """
policies:
  - id: p1
    effect: allow
    target:
      - attr: salary
        op: eq
        value: 100
"""
    _expect_load_error(text, "政策 p1 使用未知屬性: 'salary'")


def test_unknown_operator_rejected() -> None:
    text = """
policies:
  - id: p1
    effect: allow
    target:
      - attr: department
        op: regex
        value: a
"""
    _expect_load_error(text, "政策 p1 使用未知運算子: 'regex'")


@pytest.mark.parametrize("value_line", ["value: write", "value: []"])
def test_in_value_must_be_non_empty_list(value_line: str) -> None:
    text = f"""
policies:
  - id: p1
    effect: allow
    target:
      - attr: requested_action
        op: in
        {value_line}
"""
    _expect_load_error(text, "政策 p1 的 in value 必須是非空清單")


def test_gte_on_non_numeric_attribute_rejected() -> None:
    text = """
policies:
  - id: p1
    effect: allow
    target:
      - attr: department
        op: gte
        value: 3
"""
    _expect_load_error(text, "政策 p1 的 gte 只能用於數值屬性: department")


@pytest.mark.parametrize("bad", ["value: high", "value: true"])
def test_gte_value_must_be_integer(bad: str) -> None:
    text = f"""
policies:
  - id: p1
    effect: allow
    target:
      - attr: sensitivity_level
        op: gte
        {bad}
"""
    _expect_load_error(text, "政策 p1 的 gte value 必須是整數")


@pytest.mark.parametrize("bad", ["value: [a, b]", "value: true"])
def test_scalar_value_must_be_str_or_int(bad: str) -> None:
    text = f"""
policies:
  - id: p1
    effect: allow
    target:
      - attr: department
        op: eq
        {bad}
"""
    _expect_load_error(text, "政策 p1 的 eq value 必須是字串或整數")


def test_in_item_must_be_scalar() -> None:
    text = """
policies:
  - id: p1
    effect: allow
    target:
      - attr: department
        op: in
        value: [[nested], list]
"""
    _expect_load_error(text, "政策 p1 的 in value 必須是字串或整數")
