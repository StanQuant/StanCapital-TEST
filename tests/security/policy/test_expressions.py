"""安全 expression interpreter 測試。"""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
from typing import cast

import pytest
from src.security.policy.errors import PolicyEvaluationError, PolicyExpressionError
from src.security.policy.expressions import (
    PolicyExpression,
    _compare,
    _eval_node,
    _resolve_path,
    _validate_node,
    compile_expression,
    evaluate_expression,
)

from .conftest import base_request, raises_starting


def test_expression_supports_allowed_boolean_and_comparison_subset() -> None:
    request = base_request()
    assert evaluate_expression(
        compile_expression(
            'department == "research" and action in ["read_documents", "perform_analysis"]'
        ),
        request,
    )
    assert evaluate_expression(compile_expression('not (department == "trading")'), request)
    assert evaluate_expression(compile_expression("1 <= resource.sensitivity_level <= 3"), request)
    assert evaluate_expression(compile_expression("resource.sensitivity_level < 3"), request)
    assert evaluate_expression(compile_expression("resource.sensitivity_level <= 2"), request)
    assert evaluate_expression(compile_expression("atr.risk_score > 11"), request)
    assert evaluate_expression(compile_expression("atr.risk_score >= 12"), request)
    assert evaluate_expression(compile_expression('department != "trading"'), request)
    assert evaluate_expression(
        compile_expression('department == "trading" or action == "read_documents"'), request
    )
    assert compile_expression("subject.agent_id.real == 1").referenced_paths == frozenset(
        {"subject.agent_id.real"}
    )
    assert evaluate_expression(compile_expression('action not in ["external_upload"]'), request)
    assert not evaluate_expression(compile_expression('subject.department == "trading"'), request)
    assert compile_expression("atr.risk_score >= 10").referenced_paths == frozenset(
        {"atr.risk_score"}
    )


def test_expression_resolves_every_allowed_name_and_context_path() -> None:
    """逐一引用每個允許名稱與 context 路徑：殺 _ALLOWED_NAMES 白名單與 context 鍵變異。"""
    request = base_request()
    top_level = {
        'tenant_id == "stanley"',
        'subject_id == "user-1"',
        'subject_type == "agent"',
        'department == "research"',
        'project == "alpha"',
        'agent_id == "agent-1"',
        'action == "read_documents"',
        'resource_type == "document"',
        'resource_id == "doc-1"',
        "sensitivity_level == 2",
        'risk_category == "normal"',
        'trace_id == "trace-1"',
    }
    nested = {
        'subject.id == "user-1"',
        'subject.type == "agent"',
        'subject.department == "research"',
        'subject.project == "alpha"',
        'subject.agent_id == "agent-1"',
        'resource.type == "document"',
        'resource.id == "doc-1"',
        "resource.sensitivity_level == 2",
        'resource.risk_category == "normal"',
        "atr.risk_score == 12",
        'atr.risk_category == "safe"',
    }
    for source in top_level | nested:
        assert evaluate_expression(compile_expression(source), request), source


def test_expression_comparison_operators_kill_boundary_mutants() -> None:
    """sensitivity_level == 2 時逐一驗每個比較運算子的邊界，殺 < / <= / > / >= / in 變異。"""
    request = base_request()

    def ev(source: str) -> bool:
        return evaluate_expression(compile_expression(source), request)

    assert ev("sensitivity_level <= 2")
    assert not ev("sensitivity_level < 2")
    assert ev("sensitivity_level < 3")
    assert ev("sensitivity_level >= 2")
    assert not ev("sensitivity_level > 2")
    assert ev("sensitivity_level > 1")
    assert ev("sensitivity_level == 2")
    assert not ev("sensitivity_level == 3")
    assert ev("sensitivity_level != 3")
    assert not ev("sensitivity_level != 2")
    assert ev('action in ["read_documents", "perform_analysis"]')
    assert not ev('action in ["external_upload"]')
    assert ev('action not in ["external_upload"]')
    assert not ev('action not in ["read_documents"]')


def test_policy_expression_is_frozen_value_object() -> None:
    expression = compile_expression('action == "read_documents"')
    assert not hasattr(expression, "__dict__")
    with pytest.raises(FrozenInstanceError):
        expression.source = "x"  # type: ignore[misc]
    # tree 不參與 repr / equality(field repr=False, compare=False)。
    assert "tree=" not in repr(expression)
    assert compile_expression('action == "x"') == compile_expression('action == "x"')
    assert compile_expression('action == "x"') != compile_expression('action == "y"')


@pytest.mark.parametrize(
    ("source", "prefix"),
    [
        ("", "expression 不可為空"),
        ("action ==", "expression 語法錯誤"),
        ("unknown == 1", "未知 expression 名稱"),
        ("len(action) == 1", "不支援的 expression 節點"),
        ("resource['id'] == 'x'", "不支援的 expression 節點"),
        ("action + 'x' == 'read_documents'", "不支援的 expression 節點"),
        ("action in []", "集合常數不可為空"),
        ("action in [object()]", "集合常數只能包含 string / int / bool / null"),
        ("-1 == -1", "只支援 not 一元運算"),
        ("1 is 1", "只支援比較與 in / not in"),
        ("b'raw' == b'raw'", "不支援的常數型別"),
        ("(1).real == 1", "attribute path 必須從合法名稱開始"),
    ],
)
def test_compile_expression_rejects_unsafe_or_unknown_syntax(source: str, prefix: str) -> None:
    with raises_starting(PolicyExpressionError, prefix):
        compile_expression(source)


def test_expression_runtime_errors_fail_closed_upstream() -> None:
    with raises_starting(PolicyEvaluationError, "expression 欄位缺值"):
        evaluate_expression(
            compile_expression("atr.risk_score >= 61"), base_request(atr_risk_score=None)
        )
    with raises_starting(PolicyEvaluationError, "expression 欄位不存在"):
        evaluate_expression(compile_expression("resource.unknown == 1"), base_request())
    with raises_starting(PolicyEvaluationError, "expression 比較型別不相容"):
        evaluate_expression(
            compile_expression('resource.sensitivity_level > "high"'), base_request()
        )


def test_expression_internal_safety_branches() -> None:
    with raises_starting(PolicyEvaluationError, "expression 必須回傳 bool"):
        evaluate_expression(compile_expression("1"), base_request())
    assert _resolve_path("items", {"items": [1, "a"]}) == (1, "a")
    with raises_starting(PolicyEvaluationError, "expression 欄位型別不支援"):
        _resolve_path("items", {"items": object()})
    bad_expression = PolicyExpression(
        source="bad",
        tree=ast.Expression(
            body=ast.BinOp(left=ast.Constant(1), op=ast.Add(), right=ast.Constant(1))
        ),
        referenced_paths=frozenset(),
    )
    with raises_starting(PolicyEvaluationError, "不支援的 expression 節點"):
        _eval_node(bad_expression.tree.body, {})
    with raises_starting(PolicyEvaluationError, "不支援的比較運算"):
        _compare(1, ast.Is(), 1)
    with raises_starting(PolicyExpressionError, "只支援 and / or"):
        _validate_node(ast.BoolOp(op=cast("ast.boolop", ast.BitOr()), values=[]), set())
