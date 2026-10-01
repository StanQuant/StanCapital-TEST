"""ATR mutation 殺手測試（DoD #3）。

每個測試對應一個原本在 mutmut 存活的變異，逐一釘死。設計依 專案教訓紀錄
「mutmut 殺手測試套路」:
- frozen/slots 用 not hasattr(__dict__) + FrozenInstanceError 殺
- 邊界值 0/100、0/1 兩端各釘一次
- matcher 關鍵字逐一隔離，避免被同 payload 內其他關鍵字冗餘覆蓋
- 預設值直接 assert，殺掉預設值變異
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from src.security.atr.response import AtrResponseHandler
from src.security.atr.rulebook import load_rulebook
from src.security.atr.rules import _metadata_int, build_rules
from src.security.atr.types import (
    AtrAction,
    AtrDecision,
    AtrRuleDefinition,
    SuppressionRule,
    ThreatCode,
    TriggeredRule,
)

from tests.security.atr.conftest import BASE_RULEBOOK, make_behavior, make_engine

# --- frozen + slots（值物件不可被執行期改寫，不得長出 __dict__）---


def test_atr_rule_is_frozen_and_slots() -> None:
    rule = build_rules(load_rulebook(BASE_RULEBOOK))[0]
    assert not hasattr(rule, "__dict__")
    with pytest.raises(FrozenInstanceError):
        rule.matcher = None  # type: ignore[assignment,misc]


def test_triggered_rule_is_frozen_and_slots() -> None:
    triggered = TriggeredRule(
        code=ThreatCode.T002,
        category="Sensitive File Access",
        weight=75,
        risk_category="sensitive_file_access",
    )
    assert not hasattr(triggered, "__dict__")
    with pytest.raises(FrozenInstanceError):
        triggered.weight = 80  # type: ignore[misc]


def test_threat_score_is_slots() -> None:
    score = make_engine().score(make_behavior(target="~/.ssh/id_rsa"))
    assert not hasattr(score, "__dict__")


def test_atr_decision_is_slots_and_default_suppression_is_empty() -> None:
    score = make_engine().score(make_behavior(target="~/.ssh/id_rsa"))
    decision = AtrResponseHandler().decide(score)
    assert not hasattr(decision, "__dict__")
    # 釘住 suppression_applied 預設為空 tuple（殺預設值變異）
    assert decision.suppression_applied == ()


# --- 邊界值與預設值 ---


def test_rule_definition_weight_boundaries_are_inclusive() -> None:
    # weight=0 與 weight=100 都必須是合法（殺 0/100 邊界變異）
    assert AtrRuleDefinition(ThreatCode.T001, "cat", 0, "risk", "desc").weight == 0
    assert AtrRuleDefinition(ThreatCode.T001, "cat", 100, "risk", "desc").weight == 100
    with pytest.raises(ValueError) as exc:
        AtrRuleDefinition(ThreatCode.T001, "cat", -1, "risk", "desc")
    assert str(exc.value) == "weight 必須在 0-100 之間: -1"


def test_rule_definition_defaults_are_pinned() -> None:
    definition = AtrRuleDefinition(ThreatCode.T001, "cat", 50, "risk", "desc")
    assert definition.enabled is True
    assert definition.version == 1


def test_suppression_max_level_reduction_zero_is_valid() -> None:
    zero = SuppressionRule("SUP-0", "stanley", ThreatCode.T005, "reason", "security", 0)
    assert zero.max_level_reduction == 0
    one = SuppressionRule("SUP-1", "stanley", ThreatCode.T005, "reason", "security", 1)
    assert one.max_level_reduction == 1


def test_agent_behavior_optional_defaults_are_pinned() -> None:
    behavior = make_behavior()
    assert behavior.external_destination is None
    assert behavior.target_event_id is None
    assert behavior.metadata == {}


# --- matcher haystack 行為（空格分隔 + metadata 進 haystack）---


def test_metadata_string_values_feed_haystack() -> None:
    # metadata 的字串值必須進 haystack，否則藏在 metadata 的攻擊關鍵字會漏判
    score = make_engine().score(make_behavior(metadata={"note": "sudo escalation"}))
    assert ThreatCode.T001 in score.triggered_codes


def test_haystack_joins_fields_with_space_not_concatenation() -> None:
    # 欄位必須以空格分隔；tool_name="up" + action="load" 不可黏成 "upload" 誤觸 T004
    score = make_engine().score(
        make_behavior(tool_name="up", action="load", target="/workspace/x", payload_summary="task")
    )
    assert ThreatCode.T004 not in score.triggered_codes


# --- T004 關鍵字逐一隔離（避免冗餘覆蓋）---


@pytest.mark.parametrize(
    "payload",
    [
        "blog post here",  # 只含 "post "，不含 curl 關鍵字
        "curl -x posted data",  # 只含 "curl -x post"，不含 "post "
        "curl -xposted data",  # 只含 "curl -xpost"，不含 "post "
    ],
)
def test_t004_post_keywords_each_trigger_independently(payload: str) -> None:
    score = make_engine().score(make_behavior(payload_summary=payload))
    assert ThreatCode.T004 in score.triggered_codes


def test_t004_http_external_marker_triggers() -> None:
    # http:// 標記需獨立測（既有測試只覆蓋 https/s3/gs）
    score = make_engine().score(make_behavior(external_destination="http://evil.example/x"))
    assert ThreatCode.T004 in score.triggered_codes


def test_t004_external_marker_is_case_insensitive() -> None:
    # 外部目的地大小寫不敏感：釘住 marker 比對前的 .lower()
    score = make_engine().score(make_behavior(external_destination="HTTPS://EVIL.EXAMPLE/X"))
    assert ThreatCode.T004 in score.triggered_codes


# --- 補殺：mutmut 重跑後仍存活的真漏網變異（2026-06-23）---


def test_haystack_field_separator_must_be_real_space() -> None:
    # _haystack 的 join 分隔符必須是真實空格：跨欄位的 "post " 關鍵字
    # 只靠欄位之間那個空格才成立。分隔符若被換成別的字串，這類邊界攻擊就會漏判。
    # （殺 rules.py _haystack join 分隔符變異）
    score = make_engine().score(make_behavior(payload_summary="post"))
    assert ThreatCode.T004 in score.triggered_codes


def test_metadata_int_fails_closed_to_zero_for_invalid_types() -> None:
    # fail-closed：非 int（含 bool、字串）或缺值的 metadata 一律回 0，
    # 絕不可變成 1 灌進 file_count / tool_calls_per_minute 門檻比較。
    # （殺 rules.py _metadata_int 的 return 0 → 1 變異）
    assert _metadata_int(make_behavior(metadata={"file_count": True}), "file_count") == 0
    assert _metadata_int(make_behavior(metadata={"file_count": "99"}), "file_count") == 0
    assert _metadata_int(make_behavior(metadata={}), "file_count") == 0
    # 釘住合法整數原值會被保留（避免反向把有效值也歸零的變異）
    assert _metadata_int(make_behavior(metadata={"file_count": 42}), "file_count") == 42


def test_atr_decision_default_suppression_applied_is_empty_tuple() -> None:
    # 直接建構 AtrDecision、不傳 suppression_applied，預設必須是空 tuple。
    # 現有測試都走 decide()（會明確帶 ()），預設值本身從未被直接驗證。
    # （殺 types.py AtrDecision.suppression_applied 預設 () → None 變異）
    score = make_engine().score(make_behavior())
    decision = AtrDecision(
        score=score,
        action=AtrAction.ALLOW,
        audit_required=True,
        encrypt_trace=False,
        suspend_agent=False,
        terminate_session=False,
        notify_security_officer=False,
        requires_human_approval=False,
    )
    assert decision.suppression_applied == ()
