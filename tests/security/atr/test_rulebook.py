"""ATR rulebook 測試。"""

from __future__ import annotations

from pathlib import Path

import pytest
from src.security.atr.errors import RulebookLoadError
from src.security.atr.rulebook import load_rulebook, parse_rulebook
from src.security.atr.types import ThreatCode

BASE_YAML = Path("policies/atr/base.yaml")


def test_load_base_rulebook_has_all_threat_codes() -> None:
    rules = load_rulebook(BASE_YAML)
    assert tuple(rule.code for rule in rules) == tuple(ThreatCode)
    assert rules[1].code is ThreatCode.T002
    assert rules[1].weight == 75
    assert rules[1].risk_category == "sensitive_file_access"


def test_parse_rulebook_rejects_missing_top_key() -> None:
    with pytest.raises(RulebookLoadError) as exc:
        parse_rulebook("not_rules: []")
    assert str(exc.value) == "ATR rulebook 頂層必須是含 'rules' 鍵的對應"


def test_parse_rulebook_rejects_empty_rules() -> None:
    with pytest.raises(RulebookLoadError) as exc:
        parse_rulebook("rules: []")
    assert str(exc.value) == "'rules' 必須是非空清單"


def test_parse_rulebook_rejects_non_mapping_entry() -> None:
    with pytest.raises(RulebookLoadError) as exc:
        parse_rulebook("rules:\n  - bad")
    assert str(exc.value) == "ATR 規則項目必須是對應: 'bad'"


def test_parse_rulebook_rejects_unknown_code() -> None:
    with pytest.raises(RulebookLoadError) as exc:
        parse_rulebook(
            """
rules:
  - code: T999
    category: Bad
    risk_category: bad
    weight: 1
    description: bad
"""
        )
    assert str(exc.value) == "未知 ATR 規則 code: 'T999'"


@pytest.mark.parametrize(
    ("field", "message"),
    [
        ("category", "ATR T001 category 必須是非空字串"),
        ("risk_category", "ATR T001 risk_category 必須是非空字串"),
        ("description", "ATR T001 description 必須是非空字串"),
    ],
)
def test_parse_rulebook_rejects_bad_scalar_fields(field: str, message: str) -> None:
    yaml_text = """
rules:
  - code: T001
    category: Privilege Escalation
    risk_category: privilege_escalation
    weight: 80
    description: desc
"""
    yaml_text = yaml_text.replace(
        f"{field}: {'Privilege Escalation' if field == 'category' else 'privilege_escalation' if field == 'risk_category' else 'desc'}",
        f'{field}: ""',
    )
    with pytest.raises(RulebookLoadError) as exc:
        parse_rulebook(yaml_text)
    assert str(exc.value) == message


def test_parse_rulebook_default_enabled_and_version_are_stable() -> None:
    yaml_text = "\n".join(
        line
        for line in BASE_YAML.read_text(encoding="utf-8").splitlines()
        if "enabled:" not in line and "version:" not in line
    )
    rules = parse_rulebook(yaml_text)
    assert all(rule.enabled is True for rule in rules)
    assert all(rule.version == 1 for rule in rules)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("weight", "bad", "ATR T001 weight 必須是整數"),
        ("enabled", "bad", "ATR T001 enabled 必須是布林值"),
        ("version", "bad", "ATR T001 version 必須是整數"),
    ],
)
def test_parse_rulebook_rejects_bad_types(field: str, value: str, message: str) -> None:
    yaml_text = """
rules:
  - code: T001
    category: Privilege Escalation
    risk_category: privilege_escalation
    weight: 80
    enabled: true
    version: 1
    description: desc
"""
    old_value = 80 if field == "weight" else "true" if field == "enabled" else 1
    yaml_text = yaml_text.replace(f"{field}: {old_value}", f"{field}: {value}")
    with pytest.raises(RulebookLoadError) as exc:
        parse_rulebook(yaml_text)
    assert str(exc.value) == message


def test_parse_rulebook_rejects_value_errors_from_definition() -> None:
    with pytest.raises(RulebookLoadError) as exc:
        parse_rulebook(
            """
rules:
  - code: T001
    category: Privilege Escalation
    risk_category: privilege_escalation
    weight: 101
    description: desc
"""
        )
    assert str(exc.value) == "weight 必須在 0-100 之間: 101"


def test_parse_rulebook_rejects_duplicate_and_missing_codes() -> None:
    duplicated = BASE_YAML.read_text(encoding="utf-8").replace("code: T002", "code: T001", 1)
    with pytest.raises(RulebookLoadError) as exc:
        parse_rulebook(duplicated)
    assert str(exc.value) == "ATR 規則重複: T001"

    missing = "\n".join(
        line
        for line in BASE_YAML.read_text(encoding="utf-8").splitlines()
        if "code: T008" not in line
    )
    with pytest.raises(RulebookLoadError) as exc2:
        parse_rulebook(missing)
    assert str(exc2.value) == "ATR rulebook 缺少規則: T008"

    missing_many = "\n".join(
        line
        for line in BASE_YAML.read_text(encoding="utf-8").splitlines()
        if "code: T007" not in line and "code: T008" not in line
    )
    with pytest.raises(RulebookLoadError) as exc3:
        parse_rulebook(missing_many)
    assert str(exc3.value) == "ATR rulebook 缺少規則: T007, T008"
