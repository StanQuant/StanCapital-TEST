"""ATR rulebook · YAML 權重/描述設定 + 嚴格驗證。

D1 裁決採混合式:
- matcher 邏輯留在 rules.py，保持可測與效能
- 權重、描述、啟用狀態、版本放 YAML，方便未來商業化管理介面與租戶覆寫
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from src.security.atr.errors import RulebookLoadError
from src.security.atr.types import AtrRuleDefinition, ThreatCode


def parse_rulebook(text: str) -> tuple[AtrRuleDefinition, ...]:
    """解析 YAML 文字成 ATR 規則設定。"""
    raw = yaml.safe_load(text)
    if not isinstance(raw, dict) or "rules" not in raw:
        raise RulebookLoadError("ATR rulebook 頂層必須是含 'rules' 鍵的對應")
    entries = raw["rules"]
    if not isinstance(entries, list) or not entries:
        raise RulebookLoadError("'rules' 必須是非空清單")

    rules: list[AtrRuleDefinition] = []
    seen_codes: set[ThreatCode] = set()
    for entry in entries:
        rule = _parse_rule(entry)
        if rule.code in seen_codes:
            raise RulebookLoadError(f"ATR 規則重複: {rule.code.value}")
        seen_codes.add(rule.code)
        rules.append(rule)

    missing = set(ThreatCode) - seen_codes
    if missing:
        codes = ", ".join(sorted(code.value for code in missing))
        raise RulebookLoadError(f"ATR rulebook 缺少規則: {codes}")
    return tuple(rules)


def load_rulebook(path: Path | str) -> tuple[AtrRuleDefinition, ...]:
    """從檔案載入 ATR rulebook。"""
    return parse_rulebook(Path(path).read_text(encoding="utf-8"))


def _parse_rule(entry: Any) -> AtrRuleDefinition:
    if not isinstance(entry, dict):
        raise RulebookLoadError(f"ATR 規則項目必須是對應: {entry!r}")
    code_raw = entry.get("code")
    try:
        code = ThreatCode(str(code_raw))
    except ValueError:
        raise RulebookLoadError(f"未知 ATR 規則 code: {code_raw!r}") from None
    category = _require_str(entry.get("category"), code, "category")
    risk_category = _require_str(entry.get("risk_category"), code, "risk_category")
    description = _require_str(entry.get("description"), code, "description")
    weight = entry.get("weight")
    if not isinstance(weight, int) or isinstance(weight, bool):
        raise RulebookLoadError(f"ATR {code.value} weight 必須是整數")
    enabled = entry.get("enabled", True)
    if not isinstance(enabled, bool):
        raise RulebookLoadError(f"ATR {code.value} enabled 必須是布林值")
    version = entry.get("version", 1)
    if not isinstance(version, int) or isinstance(version, bool):
        raise RulebookLoadError(f"ATR {code.value} version 必須是整數")
    try:
        return AtrRuleDefinition(
            code=code,
            category=category,
            weight=weight,
            risk_category=risk_category,
            description=description,
            enabled=enabled,
            version=version,
        )
    except ValueError as error:
        raise RulebookLoadError(str(error)) from None


def _require_str(value: Any, code: ThreatCode, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise RulebookLoadError(f"ATR {code.value} {field_name} 必須是非空字串")
    return value
