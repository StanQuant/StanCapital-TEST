"""ATR 八類威脅 matcher。

matcher 是真正的安全邏輯，所以留在程式碼中測到 100%。
YAML rulebook 只控制權重、描述、版本與啟用狀態。
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from src.security.atr.types import AgentBehavior, AtrRuleDefinition, ThreatCode

Matcher = Callable[[AgentBehavior], bool]


@dataclass(frozen=True, slots=True)
class AtrRule:
    """一條可執行 ATR 規則。"""

    definition: AtrRuleDefinition
    matcher: Matcher

    def matches(self, behavior: AgentBehavior) -> bool:
        return self.definition.enabled and self.matcher(behavior)


def build_rules(definitions: tuple[AtrRuleDefinition, ...]) -> tuple[AtrRule, ...]:
    """把 rulebook 設定接上程式碼 matcher。"""
    matchers = _matchers()
    rules: list[AtrRule] = []
    for definition in definitions:
        rules.append(AtrRule(definition=definition, matcher=matchers[definition.code]))
    return tuple(rules)


def _haystack(behavior: AgentBehavior) -> str:
    parts = [
        behavior.tool_name,
        behavior.action,
        behavior.target,
        behavior.payload_summary,
        behavior.external_destination or "",
    ]
    parts.extend(str(value) for value in behavior.metadata.values() if value is not None)
    return " ".join(parts).lower()


def _metadata_int(behavior: AgentBehavior, key: str) -> int:
    value = behavior.metadata.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return value


def _matches_t001(behavior: AgentBehavior) -> bool:
    text = _haystack(behavior)
    keywords = ("sudo", "setuid", "setgid", "root", "chmod 777", "permission elevation")
    return any(keyword in text for keyword in keywords)


def _matches_t002(behavior: AgentBehavior) -> bool:
    text = _haystack(behavior)
    keywords = (
        ".ssh/id_rsa",
        "private_key",
        "api_key",
        "secret",
        "credential",
        "certificate",
        ".pem",
        ".env",
    )
    return any(keyword in text for keyword in keywords)


def _matches_t003(behavior: AgentBehavior) -> bool:
    text = _haystack(behavior)
    count = _metadata_int(behavior, "file_count")
    bulk_action = any(word in text for word in ("rm -rf", "recursive delete", "bulk", "mass"))
    destructive = any(word in text for word in ("delete", "overwrite", "relocate", "chmod"))
    return bulk_action or (destructive and count >= 100)


def _matches_t004(behavior: AgentBehavior) -> bool:
    text = _haystack(behavior)
    has_external = bool(behavior.external_destination)
    keywords = ("curl -x post", "curl -xpost", "post ", "upload", "export", "webhook")
    external = any(
        marker in (behavior.external_destination or "").lower()
        for marker in ("http://", "https://", "s3://", "gs://")
    )
    return (has_external and external) or any(keyword in text for keyword in keywords)


def _matches_t005(behavior: AgentBehavior) -> bool:
    text = _haystack(behavior)
    keywords = (
        "ignore previous instructions",
        "system prompt",
        "developer message",
        "jailbreak",
        "tool manipulation",
        "override instructions",
    )
    return any(keyword in text for keyword in keywords)


def _matches_t006(behavior: AgentBehavior) -> bool:
    text = _haystack(behavior)
    keywords = (
        "spawn agent",
        "create agent",
        "recursive spawning",
        "duplicate workflow",
        "self-copy",
        "unauthorized scheduler",
    )
    return any(keyword in text for keyword in keywords)


def _matches_t007(behavior: AgentBehavior) -> bool:
    text = _haystack(behavior)
    calls_per_minute = _metadata_int(behavior, "tool_calls_per_minute")
    keywords = ("tool abuse", "rate anomaly", "policy violation", "failure loop")
    return calls_per_minute >= 500 or any(keyword in text for keyword in keywords)


def _matches_t008(behavior: AgentBehavior) -> bool:
    text = _haystack(behavior)
    keywords = (
        "delete audit",
        "disable audit",
        "truncate audit",
        "approval bypass",
        "permission circumvention",
        "tamper verifier",
        "session_replication_role",
    )
    return any(keyword in text for keyword in keywords)


def _matchers() -> dict[ThreatCode, Matcher]:
    return {
        ThreatCode.T001: _matches_t001,
        ThreatCode.T002: _matches_t002,
        ThreatCode.T003: _matches_t003,
        ThreatCode.T004: _matches_t004,
        ThreatCode.T005: _matches_t005,
        ThreatCode.T006: _matches_t006,
        ThreatCode.T007: _matches_t007,
        ThreatCode.T008: _matches_t008,
    }
