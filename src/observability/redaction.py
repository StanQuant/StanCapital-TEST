"""遙測敏感資料遮蔽（fail-closed）。

logs / metrics / traces 不得記錄 API key / secret / PII 原文。本模組在序列化前掃描：
1. 欄位名命中敏感字（password / token / authorization…）→ 整個值遮蔽。
2. 字串值命中敏感樣式（email / Bearer / AWS key / PEM / 卡號）→ 遮蔽該片段。
3. 結構過深（超過 max_depth）→ 整段遮蔽，避免漏掉未檢視的內容（fail-closed）。
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

REDACTED = "***REDACTED***"

# 欄位名敏感字（小寫子字串比對）。寧可多遮，不可外漏。
_SENSITIVE_KEY_PARTS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "apikey",
        "api_key",
        "authorization",
        "credential",
        "private_key",
        "privatekey",
        "access_key",
        "accesskey",
        "refresh_token",
        "session",
        "cookie",
        "ssn",
        "cvv",
    }
)

# 值樣式：不論欄位名，命中即遮（PII / 憑證指紋）。
_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/\-]+=*"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),
    re.compile(r"\b\d(?:[ -]?\d){12,18}\b"),
)


class Redactor:
    """可重用的遮蔽器。預設規則 + 可加自訂敏感欄位名。"""

    __slots__ = ("_keys", "_max_depth")

    def __init__(self, extra_keys: Iterable[str] = (), max_depth: int = 6) -> None:
        if max_depth < 0:
            raise ValueError("max_depth 不可為負數")
        self._keys = _SENSITIVE_KEY_PARTS | {k.lower() for k in extra_keys}
        self._max_depth = max_depth

    def is_sensitive_key(self, key: str) -> bool:
        """欄位名是否命中敏感字。"""
        low = key.lower()
        return any(part in low for part in self._keys)

    def redact_text(self, text: str) -> str:
        """遮蔽字串中命中樣式的片段。"""
        for pattern in _VALUE_PATTERNS:
            text = pattern.sub(REDACTED, text)
        return text

    def redact(self, value: Any, _depth: int = 0) -> Any:
        """遞迴遮蔽任意結構（dict / list / tuple / set / str）。"""
        if _depth > self._max_depth:
            # 太深就整段遮，寧可少看資料也不漏未檢視內容。
            return REDACTED
        if isinstance(value, Mapping):
            return {
                k: (REDACTED if self.is_sensitive_key(str(k)) else self.redact(v, _depth + 1))
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [self.redact(v, _depth + 1) for v in value]
        if isinstance(value, tuple):
            return tuple(self.redact(v, _depth + 1) for v in value)
        if isinstance(value, set):
            return {self.redact(v, _depth + 1) for v in value}
        if isinstance(value, str):
            return self.redact_text(value)
        return value


# 預設遮蔽器（多數呼叫點直接用）。
_DEFAULT = Redactor()


def redact(value: Any) -> Any:
    """用預設遮蔽器遮蔽。"""
    return _DEFAULT.redact(value)


def safe_attributes(attributes: Mapping[str, Any]) -> dict[str, Any]:
    """遮蔽遙測屬性（span attributes / metric labels 共用）：

    敏感欄位名整個遮、字串值掃樣式、其餘原值通過（保留 int/bool/float 供指標用）。
    """
    safe: dict[str, Any] = {}
    for key, value in attributes.items():
        if _DEFAULT.is_sensitive_key(key):
            safe[key] = REDACTED
        elif isinstance(value, str):
            safe[key] = _DEFAULT.redact_text(value)
        else:
            safe[key] = value
    return safe
