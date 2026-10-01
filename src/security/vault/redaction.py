"""S10 secret redaction helper。"""

from __future__ import annotations

from typing import Any

from src.observability.redaction import REDACTED, Redactor
from src.security.vault.types import SecretValue

_VAULT_REDACTOR = Redactor(
    extra_keys=(
        "api_secret",
        "client_secret",
        "hmac_key",
        "secret_value",
        "vault_token",
        "authorization_header",
    )
)


def redact_secret_payload(value: Any) -> Any:
    """遮蔽任意 secret payload。"""
    if isinstance(value, SecretValue):
        return REDACTED
    return _VAULT_REDACTOR.redact(value)


def contains_plaintext(payload: Any, secret: SecretValue) -> bool:
    """測試輔助：確認 payload 是否仍含 secret 原文。"""
    plaintext = secret.reveal()
    return plaintext in repr(payload) or plaintext in str(payload)
