"""L10 Vault 錯誤型別。

Vault 是密鑰生命週期邊界；狀態不明時必須 fail-closed，不可回傳空 secret 假裝成功。
"""

from __future__ import annotations


class VaultError(Exception):
    """Vault 模組根錯誤。"""


class SecretValidationError(VaultError, ValueError):
    """SecretName / SecretValue / metadata 驗證失敗。"""


class SecretNotFoundError(VaultError, LookupError):
    """指定 secret 不存在。"""


class SecretProviderError(VaultError):
    """provider 執行失敗。"""


class SecretProviderUnavailableError(SecretProviderError):
    """provider 或其外部依賴不可用。"""


class SecretRotationError(VaultError):
    """密鑰輪換失敗。"""
