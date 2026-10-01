"""需要 secret 的 connector 初始化守門。"""

from __future__ import annotations

from dataclasses import dataclass

from src.security.vault.errors import SecretNotFoundError, SecretValidationError
from src.security.vault.provider import SecretProvider
from src.security.vault.types import SecretMetadata, SecretName


@dataclass(frozen=True, slots=True)
class SecretBackedConnector:
    """外部 connector 的最小 secret 需求描述。"""

    connector_name: str
    required_secret: SecretName

    def __post_init__(self) -> None:
        if not self.connector_name:
            raise SecretValidationError("connector_name 不可為空")


def require_connector_secret(
    provider: SecretProvider,
    connector: SecretBackedConnector,
) -> SecretMetadata:
    """connector 初始化前確認 secret 存在；不存在即 fail-closed。"""
    if not provider.exists(connector.required_secret):
        raise SecretNotFoundError(
            f"connector secret 未進 Vault，拒絕初始化: {connector.connector_name}"
        )
    return provider.get_metadata(connector.required_secret)
