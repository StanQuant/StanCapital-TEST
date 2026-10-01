"""Vault / Cloud Secret Manager 抽象 adapter。"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import Protocol

from src.security.vault.errors import (
    SecretNotFoundError,
    SecretProviderError,
    SecretProviderUnavailableError,
    SecretValidationError,
)
from src.security.vault.provider import SecretProvider
from src.security.vault.types import (
    SecretMetadata,
    SecretName,
    SecretProviderKind,
    SecretStatus,
    SecretValue,
)


class SecretManagerClient(Protocol):
    """HashiCorp Vault / AWS / GCP 等正式 secret manager 的共同 client contract。"""

    def put_secret(self, path: str, value: str, metadata: Mapping[str, str]) -> None:
        """寫入 secret。"""

    def get_secret(self, path: str) -> str:
        """讀取 secret 原文。"""

    def delete_secret(self, path: str) -> None:
        """刪除或撤銷 secret。"""

    def available(self) -> bool:
        """client 是否可用。"""


class ManagedSecretProvider(SecretProvider):
    """正式 secret manager adapter。S10 用 fake client 驗 contract，不接真雲。"""

    __slots__ = ("_client", "_metadata", "_provider_kind")

    def __init__(
        self,
        client: SecretManagerClient,
        provider_kind: SecretProviderKind = SecretProviderKind.VAULT,
    ) -> None:
        if provider_kind not in {
            SecretProviderKind.VAULT,
            SecretProviderKind.CLOUD_SECRET_MANAGER,
        }:
            raise SecretValidationError("ManagedSecretProvider 只支援 Vault / Cloud Secret Manager")
        self._client = client
        self._provider_kind = provider_kind
        self._metadata: dict[SecretName, SecretMetadata] = {}

    def set_secret(
        self,
        name: SecretName,
        value: SecretValue,
        metadata: SecretMetadata,
    ) -> SecretMetadata:
        self._ensure_available()
        stored = replace(
            metadata,
            name=name,
            provider=self._provider_kind,
            fingerprint=value.fingerprint(),
            status=SecretStatus.ACTIVE,
        ).with_update()
        self._client.put_secret(name.path(), value.reveal(), {"version": stored.version})
        self._metadata[name] = stored
        return stored

    def get_secret(self, name: SecretName) -> SecretValue:
        self._ensure_available()
        try:
            value = self._client.get_secret(name.path())
        except KeyError as exc:
            raise SecretNotFoundError(f"managed secret 不存在: {name.path()}") from exc
        if not value:
            raise SecretProviderError(f"managed secret manager 回傳空 secret: {name.path()}")
        return SecretValue(value)

    def delete_secret(self, name: SecretName) -> SecretMetadata:
        self._ensure_available()
        try:
            self._client.delete_secret(name.path())
        except KeyError as exc:
            raise SecretNotFoundError(f"managed secret 不存在: {name.path()}") from exc
        metadata = self.get_metadata(name).with_update(status=SecretStatus.DELETED)
        self._metadata[name] = metadata
        return metadata

    def exists(self, name: SecretName) -> bool:
        try:
            self.get_secret(name)
        except SecretNotFoundError:
            return False
        return True

    def list_metadata(self, tenant_id: str) -> tuple[SecretMetadata, ...]:
        if not tenant_id:
            raise SecretValidationError("tenant_id 不可為空")
        return tuple(
            metadata
            for key, metadata in sorted(self._metadata.items(), key=lambda item: item[0].path())
            if key.tenant_id == tenant_id and metadata.status is SecretStatus.ACTIVE
        )

    def get_metadata(self, name: SecretName) -> SecretMetadata:
        metadata = self._metadata.get(name)
        if metadata is None:
            raise SecretNotFoundError(f"managed metadata 不存在: {name.path()}")
        return metadata

    def rotate_secret(
        self,
        name: SecretName,
        new_value: SecretValue,
        reason: str,
    ) -> SecretMetadata:
        if not reason:
            raise SecretValidationError("rotation reason 不可為空")
        metadata = self.get_metadata(name)
        current_version = int(metadata.version.lstrip("v") or "0")
        return self.set_secret(
            name, new_value, metadata.with_update(version=f"v{current_version + 1}")
        )

    def _ensure_available(self) -> None:
        if not self._client.available():
            raise SecretProviderUnavailableError("managed secret manager client 不可用")


class VaultSecretProvider(ManagedSecretProvider):
    """HashiCorp Vault adapter skeleton。"""

    def __init__(self, client: SecretManagerClient) -> None:
        super().__init__(client, SecretProviderKind.VAULT)


class CloudSecretManagerProvider(ManagedSecretProvider):
    """AWS / GCP / Azure 類 Secret Manager adapter skeleton。"""

    def __init__(self, client: SecretManagerClient) -> None:
        super().__init__(client, SecretProviderKind.CLOUD_SECRET_MANAGER)
