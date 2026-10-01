"""測試與 demo 用 in-memory SecretProvider。"""

from __future__ import annotations

from dataclasses import replace

from src.security.vault.errors import SecretNotFoundError, SecretValidationError
from src.security.vault.provider import SecretProvider
from src.security.vault.types import (
    SecretMetadata,
    SecretName,
    SecretProviderKind,
    SecretStatus,
    SecretValue,
)


class InMemorySecretProvider(SecretProvider):
    """只供測試 / demo 使用的 provider。不可作為 production fallback。"""

    __slots__ = ("_metadata", "_values")

    def __init__(self) -> None:
        self._values: dict[SecretName, SecretValue] = {}
        self._metadata: dict[SecretName, SecretMetadata] = {}

    def set_secret(
        self,
        name: SecretName,
        value: SecretValue,
        metadata: SecretMetadata,
    ) -> SecretMetadata:
        stored = replace(
            metadata,
            name=name,
            provider=SecretProviderKind.MEMORY,
            fingerprint=value.fingerprint(),
            status=SecretStatus.ACTIVE,
        ).with_update()
        self._values[name] = value
        self._metadata[name] = stored
        return stored

    def get_secret(self, name: SecretName) -> SecretValue:
        value = self._values.get(name)
        if value is None:
            raise SecretNotFoundError(f"secret 不存在: {name.path()}")
        return value

    def delete_secret(self, name: SecretName) -> SecretMetadata:
        metadata = self.get_metadata(name)
        self._values.pop(name, None)
        deleted = metadata.with_update(status=SecretStatus.DELETED)
        self._metadata[name] = deleted
        return deleted

    def exists(self, name: SecretName) -> bool:
        return name in self._values

    def list_metadata(self, tenant_id: str) -> tuple[SecretMetadata, ...]:
        if not tenant_id:
            raise SecretValidationError("tenant_id 不可為空")
        return tuple(
            metadata
            for key, metadata in sorted(self._metadata.items(), key=lambda item: item[0].path())
            if key.tenant_id == tenant_id and key in self._values
        )

    def get_metadata(self, name: SecretName) -> SecretMetadata:
        metadata = self._metadata.get(name)
        if metadata is None:
            raise SecretNotFoundError(f"secret metadata 不存在: {name.path()}")
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
        rotated = metadata.with_update(
            fingerprint=new_value.fingerprint(),
            version=f"v{current_version + 1}",
            rotated_at=metadata.updated_at,
        )
        self._values[name] = new_value
        self._metadata[name] = rotated
        return rotated
