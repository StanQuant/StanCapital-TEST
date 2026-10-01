"""macOS Keychain provider adapter。

S10 預設用 fake runner 測試，不操作 Stanley 真 Keychain。
"""

from __future__ import annotations

from dataclasses import replace

from src.security.vault.command import CommandResult, CommandRunner, SubprocessCommandRunner
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


class KeychainSecretProvider(SecretProvider):
    """以 macOS `security` CLI 實作的 provider。"""

    __slots__ = ("_metadata", "_runner", "_service_prefix")

    def __init__(
        self,
        runner: CommandRunner | None = None,
        service_prefix: str = "stanquant-app",
    ) -> None:
        if not service_prefix:
            raise SecretValidationError("service_prefix 不可為空")
        self._runner = runner or SubprocessCommandRunner()
        self._service_prefix = service_prefix
        self._metadata: dict[SecretName, SecretMetadata] = {}

    def set_secret(
        self,
        name: SecretName,
        value: SecretValue,
        metadata: SecretMetadata,
    ) -> SecretMetadata:
        result = self._runner.run(
            [
                "security",
                "add-generic-password",
                "-U",
                "-s",
                self._service(name),
                "-a",
                self._account(name),
                "-w",
                value.reveal(),
            ]
        )
        self._ensure_ok(result, "keychain set failed")
        stored = replace(
            metadata,
            name=name,
            provider=SecretProviderKind.KEYCHAIN,
            fingerprint=value.fingerprint(),
            status=SecretStatus.ACTIVE,
        ).with_update()
        self._metadata[name] = stored
        return stored

    def get_secret(self, name: SecretName) -> SecretValue:
        result = self._runner.run(
            [
                "security",
                "find-generic-password",
                "-s",
                self._service(name),
                "-a",
                self._account(name),
                "-w",
            ]
        )
        if not result.ok:
            raise SecretNotFoundError(f"keychain secret 不存在: {name.path()}")
        value = result.stdout.rstrip("\n")
        if not value:
            raise SecretProviderError(f"keychain 回傳空 secret: {name.path()}")
        return SecretValue(value)

    def delete_secret(self, name: SecretName) -> SecretMetadata:
        result = self._runner.run(
            [
                "security",
                "delete-generic-password",
                "-s",
                self._service(name),
                "-a",
                self._account(name),
            ]
        )
        self._ensure_ok(result, "keychain delete failed")
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
            raise SecretNotFoundError(f"keychain metadata 不存在: {name.path()}")
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
        updated = metadata.with_update(version=f"v{current_version + 1}")
        return self.set_secret(name, new_value, updated)

    def _service(self, name: SecretName) -> str:
        return f"{self._service_prefix}/{name.tenant_id}/{name.service}"

    @staticmethod
    def _account(name: SecretName) -> str:
        return f"{name.purpose}/{name.environment}"

    @staticmethod
    def _ensure_ok(result: CommandResult, message: str) -> None:
        if result.ok:
            return
        if result.returncode == 127:
            raise SecretProviderUnavailableError("macOS security CLI 不可用")
        raise SecretProviderError(message)
