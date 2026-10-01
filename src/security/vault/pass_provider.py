"""Linux pass provider adapter。"""

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


class PassSecretProvider(SecretProvider):
    """以 Linux `pass` + GPG 實作的 provider。"""

    __slots__ = ("_metadata", "_prefix", "_runner")

    def __init__(
        self,
        runner: CommandRunner | None = None,
        prefix: str = "stanquant-app",
    ) -> None:
        if not prefix:
            raise SecretValidationError("prefix 不可為空")
        self._runner = runner or SubprocessCommandRunner()
        self._prefix = prefix
        self._metadata: dict[SecretName, SecretMetadata] = {}

    def set_secret(
        self,
        name: SecretName,
        value: SecretValue,
        metadata: SecretMetadata,
    ) -> SecretMetadata:
        self._ensure_available()
        result = self._runner.run(["pass", "insert", "-m", self._path(name)], value.reveal())
        self._ensure_ok(result, "pass insert failed")
        stored = replace(
            metadata,
            name=name,
            provider=SecretProviderKind.PASS,
            fingerprint=value.fingerprint(),
            status=SecretStatus.ACTIVE,
        ).with_update()
        self._metadata[name] = stored
        return stored

    def get_secret(self, name: SecretName) -> SecretValue:
        self._ensure_available()
        result = self._runner.run(["pass", "show", self._path(name)])
        if not result.ok:
            raise SecretNotFoundError(f"pass secret 不存在: {name.path()}")
        value = result.stdout.rstrip("\n")
        if not value:
            raise SecretProviderError(f"pass 回傳空 secret: {name.path()}")
        return SecretValue(value)

    def delete_secret(self, name: SecretName) -> SecretMetadata:
        self._ensure_available()
        result = self._runner.run(["pass", "rm", "-f", self._path(name)])
        self._ensure_ok(result, "pass rm failed")
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
            raise SecretNotFoundError(f"pass metadata 不存在: {name.path()}")
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

    def _path(self, name: SecretName) -> str:
        return f"{self._prefix}/{name.path()}"

    def _ensure_available(self) -> None:
        pass_result = self._runner.run(["pass", "--version"])
        if not pass_result.ok:
            raise SecretProviderUnavailableError("pass CLI 不可用或 password store 未初始化")
        gpg_result = self._runner.run(["gpg", "--version"])
        if not gpg_result.ok:
            raise SecretProviderUnavailableError("GPG 不可用，pass provider 無法解密 secret")

    @staticmethod
    def _ensure_ok(result: CommandResult, message: str) -> None:
        if result.ok:
            return
        raise SecretProviderError(message)
