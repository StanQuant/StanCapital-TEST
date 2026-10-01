"""S10 測試 fixture。"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

import pytest
from src.security.vault.command import CommandResult
from src.security.vault.types import (
    SecretMetadata,
    SecretName,
    SecretProviderKind,
    SecretValue,
)


@pytest.fixture
def secret_name() -> SecretName:
    return SecretName(
        tenant_id="stanley",
        service="audit",
        purpose="hmac_signing",
        environment="local",
    )


@pytest.fixture
def secret_value() -> SecretValue:
    return SecretValue("sq_test_secret_value_123")


@pytest.fixture
def secret_metadata(secret_name: SecretName, secret_value: SecretValue) -> SecretMetadata:
    return SecretMetadata(
        name=secret_name,
        provider=SecretProviderKind.MEMORY,
        version="v1",
        fingerprint=secret_value.fingerprint(),
        labels={"scope": "audit_hmac"},
    )


@dataclass(slots=True)
class RecordedCommand:
    args: tuple[str, ...]
    input_text: str | None


class FakeRunner:
    """fake CLI runner，避免測試碰真 Keychain / pass。"""

    def __init__(self, responses: Mapping[tuple[str, ...], CommandResult] | None = None) -> None:
        self.responses = dict(responses or {})
        self.commands: list[RecordedCommand] = []

    def run(self, args: Sequence[str], input_text: str | None = None) -> CommandResult:
        key = tuple(args)
        self.commands.append(RecordedCommand(key, input_text))
        return self.responses.get(key, CommandResult(0, "ok\n", ""))


class FakeSecretManagerClient:
    """fake managed secret client。"""

    def __init__(self, *, available: bool = True) -> None:
        self.is_available = available
        self.values: dict[str, str] = {}
        self.metadata: dict[str, dict[str, str]] = {}

    def put_secret(self, path: str, value: str, metadata: Mapping[str, str]) -> None:
        self.values[path] = value
        self.metadata[path] = dict(metadata)

    def get_secret(self, path: str) -> str:
        return self.values[path]

    def delete_secret(self, path: str) -> None:
        del self.values[path]

    def available(self) -> bool:
        return self.is_available
