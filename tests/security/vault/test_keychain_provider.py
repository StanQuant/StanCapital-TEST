"""macOS Keychain provider fake runner 測試。"""

from __future__ import annotations

import pytest
from src.security.vault.command import CommandResult
from src.security.vault.errors import (
    SecretNotFoundError,
    SecretProviderError,
    SecretProviderUnavailableError,
    SecretValidationError,
)
from src.security.vault.keychain import KeychainSecretProvider
from src.security.vault.types import SecretMetadata, SecretName, SecretProviderKind, SecretValue

from tests.security.vault.conftest import FakeRunner


def test_keychain_provider_uses_security_cli_without_real_keychain(
    secret_name: SecretName,
    secret_value: SecretValue,
    secret_metadata: SecretMetadata,
) -> None:
    find_cmd = (
        "security",
        "find-generic-password",
        "-s",
        "stanquant-app/stanley/audit",
        "-a",
        "hmac_signing/local",
        "-w",
    )
    runner = FakeRunner({find_cmd: CommandResult(0, "stored-secret\n", "")})
    provider = KeychainSecretProvider(runner)
    stored = provider.set_secret(secret_name, secret_value, secret_metadata)
    assert stored.provider is SecretProviderKind.KEYCHAIN
    assert provider.get_secret(secret_name).reveal() == "stored-secret"
    assert provider.exists(secret_name) is True
    assert provider.list_metadata("stanley") == (stored,)
    deleted = provider.delete_secret(secret_name)
    assert deleted.status.value == "deleted"
    assert runner.commands[0].args[:3] == ("security", "add-generic-password", "-U")
    assert runner.commands[0].input_text is None


def test_keychain_provider_fail_closed_paths(
    secret_name: SecretName,
    secret_metadata: SecretMetadata,
) -> None:
    missing_cmd = (
        "security",
        "find-generic-password",
        "-s",
        "stanquant-app/stanley/audit",
        "-a",
        "hmac_signing/local",
        "-w",
    )
    provider = KeychainSecretProvider(FakeRunner({missing_cmd: CommandResult(44, "", "missing")}))
    assert provider.exists(secret_name) is False
    with pytest.raises(SecretNotFoundError):
        provider.get_secret(secret_name)
    with pytest.raises(SecretNotFoundError):
        provider.get_metadata(secret_name)
    with pytest.raises(SecretValidationError):
        provider.list_metadata("")

    unavailable = KeychainSecretProvider(
        FakeRunner(
            {
                (
                    "security",
                    "add-generic-password",
                    "-U",
                    "-s",
                    "stanquant-app/stanley/audit",
                    "-a",
                    "hmac_signing/local",
                    "-w",
                    "x",
                ): CommandResult(127, "", "not found")
            }
        )
    )
    with pytest.raises(SecretProviderUnavailableError):
        unavailable.set_secret(secret_name, SecretValue("x"), secret_metadata)
    broken = KeychainSecretProvider(
        FakeRunner(
            {
                (
                    "security",
                    "add-generic-password",
                    "-U",
                    "-s",
                    "stanquant-app/stanley/audit",
                    "-a",
                    "hmac_signing/local",
                    "-w",
                    "x",
                ): CommandResult(1, "", "boom")
            }
        )
    )
    with pytest.raises(SecretProviderError):
        broken.set_secret(secret_name, SecretValue("x"), secret_metadata)


def test_keychain_provider_rejects_empty_service_prefix() -> None:
    with pytest.raises(SecretValidationError):
        KeychainSecretProvider(service_prefix="")


def test_keychain_provider_empty_stdout_is_error(secret_name: SecretName) -> None:
    find_cmd = (
        "security",
        "find-generic-password",
        "-s",
        "stanquant-app/stanley/audit",
        "-a",
        "hmac_signing/local",
        "-w",
    )
    provider = KeychainSecretProvider(FakeRunner({find_cmd: CommandResult(0, "", "")}))
    with pytest.raises(SecretProviderError):
        provider.get_secret(secret_name)


def test_keychain_provider_rotation(
    secret_name: SecretName,
    secret_value: SecretValue,
    secret_metadata: SecretMetadata,
) -> None:
    provider = KeychainSecretProvider(FakeRunner())
    provider.set_secret(secret_name, secret_value, secret_metadata)
    rotated = provider.rotate_secret(secret_name, SecretValue("new-keychain-value"), "scheduled")
    assert rotated.version == "v2"
    with pytest.raises(SecretValidationError):
        provider.rotate_secret(secret_name, SecretValue("x"), "")
