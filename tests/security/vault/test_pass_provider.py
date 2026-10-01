"""Linux pass provider fake runner 測試。"""

from __future__ import annotations

import pytest
from src.security.vault.command import CommandResult
from src.security.vault.errors import (
    SecretNotFoundError,
    SecretProviderError,
    SecretProviderUnavailableError,
    SecretValidationError,
)
from src.security.vault.pass_provider import PassSecretProvider
from src.security.vault.types import SecretMetadata, SecretName, SecretProviderKind, SecretValue

from tests.security.vault.conftest import FakeRunner


def _path() -> str:
    return "stanquant-app/tenant/stanley/service/audit/purpose/hmac_signing/env/local"


def test_pass_provider_uses_pass_and_gpg_status_checks(
    secret_name: SecretName,
    secret_value: SecretValue,
    secret_metadata: SecretMetadata,
) -> None:
    runner = FakeRunner({("pass", "show", _path()): CommandResult(0, "stored-pass\n", "")})
    provider = PassSecretProvider(runner)
    stored = provider.set_secret(secret_name, secret_value, secret_metadata)
    assert stored.provider is SecretProviderKind.PASS
    assert provider.get_secret(secret_name).reveal() == "stored-pass"
    assert provider.exists(secret_name) is True
    assert provider.list_metadata("stanley") == (stored,)
    deleted = provider.delete_secret(secret_name)
    assert deleted.status.value == "deleted"
    assert ("pass", "--version") in [cmd.args for cmd in runner.commands]
    assert ("gpg", "--version") in [cmd.args for cmd in runner.commands]


def test_pass_provider_fail_closed_paths(secret_name: SecretName) -> None:
    provider = PassSecretProvider(FakeRunner({("pass", "show", _path()): CommandResult(1, "", "")}))
    assert provider.exists(secret_name) is False
    with pytest.raises(SecretNotFoundError):
        provider.get_secret(secret_name)
    with pytest.raises(SecretNotFoundError):
        provider.get_metadata(secret_name)
    with pytest.raises(SecretValidationError):
        provider.list_metadata("")


def test_pass_provider_unavailable_and_command_errors(
    secret_name: SecretName,
    secret_value: SecretValue,
    secret_metadata: SecretMetadata,
) -> None:
    no_pass = PassSecretProvider(FakeRunner({("pass", "--version"): CommandResult(127, "", "")}))
    with pytest.raises(SecretProviderUnavailableError):
        no_pass.get_secret(secret_name)
    no_gpg = PassSecretProvider(
        FakeRunner({("gpg", "--version"): CommandResult(127, "", "missing")})
    )
    with pytest.raises(SecretProviderUnavailableError):
        no_gpg.get_secret(secret_name)
    insert_fails = PassSecretProvider(
        FakeRunner({("pass", "insert", "-m", _path()): CommandResult(1, "", "boom")})
    )
    with pytest.raises(SecretProviderError):
        insert_fails.set_secret(secret_name, secret_value, secret_metadata)


def test_pass_provider_rejects_empty_prefix() -> None:
    with pytest.raises(SecretValidationError):
        PassSecretProvider(prefix="")


def test_pass_provider_empty_stdout_and_rotation(
    secret_name: SecretName,
    secret_value: SecretValue,
    secret_metadata: SecretMetadata,
) -> None:
    empty = PassSecretProvider(FakeRunner({("pass", "show", _path()): CommandResult(0, "", "")}))
    with pytest.raises(SecretProviderError):
        empty.get_secret(secret_name)
    provider = PassSecretProvider(FakeRunner())
    provider.set_secret(secret_name, secret_value, secret_metadata)
    rotated = provider.rotate_secret(secret_name, SecretValue("new-pass-value"), "scheduled")
    assert rotated.version == "v2"
    with pytest.raises(SecretValidationError):
        provider.rotate_secret(secret_name, SecretValue("x"), "")
