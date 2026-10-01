"""InMemorySecretProvider 測試。"""

from __future__ import annotations

import pytest
from src.security.vault.errors import SecretNotFoundError, SecretValidationError
from src.security.vault.memory import InMemorySecretProvider
from src.security.vault.types import SecretMetadata, SecretName, SecretStatus, SecretValue


def test_memory_provider_crud_and_metadata(
    secret_name: SecretName,
    secret_value: SecretValue,
    secret_metadata: SecretMetadata,
) -> None:
    provider = InMemorySecretProvider()
    stored = provider.set_secret(secret_name, secret_value, secret_metadata)
    assert stored.provider.value == "memory"
    assert provider.exists(secret_name) is True
    assert provider.get_secret(secret_name).reveal() == "sq_test_secret_value_123"
    assert provider.get_metadata(secret_name).fingerprint == secret_value.fingerprint()
    assert provider.list_metadata("stanley") == (stored,)
    assert provider.list_metadata("other") == ()

    deleted = provider.delete_secret(secret_name)
    assert deleted.status is SecretStatus.DELETED
    assert provider.exists(secret_name) is False
    assert provider.get_metadata(secret_name).status is SecretStatus.DELETED
    assert provider.list_metadata("stanley") == ()
    with pytest.raises(SecretNotFoundError):
        provider.get_secret(secret_name)


def test_memory_provider_missing_and_validation(secret_name: SecretName) -> None:
    provider = InMemorySecretProvider()
    with pytest.raises(SecretNotFoundError):
        provider.get_secret(secret_name)
    with pytest.raises(SecretNotFoundError):
        provider.get_metadata(secret_name)
    with pytest.raises(SecretValidationError):
        provider.list_metadata("")


def test_memory_provider_rotation(
    secret_name: SecretName,
    secret_value: SecretValue,
    secret_metadata: SecretMetadata,
) -> None:
    provider = InMemorySecretProvider()
    stored = provider.set_secret(secret_name, secret_value, secret_metadata)
    rotated = provider.rotate_secret(secret_name, SecretValue("new_secret_value"), "scheduled")
    assert rotated.version == "v2"
    assert rotated.status is SecretStatus.ACTIVE
    assert rotated.fingerprint == SecretValue("new_secret_value").fingerprint()
    assert rotated.rotated_at == stored.updated_at
    assert provider.get_secret(secret_name).reveal() == "new_secret_value"
    with pytest.raises(SecretValidationError, match="reason"):
        provider.rotate_secret(secret_name, SecretValue("x"), "")


def test_memory_provider_rotation_fails_closed_for_missing_secret(secret_name: SecretName) -> None:
    provider = InMemorySecretProvider()

    with pytest.raises(SecretValidationError, match="reason"):
        provider.rotate_secret(secret_name, SecretValue("new_secret_value"), "")
    with pytest.raises(SecretNotFoundError):
        provider.rotate_secret(secret_name, SecretValue("new_secret_value"), "scheduled")
