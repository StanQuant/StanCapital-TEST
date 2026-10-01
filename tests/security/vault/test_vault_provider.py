"""Managed Vault / Cloud Secret Manager provider 測試。"""

from __future__ import annotations

import pytest
from src.security.vault.errors import (
    SecretNotFoundError,
    SecretProviderError,
    SecretProviderUnavailableError,
    SecretValidationError,
)
from src.security.vault.types import SecretMetadata, SecretName, SecretProviderKind, SecretValue
from src.security.vault.vault_provider import (
    CloudSecretManagerProvider,
    ManagedSecretProvider,
    VaultSecretProvider,
)

from tests.security.vault.conftest import FakeSecretManagerClient


def test_vault_provider_contract(
    secret_name: SecretName,
    secret_value: SecretValue,
    secret_metadata: SecretMetadata,
) -> None:
    client = FakeSecretManagerClient()
    provider = VaultSecretProvider(client)
    stored = provider.set_secret(secret_name, secret_value, secret_metadata)
    assert stored.provider is SecretProviderKind.VAULT
    assert provider.get_secret(secret_name).reveal() == secret_value.reveal()
    assert provider.exists(secret_name) is True
    assert provider.list_metadata("stanley") == (stored,)
    assert client.metadata[secret_name.path()] == {"version": "v1"}
    deleted = provider.delete_secret(secret_name)
    assert deleted.status.value == "deleted"
    assert provider.exists(secret_name) is False


def test_cloud_secret_manager_provider_contract(
    secret_name: SecretName,
    secret_value: SecretValue,
    secret_metadata: SecretMetadata,
) -> None:
    client = FakeSecretManagerClient()
    provider = CloudSecretManagerProvider(client)
    stored = provider.set_secret(secret_name, secret_value, secret_metadata)
    assert stored.provider is SecretProviderKind.CLOUD_SECRET_MANAGER
    rotated = provider.rotate_secret(secret_name, SecretValue("cloud-new"), "scheduled")
    assert rotated.version == "v2"
    assert provider.get_secret(secret_name).reveal() == "cloud-new"


def test_managed_provider_fail_closed_paths(secret_name: SecretName) -> None:
    unavailable = VaultSecretProvider(FakeSecretManagerClient(available=False))
    with pytest.raises(SecretProviderUnavailableError):
        unavailable.get_secret(secret_name)
    provider = VaultSecretProvider(FakeSecretManagerClient())
    assert provider.exists(secret_name) is False
    with pytest.raises(SecretNotFoundError):
        provider.get_secret(secret_name)
    with pytest.raises(SecretNotFoundError):
        provider.get_metadata(secret_name)
    with pytest.raises(SecretValidationError):
        provider.list_metadata("")


def test_managed_provider_validation_and_empty_secret(
    secret_name: SecretName,
    secret_metadata: SecretMetadata,
) -> None:
    with pytest.raises(SecretValidationError):
        ManagedSecretProvider(FakeSecretManagerClient(), SecretProviderKind.MEMORY)
    client = FakeSecretManagerClient()
    client.values[secret_name.path()] = ""
    provider = VaultSecretProvider(client)
    with pytest.raises(SecretProviderError):
        provider.get_secret(secret_name)
    with pytest.raises(SecretValidationError):
        provider.rotate_secret(secret_name, SecretValue("x"), "")


def test_managed_provider_delete_missing_after_metadata_exists(
    secret_name: SecretName,
    secret_value: SecretValue,
    secret_metadata: SecretMetadata,
) -> None:
    client = FakeSecretManagerClient()
    provider = VaultSecretProvider(client)
    provider.set_secret(secret_name, secret_value, secret_metadata)
    client.values.clear()
    with pytest.raises(SecretNotFoundError):
        provider.delete_secret(secret_name)
