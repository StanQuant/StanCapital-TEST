"""connector secret fail-closed 測試。"""

from __future__ import annotations

import pytest
from src.security.vault.connector import SecretBackedConnector, require_connector_secret
from src.security.vault.errors import SecretNotFoundError, SecretValidationError
from src.security.vault.memory import InMemorySecretProvider
from src.security.vault.types import SecretMetadata, SecretName, SecretValue


def test_prediction_market_connector_fails_closed_without_secret(secret_name: SecretName) -> None:
    connector = SecretBackedConnector("prediction-market-paper", secret_name)
    provider = InMemorySecretProvider()
    with pytest.raises(SecretNotFoundError, match="拒絕初始化"):
        require_connector_secret(provider, connector)


def test_connector_secret_passes_when_metadata_exists(
    secret_name: SecretName,
    secret_value: SecretValue,
    secret_metadata: SecretMetadata,
) -> None:
    connector = SecretBackedConnector("prediction-market-paper", secret_name)
    provider = InMemorySecretProvider()
    stored = provider.set_secret(secret_name, secret_value, secret_metadata)
    assert require_connector_secret(provider, connector) == stored


def test_connector_name_required(secret_name: SecretName) -> None:
    with pytest.raises(SecretValidationError):
        SecretBackedConnector("", secret_name)
