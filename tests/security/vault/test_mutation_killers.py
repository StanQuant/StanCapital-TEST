"""S10 mutation 殺手測試。

針對 docs/slices/S10-mutation-review.md 的 survivor 補強（比照 S07 前例）：
1. 錯誤訊息全部用完整字串釘住——訊息是 incident response 與法遵稽核的介面。
2. 跨租戶隔離、redaction、不可變值物件等安全契約用行為測試釘死。
3. CLI adapter 的命令參數、版本解析 fail-closed、刪除後 metadata 保留一併鎖定。
等價變異（型別註解、無實效 __slots__、被覆寫的 dataclass repr 參數、
redaction 子字串冗餘鍵）列於 mutation-review 豁免清單，不在此檔硬殺。
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import FrozenInstanceError, replace
from datetime import datetime

import pytest
from src.security.vault.audit import SecretAuditEvent
from src.security.vault.command import CommandResult
from src.security.vault.connector import SecretBackedConnector, require_connector_secret
from src.security.vault.errors import (
    SecretNotFoundError,
    SecretProviderError,
    SecretProviderUnavailableError,
    SecretValidationError,
)
from src.security.vault.keychain import KeychainSecretProvider
from src.security.vault.memory import InMemorySecretProvider
from src.security.vault.pass_provider import PassSecretProvider
from src.security.vault.redaction import contains_plaintext
from src.security.vault.rotation import (
    DEFAULT_ROTATION_TEMPLATE,
    RotationTemplate,
    rotation_due,
    rotation_notice_due,
)
from src.security.vault.sinks import SecretAuditProjection, _hash_redacted_payload
from src.security.vault.types import (
    SecretAction,
    SecretMetadata,
    SecretName,
    SecretProviderKind,
    SecretRotationPolicy,
    SecretStatus,
    SecretValue,
)
from src.security.vault.vault_provider import ManagedSecretProvider, VaultSecretProvider

from tests.security.vault.conftest import FakeRunner, FakeSecretManagerClient

_NAIVE = datetime(2026, 1, 1)  # 故意 naive，測 tz-aware 驗證。
_SHA256_HEX = "a" * 64


def _assert_raises_message(
    exc_type: type[BaseException], message: str, call: Callable[[], object]
) -> None:
    """斷言呼叫拋出指定例外且訊息完全一致（釘住訊息文案，殺 string mutant）。"""
    with pytest.raises(exc_type) as excinfo:
        call()
    assert str(excinfo.value) == message


def _other_name() -> SecretName:
    return SecretName(
        tenant_id="other",
        service="audit",
        purpose="hmac_signing",
        environment="local",
    )


def _name_for(service: str) -> SecretName:
    return SecretName(
        tenant_id="stanley",
        service=service,
        purpose="hmac_signing",
        environment="local",
    )


# ---------------------------------------------------------------------------
# types.py — 錯誤訊息契約
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {"tenant_id": "", "service": "s", "purpose": "p", "environment": "e"},
            "tenant_id 不可為空",
        ),
        (
            {"tenant_id": "t", "service": "", "purpose": "p", "environment": "e"},
            "service 不可為空",
        ),
        (
            {"tenant_id": "t", "service": "s", "purpose": "", "environment": "e"},
            "purpose 不可為空",
        ),
        (
            {"tenant_id": "t", "service": "s", "purpose": "p", "environment": ""},
            "environment 不可為空",
        ),
        (
            {"tenant_id": "bad/val", "service": "s", "purpose": "p", "environment": "e"},
            "tenant_id 只能使用英數、底線、點、連字號，且不可含路徑符號: bad/val",
        ),
    ],
)
def test_secret_name_validation_messages(kwargs: dict[str, str], message: str) -> None:
    with pytest.raises(SecretValidationError) as excinfo:
        SecretName(**kwargs)
    assert str(excinfo.value) == message


def test_secret_value_validation_messages() -> None:
    with pytest.raises(SecretValidationError) as excinfo:
        SecretValue("")
    assert str(excinfo.value) == "secret value 不可為空"
    with pytest.raises(SecretValidationError) as excinfo:
        SecretValue("abc").fingerprint(7)
    assert str(excinfo.value) == "fingerprint length 必須在 8-64 之間"


def test_secret_value_requires_plaintext_argument() -> None:
    with pytest.raises(TypeError):
        SecretValue()  # type: ignore[call-arg]


def test_secret_value_fingerprint_accepts_boundary_lengths() -> None:
    value = SecretValue("abc")
    digest = hashlib.sha256(b"abc").hexdigest()
    assert value.fingerprint(8) == digest[:8]
    assert value.fingerprint(64) == digest


def test_secret_value_is_frozen_and_slotted() -> None:
    value = SecretValue("abc")
    with pytest.raises(FrozenInstanceError):
        value.plaintext = "changed"  # type: ignore[misc]
    assert not hasattr(value, "__dict__")


def test_secret_metadata_is_frozen_and_slotted(secret_metadata: SecretMetadata) -> None:
    with pytest.raises(FrozenInstanceError):
        secret_metadata.version = "v9"  # type: ignore[misc]
    assert not hasattr(secret_metadata, "__dict__")


def test_secret_metadata_labels_default_to_empty_mapping(
    secret_name: SecretName, secret_value: SecretValue
) -> None:
    metadata = SecretMetadata(
        name=secret_name,
        provider=SecretProviderKind.MEMORY,
        version="v1",
        fingerprint=secret_value.fingerprint(),
    )
    assert dict(metadata.labels) == {}


def test_secret_metadata_validation_messages(
    secret_name: SecretName, secret_value: SecretValue
) -> None:
    base = {
        "name": secret_name,
        "provider": SecretProviderKind.MEMORY,
        "version": "v1",
        "fingerprint": secret_value.fingerprint(),
    }
    cases = [
        ({**base, "version": ""}, "version 不可為空"),
        ({**base, "fingerprint": ""}, "fingerprint 不可為空"),
        ({**base, "created_at": _NAIVE}, "created_at 必須是 tz-aware 時間"),
        ({**base, "updated_at": _NAIVE}, "updated_at 必須是 tz-aware 時間"),
        ({**base, "rotated_at": _NAIVE}, "rotated_at 必須是 tz-aware 時間"),
        ({**base, "expires_at": _NAIVE}, "expires_at 必須是 tz-aware 時間"),
        ({**base, "labels": {"": "x"}}, "label key 不可為空"),
        ({**base, "labels": {"scope": ""}}, "label value 不可為空"),
    ]
    for kwargs, message in cases:
        with pytest.raises(SecretValidationError) as excinfo:
            SecretMetadata(**kwargs)  # type: ignore[arg-type]
        assert str(excinfo.value) == message


def test_rotation_policy_defaults_and_boundaries() -> None:
    policy = SecretRotationPolicy()
    assert policy.max_age_days == 90
    assert policy.notify_before_days == 14
    tight = SecretRotationPolicy(max_age_days=1, notify_before_days=0)
    assert tight.notify_before_days == 0
    with pytest.raises(FrozenInstanceError):
        policy.max_age_days = 1  # type: ignore[misc]
    assert not hasattr(policy, "__dict__")


def test_rotation_policy_validation_messages() -> None:
    with pytest.raises(SecretValidationError) as excinfo:
        SecretRotationPolicy(max_age_days=0)
    assert str(excinfo.value) == "max_age_days 必須大於 0"
    with pytest.raises(SecretValidationError) as excinfo:
        SecretRotationPolicy(max_age_days=90, notify_before_days=95)
    assert str(excinfo.value) == "notify_before_days 必須小於 max_age_days 且不可為負"


# ---------------------------------------------------------------------------
# command.py — CommandResult 值物件契約
# ---------------------------------------------------------------------------


def test_command_result_defaults_frozen_and_slotted() -> None:
    result = CommandResult(0)
    assert result.stdout == ""
    assert result.stderr == ""
    with pytest.raises(FrozenInstanceError):
        result.returncode = 1  # type: ignore[misc]
    assert not hasattr(result, "__dict__")


# ---------------------------------------------------------------------------
# audit.py / connector.py — 不可變與訊息契約
# ---------------------------------------------------------------------------


def _event(metadata: SecretMetadata, **overrides: object) -> SecretAuditEvent:
    kwargs: dict[str, object] = {
        "action": SecretAction.READ,
        "metadata": metadata,
        "actor_id": "agent-1",
        "trace_id": "trace-1",
        "result": "success",
        "reason": "mutation killer",
    }
    kwargs.update(overrides)
    return SecretAuditEvent(**kwargs)  # type: ignore[arg-type]


def test_secret_audit_event_is_frozen_and_slotted(secret_metadata: SecretMetadata) -> None:
    event = _event(secret_metadata)
    with pytest.raises(FrozenInstanceError):
        event.result = "tampered"  # type: ignore[misc]
    assert not hasattr(event, "__dict__")


def test_secret_audit_event_validation_messages(secret_metadata: SecretMetadata) -> None:
    with pytest.raises(ValueError) as excinfo:
        _event(secret_metadata, actor_id="")
    assert str(excinfo.value) == "actor_id 不可為空"
    with pytest.raises(ValueError) as excinfo:
        _event(secret_metadata, timestamp=_NAIVE)
    assert str(excinfo.value) == "timestamp 必須是 tz-aware 時間"
    with pytest.raises(ValueError) as excinfo:
        _event(secret_metadata, failure_category="")
    assert str(excinfo.value) == "failure_category 不可為空字串"


def test_secret_backed_connector_is_frozen_slotted_with_messages(
    secret_name: SecretName,
) -> None:
    connector = SecretBackedConnector("polymarket", secret_name)
    with pytest.raises(FrozenInstanceError):
        connector.connector_name = "x"  # type: ignore[misc]
    assert not hasattr(connector, "__dict__")
    _assert_raises_message(
        SecretValidationError,
        "connector_name 不可為空",
        lambda: SecretBackedConnector("", secret_name),
    )
    _assert_raises_message(
        SecretNotFoundError,
        "connector secret 未進 Vault，拒絕初始化: polymarket",
        lambda: require_connector_secret(InMemorySecretProvider(), connector),
    )


# ---------------------------------------------------------------------------
# redaction.py — repr / str 單邊外漏也要抓到
# ---------------------------------------------------------------------------


class _ReprOnlyLeak:
    def __repr__(self) -> str:
        return "sq_leak_via_repr_only"

    def __str__(self) -> str:
        return "safe"


class _StrOnlyLeak:
    def __repr__(self) -> str:
        return "safe"

    def __str__(self) -> str:
        return "sq_leak_via_str_only"


def test_contains_plaintext_detects_single_channel_leaks() -> None:
    repr_secret = SecretValue("sq_leak_via_repr_only")
    str_secret = SecretValue("sq_leak_via_str_only")
    assert contains_plaintext(_ReprOnlyLeak(), repr_secret) is True
    assert contains_plaintext(_StrOnlyLeak(), str_secret) is True
    assert contains_plaintext("clean payload", repr_secret) is False


# ---------------------------------------------------------------------------
# rotation.py — 訊息與範本契約
# ---------------------------------------------------------------------------


def test_rotation_helpers_reject_naive_now(secret_metadata: SecretMetadata) -> None:
    policy = SecretRotationPolicy()
    with pytest.raises(ValueError) as excinfo:
        rotation_due(secret_metadata, policy, now=_NAIVE)
    assert str(excinfo.value) == "now 必須是 tz-aware 時間"
    with pytest.raises(ValueError) as excinfo:
        rotation_notice_due(secret_metadata, policy, now=_NAIVE)
    assert str(excinfo.value) == "now 必須是 tz-aware 時間"


def test_rotation_template_is_frozen_slotted_with_messages() -> None:
    template = RotationTemplate(schedule="0 3 * * *", command="echo rotate")
    with pytest.raises(FrozenInstanceError):
        template.schedule = "x"  # type: ignore[misc]
    assert not hasattr(template, "__dict__")
    with pytest.raises(ValueError) as excinfo:
        RotationTemplate(schedule="", command="echo rotate")
    assert str(excinfo.value) == "schedule 不可為空"
    with pytest.raises(ValueError) as excinfo:
        RotationTemplate(schedule="0 3 * * *", command="")
    assert str(excinfo.value) == "command 不可為空"


def test_default_rotation_template_contract() -> None:
    assert DEFAULT_ROTATION_TEMPLATE.schedule == "0 3 * * *"
    assert DEFAULT_ROTATION_TEMPLATE.command == (
        "cd /app && .venv/bin/python -m src.security.vault.rotate "
        "--policy max-age-days=90 --dry-run"
    )
    assert DEFAULT_ROTATION_TEMPLATE.render() == (
        "0 3 * * * cd /app && .venv/bin/python -m src.security.vault.rotate "
        "--policy max-age-days=90 --dry-run\n"
    )


# ---------------------------------------------------------------------------
# memory.py — 訊息、排序、rotate 狀態、版本解析 fail-closed
# ---------------------------------------------------------------------------


def test_memory_provider_error_messages(secret_name: SecretName) -> None:
    provider = InMemorySecretProvider()
    _assert_raises_message(
        SecretNotFoundError,
        f"secret 不存在: {secret_name.path()}",
        lambda: provider.get_secret(secret_name),
    )
    _assert_raises_message(
        SecretNotFoundError,
        f"secret metadata 不存在: {secret_name.path()}",
        lambda: provider.get_metadata(secret_name),
    )
    _assert_raises_message(
        SecretValidationError,
        "tenant_id 不可為空",
        lambda: provider.list_metadata(""),
    )


def test_memory_provider_list_metadata_sorted_by_path(
    secret_value: SecretValue, secret_metadata: SecretMetadata
) -> None:
    provider = InMemorySecretProvider()
    late = _name_for("zzz-service")
    early = _name_for("aaa-service")
    provider.set_secret(late, secret_value, secret_metadata)
    provider.set_secret(early, secret_value, secret_metadata)
    listed = provider.list_metadata("stanley")
    assert [m.name for m in listed] == [early, late]


def test_memory_provider_rotate_persists_rotated_metadata(
    secret_name: SecretName, secret_value: SecretValue, secret_metadata: SecretMetadata
) -> None:
    provider = InMemorySecretProvider()
    provider.set_secret(secret_name, secret_value, secret_metadata)
    rotated = provider.rotate_secret(secret_name, SecretValue("new-secret-1"), "scheduled")
    assert provider.get_metadata(secret_name) == rotated
    assert rotated.version == "v2"
    with pytest.raises(SecretValidationError) as excinfo:
        provider.rotate_secret(secret_name, SecretValue("new-secret-2"), "")
    assert str(excinfo.value) == "rotation reason 不可為空"


def test_memory_provider_rotate_version_parsing_fail_closed(
    secret_name: SecretName, secret_value: SecretValue, secret_metadata: SecretMetadata
) -> None:
    provider = InMemorySecretProvider()
    provider.set_secret(secret_name, secret_value, replace(secret_metadata, version="v"))
    rotated = provider.rotate_secret(secret_name, SecretValue("new-secret-1"), "empty version")
    assert rotated.version == "v1"
    provider.set_secret(secret_name, secret_value, replace(secret_metadata, version="vX3"))
    with pytest.raises(ValueError, match="X3"):
        provider.rotate_secret(secret_name, SecretValue("new-secret-2"), "bad version")


# ---------------------------------------------------------------------------
# keychain.py — 命令契約、租戶隔離、rstrip、訊息
# ---------------------------------------------------------------------------

_FIND_CMD = (
    "security",
    "find-generic-password",
    "-s",
    "stanquant-app/stanley/audit",
    "-a",
    "hmac_signing/local",
    "-w",
)


def test_keychain_delete_issues_exact_security_command(
    secret_name: SecretName, secret_value: SecretValue, secret_metadata: SecretMetadata
) -> None:
    runner = FakeRunner()
    provider = KeychainSecretProvider(runner)
    provider.set_secret(secret_name, secret_value, secret_metadata)
    deleted = provider.delete_secret(secret_name)
    assert runner.commands[-1].args == (
        "security",
        "delete-generic-password",
        "-s",
        "stanquant-app/stanley/audit",
        "-a",
        "hmac_signing/local",
    )
    assert deleted.status is SecretStatus.DELETED
    assert provider.get_metadata(secret_name).status is SecretStatus.DELETED


def test_keychain_get_secret_only_strips_trailing_newline(
    secret_name: SecretName,
) -> None:
    runner = FakeRunner({_FIND_CMD: CommandResult(0, "valueX\n", "")})
    provider = KeychainSecretProvider(runner)
    assert provider.get_secret(secret_name).reveal() == "valueX"


def test_keychain_list_metadata_isolates_tenant_and_status(
    secret_name: SecretName, secret_value: SecretValue, secret_metadata: SecretMetadata
) -> None:
    provider = KeychainSecretProvider(FakeRunner())
    other = _other_name()
    other_stored = provider.set_secret(other, secret_value, secret_metadata)
    provider.set_secret(secret_name, secret_value, secret_metadata)
    provider.delete_secret(secret_name)
    assert provider.list_metadata("stanley") == ()
    assert provider.list_metadata("other") == (other_stored,)


def test_keychain_list_metadata_sorted_by_path(
    secret_value: SecretValue, secret_metadata: SecretMetadata
) -> None:
    provider = KeychainSecretProvider(FakeRunner())
    late = _name_for("zzz-service")
    early = _name_for("aaa-service")
    provider.set_secret(late, secret_value, secret_metadata)
    provider.set_secret(early, secret_value, secret_metadata)
    assert [m.name for m in provider.list_metadata("stanley")] == [early, late]


def test_keychain_error_messages(
    secret_name: SecretName, secret_value: SecretValue, secret_metadata: SecretMetadata
) -> None:
    _assert_raises_message(
        SecretValidationError,
        "service_prefix 不可為空",
        lambda: KeychainSecretProvider(FakeRunner(), service_prefix=""),
    )

    missing = KeychainSecretProvider(FakeRunner({_FIND_CMD: CommandResult(44, "", "missing")}))
    _assert_raises_message(
        SecretNotFoundError,
        f"keychain secret 不存在: {secret_name.path()}",
        lambda: missing.get_secret(secret_name),
    )
    _assert_raises_message(
        SecretNotFoundError,
        f"keychain metadata 不存在: {secret_name.path()}",
        lambda: missing.get_metadata(secret_name),
    )
    _assert_raises_message(
        SecretValidationError,
        "tenant_id 不可為空",
        lambda: missing.list_metadata(""),
    )

    empty = KeychainSecretProvider(FakeRunner({_FIND_CMD: CommandResult(0, "\n", "")}))
    _assert_raises_message(
        SecretProviderError,
        f"keychain 回傳空 secret: {secret_name.path()}",
        lambda: empty.get_secret(secret_name),
    )

    add_cmd = (
        "security",
        "add-generic-password",
        "-U",
        "-s",
        "stanquant-app/stanley/audit",
        "-a",
        "hmac_signing/local",
        "-w",
        secret_value.reveal(),
    )
    failing = KeychainSecretProvider(FakeRunner({add_cmd: CommandResult(1, "", "boom")}))
    _assert_raises_message(
        SecretProviderError,
        "keychain set failed",
        lambda: failing.set_secret(secret_name, secret_value, secret_metadata),
    )

    unavailable = KeychainSecretProvider(FakeRunner({add_cmd: CommandResult(127, "", "")}))
    _assert_raises_message(
        SecretProviderUnavailableError,
        "macOS security CLI 不可用",
        lambda: unavailable.set_secret(secret_name, secret_value, secret_metadata),
    )

    delete_cmd = (
        "security",
        "delete-generic-password",
        "-s",
        "stanquant-app/stanley/audit",
        "-a",
        "hmac_signing/local",
    )
    failing_delete = KeychainSecretProvider(FakeRunner({delete_cmd: CommandResult(1, "", "")}))
    failing_delete.set_secret(secret_name, secret_value, secret_metadata)
    _assert_raises_message(
        SecretProviderError,
        "keychain delete failed",
        lambda: failing_delete.delete_secret(secret_name),
    )

    ok_provider = KeychainSecretProvider(FakeRunner())
    ok_provider.set_secret(secret_name, secret_value, secret_metadata)
    _assert_raises_message(
        SecretValidationError,
        "rotation reason 不可為空",
        lambda: ok_provider.rotate_secret(secret_name, secret_value, ""),
    )


def test_keychain_rotate_version_parsing_fail_closed(
    secret_name: SecretName, secret_value: SecretValue, secret_metadata: SecretMetadata
) -> None:
    provider = KeychainSecretProvider(FakeRunner())
    provider.set_secret(secret_name, secret_value, replace(secret_metadata, version="v"))
    rotated = provider.rotate_secret(secret_name, SecretValue("new-secret-1"), "empty version")
    assert rotated.version == "v1"
    provider.set_secret(secret_name, secret_value, replace(secret_metadata, version="vX3"))
    with pytest.raises(ValueError, match="X3"):
        provider.rotate_secret(secret_name, SecretValue("new-secret-2"), "bad version")


# ---------------------------------------------------------------------------
# pass_provider.py — 同一組安全契約
# ---------------------------------------------------------------------------

_PASS_PATH = "stanquant-app/tenant/stanley/service/audit/purpose/hmac_signing/env/local"
_SHOW_CMD = ("pass", "show", _PASS_PATH)


def test_pass_delete_issues_exact_command_and_keeps_metadata(
    secret_name: SecretName, secret_value: SecretValue, secret_metadata: SecretMetadata
) -> None:
    runner = FakeRunner()
    provider = PassSecretProvider(runner)
    provider.set_secret(secret_name, secret_value, secret_metadata)
    deleted = provider.delete_secret(secret_name)
    assert runner.commands[-1].args == ("pass", "rm", "-f", _PASS_PATH)
    assert deleted.status is SecretStatus.DELETED
    assert provider.get_metadata(secret_name).status is SecretStatus.DELETED


def test_pass_get_secret_only_strips_trailing_newline(secret_name: SecretName) -> None:
    runner = FakeRunner({_SHOW_CMD: CommandResult(0, "valueX\n", "")})
    provider = PassSecretProvider(runner)
    assert provider.get_secret(secret_name).reveal() == "valueX"


def test_pass_list_metadata_isolates_tenant_and_sorts(
    secret_name: SecretName, secret_value: SecretValue, secret_metadata: SecretMetadata
) -> None:
    provider = PassSecretProvider(FakeRunner())
    other = _other_name()
    other_stored = provider.set_secret(other, secret_value, secret_metadata)
    provider.set_secret(secret_name, secret_value, secret_metadata)
    provider.delete_secret(secret_name)
    assert provider.list_metadata("stanley") == ()
    assert provider.list_metadata("other") == (other_stored,)

    sorter = PassSecretProvider(FakeRunner())
    late = _name_for("zzz-service")
    early = _name_for("aaa-service")
    sorter.set_secret(late, secret_value, secret_metadata)
    sorter.set_secret(early, secret_value, secret_metadata)
    assert [m.name for m in sorter.list_metadata("stanley")] == [early, late]


def test_pass_error_messages(
    secret_name: SecretName, secret_value: SecretValue, secret_metadata: SecretMetadata
) -> None:
    _assert_raises_message(
        SecretValidationError,
        "prefix 不可為空",
        lambda: PassSecretProvider(FakeRunner(), prefix=""),
    )

    missing = PassSecretProvider(FakeRunner({_SHOW_CMD: CommandResult(1, "", "missing")}))
    _assert_raises_message(
        SecretNotFoundError,
        f"pass secret 不存在: {secret_name.path()}",
        lambda: missing.get_secret(secret_name),
    )
    _assert_raises_message(
        SecretNotFoundError,
        f"pass metadata 不存在: {secret_name.path()}",
        lambda: missing.get_metadata(secret_name),
    )
    _assert_raises_message(
        SecretValidationError,
        "tenant_id 不可為空",
        lambda: missing.list_metadata(""),
    )

    empty = PassSecretProvider(FakeRunner({_SHOW_CMD: CommandResult(0, "\n", "")}))
    _assert_raises_message(
        SecretProviderError,
        f"pass 回傳空 secret: {secret_name.path()}",
        lambda: empty.get_secret(secret_name),
    )

    insert_cmd = ("pass", "insert", "-m", _PASS_PATH)
    failing = PassSecretProvider(FakeRunner({insert_cmd: CommandResult(1, "", "boom")}))
    _assert_raises_message(
        SecretProviderError,
        "pass insert failed",
        lambda: failing.set_secret(secret_name, secret_value, secret_metadata),
    )

    rm_cmd = ("pass", "rm", "-f", _PASS_PATH)
    failing_rm = PassSecretProvider(FakeRunner({rm_cmd: CommandResult(1, "", "")}))
    failing_rm.set_secret(secret_name, secret_value, secret_metadata)
    _assert_raises_message(
        SecretProviderError,
        "pass rm failed",
        lambda: failing_rm.delete_secret(secret_name),
    )

    no_pass = PassSecretProvider(FakeRunner({("pass", "--version"): CommandResult(1, "", "")}))
    _assert_raises_message(
        SecretProviderUnavailableError,
        "pass CLI 不可用或 password store 未初始化",
        lambda: no_pass.get_secret(secret_name),
    )

    no_gpg = PassSecretProvider(FakeRunner({("gpg", "--version"): CommandResult(1, "", "")}))
    _assert_raises_message(
        SecretProviderUnavailableError,
        "GPG 不可用，pass provider 無法解密 secret",
        lambda: no_gpg.get_secret(secret_name),
    )

    ok_provider = PassSecretProvider(FakeRunner())
    ok_provider.set_secret(secret_name, secret_value, secret_metadata)
    _assert_raises_message(
        SecretValidationError,
        "rotation reason 不可為空",
        lambda: ok_provider.rotate_secret(secret_name, secret_value, ""),
    )


def test_pass_rotate_version_parsing_fail_closed(
    secret_name: SecretName, secret_value: SecretValue, secret_metadata: SecretMetadata
) -> None:
    provider = PassSecretProvider(FakeRunner())
    provider.set_secret(secret_name, secret_value, replace(secret_metadata, version="v"))
    rotated = provider.rotate_secret(secret_name, SecretValue("new-secret-1"), "empty version")
    assert rotated.version == "v1"
    provider.set_secret(secret_name, secret_value, replace(secret_metadata, version="vX3"))
    with pytest.raises(ValueError, match="X3"):
        provider.rotate_secret(secret_name, SecretValue("new-secret-2"), "bad version")


# ---------------------------------------------------------------------------
# vault_provider.py — managed adapter 的同組契約
# ---------------------------------------------------------------------------


def test_managed_provider_error_messages(
    secret_name: SecretName, secret_value: SecretValue, secret_metadata: SecretMetadata
) -> None:
    _assert_raises_message(
        SecretValidationError,
        "ManagedSecretProvider 只支援 Vault / Cloud Secret Manager",
        lambda: ManagedSecretProvider(FakeSecretManagerClient(), SecretProviderKind.MEMORY),
    )

    provider = VaultSecretProvider(FakeSecretManagerClient())
    _assert_raises_message(
        SecretNotFoundError,
        f"managed secret 不存在: {secret_name.path()}",
        lambda: provider.get_secret(secret_name),
    )
    _assert_raises_message(
        SecretNotFoundError,
        f"managed secret 不存在: {secret_name.path()}",
        lambda: provider.delete_secret(secret_name),
    )
    _assert_raises_message(
        SecretNotFoundError,
        f"managed metadata 不存在: {secret_name.path()}",
        lambda: provider.get_metadata(secret_name),
    )
    _assert_raises_message(
        SecretValidationError,
        "tenant_id 不可為空",
        lambda: provider.list_metadata(""),
    )

    empty_client = FakeSecretManagerClient()
    empty_client.values[secret_name.path()] = ""
    empty = VaultSecretProvider(empty_client)
    _assert_raises_message(
        SecretProviderError,
        f"managed secret manager 回傳空 secret: {secret_name.path()}",
        lambda: empty.get_secret(secret_name),
    )

    offline = VaultSecretProvider(FakeSecretManagerClient(available=False))
    _assert_raises_message(
        SecretProviderUnavailableError,
        "managed secret manager client 不可用",
        lambda: offline.set_secret(secret_name, secret_value, secret_metadata),
    )

    ok_provider = VaultSecretProvider(FakeSecretManagerClient())
    ok_provider.set_secret(secret_name, secret_value, secret_metadata)
    _assert_raises_message(
        SecretValidationError,
        "rotation reason 不可為空",
        lambda: ok_provider.rotate_secret(secret_name, secret_value, ""),
    )


def test_managed_provider_delete_keeps_metadata_and_isolates_tenant(
    secret_name: SecretName, secret_value: SecretValue, secret_metadata: SecretMetadata
) -> None:
    provider = VaultSecretProvider(FakeSecretManagerClient())
    other = _other_name()
    other_stored = provider.set_secret(other, secret_value, secret_metadata)
    provider.set_secret(secret_name, secret_value, secret_metadata)
    provider.delete_secret(secret_name)
    assert provider.get_metadata(secret_name).status is SecretStatus.DELETED
    assert provider.list_metadata("stanley") == ()
    assert provider.list_metadata("other") == (other_stored,)

    sorter = VaultSecretProvider(FakeSecretManagerClient())
    late = _name_for("zzz-service")
    early = _name_for("aaa-service")
    sorter.set_secret(late, secret_value, secret_metadata)
    sorter.set_secret(early, secret_value, secret_metadata)
    assert [m.name for m in sorter.list_metadata("stanley")] == [early, late]


def test_managed_provider_rotate_version_parsing_fail_closed(
    secret_name: SecretName, secret_value: SecretValue, secret_metadata: SecretMetadata
) -> None:
    provider = VaultSecretProvider(FakeSecretManagerClient())
    provider.set_secret(secret_name, secret_value, replace(secret_metadata, version="v"))
    rotated = provider.rotate_secret(secret_name, SecretValue("new-secret-1"), "empty version")
    assert rotated.version == "v1"
    provider.set_secret(secret_name, secret_value, replace(secret_metadata, version="vX3"))
    with pytest.raises(ValueError, match="X3"):
        provider.rotate_secret(secret_name, SecretValue("new-secret-2"), "bad version")


# ---------------------------------------------------------------------------
# sinks.py — 投影預設值、邊界、hash 編碼契約
# ---------------------------------------------------------------------------


def _projection(**overrides: object) -> SecretAuditProjection:
    kwargs: dict[str, object] = {
        "tenant_id": "stanley",
        "actor_id": "agent-1",
        "action": "secret.read",
        "resource": "tenant/stanley/service/audit",
        "request_payload_hash": _SHA256_HEX,
        "response_status": "success",
        "trace_id": "trace-1",
    }
    kwargs.update(overrides)
    return SecretAuditProjection(**kwargs)  # type: ignore[arg-type]


def test_projection_defaults_and_risk_boundaries() -> None:
    projection = _projection()
    assert projection.risk_score == 0
    assert dict(projection.metadata) == {}
    assert _projection(risk_score=100).risk_score == 100


def test_projection_validation_messages() -> None:
    with pytest.raises(ValueError) as excinfo:
        _projection(tenant_id="")
    assert str(excinfo.value) == "tenant_id 不可為空"
    with pytest.raises(ValueError) as excinfo:
        _projection(risk_score=101)
    assert str(excinfo.value) == "risk_score 必須在 0-100 之間"
    with pytest.raises(ValueError) as excinfo:
        _projection(request_payload_hash="short")
    assert str(excinfo.value) == "request_payload_hash 必須是 SHA256 hex"


def test_hash_redacted_payload_uses_compact_sorted_json() -> None:
    expected = hashlib.sha256(b'{"a":"1","b":"2"}').hexdigest()
    assert _hash_redacted_payload({"b": "2", "a": "1"}) == expected
