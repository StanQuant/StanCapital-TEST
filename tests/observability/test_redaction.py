"""遙測敏感資料遮蔽測試。"""

from __future__ import annotations

import pytest
from src.observability.redaction import (
    _SENSITIVE_KEY_PARTS,
    REDACTED,
    Redactor,
    redact,
)


def test_sensitive_key_redacted() -> None:
    out = redact({"password": "hunter2", "user": "stanley"})
    assert out == {"password": REDACTED, "user": "stanley"}


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "api_key",
        "apiKey",
        "AUTHORIZATION",
        "refresh_token",
        "access_key",
        "session_id",
        "cookie",
        "user_ssn",
        "card_cvv",
    ],
)
def test_sensitive_key_variants(key: str) -> None:
    assert Redactor().is_sensitive_key(key) is True


def test_non_sensitive_key() -> None:
    assert Redactor().is_sensitive_key("tenant_id") is False


def test_nested_mapping() -> None:
    out = redact({"outer": {"secret": "x", "ok": "y"}})
    assert out == {"outer": {"secret": REDACTED, "ok": "y"}}


def test_list_recursion() -> None:
    out = redact([{"token": "t"}, "plain"])
    assert out == [{"token": REDACTED}, "plain"]


def test_tuple_recursion() -> None:
    out = redact(({"token": "t"}, "plain"))
    assert out == ({"token": REDACTED}, "plain")
    assert isinstance(out, tuple)


def test_set_recursion() -> None:
    out = redact({"a@b.com", "plain"})
    assert out == {REDACTED, "plain"}
    assert isinstance(out, set)


def test_non_str_passthrough() -> None:
    assert redact(42) == 42
    assert redact(None) is None
    assert redact(True) is True


def test_email_value_redacted() -> None:
    assert redact("contact stanley@example.com now") == f"contact {REDACTED} now"


def test_bearer_value_redacted() -> None:
    assert redact("Authorization: Bearer abc.def-123") == f"Authorization: {REDACTED}"


def test_aws_key_redacted() -> None:
    assert redact("key=AKIAIOSFODNN7EXAMPLE") == f"key={REDACTED}"  # pragma: allowlist secret


def test_pem_private_key_redacted() -> None:
    # 用非黑名單字樣（FAKE）避免 detect-private-key hook 誤判，仍符合 redaction 正規式
    text = "-----BEGIN FAKE PRIVATE KEY-----blah"  # pragma: allowlist secret
    assert redact(text) == f"{REDACTED}blah"


def test_credit_card_redacted() -> None:
    assert redact("pan 4111 1111 1111 1111 end") == f"pan {REDACTED} end"


def test_max_depth_redacts() -> None:
    r = Redactor(max_depth=1)
    out = r.redact({"a": {"b": {"c": "deep"}}})
    # depth 0: a, depth 1: b -> redact(value at depth2) -> depth>max => REDACTED
    assert out == {"a": {"b": REDACTED}}


def test_extra_keys() -> None:
    r = Redactor(extra_keys=["badge"])
    assert r.redact({"badge": "1234"}) == {"badge": REDACTED}


def test_negative_max_depth_rejected() -> None:
    with pytest.raises(ValueError, match="max_depth 不可為負數"):
        Redactor(max_depth=-1)


def test_redactor_slots_no_dict() -> None:
    assert not hasattr(Redactor(), "__dict__")


# ---- mutation killers ----


@pytest.mark.parametrize("key", sorted(_SENSITIVE_KEY_PARTS))
def test_every_sensitive_key_part_detected(key: str) -> None:
    # 任一敏感字被改名都會讓此鍵漏判 → 殺死字串變異
    assert Redactor().is_sensitive_key(key) is True


def test_default_max_depth_is_six() -> None:
    assert Redactor()._max_depth == 6


def test_dict_value_depth_increment() -> None:
    # max_depth=0：值在 depth1 應被遮（驗證 depth + 1，殺 +1→-1 變異）
    assert Redactor(max_depth=0).redact({"ok": "plain"}) == {"ok": REDACTED}


def test_list_depth_increment() -> None:
    assert Redactor(max_depth=0).redact(["plain"]) == [REDACTED]


def test_tuple_depth_increment() -> None:
    assert Redactor(max_depth=0).redact(("plain",)) == (REDACTED,)


def test_set_depth_increment() -> None:
    assert Redactor(max_depth=0).redact({"plain"}) == {REDACTED}


def test_top_level_not_over_depth() -> None:
    # 頂層 depth0 不超過 max_depth0，應正常處理而非整段遮
    assert Redactor(max_depth=0).redact({"password": "x"}) == {"password": REDACTED}


def test_extra_keys_merged_not_replaced() -> None:
    # 自訂鍵須與預設聯集（殺 | 變 & / 覆蓋等變異）
    r = Redactor(extra_keys=["badge"])
    assert r.is_sensitive_key("badge") is True
    assert r.is_sensitive_key("password") is True


def test_negative_max_depth_exact_message() -> None:
    with pytest.raises(ValueError) as exc:
        Redactor(max_depth=-1)
    assert str(exc.value) == "max_depth 不可為負數"


def test_list_increment_is_exactly_one() -> None:
    # max_depth=1：值在 depth1 不超過 → 不遮（殺 +1→+2 變異）
    assert Redactor(max_depth=1).redact(["plain"]) == ["plain"]


def test_tuple_increment_is_exactly_one() -> None:
    assert Redactor(max_depth=1).redact(("plain",)) == ("plain",)


def test_set_increment_is_exactly_one() -> None:
    assert Redactor(max_depth=1).redact({"plain"}) == {"plain"}
