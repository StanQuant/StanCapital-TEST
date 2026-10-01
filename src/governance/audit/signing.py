"""L11 Audit · 可插拔簽章(record_hash / checkpoint_hash 的信任根)。

為什麼存在(B-006 信任根外移):
  純 SHA256 的雜湊鏈能抓「改了之後沒同步重算」的篡改,但握有 DB 寫權的內鬼
  仍可「改記錄 + 自行重算整條鏈」偽造出自洽的假鏈(因為 SHA256 無秘密、人人可算)。
  把指紋改成 HMAC-SHA256、金鑰放 DB 外(環境變數 / Vault),無金鑰就偽造不出有效指紋,
  即使內鬼也無法重算出通得過驗證的假鏈。

向後相容(關鍵不變式):
  預設 `sha256_sign` 與歷史行為「位元相同」——既有稽核資料照常驗證、不需重算。
  HMAC 純選配: 設了 STANQUANT_AUDIT_HMAC_KEY 才啟用(且僅對啟用後新寫入的資料生效;
  既有資料的遷移屬 B-006 外部錨定範疇)。

簽章器形狀:
  `Signer = Callable[[preimage], 64 字元 hex 摘要]`。HMAC-SHA256 摘要也是 64 hex,
  與既有欄位驗證(_SHA256_HEX)相容,不需改 schema。
"""

from __future__ import annotations

import hashlib
import hmac
import os
from collections.abc import Callable, Mapping

# preimage 字串 → 64 字元 hex 摘要
Signer = Callable[[str], str]

# 設了才啟用 HMAC;不設 = 維持純 SHA256(向後相容)
AUDIT_HMAC_KEY_ENV = "STANQUANT_AUDIT_HMAC_KEY"


def sha256_sign(preimage: str) -> str:
    """純 SHA256(預設 · 與歷史行為位元相同)。"""
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()


def make_hmac_signer(key: bytes) -> Signer:
    """產生 HMAC-SHA256 簽章器。金鑰 DB 外,無金鑰偽造不出有效指紋。"""
    if not key:
        raise ValueError("HMAC 金鑰不可為空")

    def sign(preimage: str) -> str:
        return hmac.new(key, preimage.encode("utf-8"), hashlib.sha256).hexdigest()

    return sign


# 模組級預設(無狀態純函式)
DEFAULT_SIGNER: Signer = sha256_sign


def signer_from_env(env: Mapping[str, str] | None = None) -> Signer:
    """有金鑰 → HMAC 簽章器;否則回預設 SHA256(向後相容)。env 可注入(測試用)。"""
    source = os.environ if env is None else env
    key = source.get(AUDIT_HMAC_KEY_ENV, "")
    if key:
        return make_hmac_signer(key.encode("utf-8"))
    return DEFAULT_SIGNER
