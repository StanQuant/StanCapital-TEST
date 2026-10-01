"""L11 Audit Merkle 強化層(D1 裁決 c) · 批次封印與單筆存在證明。

樹規則:
- 葉 = 該批記錄的 record_hash(已是 SHA256，不再重雜湊)
- 內部節點 = SHA256(left + right)，奇數節點直接晉級(不複製，避免重複葉歧義)
- 封印指紋 = SHA256(prev_checkpoint_hash + canonical(封印欄位))，封印之間串成第二條鏈

用途:
- 常規驗證走封印層(量是記錄層的 1/批次大小)做低成本巡檢；惟封印層只驗封印鏈
  自洽，抓不到「批內改記錄 + 同步重算」的篡改，故須週期穿插記錄層深掃
  (verify_tenant_chain / verify_batch)，深掃亦是警報後取證主力
- generate_proof / verify_proof: 向第三方證明單筆記錄存在，不用提供整批資料
  (S28 法遵 / 外部稽核直接受益)
"""

from __future__ import annotations

import hashlib
from typing import Literal

from src.governance.audit.chain import canonical_json
from src.governance.audit.signing import DEFAULT_SIGNER, Signer
from src.governance.audit.types import MerkleCheckpoint

# 每滿多少筆記錄蓋一個封印(規格 §3 類別 3 預設值)
CHECKPOINT_BATCH_SIZE = 1000

# 證明可能從外部 API / 稽核方傳入，方向在執行期採白名單驗證。
ProofStep = tuple[str, str]


def _pair_hash(left: str, right: str) -> str:
    return hashlib.sha256((left + right).encode("utf-8")).hexdigest()


def merkle_root(leaf_hashes: list[str]) -> str:
    """整批葉雜湊算樹根。空批拒絕(封印必然對應至少一筆記錄)。"""
    if not leaf_hashes:
        raise ValueError("Merkle 樹至少需要一片葉(空批不可封印)")
    level = list(leaf_hashes)
    while len(level) > 1:
        next_level: list[str] = []
        for i in range(0, len(level) - 1, 2):
            next_level.append(_pair_hash(level[i], level[i + 1]))
        if len(level) % 2 == 1:
            # 奇數節點直接晉級
            next_level.append(level[-1])
        level = next_level
    return level[0]


def generate_proof(leaf_hashes: list[str], leaf_index: int) -> tuple[ProofStep, ...]:
    """產生第 leaf_index 片葉的存在證明(兄弟節點雜湊一路到根)。"""
    if not 0 <= leaf_index < len(leaf_hashes):
        raise ValueError(f"leaf_index 超出範圍: {leaf_index}(共 {len(leaf_hashes)} 片葉)")
    proof: list[ProofStep] = []
    level = list(leaf_hashes)
    index = leaf_index
    while len(level) > 1:
        next_level: list[str] = []
        for i in range(0, len(level) - 1, 2):
            next_level.append(_pair_hash(level[i], level[i + 1]))
        if len(level) % 2 == 1:
            next_level.append(level[-1])

        sibling = index ^ 1  # 同一對的另一邊
        if sibling < len(level) and sibling != index:
            side: Literal["left", "right"] = "left" if sibling < index else "right"
            proof.append((side, level[sibling]))
        # 奇數尾巴直接晉級時沒有兄弟，不加證明步驟
        index //= 2
        level = next_level
    return tuple(proof)


def verify_proof(leaf_hash: str, proof: tuple[ProofStep, ...], root: str) -> bool:
    """驗證單筆存在證明: 沿證明步驟重算到根，與封印存的樹根比對。"""
    current = leaf_hash
    for side, sibling_hash in proof:
        if side == "left":
            current = _pair_hash(sibling_hash, current)
        elif side == "right":
            current = _pair_hash(current, sibling_hash)
        else:
            return False
    return current == root


def compute_checkpoint_hash(
    *,
    prev_checkpoint_hash: str,
    tenant_id: str,
    checkpoint_index: int,
    start_sequence: int,
    end_sequence: int,
    batch_merkle_root: str,
    signer: Signer = DEFAULT_SIGNER,
) -> str:
    """鑄造封印指紋(封印層的鏈規則，與記錄層 compute_record_hash 同構)。

    signer 預設純 SHA256(向後相容);注入 HMAC 簽章器即啟用信任根外移(B-006)。
    封印的 merkle_root 仍是純 SHA256(無秘密的存在證明)，HMAC 只保護封印鏈指紋本身。
    """
    preimage = prev_checkpoint_hash + canonical_json(
        {
            "tenant_id": tenant_id,
            "checkpoint_index": checkpoint_index,
            "start_sequence": start_sequence,
            "end_sequence": end_sequence,
            "merkle_root": batch_merkle_root,
        }
    )
    return signer(preimage)


def recompute_checkpoint_hash(
    checkpoint: MerkleCheckpoint, *, signer: Signer = DEFAULT_SIGNER
) -> str:
    """重算既有封印的指紋(驗證路徑)。須與寫入時相同的 signer。"""
    return compute_checkpoint_hash(
        prev_checkpoint_hash=checkpoint.prev_checkpoint_hash,
        tenant_id=checkpoint.tenant_id,
        checkpoint_index=checkpoint.checkpoint_index,
        start_sequence=checkpoint.start_sequence,
        end_sequence=checkpoint.end_sequence,
        batch_merkle_root=checkpoint.merkle_root,
        signer=signer,
    )
