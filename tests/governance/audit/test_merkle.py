"""S05 · Merkle 強化層測試。

重點: 樹根決定性、奇數葉晉級、每片葉的證明都可驗、封印鏈指紋敏感性。
"""

from __future__ import annotations

import hashlib

import pytest
from src.governance.audit.merkle import (
    CHECKPOINT_BATCH_SIZE,
    compute_checkpoint_hash,
    generate_proof,
    merkle_root,
    recompute_checkpoint_hash,
    verify_proof,
)
from src.governance.audit.types import GENESIS_HASH, MerkleCheckpoint


def _leaf(n: int) -> str:
    """造第 n 片葉(固定內容 → 固定雜湊，測試可重現)。"""
    return hashlib.sha256(f"leaf-{n}".encode()).hexdigest()


def _pair(left: str, right: str) -> str:
    return hashlib.sha256((left + right).encode("utf-8")).hexdigest()


# ============================================================================
# merkle_root: 結構正確性(小樹手算對照)與決定性
# ============================================================================


def test_root_of_single_leaf_is_the_leaf() -> None:
    assert merkle_root([_leaf(0)]) == _leaf(0)


def test_root_of_two_leaves_is_pair_hash() -> None:
    assert merkle_root([_leaf(0), _leaf(1)]) == _pair(_leaf(0), _leaf(1))


def test_root_of_three_leaves_odd_promotion() -> None:
    # 奇數葉: 第 3 片直接晉級，與 (h01, leaf2) 再配對
    h01 = _pair(_leaf(0), _leaf(1))
    assert merkle_root([_leaf(0), _leaf(1), _leaf(2)]) == _pair(h01, _leaf(2))


def test_root_of_four_leaves_two_levels() -> None:
    h01 = _pair(_leaf(0), _leaf(1))
    h23 = _pair(_leaf(2), _leaf(3))
    assert merkle_root([_leaf(n) for n in range(4)]) == _pair(h01, h23)


def test_root_is_deterministic() -> None:
    leaves = [_leaf(n) for n in range(7)]
    assert merkle_root(leaves) == merkle_root(leaves)


def test_root_changes_when_any_leaf_changes() -> None:
    leaves = [_leaf(n) for n in range(5)]
    for i in range(5):
        tampered = list(leaves)
        tampered[i] = _leaf(999)
        assert merkle_root(tampered) != merkle_root(leaves), f"改第 {i} 片葉沒被反映到樹根"


def test_root_changes_when_leaf_order_swapped() -> None:
    assert merkle_root([_leaf(0), _leaf(1)]) != merkle_root([_leaf(1), _leaf(0)])


def test_root_rejects_empty_batch() -> None:
    with pytest.raises(ValueError) as exc_info:
        merkle_root([])
    assert str(exc_info.value) == "Merkle 樹至少需要一片葉(空批不可封印)"


def test_checkpoint_batch_size_contract() -> None:
    assert CHECKPOINT_BATCH_SIZE == 1000


# ============================================================================
# generate_proof / verify_proof: 各種樹形下每片葉都可證明
# ============================================================================


@pytest.mark.parametrize("n_leaves", [1, 2, 3, 4, 5, 8, 13])
def test_every_leaf_proof_verifies(n_leaves: int) -> None:
    leaves = [_leaf(n) for n in range(n_leaves)]
    root = merkle_root(leaves)
    for i in range(n_leaves):
        proof = generate_proof(leaves, i)
        assert verify_proof(leaves[i], proof, root), f"{n_leaves} 葉樹的第 {i} 片葉證明失敗"


def test_proof_fails_for_wrong_leaf() -> None:
    leaves = [_leaf(n) for n in range(4)]
    root = merkle_root(leaves)
    proof = generate_proof(leaves, 0)
    assert not verify_proof(_leaf(999), proof, root)


def test_proof_fails_for_wrong_root() -> None:
    leaves = [_leaf(n) for n in range(4)]
    proof = generate_proof(leaves, 0)
    assert not verify_proof(_leaf(0), proof, "f" * 64)


def test_proof_fails_with_tampered_step() -> None:
    leaves = [_leaf(n) for n in range(4)]
    root = merkle_root(leaves)
    proof = generate_proof(leaves, 0)
    tampered = ((proof[0][0], "e" * 64), *proof[1:])
    assert not verify_proof(_leaf(0), tampered, root)


def test_proof_rejects_unknown_side() -> None:
    invalid_proof = (("up", _leaf(1)),)
    assert not verify_proof(_leaf(0), invalid_proof, _leaf(2))


def test_single_leaf_proof_is_empty() -> None:
    leaves = [_leaf(0)]
    assert generate_proof(leaves, 0) == ()
    assert verify_proof(_leaf(0), (), merkle_root(leaves))


@pytest.mark.parametrize("bad_index", [-1, 3, 100])
def test_proof_rejects_out_of_range_index(bad_index: int) -> None:
    with pytest.raises(ValueError) as exc_info:
        generate_proof([_leaf(n) for n in range(3)], bad_index)
    assert str(exc_info.value) == f"leaf_index 超出範圍: {bad_index}(共 3 片葉)"


# ============================================================================
# 封印鏈: 指紋決定性與逐欄位敏感性
# ============================================================================


def _mint_checkpoint(**overrides: object) -> str:
    defaults: dict[str, object] = {
        "prev_checkpoint_hash": GENESIS_HASH,
        "tenant_id": "tenant-a",
        "checkpoint_index": 1,
        "start_sequence": 1,
        "end_sequence": 1000,
        "batch_merkle_root": _leaf(0),
    }
    defaults.update(overrides)
    return compute_checkpoint_hash(**defaults)  # type: ignore[arg-type]


def test_checkpoint_hash_deterministic() -> None:
    assert _mint_checkpoint() == _mint_checkpoint()


def test_checkpoint_hash_golden_contract() -> None:
    assert _mint_checkpoint() == "946f8c251ffc6855cabb5e971a5a02939667a5033cbb5ea8bdd16f3e3f0106e1"


@pytest.mark.parametrize(
    "overrides",
    [
        {"prev_checkpoint_hash": "f" * 64},
        {"tenant_id": "tenant-b"},
        {"checkpoint_index": 2},
        {"start_sequence": 2},
        {"end_sequence": 999},
        {"batch_merkle_root": _leaf(1)},
    ],
    ids=lambda d: next(iter(d)),
)
def test_checkpoint_hash_changes_on_any_field(overrides: dict[str, object]) -> None:
    assert _mint_checkpoint(**overrides) != _mint_checkpoint()


def test_recompute_checkpoint_hash_round_trip() -> None:
    minted = _mint_checkpoint()
    checkpoint = MerkleCheckpoint(
        tenant_id="tenant-a",
        checkpoint_index=1,
        start_sequence=1,
        end_sequence=1000,
        merkle_root=_leaf(0),
        prev_checkpoint_hash=GENESIS_HASH,
        checkpoint_hash=minted,
    )
    assert recompute_checkpoint_hash(checkpoint) == minted == checkpoint.checkpoint_hash


# ============================================================================
# MerkleCheckpoint 型別建構期驗證
# ============================================================================


@pytest.mark.parametrize(
    ("overrides", "message_part"),
    [
        ({"tenant_id": ""}, "tenant_id 不可為空"),
        ({"checkpoint_index": 0}, "checkpoint_index 必須 >= 1"),
        ({"start_sequence": 0}, "start_sequence 必須 >= 1"),
        ({"end_sequence": 0}, "end_sequence 不可小於 start_sequence"),
        ({"merkle_root": "bad"}, "merkle_root"),
        ({"prev_checkpoint_hash": "bad"}, "prev_checkpoint_hash"),
        ({"checkpoint_hash": "bad"}, "checkpoint_hash"),
    ],
)
def test_checkpoint_type_rejects_invalid(overrides: dict[str, object], message_part: str) -> None:
    defaults: dict[str, object] = {
        "tenant_id": "t",
        "checkpoint_index": 1,
        "start_sequence": 1,
        "end_sequence": 1000,
        "merkle_root": "a" * 64,
        "prev_checkpoint_hash": GENESIS_HASH,
        "checkpoint_hash": "b" * 64,
    }
    defaults.update(overrides)
    with pytest.raises(ValueError, match=message_part):
        MerkleCheckpoint(**defaults)  # type: ignore[arg-type]


def test_checkpoint_single_record_batch_accepted() -> None:
    # 日結時批可能只有 1 筆(start == end 合法)
    checkpoint = MerkleCheckpoint(
        tenant_id="t",
        checkpoint_index=1,
        start_sequence=5,
        end_sequence=5,
        merkle_root="a" * 64,
        prev_checkpoint_hash=GENESIS_HASH,
        checkpoint_hash="b" * 64,
    )
    assert checkpoint.end_sequence == 5
