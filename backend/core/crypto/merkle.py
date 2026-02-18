"""
core/crypto/merkle.py — Merkle tree for proof-of-existence.

Provides:
  - hash_leaf(data)              → SHA-256 hex digest of a string
  - build_root(hashes)           → Merkle root from a list of leaf hashes
  - build_proof(hashes, index)   → (root, proof_path) for inclusion proof

A proof_path is a list of {"sibling": <hash>, "position": "left"|"right"}
dicts that allow any verifier to recompute the root from a single leaf
without accessing any other leaves.
"""

import hashlib
from typing import Optional


def hash_leaf(data: str) -> str:
    """SHA-256 hash of a UTF-8 string."""
    return hashlib.sha256(data.encode()).hexdigest()


def _hash_pair(left: str, right: str) -> str:
    """Combine two sibling hashes into their parent."""
    return hashlib.sha256((left + right).encode()).hexdigest()


def build_root(hashes: list[str]) -> Optional[str]:
    """
    Compute the Merkle root of a list of leaf hashes.
    Returns None for an empty list.
    Odd-length levels duplicate the last hash.
    """
    if not hashes:
        return None
    if len(hashes) == 1:
        return hashes[0]

    next_level = []
    for i in range(0, len(hashes), 2):
        left  = hashes[i]
        right = hashes[i + 1] if i + 1 < len(hashes) else left
        next_level.append(_hash_pair(left, right))

    return build_root(next_level)


def build_proof(hashes: list[str], index: int) -> tuple[Optional[str], list]:
    """
    Return (root, proof_path) for the leaf at `index`.

    proof_path is a list of steps:
      [{"sibling": <hex>, "position": "left"|"right"}, ...]

    To verify: start with leaf hash, then at each step combine it with
    the sibling (sibling on the left or right as indicated) to walk up
    to the root.
    """
    if not hashes:
        return None, []

    proof_path = []
    current = list(hashes)
    current_index = index

    while len(current) > 1:
        next_level = []
        next_index = current_index // 2

        for i in range(0, len(current), 2):
            left  = current[i]
            right = current[i + 1] if i + 1 < len(current) else left

            # Capture sibling of the target node
            if i == current_index:
                proof_path.append({"sibling": right, "position": "right"})
            elif i + 1 == current_index:
                proof_path.append({"sibling": left, "position": "left"})

            next_level.append(_hash_pair(left, right))

        current = next_level
        current_index = next_index

    return current[0], proof_path


def verify_proof(leaf_hash: str, proof_path: list, expected_root: str) -> bool:
    """
    Client-side verification: recompute root from leaf + proof_path.
    Returns True if computed root matches expected_root.
    """
    current = leaf_hash
    for step in proof_path:
        sibling  = step["sibling"]
        position = step["position"]
        if position == "left":
            current = _hash_pair(sibling, current)
        else:
            current = _hash_pair(current, sibling)
    return current == expected_root
