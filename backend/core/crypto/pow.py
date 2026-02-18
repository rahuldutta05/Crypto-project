"""
core/crypto/pow.py — Proof-of-Work for spam/Sybil resistance.

The client must find a nonce such that:
    SHA-256(commitment + nonce).startswith("0" * difficulty)

This makes generating fake submissions computationally expensive
without identifying the submitter.
"""

import hashlib
from config import POW_DIFFICULTY


def verify(commitment: str, nonce: str, difficulty: int = POW_DIFFICULTY) -> bool:
    """
    Return True if SHA-256(commitment + nonce) has `difficulty` leading zeroes.
    """
    digest = hashlib.sha256((commitment + nonce).encode()).hexdigest()
    return digest.startswith("0" * difficulty)
