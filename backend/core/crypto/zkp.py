"""
core/crypto/zkp.py — Zero-Knowledge-style identity commitments.

This implements a simplified Semaphore-style commitment scheme:

    identity_secret  (private, user keeps this)
        ↓ SHA-256
    nullifier        (private, used to prevent double-submission)
        ↓ SHA-256
    commitment       (public, submitted to the server)

Properties:
  - The server sees only the commitment — it cannot reverse it to learn
    the identity secret or nullifier.
  - To submit, the user proves knowledge of (nullifier, nonce) such that:
      · SHA-256(nullifier) == commitment  (valid commitment)
      · SHA-256(commitment + nonce) starts with "000..." (PoW)
  - Each identity_secret produces exactly one nullifier and one commitment,
    enforcing one submission per identity without revealing who they are.

Note: A full ZKP would use a zk-SNARK circuit. This is a hash-based
approximation suitable for server-side enforcement without a trusted setup.
"""

import hashlib
import secrets


def generate_identity_secret() -> str:
    """Generate a fresh 256-bit identity secret (client-side only)."""
    return secrets.token_hex(32)


def derive_nullifier(identity_secret: str) -> str:
    """Derive the nullifier from an identity secret."""
    return hashlib.sha256(identity_secret.encode()).hexdigest()


def derive_commitment(nullifier: str) -> str:
    """Derive the public commitment from a nullifier."""
    return hashlib.sha256(nullifier.encode()).hexdigest()


def commitment_from_secret(identity_secret: str) -> str:
    """Convenience: derive commitment directly from identity secret."""
    return derive_commitment(derive_nullifier(identity_secret))


def verify_commitment_chain(identity_secret: str, commitment: str) -> bool:
    """Verify that a commitment correctly derives from an identity secret."""
    return commitment_from_secret(identity_secret) == commitment
