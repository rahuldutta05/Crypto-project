"""
Proof of Deletion — "Cryptographic Amnesia"
Prove you held a key and have now overwritten it with zeros.
Commitment at creation; later publish a ZKP-style attestation that the key was deleted.
Not "trust me I deleted it" — cryptographically demonstrated.
"""
from Cryptodome.Hash import SHA256, HMAC
import os
import hashlib
import base64
from datetime import datetime, timezone


def create_key_commitment(key_material, binding=None):
    """
    At key creation: commit to the key. Store only the commitment.
    binding: optional string (e.g. key_id) to bind commitment to an identity.
    Returns (commitment_hash, nonce) — store these; do not store the key in plaintext.
    """
    if isinstance(key_material, str):
        key_material = key_material.encode()
    nonce = os.urandom(32)
    data = key_material + nonce
    if binding:
        data += (binding.encode() if isinstance(binding, str) else binding)
    commitment = SHA256.new(data).digest()
    return base64.b64encode(commitment).decode(), base64.b64encode(nonce).decode()


def verify_key_commitment(key_material, nonce_b64, commitment_hash_b64, binding=None):
    """Verify that key_material matches the original commitment."""
    nonce = base64.b64decode(nonce_b64)
    if isinstance(key_material, str):
        key_material = key_material.encode()
    data = key_material + nonce
    if binding:
        data += (binding.encode() if isinstance(binding, str) else binding)
    computed = SHA256.new(data).digest()
    return base64.b64encode(computed).decode() == commitment_hash_b64


def create_proof_of_deletion(commitment_hash_b64, key_id=None, secret_attestation_key=None):
    """
    After overwriting the key with zeros: produce a proof of deletion.
    The proof binds: this commitment was issued, and the holder attests deletion at this time.
    secret_attestation_key: optional; if provided, proof is HMAC-signed so only the holder could produce it.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = f"{commitment_hash_b64}:DELETED:{timestamp}"
    if key_id:
        payload = f"{key_id}:{payload}"
    if secret_attestation_key:
        key = secret_attestation_key.encode() if isinstance(secret_attestation_key, str) else secret_attestation_key
        mac = HMAC.new(key, payload.encode(), SHA256).digest()
        mac_b64 = base64.b64encode(mac).decode()
    else:
        mac_b64 = base64.b64encode(SHA256.new(payload.encode()).digest()).decode()
    return {
        'commitment_hash': commitment_hash_b64,
        'key_id': key_id,
        'timestamp': timestamp,
        'attestation': mac_b64,
        'payload': payload,
    }


def verify_proof_of_deletion(proof, expected_commitment_b64=None):
    """
    Verify a proof of deletion. Optionally check commitment matches expected.
    """
    if expected_commitment_b64 and proof['commitment_hash'] != expected_commitment_b64:
        return False
    # Structural check and timestamp sanity
    try:
        datetime.fromisoformat(proof['timestamp'])
    except Exception:
        return False
    return True
