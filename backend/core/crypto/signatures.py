"""
core/crypto/signatures.py — RSA-PSS signing for proof-of-existence.

The server's signing key is generated once and persisted to disk as a PEM file.
This means signatures created before a restart remain verifiable after it —
unlike the original code which regenerated the key in memory on every startup.

Public key is also exposed so external verifiers can check signatures
without trusting the server.
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from config import SIGNING_KEY_FILE, VAULT_DIR


def _load_or_create_signing_key():
    """Load the RSA private key from PEM, or generate and save a new one."""
    os.makedirs(VAULT_DIR, exist_ok=True)

    if os.path.exists(SIGNING_KEY_FILE):
        with open(SIGNING_KEY_FILE, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(SIGNING_KEY_FILE, "wb") as f:
        f.write(pem)

    print("[Signatures] New RSA signing key generated and saved to", SIGNING_KEY_FILE)
    return private_key


_private_key = _load_or_create_signing_key()
_public_key  = _private_key.public_key()

_PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)


def sign(data: str) -> str:
    """Sign a UTF-8 string. Returns hex-encoded signature."""
    return _private_key.sign(data.encode(), _PSS_PADDING, hashes.SHA256()).hex()


def verify(data: str, signature_hex: str) -> bool:
    """Verify a hex-encoded RSA-PSS signature against data."""
    try:
        _public_key.verify(
            bytes.fromhex(signature_hex),
            data.encode(),
            _PSS_PADDING,
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def get_public_key_pem() -> str:
    """Return the server's public key as a PEM string for external verifiers."""
    return _public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
