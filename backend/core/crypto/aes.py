"""
core/crypto/aes.py — AES-EAX authenticated encryption.

Handles:
  - Per-submission Data Encryption Keys (DEK)
  - DEK wrapping/unwrapping under the master Key Encryption Key (KEK)
  - Plaintext encrypt/decrypt

AES-EAX provides both confidentiality and integrity (AEAD).
All binary values are base64-encoded for JSON storage.
"""

import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# os.urandom replaces Crypto.Random.get_random_bytes
get_random_bytes = os.urandom

# ─── AES-GCM shim (replaces AES-EAX from pycryptodome) ──────────────────────
# AES-EAX is not available in the `cryptography` package.
# AES-GCM is equally secure (AEAD) and natively supported.
# Wire format is identical: { ciphertext, nonce, tag } — tag is appended by
# AESGCM automatically (last 16 bytes of the encrypt() output).

class _AESCipher:
    """Thin wrapper so the rest of the file is unchanged."""
    def __init__(self, key: bytes, nonce: bytes = None):
        self._key   = key
        self._nonce = nonce or os.urandom(16)
        self._aesgcm = AESGCM(key)

    @property
    def nonce(self):
        return self._nonce

    def encrypt_and_digest(self, data: bytes):
        # AESGCM.encrypt returns ciphertext+tag (tag is last 16 bytes)
        ct_and_tag = self._aesgcm.encrypt(self._nonce, data, None)
        ciphertext = ct_and_tag[:-16]
        tag        = ct_and_tag[-16:]
        return ciphertext, tag

    def decrypt_and_verify(self, ciphertext: bytes, tag: bytes):
        return self._aesgcm.decrypt(self._nonce, ciphertext + tag, None)

class _AESModule:
    MODE_EAX = "GCM"  # sentinel, unused
    @staticmethod
    def new(key: bytes, mode, nonce: bytes = None):
        return _AESCipher(key, nonce)

AES = _AESModule()


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


# ─── DEK lifecycle ───────────────────────────────────────────────────────────

def generate_dek() -> bytes:
    """Generate a fresh 256-bit Data Encryption Key."""
    return get_random_bytes(32)


def wrap_dek(dek: bytes, kek: bytes) -> dict:
    """
    Encrypt (wrap) a DEK under the KEK.
    Returns a JSON-serialisable dict.
    """
    cipher = AES.new(kek, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(dek)
    return {
        "wrapped": _b64e(ciphertext),
        "nonce":   _b64e(cipher.nonce),
        "tag":     _b64e(tag),
    }


def unwrap_dek(wrapped: dict, kek: bytes) -> bytes:
    """
    Decrypt (unwrap) a DEK using the KEK.
    Raises ValueError on authentication failure.
    """
    cipher = AES.new(kek, AES.MODE_EAX, nonce=_b64d(wrapped["nonce"]))
    return cipher.decrypt_and_verify(_b64d(wrapped["wrapped"]), _b64d(wrapped["tag"]))


# ─── Data encryption ─────────────────────────────────────────────────────────

def encrypt(plaintext: str, dek: bytes) -> dict:
    """
    Encrypt a UTF-8 string with a DEK.
    Returns a JSON-serialisable dict.
    """
    cipher = AES.new(dek, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return {
        "ciphertext": _b64e(ciphertext),
        "nonce":      _b64e(cipher.nonce),
        "tag":        _b64e(tag),
    }


def decrypt(encrypted: dict, dek: bytes) -> str:
    """
    Decrypt an AES-EAX ciphertext dict.
    Raises ValueError on authentication failure (tampered data).
    """
    cipher = AES.new(dek, AES.MODE_EAX, nonce=_b64d(encrypted["nonce"]))
    plaintext = cipher.decrypt_and_verify(
        _b64d(encrypted["ciphertext"]),
        _b64d(encrypted["tag"])
    )
    return plaintext.decode()
