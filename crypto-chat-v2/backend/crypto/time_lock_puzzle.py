"""
Time-Lock Puzzles / VDF (Verifiable Delay Functions)
Encrypt a message so it cannot be decrypted until a specific time — not policy,
but math: N sequential operations that take exactly X time regardless of compute power.
"""
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import SHA256
import hashlib
import base64
import time


def _sequential_hash(key, iterations):
    """VDF-style: N sequential hashes. Cannot be parallelized."""
    h = key
    for _ in range(iterations):
        h = hashlib.sha256(h).digest()
    return h


def create_time_lock_encryption(plaintext, iterations=100000, salt=None):
    """
    Encrypt so decryption requires `iterations` sequential SHA256 steps.
    More iterations = longer minimum time to decrypt (e.g. ~1s per 100k on modest CPU).
    Returns (ciphertext_b64, nonce_b64, salt_b64, iterations).
    """
    if salt is None:
        salt = get_random_bytes(32)
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    key_seed = get_random_bytes(32)
    key = _sequential_hash(key_seed, iterations)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    nonce = cipher.nonce
    return {
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'tag': base64.b64encode(tag).decode(),
        'nonce': base64.b64encode(nonce).decode(),
        'salt': base64.b64encode(salt).decode(),
        'key_seed': base64.b64encode(key_seed).decode(),
        'iterations': iterations,
    }


def solve_time_lock_and_decrypt(payload):
    """
    Perform N sequential hashes then decrypt. Cannot be sped up with more CPUs.
    """
    key_seed = base64.b64decode(payload['key_seed'])
    iterations = payload['iterations']
    key = _sequential_hash(key_seed, iterations)
    ciphertext = base64.b64decode(payload['ciphertext'])
    tag = base64.b64decode(payload['tag'])
    nonce = base64.b64decode(payload['nonce'])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()


def iterations_for_seconds(approx_seconds, one_iteration_sec=1e-5):
    """Rough iteration count so that solve_time_lock takes ~ approx_seconds."""
    return max(1000, int(approx_seconds / one_iteration_sec))
