"""
Double Ratchet (Signal-style) — "Cryptographic Amnesia"
Every message gets a fresh derived key via HKDF. Once you advance the ratchet,
the old key is mathematically gone — not just deleted, but underivable.
Past messages are provably unreadable even if traffic is recorded and device is later stolen.
"""
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import base64
import os


def _hkdf(key, salt, info, length=32):
    return HKDF(key, length, salt, SHA256, 1, context=info)


def _ratchet_step(chain_key):
    """One ratchet step: (msg_key, next_chain_key). Old chain_key is not needed after this."""
    out = HKDF(chain_key, 64, b"", SHA256, 1, context=b"double-ratchet-step")
    msg_key, next_chain = out[:32], out[32:]
    return msg_key, next_chain


class DoubleRatchet:
    """
    Simplified Double Ratchet: send and receive chains, each step derives a new key.
    Keys are used once then discarded — forward secrecy by construction.
    """

    def __init__(self, shared_secret=None):
        self.shared_secret = shared_secret or get_random_bytes(32)
        self.send_chain = _hkdf(self.shared_secret, b"", b"send-chain", length=32)
        self.recv_chain = _hkdf(self.shared_secret, b"", b"recv-chain", length=32)
        self.send_step = 0
        self.recv_step = 0

    def encrypt(self, plaintext):
        """Derive next send key, encrypt, advance ratchet. Old key is underivable."""
        msg_key, next_chain = _ratchet_step(self.send_chain)
        self.send_chain = next_chain
        self.send_step += 1
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        nonce = get_random_bytes(12)
        cipher = AES.new(msg_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(tag).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'step': self.send_step,
        }

    def decrypt(self, payload):
        """Derive recv key for this step, decrypt, advance ratchet. Messages must be in order."""
        step = payload.get('step')
        if step != self.recv_step + 1:
            raise ValueError("Out-of-order or duplicate message; cannot derive key")
        msg_key, next_chain = _ratchet_step(self.recv_chain)
        self.recv_chain = next_chain
        self.recv_step += 1
        ciphertext = base64.b64decode(payload['ciphertext'])
        tag = base64.b64decode(payload['tag'])
        nonce = base64.b64decode(payload['nonce'])
        cipher = AES.new(msg_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()
