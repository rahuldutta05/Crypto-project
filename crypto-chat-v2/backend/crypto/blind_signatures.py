"""
Blind Signatures (Chaum's Scheme) — "Carbon-paper envelope"
Server signs your authentication token without ever seeing it.
You later reveal the token; server can verify it's genuine but has zero record
of having issued it to you. How anonymous e-cash works.
"""
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Util.number import bytes_to_long, long_to_bytes
import os
import base64
import hashlib


def server_keygen(key_size=2048):
    """Server generates RSA keypair for blind signing."""
    key = RSA.generate(key_size)
    return {
        'private_key': key.export_key().decode(),
        'public_key': key.publickey().export_key().decode(),
    }


def blind_message(message, server_public_key_pem):
    """
    Client: blind the message so server can't see it.
    Returns (blinded_message_int, blinding_secret) for later unblinding.
    Message is hashed first so we can sign arbitrary length.
    """
    if isinstance(message, str):
        message = message.encode()
    m_hash = bytes_to_long(SHA256.new(message).digest())
    pub = RSA.import_key(server_public_key_pem)
    n, e = pub.n, pub.e
    # r random in Z_n*
    r = 1
    while r == 1 or pow(r, -1, n) is None:
        r = bytes_to_long(os.urandom(pub.size_in_bytes() - 1)) % n
    # Blinded: m' = m * r^e mod n (so server will return m^d * r mod n)
    m_blind = (m_hash * pow(r, e, n)) % n
    return m_blind, r, n


def blind_sign(blinded_message_int, server_private_key_pem):
    """
    Server: sign the blinded message without knowing the content.
    Returns signature of blinded message: s' = m'^d mod n.
    """
    priv = RSA.import_key(server_private_key_pem)
    s_blind = pow(blinded_message_int, priv.d, priv.n)
    return s_blind


def unblind_signature(s_blind, r, n):
    """
    Client: remove blinding to get signature on original message.
    s = s' * r^{-1} mod n = m^d mod n.
    """
    r_inv = pow(r, -1, n)
    s = (s_blind * r_inv) % n
    return s


def verify_blind_signature(message, signature_int, server_public_key_pem):
    """
    Anyone: verify that signature is valid for message under server's public key.
    Checks signature^e ≡ H(message) (mod n).
    """
    if isinstance(message, str):
        message = message.encode()
    m_hash = bytes_to_long(SHA256.new(message).digest())
    pub = RSA.import_key(server_public_key_pem)
    recovered = pow(signature_int, pub.e, pub.n)
    return recovered == m_hash


def encode_blind_token_for_storage(signature_int, n_bytes=256):
    """Encode signature as fixed-length bytes for storage/transmission."""
    return long_to_bytes(signature_int, n_bytes or 256)


def decode_blind_token_from_storage(signature_bytes):
    """Decode stored signature back to int."""
    return bytes_to_long(signature_bytes)
