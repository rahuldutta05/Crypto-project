"""
Ring Signatures — "The Phantom Sender"
Proves a message came from one of N registered users; nobody can tell which one.
Same primitive used in Monero (privacy cryptocurrency). Toy implementation.
"""
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Util.number import bytes_to_long, long_to_bytes
import os
import base64
import json


def _hash_message(message):
    if isinstance(message, str):
        message = message.encode()
    return bytes_to_long(SHA256.new(message).digest())


def ring_keygen_shared_modulus(ring_size=5, key_bits=2048):
    """
    Generate a ring where all members share the same modulus n (toy / demo).
    Returns (public_ring, private_keys). public_ring = [(n, e_i)]; private_keys = [d_i].
    """
    key = RSA.generate(key_bits)
    n = key.n
    phi = (key.p - 1) * (key.q - 1)
    public_ring = []
    private_keys = []
    for _ in range(ring_size):
        e = 65537
        while True:
            try:
                d = pow(e, -1, phi)
                break
            except Exception:
                e += 2
        public_ring.append((n, e))
        private_keys.append(d)
    return public_ring, private_keys, n


def ring_sign(message, signer_private_exponent_d, signer_index, public_ring, modulus_n):
    """
    Sign so that the signature proves it came from one of the ring members.
    public_ring = list of (n, e) with same n; modulus_n is that n.
    """
    if isinstance(message, str):
        message = message.encode()
    n, ring_size = modulus_n, len(public_ring)
    c = _hash_message(message) % n
    if c == 0:
        c = 1
    x_list = [0] * ring_size
    # For i != signer: pick random x_i, compute z_i = x_i^e_i mod n
    product_inv = 1
    for i in range(ring_size):
        if i == signer_index:
            continue
        x_i = bytes_to_long(os.urandom(n.bit_length() // 8)) % n
        if x_i == 0:
            x_i = 1
        x_list[i] = x_i
        _, e_i = public_ring[i]
        z_i = pow(x_i, e_i, n)
        product_inv = (product_inv * pow(z_i, -1, n)) % n
    # z_s = c * product_{i!=s} z_i^{-1} mod n; x_s = z_s^d_s
    z_s = (c * product_inv) % n
    d_s = signer_private_exponent_d
    x_list[signer_index] = pow(z_s, d_s, n)
    sig = {'c': c, 'x': x_list, 'ring': [(str(n), str(e)) for n, e in public_ring], 'n': ring_size}
    return {'signature': base64.b64encode(json.dumps(sig, default=str).encode()).decode(), 'ring_size': ring_size}


def ring_verify(message, signature_b64):
    """Verify that the signature was produced by one of the ring members."""
    if isinstance(message, str):
        message = message.encode()
    raw = json.loads(base64.b64decode(signature_b64).decode())
    c, x_list, ring, n = raw['c'], raw['x'], raw['ring'], raw['n']
    if len(x_list) != n or len(ring) != n:
        return False
    mod_n = int(ring[0][0])
    product = 1
    for i in range(n):
        ni, ei = int(ring[i][0]), int(ring[i][1])
        xi = int(x_list[i]) if isinstance(x_list[i], str) else x_list[i]
        product = (product * pow(xi, ei, mod_n)) % mod_n
    c_computed = _hash_message(message) % mod_n
    if c_computed == 0:
        c_computed = 1
    return product == c_computed


def ring_verify_with_ring(message, signature_b64, expected_public_ring, expected_n):
    """Verify and check the ring matches expected (same modulus and exponents)."""
    if not ring_verify(message, signature_b64):
        return False
    raw = json.loads(base64.b64decode(signature_b64).decode())
    actual = [(r[0], r[1]) for r in raw['ring']]
    expected = [(str(n), str(e)) for n, e in expected_public_ring]
    return len(actual) == len(expected) and set(actual) == set(expected)
