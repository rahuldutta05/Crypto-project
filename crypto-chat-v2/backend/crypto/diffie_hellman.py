"""
Diffie-Hellman Key Exchange
Used for establishing shared secrets between devices during pairing
"""

import os
import hashlib
from Cryptodome.Util import number


class DiffieHellman:
    """
    Diffie-Hellman key exchange implementation
    Uses RFC 3526 2048-bit MODP Group 14
    """

    # RFC 3526 2048-bit MODP Group 14 (well-known safe prime)
    P = int(
        'FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1'
        '29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD'
        'EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245'
        'E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED'
        'EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D'
        'C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F'
        '83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D'
        '670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B'
        'E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9'
        'DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510'
        '15728E5A 8AACAA68 FFFFFFFF FFFFFFFF'.replace(' ', ''),
        16
    )

    G = 2  # Generator

    def __init__(self):
        """Initialize DH with random private key"""
        # Generate random private key (256 bits)
        self.private_key = number.getRandomRange(2, self.P - 1)

        # Compute public key: g^private mod p
        self._public_key_int = pow(self.G, self.private_key, self.P)

        # Store as hex string for JSON serialization (large int won't serialize)
        self.public_key = hex(self._public_key_int)[2:]  # hex string without '0x'

    def compute_shared_secret(self, other_public_key_hex):
        """
        Compute shared secret given other party's public key (hex string)
        shared_secret = other_public^private mod p
        """
        if isinstance(other_public_key_hex, int):
            other_public_key_int = other_public_key_hex
        else:
            # Accept hex string
            other_public_key_int = int(other_public_key_hex, 16)

        # Verify public key is valid
        if other_public_key_int < 2 or other_public_key_int >= self.P:
            raise ValueError("Invalid public key")

        # Compute shared secret
        shared_secret_int = pow(other_public_key_int, self.private_key, self.P)

        # Return as hex string
        return hex(shared_secret_int)[2:]

    @staticmethod
    def derive_session_key(shared_secret_hex, salt=None):
        """
        Derive AES session key from shared secret using PBKDF2
        """
        from Cryptodome.Protocol.KDF import PBKDF2
        from Cryptodome.Hash import SHA256

        if salt is None:
            salt = os.urandom(32)

        if isinstance(shared_secret_hex, str):
            password = shared_secret_hex.encode()
        else:
            password = shared_secret_hex

        # Derive 32-byte key (AES-256)
        key = PBKDF2(
            password=password,
            salt=salt,
            dkLen=32,
            count=100000,
            hmac_hash_module=SHA256
        )

        import base64
        return key, base64.b64encode(salt).decode()

    def get_private_key_hex(self):
        """Return private key as hex string (for temporary server-side storage)"""
        return hex(self.private_key)[2:]

    @classmethod
    def from_private_key_hex(cls, private_key_hex):
        """Reconstruct DH instance from stored private key hex"""
        instance = cls.__new__(cls)
        instance.private_key = int(private_key_hex, 16)
        instance._public_key_int = pow(cls.G, instance.private_key, cls.P)
        instance.public_key = hex(instance._public_key_int)[2:]
        return instance


# Example usage for testing
if __name__ == '__main__':
    alice = DiffieHellman()
    print(f"Alice's public key (hex, first 64 chars): {alice.public_key[:64]}...")

    bob = DiffieHellman()
    print(f"Bob's public key (hex, first 64 chars): {bob.public_key[:64]}...")

    alice_shared = alice.compute_shared_secret(bob.public_key)
    bob_shared = bob.compute_shared_secret(alice.public_key)

    print(f"\nAlice's shared secret (first 50): {alice_shared[:50]}...")
    print(f"Bob's shared secret   (first 50): {bob_shared[:50]}...")
    print(f"Secrets match: {alice_shared == bob_shared}")

    session_key, salt = DiffieHellman.derive_session_key(alice_shared)
    print(f"\nSession key (hex): {session_key.hex()}")
