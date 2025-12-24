import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

KEY_EXPIRY_MINUTES = 5

ENCRYPTED_DATA_PATH = os.path.join(BASE_DIR, "storage/encrypted_data")
ENCRYPTED_KEYS_PATH = os.path.join(BASE_DIR, "storage/encrypted_keys")

RSA_KEY_SIZE = 2048
HASH_ALGORITHM = "SHA256"
