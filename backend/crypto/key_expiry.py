import os

def destroy_encrypted_key(key_file_path):
    """
    Permanently deletes the encrypted AES key file.
    This makes decryption mathematically impossible.
    """
    if os.path.exists(key_file_path):
        os.remove(key_file_path)
        return True
    return False
