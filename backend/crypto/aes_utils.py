from cryptography.fernet import Fernet

def generate_aes_key():
    return Fernet.generate_key()

def encrypt_data(data, key):
    return Fernet(key).encrypt(data)

def decrypt_data(data, key):
    return Fernet(key).decrypt(data)
