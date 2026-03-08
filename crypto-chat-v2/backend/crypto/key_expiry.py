from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import PBKDF2
import base64
import json
from datetime import datetime, timedelta
import os

def generate_session_key():
    """Generate AES-256 session key"""
    return get_random_bytes(32)

def encrypt_message(message, session_key):
    """Encrypt message with AES-256-GCM"""
    if isinstance(message, str):
        message = message.encode()
    
    cipher = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    
    return {
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'tag': base64.b64encode(tag).decode(),
        'nonce': base64.b64encode(cipher.nonce).decode()
    }

def decrypt_message(encrypted_data, session_key):
    """Decrypt AES-256-GCM encrypted message"""
    try:
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        tag = base64.b64decode(encrypted_data['tag'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        
        cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        return plaintext.decode()
    except Exception as e:
        raise ValueError("Decryption failed - key may have expired or is invalid")

def create_time_locked_key(session_key, expiry_time):
    """
    Create time-locked encryption key
    The key includes expiry metadata and will be automatically deleted
    """
    key_id = os.urandom(16).hex()
    
    return {
        'key_id': key_id,
        'session_key': base64.b64encode(session_key).decode(),
        'created_at': datetime.utcnow().isoformat(),
        'expires_at': expiry_time.isoformat(),
        'status': 'active'
    }

def is_key_expired(key_data):
    """Check if a time-locked key has expired"""
    if key_data['status'] == 'expired':
        return True
    
    expires_at = datetime.fromisoformat(key_data['expires_at'])
    return datetime.utcnow() >= expires_at

def expire_key(key_data):
    """
    Permanently expire a key by destroying the session key
    This makes all messages encrypted with this key permanently undecryptable
    """
    key_data['status'] = 'expired'
    key_data['session_key'] = None  # Permanently destroy the key
    key_data['expired_at'] = datetime.utcnow().isoformat()
    return key_data

def derive_key_from_password(password, salt=None):
    """Derive encryption key from password using PBKDF2"""
    if salt is None:
        salt = get_random_bytes(32)
    
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    
    return {
        'key': key,
        'salt': base64.b64encode(salt).decode()
    }

class TimeLockCipher:
    """
    Wrapper class for time-locked encryption
    Ensures keys are checked for expiry before decryption
    """
    
    def __init__(self, key_storage):
        self.key_storage = key_storage
    
    def encrypt(self, message, expiry_delta=timedelta(hours=24)):
        """Encrypt message with time-locked key"""
        session_key = generate_session_key()
        encrypted = encrypt_message(message, session_key)
        
        expiry_time = datetime.utcnow() + expiry_delta
        key_data = create_time_locked_key(session_key, expiry_time)
        
        # Store key
        self.key_storage[key_data['key_id']] = key_data
        
        return {
            'key_id': key_data['key_id'],
            'encrypted_data': encrypted,
            'expires_at': expiry_time.isoformat()
        }
    
    def decrypt(self, key_id, encrypted_data):
        """Decrypt message if key hasn't expired"""
        if key_id not in self.key_storage:
            raise ValueError("Key not found")
        
        key_data = self.key_storage[key_id]
        
        # Check expiry
        if is_key_expired(key_data):
            raise ValueError("Key has expired - message is permanently undecryptable")
        
        # Decrypt
        session_key = base64.b64decode(key_data['session_key'])
        return decrypt_message(encrypted_data, session_key)
    
    def check_and_expire_keys(self):
        """Check all keys and expire those past their expiry time"""
        expired_count = 0
        for key_id, key_data in list(self.key_storage.items()):
            if key_data['status'] == 'active' and is_key_expired(key_data):
                self.key_storage[key_id] = expire_key(key_data)
                expired_count += 1
        
        return expired_count
