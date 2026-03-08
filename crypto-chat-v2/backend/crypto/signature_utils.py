from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import PKCS1_OAEP
import base64
import json

def generate_keypair(key_size=2048):
    """Generate RSA keypair"""
    key = RSA.generate(key_size)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    
    return {
        'private_key': private_key,
        'public_key': public_key,
        'key_size': key_size
    }

def sign_data(data, private_key_pem):
    """Create digital signature for data"""
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True)
    if isinstance(data, str):
        data = data.encode()
    
    private_key = RSA.import_key(private_key_pem)
    h = SHA256.new(data)
    signature = pkcs1_15.new(private_key).sign(h)
    
    return base64.b64encode(signature).decode()

def verify_signature(data, signature_b64, public_key_pem):
    """Verify digital signature"""
    try:
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True)
        if isinstance(data, str):
            data = data.encode()
        
        public_key = RSA.import_key(public_key_pem)
        h = SHA256.new(data)
        signature = base64.b64decode(signature_b64)
        
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

def encrypt_with_public_key(data, public_key_pem):
    """Encrypt data with RSA public key"""
    if isinstance(data, dict):
        data = json.dumps(data)
    if isinstance(data, str):
        data = data.encode()
    
    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key)
    
    # RSA can only encrypt small amounts, so we chunk if needed
    max_chunk_size = public_key.size_in_bytes() - 42  # OAEP overhead
    encrypted_chunks = []
    
    for i in range(0, len(data), max_chunk_size):
        chunk = data[i:i + max_chunk_size]
        encrypted_chunk = cipher.encrypt(chunk)
        encrypted_chunks.append(base64.b64encode(encrypted_chunk).decode())
    
    return encrypted_chunks

def decrypt_with_private_key(encrypted_chunks, private_key_pem):
    """Decrypt data with RSA private key"""
    private_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(private_key)
    
    decrypted_data = b''
    for chunk_b64 in encrypted_chunks:
        chunk = base64.b64decode(chunk_b64)
        decrypted_chunk = cipher.decrypt(chunk)
        decrypted_data += decrypted_chunk
    
    return decrypted_data.decode()

def create_anonymous_id(public_key_pem):
    """Create anonymous identifier from public key"""
    from crypto.hash_utils import hash_data
    return hash_data(public_key_pem)[:16]  # Short anonymous ID
