import hashlib
import json
from datetime import datetime
import os

def hash_data(data):
    """Create SHA-256 hash of data"""
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True)
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()

def create_merkle_root(hashes):
    """Create Merkle root from list of hashes"""
    if not hashes:
        return None
    if len(hashes) == 1:
        return hashes[0]
    
    # Pair up hashes and hash them together
    new_level = []
    for i in range(0, len(hashes), 2):
        if i + 1 < len(hashes):
            combined = hashes[i] + hashes[i + 1]
        else:
            combined = hashes[i] + hashes[i]
        new_level.append(hash_data(combined))
    
    return create_merkle_root(new_level)

def create_proof_of_existence(data, metadata=None):
    """
    Create cryptographic proof that data existed at a specific time
    Returns proof object without storing the original data
    """
    timestamp = datetime.utcnow().isoformat()
    data_hash = hash_data(data)
    
    proof = {
        'hash': data_hash,
        'timestamp': timestamp,
        'algorithm': 'sha256',
        'metadata': metadata or {}
    }
    
    # Create a chain hash including timestamp
    chain_data = f"{data_hash}:{timestamp}"
    proof['proof_hash'] = hash_data(chain_data)
    
    return proof

def verify_proof_of_existence(data, proof):
    """Verify that data matches a proof-of-existence"""
    data_hash = hash_data(data)
    
    if data_hash != proof['hash']:
        return False, "Data hash does not match proof"
    
    # Verify chain hash
    chain_data = f"{data_hash}:{proof['timestamp']}"
    expected_proof_hash = hash_data(chain_data)
    
    if expected_proof_hash != proof['proof_hash']:
        return False, "Proof chain is invalid"
    
    return True, "Proof verified successfully"

def create_commitment(secret):
    """
    Create a cryptographic commitment (for anonymous auth)
    Returns (commitment, nonce)
    """
    nonce = os.urandom(32).hex()
    commitment_data = f"{secret}:{nonce}"
    commitment = hash_data(commitment_data)
    return commitment, nonce

def verify_commitment(secret, nonce, commitment):
    """Verify a cryptographic commitment"""
    commitment_data = f"{secret}:{nonce}"
    expected_commitment = hash_data(commitment_data)
    return expected_commitment == commitment
