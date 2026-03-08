from flask import Blueprint, request, jsonify
import json
from crypto.hash_utils import verify_proof_of_existence
from crypto.merkle_proofs import create_merkle_proof, verify_merkle_proof
from crypto.proof_of_deletion import create_proof_of_deletion, verify_proof_of_deletion

verify_bp = Blueprint('verify', __name__)

def load_proofs():
    with open('storage/proof.json', 'r') as f:
        return json.load(f)


def load_merkle_state():
    with open('storage/merkle_state.json', 'r') as f:
        return json.load(f)


@verify_bp.route('/proof/<message_id>', methods=['GET'])
def get_proof(message_id):
    """Get proof-of-existence for a message"""
    try:
        proofs = load_proofs()
        
        if message_id not in proofs:
            return jsonify({'error': 'Proof not found'}), 404
        
        proof = proofs[message_id]
        
        return jsonify({
            'proof': proof,
            'message': 'This proof demonstrates the message existed at the recorded timestamp'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@verify_bp.route('/verify', methods=['POST'])
def verify_message():
    """Verify a message against its proof-of-existence"""
    try:
        data = request.json
        message = data.get('message')
        proof = data.get('proof')
        
        is_valid, message_text = verify_proof_of_existence(message, proof)
        
        if is_valid:
            return jsonify({
                'valid': True,
                'message': message_text,
                'timestamp': proof['timestamp']
            })
        else:
            return jsonify({
                'valid': False,
                'error': message_text
            }), 400
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@verify_bp.route('/integrity/<message_id>', methods=['POST'])
def check_integrity(message_id):
    """Check if message matches its stored proof"""
    try:
        data = request.json
        message = data.get('message')
        
        proofs = load_proofs()
        if message_id not in proofs:
            return jsonify({'error': 'Proof not found'}), 404
        
        proof = proofs[message_id]
        is_valid, result = verify_proof_of_existence(message, proof)
        
        return jsonify({
            'valid': is_valid,
            'message': result,
            'proof_timestamp': proof['timestamp'],
            'proof_hash': proof['proof_hash']
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# ── Merkle Proof Trees: prove one message existed without revealing others ─────

@verify_bp.route('/merkle/root', methods=['GET'])
def get_merkle_root():
    """Get current Merkle root (32 bytes). Proves aggregate existence of all messages."""
    try:
        state = load_merkle_state()
        return jsonify({
            'root_hash': state.get('root_hash'),
            'tree_size': state.get('tree_size', 0),
            'message': 'Prove any single message existed with a Merkle path — without revealing others'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@verify_bp.route('/merkle/proof/<message_id>', methods=['GET'])
def get_merkle_proof_for_message(message_id):
    """Get Merkle path for a message. Proof the size of a tweet, covering millions."""
    try:
        proofs = load_proofs()
        if message_id not in proofs:
            return jsonify({'error': 'Proof not found'}), 404
        proof = proofs[message_id]
        leaf_index = proof.get('merkle_index')
        if leaf_index is None:
            return jsonify({'error': 'Merkle index not stored for this message'}), 404
        state = load_merkle_state()
        leaves = state.get('leaf_hashes', [])
        if leaf_index >= len(leaves):
            return jsonify({'error': 'Merkle state out of sync'}), 404
        merkle_proof = create_merkle_proof(leaves, leaf_index)
        return jsonify({
            'message_id': message_id,
            'proof': merkle_proof,
            'message': 'Verify with this path: leaf_hash + path -> root_hash'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@verify_bp.route('/merkle/verify', methods=['POST'])
def verify_merkle_path_endpoint():
    """Verify a Merkle proof (path + leaf_hash -> root_hash)."""
    try:
        data = request.json
        proof = data.get('proof')
        if not proof:
            return jsonify({'valid': False, 'error': 'proof required'}), 400
        valid = verify_merkle_proof(proof)
        return jsonify({
            'valid': valid,
            'message': 'Message existed in tree at recorded time' if valid else 'Invalid proof'
        })
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)}), 400


# ── Proof of Deletion: prove you deleted a key ────────────────────────────────

@verify_bp.route('/proof-of-deletion', methods=['POST'])
def submit_proof_of_deletion():
    """Submit a proof of deletion. Commitment was issued; holder attests key overwritten."""
    try:
        data = request.json
        commitment_hash = data.get('commitment_hash')
        key_id = data.get('key_id')
        attestation_key = data.get('attestation_key')  # optional HMAC key
        proof = create_proof_of_deletion(commitment_hash, key_id=key_id, secret_attestation_key=attestation_key)
        # Record as deleted so verifiers can check
        with open('storage/deleted_commitments.json', 'r') as f:
            deleted = json.load(f)
        deleted.append({'commitment_hash': commitment_hash, 'proof': proof})
        with open('storage/deleted_commitments.json', 'w') as f:
            json.dump(deleted, f, indent=2)
        return jsonify({
            'success': True,
            'proof': proof,
            'message': 'Proof of deletion recorded — cryptographically demonstrated'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@verify_bp.route('/proof-of-deletion/verify', methods=['POST'])
def verify_proof_of_deletion_endpoint():
    """Verify a proof of deletion."""
    try:
        data = request.json
        proof = data.get('proof')
        expected_commitment = data.get('expected_commitment')
        if not proof:
            return jsonify({'valid': False, 'error': 'proof required'}), 400
        valid = verify_proof_of_deletion(proof, expected_commitment_b64=expected_commitment)
        return jsonify({
            'valid': valid,
            'message': 'Deletion attested and binding' if valid else 'Invalid proof'
        })
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)}), 400
