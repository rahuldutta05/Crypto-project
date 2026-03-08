from flask import Blueprint, request, jsonify
import json
from crypto.hash_utils import verify_proof_of_existence

verify_bp = Blueprint('verify', __name__)

def load_proofs():
    with open('storage/proof.json', 'r') as f:
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
