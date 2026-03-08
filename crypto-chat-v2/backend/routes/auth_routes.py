from flask import Blueprint, request, jsonify
import json
import os
from datetime import datetime, timedelta
from crypto.signature_utils import generate_keypair, sign_data, verify_signature, create_anonymous_id
from crypto.hash_utils import create_commitment, verify_commitment, hash_data

auth_bp = Blueprint('auth', __name__)

def load_tokens():
    with open('storage/tokens.json', 'r') as f:
        return json.load(f)

def save_tokens(tokens):
    with open('storage/tokens.json', 'w') as f:
        json.dump(tokens, f, indent=2)

@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Anonymous registration with zero-knowledge proof
    User proves they can create valid signatures without revealing identity
    """
    try:
        data = request.json
        
        # Generate keypair for user (in real app, client generates this)
        keypair = generate_keypair()
        
        # Create anonymous ID from public key
        anon_id = create_anonymous_id(keypair['public_key'])
        
        # Create commitment for zero-knowledge proof
        secret = os.urandom(32).hex()
        commitment, nonce = create_commitment(secret)
        
        # Store user data
        tokens = load_tokens()
        tokens[anon_id] = {
            'public_key': keypair['public_key'],
            'commitment': commitment,
            'nonce': nonce,
            'secret': secret,  # In production, server wouldn't store this
            'created_at': datetime.utcnow().isoformat(),
            'status': 'active'
        }
        save_tokens(tokens)
        
        return jsonify({
            'success': True,
            'anon_id': anon_id,
            'private_key': keypair['private_key'],  # Client stores this securely
            'public_key': keypair['public_key'],
            'commitment': commitment,
            'message': 'Anonymous identity created successfully'
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@auth_bp.route('/challenge', methods=['POST'])
def get_challenge():
    """
    Get authentication challenge for zero-knowledge proof
    """
    try:
        data = request.json
        anon_id = data.get('anon_id')
        
        tokens = load_tokens()
        if anon_id not in tokens:
            return jsonify({'error': 'Anonymous ID not found'}), 404
        
        # Generate challenge
        challenge = os.urandom(32).hex()
        
        # Store challenge temporarily
        tokens[anon_id]['challenge'] = challenge
        tokens[anon_id]['challenge_time'] = datetime.utcnow().isoformat()
        save_tokens(tokens)
        
        return jsonify({
            'challenge': challenge,
            'expires_in': 300  # 5 minutes
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@auth_bp.route('/verify', methods=['POST'])
def verify_identity():
    """
    Verify zero-knowledge proof without revealing identity
    User signs challenge to prove they own the private key
    """
    try:
        data = request.json
        anon_id = data.get('anon_id')
        signature = data.get('signature')
        
        tokens = load_tokens()
        if anon_id not in tokens:
            return jsonify({'error': 'Anonymous ID not found'}), 404
        
        user_data = tokens[anon_id]
        
        # Check challenge expiry
        challenge_time = datetime.fromisoformat(user_data['challenge_time'])
        if datetime.utcnow() - challenge_time > timedelta(minutes=5):
            return jsonify({'error': 'Challenge expired'}), 401
        
        # Verify signature
        challenge = user_data['challenge']
        public_key = user_data['public_key']
        
        if not verify_signature(challenge, signature, public_key):
            return jsonify({'error': 'Invalid signature'}), 401
        
        # Create session token
        session_token = os.urandom(32).hex()
        tokens[anon_id]['session_token'] = session_token
        tokens[anon_id]['session_expires'] = (datetime.utcnow() + timedelta(hours=12)).isoformat()
        save_tokens(tokens)
        
        return jsonify({
            'success': True,
            'session_token': session_token,
            'anon_id': anon_id,
            'message': 'Identity verified without revealing personal information'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@auth_bp.route('/validate', methods=['POST'])
def validate_session():
    """Validate session token"""
    try:
        data = request.json
        anon_id = data.get('anon_id')
        session_token = data.get('session_token')
        
        tokens = load_tokens()
        if anon_id not in tokens:
            return jsonify({'valid': False, 'error': 'User not found'}), 404
        
        user_data = tokens[anon_id]
        
        if user_data.get('session_token') != session_token:
            return jsonify({'valid': False, 'error': 'Invalid token'}), 401
        
        # Check expiry
        expires = datetime.fromisoformat(user_data['session_expires'])
        if datetime.utcnow() >= expires:
            return jsonify({'valid': False, 'error': 'Token expired'}), 401
        
        return jsonify({
            'valid': True,
            'anon_id': anon_id,
            'public_key': user_data['public_key']
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400
