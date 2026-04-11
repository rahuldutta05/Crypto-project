from flask import Blueprint, request, jsonify
from monitoring.security_monitor import security_monitor
import json
import os
from datetime import datetime, timedelta, timezone
from crypto.signature_utils import generate_keypair, sign_data, verify_signature, create_anonymous_id
from crypto.hash_utils import create_commitment, verify_commitment, hash_data
from crypto.blind_signatures import (
    server_keygen, blind_message, blind_sign, unblind_signature,
    verify_blind_signature
)

auth_bp = Blueprint('auth', __name__)

BLIND_KEY_PATH = 'storage/blind_signing_key.json'


def _get_blind_signing_key():
    if os.path.exists(BLIND_KEY_PATH):
        with open(BLIND_KEY_PATH, 'r') as f:
            return json.load(f)
    key = server_keygen()
    with open(BLIND_KEY_PATH, 'w') as f:
        json.dump(key, f, indent=2)
    return key

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
            'created_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
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
            security_monitor.log_event('unauthorized_attempt', {
                'action': 'get_challenge',
                'anon_id': anon_id,
                'ip': request.remote_addr,
                'note': 'Attempted to get challenge for unknown ID'
            })
            return jsonify({'error': 'Anonymous ID not found'}), 404
        
        # Generate challenge
        challenge = os.urandom(32).hex()
        
        # Store challenge temporarily
        tokens[anon_id]['challenge'] = challenge
        tokens[anon_id]['challenge_time'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
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
            security_monitor.log_event('auth_failure', {
                'reason': 'unknown_id',
                'anon_id': anon_id,
                'ip': request.remote_addr
            })
            return jsonify({'error': 'Anonymous ID not found'}), 404
        
        user_data = tokens[anon_id]
        
        # Check challenge expiry
        # Need to handle Z for fromisoformat if Python < 3.11
        challenge_time_str = user_data['challenge_time']
        challenge_time = datetime.fromisoformat(challenge_time_str.replace('Z', '+00:00'))
        if datetime.now(timezone.utc) - challenge_time > timedelta(minutes=5):
            return jsonify({'error': 'Challenge expired'}), 401
        
        # Verify signature
        challenge = user_data['challenge']
        public_key = user_data['public_key']
        
        if not verify_signature(challenge, signature, public_key):
            security_monitor.log_event('auth_failure', {
                'reason': 'invalid_signature',
                'anon_id': anon_id,
                'ip': request.remote_addr
            })
            return jsonify({'error': 'Invalid signature'}), 401
        
        # Create session token
        session_token = os.urandom(32).hex()
        tokens[anon_id]['session_token'] = session_token
        tokens[anon_id]['session_expires'] = (datetime.now(timezone.utc) + timedelta(hours=12)).isoformat().replace('+00:00', 'Z')
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
        expires_str = user_data['session_expires']
        expires = datetime.fromisoformat(expires_str.replace('Z', '+00:00'))
        if datetime.now(timezone.utc) >= expires:
            return jsonify({'valid': False, 'error': 'Token expired'}), 401
        
        return jsonify({
            'valid': True,
            'anon_id': anon_id,
            'public_key': user_data['public_key']
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# ── Blind Signatures (Chaum): server signs without seeing the token ───────────

@auth_bp.route('/blind-public-key', methods=['GET'])
def get_blind_public_key():
    """Get server's public key for blind signing. Server never sees the token."""
    try:
        key = _get_blind_signing_key()
        return jsonify({
            'public_key': key['public_key'],
            'message': 'Use this to blind your token; server will sign without seeing it'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@auth_bp.route('/blind-sign', methods=['POST'])
def blind_sign_endpoint():
    """
    Submit blinded message. Server signs it without ever seeing the content.
    Client later unblinds to get signature on original token — anonymous e-cash style.
    """
    try:
        data = request.json
        blinded_message = data.get('blinded_message')  # int or str of int
        if blinded_message is None:
            return jsonify({'error': 'blinded_message required'}), 400
        key = _get_blind_signing_key()
        blinded_int = int(blinded_message)
        signed_blind = blind_sign(blinded_int, key['private_key'])
        return jsonify({
            'signed_blinded': str(signed_blind),
            'message': 'Signature on blinded token; unblind client-side to get token signature'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@auth_bp.route('/verify-blind-token', methods=['POST'])
def verify_blind_token():
    """
    Verify a (token, signature) pair. Server can verify it's genuine but has
    zero record of having issued it to you specifically.
    """
    try:
        data = request.json
        token = data.get('token')  # raw token string
        signature = data.get('signature')  # int or str
        if not token or signature is None:
            return jsonify({'valid': False, 'error': 'token and signature required'}), 400
        key = _get_blind_signing_key()
        sig_int = int(signature)
        valid = verify_blind_signature(token, sig_int, key['public_key'])
        return jsonify({
            'valid': valid,
            'message': 'Token is genuine' if valid else 'Invalid or forged token'
        })
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)}), 400
