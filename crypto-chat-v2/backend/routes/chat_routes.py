from flask import Blueprint, request, jsonify
import json
from datetime import datetime, timedelta
from crypto.key_expiry import TimeLockCipher, generate_session_key, encrypt_message
from crypto.signature_utils import encrypt_with_public_key, sign_data
from crypto.hash_utils import create_proof_of_existence
from monitoring.security_monitor import security_monitor
import os

chat_bp = Blueprint('chat', __name__)


def load_messages():
    with open('storage/messages.json', 'r') as f:
        return json.load(f)


def save_messages(messages):
    with open('storage/messages.json', 'w') as f:
        json.dump(messages, f, indent=2)


def load_keys():
    with open('storage/keys.json', 'r') as f:
        return json.load(f)


def save_keys(keys):
    with open('storage/keys.json', 'w') as f:
        json.dump(keys, f, indent=2)


def load_proofs():
    with open('storage/proof.json', 'r') as f:
        return json.load(f)


def save_proofs(proofs):
    with open('storage/proof.json', 'w') as f:
        json.dump(proofs, f, indent=2)


def load_nonces():
    try:
        with open('storage/nonces.json', 'r') as f:
            return json.load(f)
    except Exception:
        return []


def save_nonces(nonces):
    with open('storage/nonces.json', 'w') as f:
        json.dump(nonces, f, indent=2)


@chat_bp.route('/send', methods=['POST'])
def send_message():
    """
    Send end-to-end encrypted message with time-locked keys (REST API flow).
    For real-time chat use the WebSocket send_message event in app.py.
    """
    try:
        data = request.json
        sender_id = data.get('sender_id')
        recipient_id = data.get('recipient_id')
        message_text = data.get('message')
        expiry_hours = data.get('expiry_hours', 24)
        sender_private_key = data.get('sender_private_key')
        recipient_public_key = data.get('recipient_public_key')
        nonce = data.get('nonce')

        # Anti-replay check
        if nonce:
            nonces = load_nonces()
            used = [n['nonce'] if isinstance(n, dict) else n for n in nonces]
            if nonce in used:
                security_monitor.log_event('replay_attack_detected', {
                    'nonce': nonce,
                    'sender': sender_id,
                    'ip': request.remote_addr
                })
                return jsonify({'error': 'Replay attack detected - nonce already used'}), 409

            nonces.append({
                'nonce': nonce,
                'timestamp': datetime.utcnow().isoformat(),
                'sender': sender_id
            })
            save_nonces(nonces)

        # Create proof of existence (before encryption)
        proof = create_proof_of_existence(
            message_text,
            metadata={
                'sender': sender_id,
                'recipient': recipient_id,
                'type': 'chat_message'
            }
        )

        # Encrypt message with session key
        session_key = generate_session_key()
        encrypted_msg = encrypt_message(message_text, session_key)

        # Encrypt session key with recipient's public key (if provided)
        encrypted_session_key = None
        if recipient_public_key:
            encrypted_session_key = encrypt_with_public_key(
                session_key,
                recipient_public_key
            )

        # Sign the encrypted message (if private key provided)
        signature = None
        if sender_private_key:
            signature = sign_data(encrypted_msg, sender_private_key)

        # Create time-locked key
        keys = load_keys()
        key_storage = keys.get('keys', {})
        cipher = TimeLockCipher(key_storage)

        expiry_delta = timedelta(hours=expiry_hours)
        time_lock = cipher.encrypt(message_text, expiry_delta)

        keys['keys'] = key_storage
        save_keys(keys)

        # Store minimal metadata only (PROOF OF EXISTENCE - no content!)
        messages = load_messages()
        message_id = os.urandom(16).hex()

        messages[message_id] = {
            'id': message_id,
            'sender': sender_id,
            'recipient': recipient_id,
            'encrypted_data': encrypted_msg,          # encrypted, not plaintext
            'encrypted_session_key': encrypted_session_key,
            'signature': signature,
            'time_lock_key_id': time_lock['key_id'],
            'proof_hash': proof['proof_hash'],
            'timestamp': datetime.utcnow().isoformat(),
            'expires_at': time_lock['expires_at'],
            'status': 'active'
        }
        save_messages(messages)

        # Store proof separately
        proofs = load_proofs()
        proofs[message_id] = proof
        save_proofs(proofs)

        security_monitor.log_event('message_sent', {
            'message_id': message_id,
            'sender': sender_id,
            'recipient': recipient_id,
            'proof_hash': proof['proof_hash']
        })

        return jsonify({
            'success': True,
            'message_id': message_id,
            'proof_hash': proof['proof_hash'],
            'expires_at': time_lock['expires_at'],
            'message': 'Message sent with end-to-end encryption and time-lock'
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@chat_bp.route('/receive/<recipient_id>', methods=['GET'])
def receive_messages(recipient_id):
    """Retrieve encrypted messages for recipient"""
    try:
        messages = load_messages()
        now_str = datetime.utcnow().isoformat()

        recipient_messages = []
        for msg_id, msg in messages.items():
            if msg['recipient'] == recipient_id and msg['status'] == 'active':
                expires_at = msg.get('expires_at', '')
                if expires_at and now_str >= expires_at:
                    msg['status'] = 'expired'
                else:
                    recipient_messages.append({
                        'message_id': msg_id,
                        'sender': msg['sender'],
                        'encrypted_data': msg.get('encrypted_data'),
                        'encrypted_session_key': msg.get('encrypted_session_key'),
                        'signature': msg.get('signature'),
                        'timestamp': msg['timestamp'],
                        'expires_at': msg['expires_at']
                    })

        save_messages(messages)

        return jsonify({
            'messages': recipient_messages,
            'count': len(recipient_messages)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@chat_bp.route('/decrypt', methods=['POST'])
def decrypt_message_endpoint():
    """
    Decrypt message with private key.
    (Demonstration endpoint - in production client does this client-side)
    """
    try:
        from crypto.signature_utils import decrypt_with_private_key
        from crypto.key_expiry import decrypt_message as decrypt_aes
        import base64

        data = request.json
        encrypted_session_key = data.get('encrypted_session_key')
        encrypted_data = data.get('encrypted_data')
        recipient_private_key = data.get('recipient_private_key')

        # Decrypt session key with recipient private key
        session_key_raw = decrypt_with_private_key(
            encrypted_session_key,
            recipient_private_key
        )

        session_key = base64.b64decode(session_key_raw)

        # Decrypt message
        message = decrypt_aes(encrypted_data, session_key)

        return jsonify({
            'success': True,
            'message': message
        })

    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 400


@chat_bp.route('/history/<user_id>', methods=['GET'])
def get_chat_history(user_id):
    """Get chat history for a user (metadata only, no content)"""
    try:
        messages = load_messages()

        user_messages = []
        for msg_id, msg in messages.items():
            if msg['sender'] == user_id or msg['recipient'] == user_id:
                user_messages.append({
                    'message_id': msg_id,
                    'sender': msg['sender'],
                    'recipient': msg['recipient'],
                    'timestamp': msg['timestamp'],
                    'expires_at': msg.get('expires_at'),
                    'status': msg['status'],
                    'proof_hash': msg.get('proof_hash'),
                    'is_sender': msg['sender'] == user_id
                })

        user_messages.sort(key=lambda x: x['timestamp'], reverse=True)

        return jsonify({
            'messages': user_messages,
            'count': len(user_messages)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 400
