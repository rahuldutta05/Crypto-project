"""
Device Pairing Routes - QR Code + Diffie-Hellman Key Exchange
Implements Signal-style device pairing with safety numbers
"""

from flask import Blueprint, request, jsonify
import json
import os
import qrcode
from io import BytesIO
import base64
from crypto.diffie_hellman import DiffieHellman
from crypto.signature_utils import generate_keypair, create_anonymous_id
from crypto.hash_utils import hash_data
from datetime import datetime

pairing_bp = Blueprint('pairing', __name__)

# In-memory store for pending DH instances (private keys don't persist to disk)
# { device_id: DiffieHellman instance }
_pending_dh = {}


def load_devices():
    with open('storage/devices.json', 'r') as f:
        return json.load(f)


def save_devices(devices):
    with open('storage/devices.json', 'w') as f:
        json.dump(devices, f, indent=2)


@pairing_bp.route('/initiate', methods=['POST'])
def initiate_pairing():
    """
    Initiate device pairing - generates QR code for scanning

    CORE PRINCIPLE: Anonymous but Verifiable
    - No username/password
    - Device proves ownership via cryptographic challenge
    """
    try:
        # Generate RSA keypair for device
        keypair = generate_keypair()

        # Generate Diffie-Hellman parameters for session key exchange
        dh = DiffieHellman()
        dh_public_hex = dh.public_key  # hex string, JSON-safe

        # Create anonymous device ID
        device_id = create_anonymous_id(keypair['public_key'])

        # Generate challenge for device verification
        challenge = os.urandom(32).hex()

        # Store DH instance in memory so complete_pairing can use correct private key
        _pending_dh[device_id] = dh.get_private_key_hex()

        # Store device info
        devices = load_devices()
        devices[device_id] = {
            'device_id': device_id,
            'public_key': keypair['public_key'],
            'dh_public_key': dh_public_hex,
            'challenge': challenge,
            'created_at': datetime.utcnow().isoformat(),
            'paired_with': None,
            'safety_number': None,
            'status': 'pending_pairing'
        }
        save_devices(devices)

        # Create QR code data
        qr_data = {
            'device_id': device_id,
            'server_url': request.host_url.rstrip('/'),
            'dh_public_key': dh_public_hex,
            'challenge': challenge,
            'timestamp': datetime.utcnow().isoformat()
        }

        # Generate QR code image
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(json.dumps(qr_data))
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Convert to base64
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()

        return jsonify({
            'success': True,
            'device_id': device_id,
            'private_key': keypair['private_key'],  # Client stores this securely
            'public_key': keypair['public_key'],
            'qr_code': f'data:image/png;base64,{img_str}',
            'qr_data': qr_data,
            'message': 'Device registered - scan QR code to pair'
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@pairing_bp.route('/scan', methods=['POST'])
def scan_qr_code():
    """
    Second device scans QR code and initiates pairing
    Performs Diffie-Hellman key exchange
    """
    try:
        data = request.json
        scanned_data = data.get('qr_data')

        device1_id = scanned_data['device_id']
        device1_dh_public_hex = scanned_data['dh_public_key']

        # Generate keypair for second device
        keypair = generate_keypair()
        device2_id = create_anonymous_id(keypair['public_key'])

        # Generate DH parameters for device 2
        dh2 = DiffieHellman()
        device2_dh_public_hex = dh2.public_key

        # Compute shared secret (Diffie-Hellman) using device1's public key
        shared_secret = dh2.compute_shared_secret(device1_dh_public_hex)

        # Generate Signal-style safety number
        devices = load_devices()

        if device1_id not in devices:
            return jsonify({'error': 'Original device not found'}), 404

        device1_public_key = devices[device1_id]['public_key']
        safety_number = generate_safety_number(device1_public_key, keypair['public_key'])

        # Store device 2
        devices[device2_id] = {
            'device_id': device2_id,
            'public_key': keypair['public_key'],
            'dh_public_key': device2_dh_public_hex,
            'created_at': datetime.utcnow().isoformat(),
            'paired_with': device1_id,
            'safety_number': safety_number,
            'status': 'paired'
        }

        # Update device 1 as fully paired
        devices[device1_id]['paired_with'] = device2_id
        devices[device1_id]['safety_number'] = safety_number
        devices[device1_id]['status'] = 'paired'
        devices[device1_id]['peer_dh_public'] = device2_dh_public_hex

        save_devices(devices)

        # Derive session key for encryption
        session_key_bytes, salt_b64 = DiffieHellman.derive_session_key(shared_secret)
        session_key_b64 = base64.b64encode(session_key_bytes).decode()

        return jsonify({
            'success': True,
            'device_id': device2_id,
            'private_key': keypair['private_key'],
            'public_key': keypair['public_key'],
            'paired_device': device1_id,
            'safety_number': safety_number,
            'dh_public_key': device2_dh_public_hex,
            'session_key': session_key_b64,   # AES-256 key derived from shared secret
            'session_salt': salt_b64,
            'message': 'Devices paired successfully - verify safety numbers!'
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@pairing_bp.route('/complete', methods=['POST'])
def complete_pairing():
    """
    Device 1 receives device 2's DH public key and completes exchange.
    Uses the stored private key from initiate_pairing (not a new random one).
    """
    try:
        data = request.json
        device1_id = data.get('device_id')
        device2_dh_public_hex = data.get('device2_dh_public')

        devices = load_devices()

        if device1_id not in devices:
            return jsonify({'error': 'Device not found'}), 404

        # Retrieve stored DH private key for device 1
        private_key_hex = _pending_dh.get(device1_id)
        if not private_key_hex:
            return jsonify({'error': 'DH session expired - please re-initiate pairing'}), 400

        # Reconstruct DH instance from stored private key
        dh1 = DiffieHellman.from_private_key_hex(private_key_hex)
        shared_secret = dh1.compute_shared_secret(device2_dh_public_hex)

        # Clean up pending DH state
        _pending_dh.pop(device1_id, None)

        safety_number = devices[device1_id].get('safety_number')

        # Derive session key
        session_key_bytes, salt_b64 = DiffieHellman.derive_session_key(shared_secret)
        session_key_b64 = base64.b64encode(session_key_bytes).decode()

        return jsonify({
            'success': True,
            'paired_device': devices[device1_id].get('paired_with'),
            'safety_number': safety_number,
            'session_key': session_key_b64,
            'session_salt': salt_b64,
            'message': 'Pairing complete - secure channel established'
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@pairing_bp.route('/verify-safety-number', methods=['POST'])
def verify_safety_number():
    """
    Verify safety numbers match (MITM detection)
    """
    try:
        data = request.json
        device_id = data.get('device_id')
        reported_safety_number = data.get('safety_number')

        devices = load_devices()

        if device_id not in devices:
            return jsonify({'error': 'Device not found'}), 404

        actual_safety_number = devices[device_id]['safety_number']

        if actual_safety_number == reported_safety_number:
            return jsonify({
                'verified': True,
                'message': '✓ Safety numbers match - connection is secure'
            })
        else:
            # MITM DETECTED!
            from monitoring.security_monitor import security_monitor
            security_monitor.log_event('mitm_detected', {
                'device_id': device_id,
                'expected': actual_safety_number,
                'received': reported_safety_number
            })

            return jsonify({
                'verified': False,
                'message': '⚠️ SECURITY WARNING: Safety numbers do not match!',
                'warning': 'Possible man-in-the-middle attack detected'
            }), 403

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@pairing_bp.route('/list-devices', methods=['GET'])
def list_devices():
    """List all registered devices (for admin)"""
    try:
        devices = load_devices()

        device_list = []
        for device_id, device in devices.items():
            device_list.append({
                'device_id': device_id,
                'created_at': device['created_at'],
                'status': device['status'],
                'paired_with': device.get('paired_with'),
                'safety_number': device.get('safety_number')
            })

        return jsonify({
            'devices': device_list,
            'total': len(device_list)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 400


def generate_safety_number(public_key1, public_key2):
    """
    Generate Signal-style safety number.
    Combination of both public keys ensures both parties see same number.
    If MITM occurs, numbers will differ.
    """
    # Ensure consistent ordering
    keys = sorted([public_key1, public_key2])
    combined = ''.join(keys)

    # Hash to create fingerprint
    fingerprint = hash_data(combined)

    # Convert to 6-digit number (easy to compare verbally)
    safety_number = int.from_bytes(bytes.fromhex(fingerprint[:6]), 'big') % 1000000

    return f"{safety_number:06d}"
