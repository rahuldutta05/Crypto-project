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
from datetime import datetime, timedelta, timezone
from github_storage import load_json, save_json
from config import Config
import random

pairing_bp = Blueprint('pairing', __name__)

# In-memory cache for DH private keys (also persisted to devices.json as fallback)
_pending_dh = {}

PAIRING_CODE_TTL = timedelta(minutes=10)  # Extended to 10 mins for cross-device reliability


def _generate_pairing_code():
    """Generate a unique 6-digit pairing code that isn't already pending in devices.json."""
    devices = load_devices()
    now = datetime.now(timezone.utc)
    # Collect all unexpired codes already in use
    active_codes = set()
    for d in devices.values():
        code = d.get('pairing_code')
        if code and d.get('status') == 'pending_pairing':
            created_str = d.get('created_at', '')
            try:
                created_dt = datetime.fromisoformat(created_str.replace('Z', '+00:00'))
                if now - created_dt < PAIRING_CODE_TTL:
                    active_codes.add(code)
            except Exception:
                pass
    for _ in range(20):
        code = f"{random.randint(0, 999999):06d}"
        if code not in active_codes:
            return code
    raise RuntimeError("Unable to allocate pairing code")


def load_devices():
    return load_json('devices.json', default={})


def save_devices(devices):
    save_json('devices.json', devices)


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

        # Store DH private key — in-memory AND in devices.json for restart resilience
        dh_private_hex = dh.get_private_key_hex()
        _pending_dh[device_id] = dh_private_hex

        # Allocate a short pairing code (6 digits) — stored in devices.json (persistent)
        pairing_code = _generate_pairing_code()

        # Store device info (including dh_private_key for restart resilience)
        devices = load_devices()
        devices[device_id] = {
            'device_id': device_id,
            'public_key': keypair['public_key'],
            'dh_public_key': dh_public_hex,
            'dh_private_key': dh_private_hex,
            'challenge': challenge,
            'created_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'paired_with': None,
            'safety_number': None,
            'status': 'pending_pairing',
            'pairing_code': pairing_code
        }
        save_devices(devices)

        # Create QR code data
        qr_data = {
            'device_id': device_id,
            'server_url': request.host_url.rstrip('/'),
            'dh_public_key': dh_public_hex,
            'challenge': challenge,
            'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
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
            'pairing_code': pairing_code,
            'pair_url': f"{Config.FRONTEND_URL.rstrip('/')}/pair?code={pairing_code}",
            'message': 'Device registered - scan QR code to pair'
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@pairing_bp.route('/lookup', methods=['GET'])
def lookup_pairing():
    """
    Lookup pairing QR payload by a short code.
    Reads from devices.json (persistent GitHub storage) so it survives
    Railway restarts and works across multiple server instances.
    """
    try:
        code = (request.args.get('code') or '').strip()
        if not code or not code.isdigit() or len(code) != 6:
            return jsonify({'error': 'Invalid code'}), 400

        devices = load_devices()
        now = datetime.now(timezone.utc)

        # Find the device with this pending pairing code
        device_id = None
        device_data = None
        for did, d in devices.items():
            if d.get('pairing_code') == code and d.get('status') == 'pending_pairing':
                # Check TTL
                created_str = d.get('created_at', '')
                try:
                    created_dt = datetime.fromisoformat(created_str.replace('Z', '+00:00'))
                    if now - created_dt < PAIRING_CODE_TTL:
                        device_id = did
                        device_data = d
                        break
                except Exception:
                    pass

        if not device_id:
            return jsonify({'error': 'Code expired or not found'}), 404

        qr_data = {
            'device_id': device_id,
            'server_url': request.host_url.rstrip('/'),
            'dh_public_key': device_data.get('dh_public_key'),
            'challenge': device_data.get('challenge'),
            'timestamp': device_data.get('created_at')
        }

        return jsonify({'success': True, 'qr_data': qr_data}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@pairing_bp.route('/complete-auto', methods=['POST'])
def complete_pairing_auto():
    """
    Auto-complete pairing for Device A once Device B has joined.
    This removes the manual step of copy/pasting Device B's DH public key.
    """
    try:
        data = request.json or {}
        device1_id = data.get('device_id')
        if not device1_id:
            return jsonify({'error': 'device_id required'}), 400

        devices = load_devices()
        if device1_id not in devices:
            return jsonify({'error': 'Device not found'}), 404

        device2_dh_public_hex = devices[device1_id].get('peer_dh_public')
        if not device2_dh_public_hex:
            return jsonify({'error': 'Waiting for Device B to join'}), 409

        # Try in-memory cache first, fall back to devices.json (survives restarts)
        private_key_hex = _pending_dh.get(device1_id) or devices[device1_id].get('dh_private_key')
        if not private_key_hex:
            return jsonify({'error': 'DH session expired - please re-initiate pairing'}), 400

        dh1 = DiffieHellman.from_private_key_hex(private_key_hex)
        shared_secret = dh1.compute_shared_secret(device2_dh_public_hex)

        _pending_dh.pop(device1_id, None)

        devices[device1_id]['status'] = 'paired'
        save_devices(devices)

        safety_number = devices[device1_id].get('safety_number')

        stored_salt_b64 = devices[device1_id].get('session_salt')
        if stored_salt_b64:
            salt_bytes = base64.b64decode(stored_salt_b64)
            session_key_bytes, salt_b64 = DiffieHellman.derive_session_key(shared_secret, salt=salt_bytes)
        else:
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
            'created_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
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

        # Derive session key for encryption (salt is generated once here and stored)
        session_key_bytes, salt_b64 = DiffieHellman.derive_session_key(shared_secret)
        session_key_b64 = base64.b64encode(session_key_bytes).decode()

        # Store salt so Device A can derive the IDENTICAL session key in /complete
        devices[device1_id]['session_salt'] = salt_b64
        save_devices(devices)

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

        # Retrieve stored DH private key for device 1 — memory first, then devices.json
        private_key_hex = _pending_dh.get(device1_id) or devices[device1_id].get('dh_private_key')
        if not private_key_hex:
            return jsonify({'error': 'DH session expired - please re-initiate pairing'}), 400

        # Reconstruct DH instance from stored private key
        dh1 = DiffieHellman.from_private_key_hex(private_key_hex)
        shared_secret = dh1.compute_shared_secret(device2_dh_public_hex)

        # Clean up pending DH state
        _pending_dh.pop(device1_id, None)

        # Mark Device A as fully paired (scan already set Device B to 'paired')
        devices[device1_id]['status'] = 'paired'
        save_devices(devices)

        safety_number = devices[device1_id].get('safety_number')

        # Reuse Device B's PBKDF2 salt so both sides derive the IDENTICAL AES key
        stored_salt_b64 = devices[device1_id].get('session_salt')
        if stored_salt_b64:
            salt_bytes = base64.b64decode(stored_salt_b64)
            session_key_bytes, salt_b64 = DiffieHellman.derive_session_key(shared_secret, salt=salt_bytes)
        else:
            # Fallback (should not happen in normal flow)
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
                'created_at': device.get('created_at'),
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
