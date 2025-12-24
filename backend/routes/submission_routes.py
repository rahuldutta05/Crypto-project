from flask import Blueprint, request, jsonify
from crypto.aes_utils import generate_aes_key, encrypt_data
from crypto.rsa_utils import generate_rsa_keys, encrypt_aes_key
from crypto.hash_utils import generate_hash    
from crypto.signature_utils import sign_data
from config import ENCRYPTED_DATA_PATH, ENCRYPTED_KEYS_PATH, KEY_EXPIRY_MINUTES
from datetime import datetime, timedelta
import os
import uuid
import json

submission_bp = Blueprint("submission", __name__)

METADATA_FILE = os.path.join(ENCRYPTED_KEYS_PATH, "key_metadata.json")

def ensure_directories():
    os.makedirs(ENCRYPTED_DATA_PATH, exist_ok=True)
    os.makedirs(ENCRYPTED_KEYS_PATH, exist_ok=True)

def load_metadata():
    if not os.path.exists(METADATA_FILE):
        return {}
    with open(METADATA_FILE, "r") as f:
        return json.load(f)

def save_metadata(data):
    with open(METADATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

@submission_bp.route("/", methods=["POST"])
def submit_data():
    ensure_directories()
    submission_id = str(uuid.uuid4())
    plaintext = request.files["file"].read()

    aes_key = generate_aes_key()
    encrypted_data = encrypt_data(plaintext, aes_key)

    private_key, public_key = generate_rsa_keys()
    encrypted_key = encrypt_aes_key(aes_key, public_key)

    data_path = os.path.join(ENCRYPTED_DATA_PATH, submission_id)
    key_path = os.path.join(ENCRYPTED_KEYS_PATH, submission_id+".key")

    with open(data_path, "wb") as f:
        f.write(encrypted_data)

    with open(key_path, "wb") as f:
        f.write(encrypted_key)

    expiry_time = datetime.utcnow() + timedelta(minutes=KEY_EXPIRY_MINUTES)

    metadata = load_metadata()
    metadata[submission_id] = {
        "key_path": key_path,
        "expiry_time": expiry_time.isoformat()
    }
    save_metadata(metadata)

    data_hash = generate_hash(encrypted_data)
    signature = sign_data(data_hash + expiry_time.isoformat())

    return jsonify({
        "submission_id": submission_id,
        "hash": data_hash,
        "expiry_time": expiry_time.isoformat(),
        "signature": signature
    })
