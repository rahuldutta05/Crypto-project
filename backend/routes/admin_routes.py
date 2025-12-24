from flask import Blueprint, jsonify
from crypto.rsa_utils import decrypt_aes_key
from crypto.aes_utils import decrypt_data
from config import ENCRYPTED_DATA_PATH, ENCRYPTED_KEYS_PATH
import os

admin_bp = Blueprint("admin", __name__)

# DEMO ONLY — disable in production
@admin_bp.route("/decrypt/<submission_id>", methods=["GET"])
def decrypt_before_expiry(submission_id):
    data_path = os.path.join(ENCRYPTED_DATA_PATH, submission_id)
    key_path = os.path.join(ENCRYPTED_KEYS_PATH, submission_id)

    if not os.path.exists(key_path):
        return jsonify({"error": "Data expired. Decryption impossible."}), 403

    with open(key_path, "rb") as f:
        encrypted_key = f.read()

    with open(data_path, "rb") as f:
        encrypted_data = f.read()

    # Private key assumed securely loaded
    from crypto.rsa_utils import generate_rsa_keys
    private_key, _ = generate_rsa_keys()

    aes_key = decrypt_aes_key(encrypted_key, private_key)
    plaintext = decrypt_data(encrypted_data, aes_key)

    return jsonify({
        "status": "success",
        "plaintext_preview": plaintext[:100].decode(errors="ignore")
    })
