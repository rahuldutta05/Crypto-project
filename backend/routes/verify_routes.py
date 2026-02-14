from flask import Blueprint, request, jsonify
import json
import os
from crypto.hash_utils import generate_hash
from crypto.signature_utils import verify_signature

verify_bp = Blueprint("verify", __name__)
PROOF_FILE = "storage/proof.json"

@verify_bp.route("/", methods=["POST"])
def verify_message():
    message_id = request.json["message_id"]
    encrypted_message = request.json["encrypted_message"]

    proof = json.load(open(PROOF_FILE))
    stored = proof.get(message_id)

    computed_hash = generate_hash(encrypted_message.encode())

    valid = (
        stored["hash"] == computed_hash and
        verify_signature(stored["hash"] + stored["timestamp"], stored["signature"])
    )

    return jsonify({"verified": valid})
