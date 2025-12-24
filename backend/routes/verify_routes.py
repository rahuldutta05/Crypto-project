from flask import Blueprint, request, jsonify
from crypto.hash_utils import generate_hash
from crypto.signature_utils import verify_signature

verify_bp = Blueprint("verify", __name__)

@verify_bp.route("/", methods=["POST"])
def verify_data():
    original_data = request.files["file"].read()
    stored_hash = request.form["hash"]
    signature = request.form["signature"]

    computed_hash = generate_hash(original_data)
    valid = verify_signature(stored_hash, signature)

    return jsonify({"verified": computed_hash == stored_hash and valid})
