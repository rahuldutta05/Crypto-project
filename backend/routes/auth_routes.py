from flask import Blueprint, jsonify
import secrets
import hashlib

auth_bp = Blueprint("auth", __name__)
used_tokens = set()

@auth_bp.route("/token", methods=["GET"])
def generate_token():
    token = secrets.token_hex(16)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    used_tokens.add(token_hash)
    return jsonify({"token": token})
