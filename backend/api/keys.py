"""
api/keys.py — Public key registry.

Endpoints:
  POST /keys/register      Register a user's public key
  GET  /keys/<user_id>     Look up a user's public key
  GET  /keys/server/pubkey Return the server's signing public key (for proof verification)

The key registry is intentionally simple — it maps user_id → public key PEM.
In production this would integrate with a PKI or use certificate pinning.
"""

from flask import Blueprint, request, jsonify

from config import PUBLIC_KEYS_FILE
from core import storage
from core.crypto.signatures import get_public_key_pem

keys_bp = Blueprint("keys", __name__)


# ─── POST /keys/register ─────────────────────────────────────────────────────

@keys_bp.post("/register")
def register_key():
    """
    Register or update a public key for a user.

    Request body:
        user_id     — unique identifier for the user
        public_key  — PEM-encoded public key
    """
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "JSON body required"}), 400

    if "user_id" not in body or "public_key" not in body:
        return jsonify({"error": "user_id and public_key are required"}), 400

    user_id    = str(body["user_id"]).strip()
    public_key = str(body["public_key"]).strip()

    if not user_id:
        return jsonify({"error": "user_id cannot be empty"}), 400

    keys = storage.load(PUBLIC_KEYS_FILE)
    keys[user_id] = public_key
    storage.save(PUBLIC_KEYS_FILE, keys)

    return jsonify({"status": "registered", "user_id": user_id}), 201


# ─── GET /keys/<user_id> ─────────────────────────────────────────────────────

@keys_bp.get("/<user_id>")
def get_key(user_id):
    """Look up the public key for a given user."""
    keys = storage.load(PUBLIC_KEYS_FILE)

    if user_id not in keys:
        return jsonify({"error": f"No public key registered for user '{user_id}'"}), 404

    return jsonify({"user_id": user_id, "public_key": keys[user_id]})


# ─── GET /keys/server/pubkey ─────────────────────────────────────────────────

@keys_bp.get("/server/pubkey")
def server_public_key():
    """
    Return the server's RSA public key in PEM format.

    External verifiers can use this to independently verify proof-of-existence
    signatures without trusting the server's /verify endpoints.
    """
    return jsonify({"public_key_pem": get_public_key_pem()})
