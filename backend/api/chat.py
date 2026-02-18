"""
api/chat.py — End-to-end encrypted messaging with proof-of-existence.

Endpoints:
  POST /chat/send              Send an encrypted message to a user
  GET  /chat/inbox/<user_id>   Retrieve messages for a user

The server never sees plaintext. The sender encrypts the message with the
recipient's public key (fetched from /keys/<user_id>) on the client side
before calling /chat/send.

On send, the server:
  - Records a SHA-256 hash + RSA-PSS signature as a proof-of-existence
  - Sets a server-controlled expiry
  - Stores the encrypted message blob and encrypted key

After expiry, the scheduler destroys the encrypted_key, making the
message permanently unreadable.
"""

from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta, timezone
import uuid

from config import KEY_EXPIRY_MINUTES, MESSAGES_FILE, PROOFS_FILE
from core import storage
from core.crypto import merkle, signatures

chat_bp = Blueprint("chat", __name__)


# ─── POST /chat/send ─────────────────────────────────────────────────────────

@chat_bp.post("/send")
def send_message():
    """
    Store an encrypted message with a proof-of-existence.

    Request body:
        encrypted_message  — ciphertext encrypted by sender with recipient's public key
        encrypted_key      — the symmetric key encrypted with recipient's public key
        receiver           — recipient user_id

    Returns:
        message_id  — use to check proof later
        expiry      — UTC ISO timestamp when the key will be destroyed
    """
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "JSON body required"}), 400

    missing = [f for f in ("encrypted_message", "encrypted_key", "receiver") if f not in body]
    if missing:
        return jsonify({"error": f"Missing required fields: {missing}"}), 400

    encrypted_message = str(body["encrypted_message"])
    encrypted_key     = str(body["encrypted_key"])
    receiver          = str(body["receiver"])

    message_id = str(uuid.uuid4())
    expiry     = (datetime.now(timezone.utc) + timedelta(minutes=KEY_EXPIRY_MINUTES)).isoformat()

    # ── Store message ──────────────────────────────────────────────────────
    messages = storage.load(MESSAGES_FILE)
    messages[message_id] = {
        "encrypted_message": encrypted_message,
        "encrypted_key":     encrypted_key,
        "receiver":          receiver,
        "expiry":            expiry,
    }
    storage.save(MESSAGES_FILE, messages)

    # ── Proof-of-existence: hash the ciphertext + sign (hash + expiry) ────
    content_hash = merkle.hash_leaf(encrypted_message)
    signature    = signatures.sign(content_hash + expiry)

    proofs = storage.load(PROOFS_FILE)
    proofs[message_id] = {
        "hash":      content_hash,
        "signature": signature,
        "timestamp": expiry,
    }
    storage.save(PROOFS_FILE, proofs)

    return jsonify({
        "message_id": message_id,
        "expiry":     expiry,
    }), 201


# ─── GET /chat/inbox/<user_id> ───────────────────────────────────────────────

@chat_bp.get("/inbox/<user_id>")
def get_inbox(user_id):
    """
    Return all messages addressed to user_id.
    Expired messages (encrypted_key = null) are included but flagged.
    """
    messages = storage.load(MESSAGES_FILE)

    inbox = {}
    for msg_id, msg in messages.items():
        if msg.get("receiver") != user_id:
            continue
        inbox[msg_id] = {
            **msg,
            "expired": msg.get("encrypted_key") is None,
        }

    return jsonify(inbox)
