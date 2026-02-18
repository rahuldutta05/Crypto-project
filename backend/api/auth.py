"""
api/auth.py — Anonymous submission entry point.

Endpoints:
  POST /auth/identity          Generate a fresh identity (client helper)
  POST /auth/submit            Submit data anonymously with PoW + commitment
  GET  /auth/read/<msg_id>     Read a submission (fails after key expiry)

Flow:
  1. Client calls /auth/identity to get an identity_secret + commitment.
  2. Client solves PoW: finds nonce so SHA-256(commitment+nonce) ≈ "000..."
  3. Client POSTs to /auth/submit with {data, commitment, nonce}.
  4. Server verifies PoW, checks commitment not reused, encrypts data,
     stores only ciphertext + wrapped DEK + expiry. Returns msg_id.
  5. Before expiry: GET /auth/read/<msg_id> decrypts and returns plaintext.
  6. After expiry: DEK is destroyed — data is permanently unreadable.
"""

from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta, timezone

from config import KEK, KEY_EXPIRY_MINUTES, MESSAGES_FILE, COMMITMENTS_FILE, PROOFS_FILE
from core import storage
from core.crypto import aes, pow, zkp, merkle

auth_bp = Blueprint("auth", __name__)


# ─── POST /auth/identity ─────────────────────────────────────────────────────

@auth_bp.post("/identity")
def generate_identity():
    """
    Helper for clients: generate a fresh identity_secret and its commitment.

    The client should store the identity_secret locally and never send it
    to the server. Only the commitment is submitted.

    Returns:
        identity_secret  — keep private, proves ownership
        nullifier        — intermediate value (also keep private)
        commitment       — submit this to /auth/submit
    """
    secret     = zkp.generate_identity_secret()
    nullifier  = zkp.derive_nullifier(secret)
    commitment = zkp.derive_commitment(nullifier)

    return jsonify({
        "identity_secret": secret,
        "nullifier":       nullifier,
        "commitment":      commitment,
        "instructions":    (
            "Store identity_secret locally. Submit commitment + PoW nonce to /auth/submit. "
            "Never send identity_secret to the server."
        )
    })


# ─── POST /auth/submit ───────────────────────────────────────────────────────

@auth_bp.post("/submit")
def anonymous_submit():
    """
    Accept an anonymous submission.

    Request body:
        data        — the plaintext content to submit
        commitment  — SHA-256(SHA-256(identity_secret))
        nonce       — PoW nonce: SHA-256(commitment+nonce) must start with N zeros

    Guarantees:
        - One submission per commitment (deduplication)
        - PoW must pass (anti-spam)
        - Server sets expiry — client cannot extend data lifetime
        - Content encrypted immediately; only hash stored in proofs
    """
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "JSON body required"}), 400

    missing = [f for f in ("data", "commitment", "nonce") if f not in body]
    if missing:
        return jsonify({"error": f"Missing required fields: {missing}"}), 400

    data       = str(body["data"])
    commitment = str(body["commitment"])
    nonce      = str(body["nonce"])

    # ── 1. Deduplication: reject reused commitments ───────────────────────
    used_commitments = storage.load_set(COMMITMENTS_FILE)
    if commitment in used_commitments:
        return jsonify({"error": "Commitment already used — duplicate submission rejected"}), 409

    # ── 2. Proof-of-Work verification ─────────────────────────────────────
    if not pow.verify(commitment, nonce):
        return jsonify({"error": "Proof-of-Work verification failed"}), 400

    # ── 3. Mark commitment as used ────────────────────────────────────────
    used_commitments.add(commitment)
    storage.save_set(COMMITMENTS_FILE, used_commitments)

    # ── 4. Encrypt data with a fresh DEK ──────────────────────────────────
    dek       = aes.generate_dek()
    encrypted = aes.encrypt(data, dek)
    wrapped   = aes.wrap_dek(dek, KEK)

    # ── 5. Server-controlled expiry ───────────────────────────────────────
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=KEY_EXPIRY_MINUTES)).isoformat()

    # ── 6. Persist encrypted message ──────────────────────────────────────
    messages = storage.load(MESSAGES_FILE)
    msg_id   = str(len(messages) + 1)

    messages[msg_id] = {
        "ciphertext":  encrypted,
        "wrapped_dek": wrapped,
        "expiry":      expiry,
    }
    storage.save(MESSAGES_FILE, messages)

    # ── 7. Record proof-of-existence (hash only, never plaintext) ─────────
    proofs = storage.load(PROOFS_FILE)
    import time as _time
    proofs[msg_id] = {
        "hash":      merkle.hash_leaf(data),
        "timestamp": _time.time(),
    }
    storage.save(PROOFS_FILE, proofs)

    return jsonify({
        "status":  "accepted",
        "msg_id":  msg_id,
        "expiry":  expiry,
    }), 201


# ─── GET /auth/read/<msg_id> ─────────────────────────────────────────────────

@auth_bp.get("/read/<msg_id>")
def read_submission(msg_id):
    """
    Decrypt and return a submission's content.

    Returns 200 with plaintext while the DEK is still alive.
    Returns 410 Gone once the DEK has been destroyed (data is unrecoverable).

    In a production system this endpoint would require the caller to
    prove knowledge of the original commitment before decrypting.
    """
    messages = storage.load(MESSAGES_FILE)

    if msg_id not in messages:
        return jsonify({"error": "Message not found"}), 404

    msg = messages[msg_id]

    if msg.get("wrapped_dek") is None:
        return jsonify({
            "error":   "Content expired",
            "detail":  "The encryption key for this message has been destroyed. "
                       "The content is permanently unrecoverable — even by the server.",
            "msg_id":  msg_id,
            "expiry":  msg.get("expiry"),
        }), 410

    try:
        dek       = aes.unwrap_dek(msg["wrapped_dek"], KEK)
        plaintext = aes.decrypt(msg["ciphertext"], dek)
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {e}"}), 500

    return jsonify({
        "msg_id":  msg_id,
        "data":    plaintext,
        "expiry":  msg.get("expiry"),
    })
