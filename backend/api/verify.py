"""
api/verify.py — Proof-of-existence verification.

Endpoints:
  POST /verify/hash            Hash submitted data and return current Merkle root
  GET  /verify/proof/<msg_id>  Full Merkle inclusion proof for a submission
  POST /verify/signature       Verify a proof-of-existence signature
  GET  /verify/root            Current Merkle root of all submissions

These endpoints let anyone verify that specific content was submitted at a
specific time, without accessing the plaintext — which may already be expired.
"""

from flask import Blueprint, request, jsonify

from config import PROOFS_FILE
from core import storage
from core.crypto import merkle, signatures

verify_bp = Blueprint("verify", __name__)


def _get_all_proofs():
    return storage.load(PROOFS_FILE)


def _ordered_hashes(proofs: dict) -> list:
    """Return leaf hashes in insertion order."""
    return [proofs[k]["hash"] for k in proofs]


# ─── GET /verify/root ────────────────────────────────────────────────────────

@verify_bp.get("/root")
def get_root():
    """Return the current Merkle root of all recorded submission hashes."""
    proofs = _get_all_proofs()
    if not proofs:
        return jsonify({"error": "No submissions recorded yet"}), 404

    root = merkle.build_root(_ordered_hashes(proofs))
    return jsonify({
        "merkle_root":        root,
        "total_submissions":  len(proofs),
    })


# ─── POST /verify/hash ───────────────────────────────────────────────────────

@verify_bp.post("/hash")
def verify_hash():
    """
    Hash the provided data and return the current Merkle root.

    The caller can check whether their hash appears as a leaf in the tree.
    (Full inclusion proof available at /verify/proof/<msg_id>.)

    Request body:
        data  — the original plaintext to hash
    """
    body = request.get_json(silent=True)
    if not body or "data" not in body:
        return jsonify({"error": "data field required"}), 400

    proofs = _get_all_proofs()
    if not proofs:
        return jsonify({"error": "No submissions recorded yet"}), 404

    user_hash = merkle.hash_leaf(str(body["data"]))
    root      = merkle.build_root(_ordered_hashes(proofs))

    # Check if this hash is recorded (existence check without proof)
    recorded_hashes = {v["hash"] for v in proofs.values()}
    found = user_hash in recorded_hashes

    return jsonify({
        "data_hash":   user_hash,
        "merkle_root": root,
        "found":       found,
    })


# ─── GET /verify/proof/<msg_id> ──────────────────────────────────────────────

@verify_bp.get("/proof/<msg_id>")
def get_inclusion_proof(msg_id):
    """
    Return a cryptographic Merkle inclusion proof for a specific submission.

    The proof_path allows any verifier to independently reconstruct the
    Merkle root from just the leaf hash, without trusting the server.

    Verification algorithm (client-side):
        current = leaf_hash
        for step in proof_path:
            if step["position"] == "left":
                current = SHA256(step["sibling"] + current)
            else:
                current = SHA256(current + step["sibling"])
        assert current == merkle_root
    """
    proofs = _get_all_proofs()

    if msg_id not in proofs:
        return jsonify({"error": f"No proof found for msg_id '{msg_id}'"}), 404

    keys_ordered = list(proofs.keys())
    hashes       = [proofs[k]["hash"] for k in keys_ordered]
    index        = keys_ordered.index(msg_id)

    root, proof_path = merkle.build_proof(hashes, index)

    return jsonify({
        "msg_id":      msg_id,
        "leaf_hash":   proofs[msg_id]["hash"],
        "timestamp":   proofs[msg_id]["timestamp"],
        "merkle_root": root,
        "proof_path":  proof_path,
        "instructions": (
            "To verify: start with leaf_hash, apply each proof_path step "
            "(combine with sibling using SHA-256, sibling on the given position), "
            "and confirm the result equals merkle_root."
        ),
    })


# ─── POST /verify/signature ──────────────────────────────────────────────────

@verify_bp.post("/signature")
def verify_proof_signature():
    """
    Verify a proof-of-existence signature from /chat/send.

    The server signs SHA-256(ciphertext_hash + expiry) with its RSA-PSS key.
    This endpoint verifies that signature against the stored proof.

    Request body:
        msg_id  — message ID to verify
    """
    body = request.get_json(silent=True)
    if not body or "msg_id" not in body:
        return jsonify({"error": "msg_id required"}), 400

    proofs = _get_all_proofs()
    msg_id = str(body["msg_id"])

    if msg_id not in proofs:
        return jsonify({"error": f"No proof found for msg_id '{msg_id}'"}), 404

    proof = proofs[msg_id]

    # Signature is only present for chat messages (not anonymous submissions)
    if "signature" not in proof:
        return jsonify({
            "msg_id":  msg_id,
            "note":    "This submission has a hash proof but no server signature "
                       "(anonymous submission — signature not applicable).",
            "hash":    proof["hash"],
        })

    signed_data = proof["hash"] + proof["timestamp"]
    valid       = signatures.verify(signed_data, proof["signature"])

    return jsonify({
        "msg_id":    msg_id,
        "hash":      proof["hash"],
        "timestamp": proof["timestamp"],
        "valid":     valid,
    })
