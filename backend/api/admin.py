"""
api/admin.py — Protected admin endpoints.

All routes require:  Authorization: Bearer <ADMIN_TOKEN>

Set ADMIN_TOKEN in your environment before running:
    export ADMIN_TOKEN="your-secret-token"

Endpoints:
  GET  /admin/messages      Dump all stored messages (encrypted)
  GET  /admin/proofs        Dump all proof-of-existence records
  GET  /admin/commitments   Dump all used commitments
  GET  /admin/stats         System statistics
  POST /admin/expire        Trigger an immediate expiry sweep
"""

import functools
import os
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify

from config import MESSAGES_FILE, COMMITMENTS_FILE, PROOFS_FILE, ADMIN_TOKEN
from core import storage
from core.scheduler import _expire_once

admin_bp = Blueprint("admin", __name__)


# ─── Auth decorator ──────────────────────────────────────────────────────────

def require_admin(f):
    """Reject requests that don't carry the correct Bearer token."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not ADMIN_TOKEN:
            return jsonify({
                "error": "Admin access not configured.",
                "hint":  "Set the ADMIN_TOKEN environment variable before starting the server.",
            }), 503

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[len("Bearer "):] != ADMIN_TOKEN:
            return jsonify({"error": "Unauthorized"}), 401

        return f(*args, **kwargs)
    return wrapper


# ─── GET /admin/messages ─────────────────────────────────────────────────────

@admin_bp.get("/messages")
@require_admin
def dump_messages():
    """Return all messages. Expired messages have wrapped_dek = null."""
    return jsonify(storage.load(MESSAGES_FILE))


# ─── GET /admin/proofs ───────────────────────────────────────────────────────

@admin_bp.get("/proofs")
@require_admin
def dump_proofs():
    """Return all proof-of-existence records."""
    return jsonify(storage.load(PROOFS_FILE))


# ─── GET /admin/commitments ──────────────────────────────────────────────────

@admin_bp.get("/commitments")
@require_admin
def dump_commitments():
    """Return the set of all used identity commitments."""
    return jsonify(list(storage.load_set(COMMITMENTS_FILE)))


# ─── GET /admin/stats ────────────────────────────────────────────────────────

@admin_bp.get("/stats")
@require_admin
def get_stats():
    """High-level system statistics."""
    messages    = storage.load(MESSAGES_FILE)
    proofs      = storage.load(PROOFS_FILE)
    commitments = storage.load_set(COMMITMENTS_FILE)
    now         = datetime.now(timezone.utc)

    active  = 0
    expired = 0

    for msg in messages.values():
        if msg.get("wrapped_dek") is None:
            expired += 1
        else:
            active += 1

    return jsonify({
        "timestamp":          now.isoformat(),
        "total_messages":     len(messages),
        "active_messages":    active,
        "expired_messages":   expired,
        "total_proofs":       len(proofs),
        "total_commitments":  len(commitments),
    })


# ─── POST /admin/expire ──────────────────────────────────────────────────────

@admin_bp.post("/expire")
@require_admin
def force_expire():
    """
    Trigger an immediate expiry sweep outside the scheduler interval.
    Useful for testing or manual enforcement.
    """
    destroyed = _expire_once()
    return jsonify({
        "status":    "sweep complete",
        "destroyed": destroyed,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
