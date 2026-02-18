"""
config.py — Central configuration for the cryptographic backend.

All tuneable settings live here. Sensitive values (KEK, admin token)
are loaded from environment variables or bootstrapped on first run.
"""

import os
import json
import os as _os
get_random_bytes = _os.urandom

# ─── Tuneable settings ────────────────────────────────────────────────────────

# How long before a submission's DEK is destroyed (data death)
KEY_EXPIRY_MINUTES: int = int(os.environ.get("KEY_EXPIRY_MINUTES", 60))

# Proof-of-Work difficulty: number of leading zero hex digits required
# 4 = ~65k hashes, 6 = ~16M hashes. Raise to slow spam.
POW_DIFFICULTY: int = int(os.environ.get("POW_DIFFICULTY", 6))

# Scheduler interval in seconds between expiry sweeps
SCHEDULER_INTERVAL_SECONDS: int = 60

# ─── Storage paths ────────────────────────────────────────────────────────────

STORAGE_DIR         = "storage"
VAULT_DIR           = os.path.join(STORAGE_DIR, "vault")
MESSAGES_FILE       = os.path.join(STORAGE_DIR, "messages.json")
COMMITMENTS_FILE    = os.path.join(STORAGE_DIR, "commitments.json")
PROOFS_FILE         = os.path.join(STORAGE_DIR, "proofs.json")
PUBLIC_KEYS_FILE    = os.path.join(VAULT_DIR,   "public_keys.json")
KEK_FILE            = os.path.join(VAULT_DIR,   "kek.json")
SIGNING_KEY_FILE    = os.path.join(VAULT_DIR,   "signing_key.pem")

# ─── Admin auth ───────────────────────────────────────────────────────────────

# Set ADMIN_TOKEN in your environment before running.
# Example:  export ADMIN_TOKEN="my-secret-admin-token"
ADMIN_TOKEN: str = os.environ.get("ADMIN_TOKEN", "")

# ─── KEK bootstrap ───────────────────────────────────────────────────────────

def _bootstrap_kek() -> bytes:
    """
    Load the Key Encryption Key from disk, or generate and persist one.
    The KEK never changes after first run — losing it = losing all data.
    """
    os.makedirs(VAULT_DIR, exist_ok=True)

    if os.path.exists(KEK_FILE):
        with open(KEK_FILE, "r") as f:
            return bytes.fromhex(json.load(f)["kek"])

    kek = get_random_bytes(32)
    with open(KEK_FILE, "w") as f:
        json.dump({"kek": kek.hex()}, f, indent=4)

    print("[Config] New KEK generated and saved to", KEK_FILE)
    return kek


# Loaded once at import time — shared across the whole application
KEK: bytes = _bootstrap_kek()
