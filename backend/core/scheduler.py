"""
core/scheduler.py — Background thread for cryptographic data expiry.

Every SCHEDULER_INTERVAL_SECONDS seconds, sweeps all messages and destroys
the wrapped DEK of any message whose expiry time has passed.

Once the DEK is set to null, the ciphertext becomes permanently unreadable —
even by the server admin, even with the KEK. The hash in proofs.json
remains for audit purposes.

This implements "Data Death": privacy after usefulness.
"""

import time
import threading
from datetime import datetime, timezone

from config import MESSAGES_FILE, SCHEDULER_INTERVAL_SECONDS
from core import storage


def _expire_once() -> int:
    """
    Single sweep: nullify wrapped_dek for all expired messages.
    Returns the number of DEKs destroyed this sweep.
    """
    messages = storage.load(MESSAGES_FILE)
    now = datetime.now(timezone.utc)
    destroyed = 0

    for msg_id, msg in messages.items():
        # Skip messages already expired or without a DEK
        if msg.get("wrapped_dek") is None:
            continue

        try:
            # Handle both naive and timezone-aware ISO strings
            expiry_str = msg["expiry"]
            expiry = datetime.fromisoformat(expiry_str)

            # Make timezone-aware if naive (treat as UTC)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)

        except (KeyError, ValueError):
            continue

        if now >= expiry:
            msg["wrapped_dek"] = None   # 🔥 KEY DESTROYED — data is now dead
            destroyed += 1

    if destroyed:
        storage.save(MESSAGES_FILE, messages)
        print(f"[Scheduler] {datetime.now(timezone.utc).isoformat()} "
              f"— Destroyed DEKs for {destroyed} message(s).")

    return destroyed


def run_scheduler() -> None:
    """
    Infinite loop — meant to run in a daemon thread started by app.py.
    """
    print(f"[Scheduler] Started. Sweep interval: {SCHEDULER_INTERVAL_SECONDS}s")
    while True:
        try:
            _expire_once()
        except Exception as e:
            print(f"[Scheduler] Error during sweep: {e}")
        time.sleep(SCHEDULER_INTERVAL_SECONDS)


def start_background_scheduler() -> threading.Thread:
    """Create and start the scheduler as a daemon thread."""
    thread = threading.Thread(target=run_scheduler, daemon=True, name="ExpiryScheduler")
    thread.start()
    return thread
