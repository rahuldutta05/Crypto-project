from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import json
import os
from datetime import datetime


def load_json(path, default=None):
    if default is None:
        default = {}
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else '.', exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


def check_and_expire_keys():
    """
    Scheduled task to check and expire keys and messages.
    This covers two scenarios:
      1. Messages with a direct 'expires_at' timestamp (WebSocket flow)
      2. Messages linked via 'time_lock_key_id' (REST API flow)
    """
    now_str = datetime.utcnow().isoformat()

    try:
        # ── 1. Expire time-locked keys ──────────────────────────────────────────
        keys_data = load_json('storage/keys.json', {'keys': {}})
        key_storage = keys_data.get('keys', {})
        key_expired_count = 0

        for key_id, key_data in key_storage.items():
            if key_data.get('status') == 'active':
                expires_at = key_data.get('expires_at', '')
                if expires_at and now_str >= expires_at:
                    key_data['status'] = 'expired'
                    key_data['session_key'] = None   # Permanent key destruction
                    key_data['expired_at'] = now_str
                    key_expired_count += 1

        keys_data['keys'] = key_storage
        save_json('storage/keys.json', keys_data)

        # ── 2. Expire messages ───────────────────────────────────────────────────
        messages = load_json('storage/messages.json', {})
        message_expired_count = 0

        for msg_id, msg in messages.items():
            if msg.get('status') == 'active':
                # Method A: direct expires_at (WebSocket flow)
                expires_at = msg.get('expires_at', '')
                if expires_at and now_str >= expires_at:
                    messages[msg_id]['status'] = 'expired'
                    message_expired_count += 1
                    continue

                # Method B: via time_lock_key_id (REST API flow)
                key_id = msg.get('time_lock_key_id')
                if key_id and key_id in key_storage:
                    if key_storage[key_id].get('status') == 'expired':
                        messages[msg_id]['status'] = 'expired'
                        message_expired_count += 1

        save_json('storage/messages.json', messages)

        if key_expired_count > 0 or message_expired_count > 0:
            print(f"[{now_str}] 🔑 Expired {key_expired_count} keys "
                  f"and {message_expired_count} messages")

    except Exception as e:
        print(f"[{now_str}] ✗ Error during key expiry check: {e}")


def start_expiry_scheduler():
    """Start background scheduler for automatic key expiry"""
    scheduler = BackgroundScheduler()

    scheduler.add_job(
        func=check_and_expire_keys,
        trigger=IntervalTrigger(minutes=1),
        id='key_expiry_job',
        name='Check and expire time-locked keys',
        replace_existing=True
    )

    scheduler.start()
    print("🕐 Automatic key expiry scheduler started (checks every minute)")

    return scheduler
