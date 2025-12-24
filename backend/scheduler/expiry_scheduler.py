from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
import os
import json
from crypto.key_expiry import destroy_encrypted_key
from config import ENCRYPTED_KEYS_PATH

METADATA_FILE = os.path.join(ENCRYPTED_KEYS_PATH, "key_metadata.json")

def load_metadata():
    if not os.path.exists(METADATA_FILE):
        return {}
    with open(METADATA_FILE, "r") as f:
        return json.load(f)

def save_metadata(data):
    with open(METADATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def expiry_job():
    metadata = load_metadata()
    now = datetime.utcnow()

    updated_metadata = {}

    for submission_id, info in metadata.items():
        expiry_time = datetime.fromisoformat(info["expiry_time"])
        key_path = info["key_path"]

        if now >= expiry_time:
            destroy_encrypted_key(key_path)
        else:
            updated_metadata[submission_id] = info

    save_metadata(updated_metadata)

def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(expiry_job, "interval", minutes=1)
    scheduler.start()
