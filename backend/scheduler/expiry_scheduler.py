from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
import json
import os

MESSAGE_FILE = "storage/messages.json"

def expiry_job():
    if not os.path.exists(MESSAGE_FILE):
        return

    messages = json.load(open(MESSAGE_FILE))
    now = datetime.utcnow()

    updated = {}
    for msg_id, data in messages.items():
        expiry_time = datetime.fromisoformat(data["expiry"])
        if now < expiry_time:
            updated[msg_id] = data

    json.dump(updated, open(MESSAGE_FILE, "w"), indent=4)

def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(expiry_job, "interval", seconds=30)
    scheduler.start()
