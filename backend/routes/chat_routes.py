from flask import Blueprint, request, jsonify
from crypto.hash_utils import generate_hash
from crypto.signature_utils import sign_data
from config import KEY_EXPIRY_MINUTES
from datetime import datetime, timedelta
import json
import os
import uuid

chat_bp = Blueprint("chat", __name__)
MESSAGE_FILE = "storage/messages.json"
PROOF_FILE = "storage/proof.json"

def load_json(file):
    if not os.path.exists(file):
        return {}
    return json.load(open(file))

def save_json(file, data):
    json.dump(data, open(file, "w"), indent=4)

@chat_bp.route("/send", methods=["POST"])
def send_message():
    data = request.json
    message_id = str(uuid.uuid4())

    encrypted_message = data["encrypted_message"]
    encrypted_key = data["encrypted_key"]
    receiver = data["receiver"]

    expiry = (datetime.utcnow() + timedelta(minutes=KEY_EXPIRY_MINUTES)).isoformat()

    messages = load_json(MESSAGE_FILE)
    messages[message_id] = {
        "encrypted_message": encrypted_message,
        "encrypted_key": encrypted_key,
        "receiver": receiver,
        "expiry": expiry
    }
    save_json(MESSAGE_FILE, messages)

    # proof-of-existence
    hash_val = generate_hash(encrypted_message.encode())
    signature = sign_data(hash_val + expiry)

    proof = load_json(PROOF_FILE)
    proof[message_id] = {
        "hash": hash_val,
        "signature": signature,
        "timestamp": expiry
    }
    save_json(PROOF_FILE, proof)

    return jsonify({"message_id": message_id, "expiry": expiry})

@chat_bp.route("/inbox/<user_id>", methods=["GET"])
def get_messages(user_id):
    messages = load_json(MESSAGE_FILE)
    user_msgs = {
        k: v for k, v in messages.items()
        if v["receiver"] == user_id
    }
    return jsonify(user_msgs)
