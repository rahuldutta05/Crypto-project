from flask import Blueprint, request, jsonify
import json
import os
from flask import jsonify

key_bp = Blueprint("key", __name__)
KEY_FILE = "storage/keys.json"

def load_keys():
    if not os.path.exists(KEY_FILE):
        return {}
    return json.load(open(KEY_FILE))

def save_keys(data):
    json.dump(data, open(KEY_FILE, "w"), indent=4)

@key_bp.route("/register", methods=["POST"])
def register_key():
    user_id = request.json["user_id"]
    public_key = request.json["public_key"]

    keys = load_keys()
    keys[user_id] = public_key
    save_keys(keys)

    return jsonify({"status": "registered"})

@key_bp.route("/<user_id>", methods=["GET"])
def get_key(user_id):
    keys = load_keys()
    if user_id not in keys:
        return jsonify({"error": "Key not found"}), 404
    return jsonify({"public_key": keys[user_id]})