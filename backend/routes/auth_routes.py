from flask import Blueprint, jsonify
import secrets
import json
import os

auth_bp = Blueprint("auth", __name__)
TOKEN_FILE = "storage/tokens.json"

def load_tokens():
    if not os.path.exists(TOKEN_FILE):
        return {}
    return json.load(open(TOKEN_FILE))

def save_tokens(data):
    json.dump(data, open(TOKEN_FILE, "w"), indent=4)

@auth_bp.route("/token", methods=["GET"])
def generate_token():
    token = secrets.token_hex(16)
    tokens = load_tokens()
    tokens[token] = False
    save_tokens(tokens)
    return jsonify({"token": token})
