from flask import Blueprint, jsonify
import json

admin_bp = Blueprint("admin", __name__)

@admin_bp.route("/dump/messages", methods=["GET"])
def dump_messages():
    return jsonify(json.load(open("storage/messages.json")))
