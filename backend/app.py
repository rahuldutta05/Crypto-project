from flask import Flask, jsonify
from routes.auth_routes import auth_bp
from routes.submission_routes import submission_bp
from routes.verify_routes import verify_bp
from routes.admin_routes import admin_bp
from scheduler.expiry_scheduler import start_scheduler

import os
from config import ENCRYPTED_DATA_PATH, ENCRYPTED_KEYS_PATH

os.makedirs(ENCRYPTED_DATA_PATH, exist_ok=True)
os.makedirs(ENCRYPTED_KEYS_PATH, exist_ok=True)

def create_app():
    app = Flask(__name__)

    @app.route("/")
    def home():
        return jsonify({
            "status": "Cryptographic Lifecycle Backend Running",
            "routes": [
                "/auth/token",
                "/submit",
                "/verify",
                "/admin"
            ]
        })

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(submission_bp, url_prefix="/submit")
    app.register_blueprint(verify_bp, url_prefix="/verify")
    app.register_blueprint(admin_bp, url_prefix="/admin")

    start_scheduler()
    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
