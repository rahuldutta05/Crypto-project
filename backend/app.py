"""
app.py — Flask application factory.

Creates and configures the Flask app, registers all blueprints,
and starts the background expiry scheduler thread.
"""

from flask import Flask, jsonify
from flask_cors import CORS

from api.auth   import auth_bp
from api.chat   import chat_bp
from api.keys   import keys_bp
from api.verify import verify_bp
from api.admin  import admin_bp
from core.scheduler import start_background_scheduler


def create_app() -> Flask:
    app = Flask(__name__)
    CORS(app)

    # ── Register blueprints ───────────────────────────────────────────────
    app.register_blueprint(auth_bp,   url_prefix="/auth")
    app.register_blueprint(chat_bp,   url_prefix="/chat")
    app.register_blueprint(keys_bp,   url_prefix="/keys")
    app.register_blueprint(verify_bp, url_prefix="/verify")
    app.register_blueprint(admin_bp,  url_prefix="/admin")

    # ── Global error handlers ─────────────────────────────────────────────
    @app.errorhandler(404)
    def not_found(_):
        return jsonify({"error": "Endpoint not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(_):
        return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({"error": "Internal server error", "detail": str(e)}), 500

    # ── Start background expiry scheduler ─────────────────────────────────
    start_background_scheduler()

    return app
