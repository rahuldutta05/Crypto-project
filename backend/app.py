from flask import Flask
from routes.auth_routes import auth_bp
from routes.key_routes import key_bp
from routes.chat_routes import chat_bp
from routes.verify_routes import verify_bp
from routes.admin_routes import admin_bp
from scheduler.expiry_scheduler import start_scheduler
from flask_cors import CORS

def create_app():
    app = Flask(__name__)
    CORS(app)
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(key_bp, url_prefix="/keys")
    app.register_blueprint(chat_bp, url_prefix="/chat")
    app.register_blueprint(verify_bp, url_prefix="/verify")
    app.register_blueprint(admin_bp, url_prefix="/admin")

    start_scheduler()

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)