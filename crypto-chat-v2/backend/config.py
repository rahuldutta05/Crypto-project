import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-CHANGE-IN-PRODUCTION'
    
    # Cryptographic settings
    KEY_SIZE = 2048  # RSA key size
    HASH_ALGORITHM = 'sha256'
    
    # Time-lock settings (Core Principle #3: Cryptographic Expiry)
    DEFAULT_MESSAGE_EXPIRY = timedelta(minutes=60)  # Messages expire after 1 hour
    MAX_MESSAGE_EXPIRY = timedelta(hours=24)
    MIN_MESSAGE_EXPIRY = timedelta(minutes=5)
    
    # Anonymous authentication (Core Principle #1)
    CHALLENGE_EXPIRY = timedelta(minutes=5)
    SESSION_EXPIRY = timedelta(hours=12)
    
    # WebSocket settings
    WEBSOCKET_PING_INTERVAL = 25
    WEBSOCKET_PING_TIMEOUT = 60
    
    # Security monitoring
    SECURITY_LOG_RETENTION_DAYS = 90  # Keep logs for 90 days
    RATE_LIMIT_PER_IP = 100  # Max requests per hour per IP
    BRUTE_FORCE_THRESHOLD = 5  # Auth failures before flagging
    
    # Storage paths
    STORAGE_DIR = 'storage'
    MESSAGES_FILE = 'storage/messages.json'
    KEYS_FILE = 'storage/keys.json'
    TOKENS_FILE = 'storage/tokens.json'
    PROOF_FILE = 'storage/proof.json'
    DEVICES_FILE = 'storage/devices.json'
    SECURITY_EVENTS_FILE = 'storage/security_events.json'
    NONCES_FILE = 'storage/nonces.json'
    
    # Production settings (uncomment for deployment)
    # ALLOWED_ORIGINS = ['https://yourdomain.com']
    # USE_SSL = True
    # SESSION_COOKIE_SECURE = True
    # SESSION_COOKIE_HTTPONLY = True
    # SESSION_COOKIE_SAMESITE = 'Lax'
