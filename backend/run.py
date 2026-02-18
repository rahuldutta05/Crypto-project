"""
run.py — Development server entry point.

For production, use gunicorn:
    gunicorn "run:app" --workers 4 --bind 0.0.0.0:5000

Environment variables:
    ADMIN_TOKEN          Required for /admin/* endpoints
    KEY_EXPIRY_MINUTES   How long before DEKs are destroyed (default: 60)
    POW_DIFFICULTY       Leading zeros required in PoW (default: 6)
    FLASK_DEBUG          Set to "1" for debug mode (never in production)
"""

import os
from app import create_app

app = create_app()

if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    port  = int(os.environ.get("PORT", 5000))

    print(f"\n{'='*55}")
    print("  Cryptographic Backend — Starting")
    print(f"  http://127.0.0.1:{port}")
    print(f"  Debug mode: {debug}")
    print(f"  Admin token set: {'yes' if os.environ.get('ADMIN_TOKEN') else 'NO — set ADMIN_TOKEN'}")
    print(f"{'='*55}\n")

    app.run(host="0.0.0.0", port=port, debug=debug)
