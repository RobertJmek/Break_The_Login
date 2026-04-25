from flask import jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

# Definim instanța limitatorului pe baza IP-ului clientului
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.getenv("LIMITER_STORAGE_URL", "memory://"), # Permite switch ușor la Redis în mediul de Producție
    strategy="moving-window", # Mult mai precis decât "fixed-window"
)

def init_rate_limiting(app):
    """
    Security Control: Rate Limiting Implementation
    Atașează protecția împotriva atacurilor de tip DoS și Brute Force.
    """
    limiter.init_app(app)

    # 1. Definim ce vede utilizatorul când este blocat (JSON, nu HTML generic)
    @app.errorhandler(429)
    def ratelimit_handler(e):
        return jsonify({
            "error": "too_many_requests",
            "message": "Ai depășit limita de cereri permise. Încearcă din nou în curând.",
            "limit": e.description
        }), 429

    # 2. Whitelisting: Citim IP-urile de încredere din .env
    # Nu hardcodăm IP-uri în cod public pentru a nu divulga infrastructura internă!
    @limiter.request_filter
    def ip_whitelist():
        # Citim IP-urile separate prin virgulă (default fallback la localhost)
        trusted_ips_raw = os.getenv("WHITELISTED_IPS", "127.0.0.1")
        trusted_ips = [ip.strip() for ip in trusted_ips_raw.split(',')]
        
        return request.remote_addr in trusted_ips
