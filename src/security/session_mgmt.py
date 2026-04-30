import os
from datetime import timedelta

def init_session_mgmt(app):
    """
    Security Control: Session/JWT Hardening
    Configurează protecția criptografică a sesiunilor, securitatea cookie-urilor și durata de viață.
    """
    secret_key = os.getenv("FLASK_SECRET_KEY")
    if not secret_key:
        raise ValueError("CRITICAL: FLASK_SECRET_KEY is missing from environment variables!")

    app.secret_key = secret_key

    # SESSION_COOKIE_SECURE=True means the browser will only send the session cookie
    # over HTTPS connections. In development (DEBUG=true) this must be False, otherwise
    # the session cookie is silently never sent over plain HTTP and every request appears
    # unauthenticated.
    # In production (DEBUG=false / unset) it is always True.
    
    debug = os.getenv("DEBUG", "false").lower() == "true"
    cookie_secure = not debug
    session_lifetime = int(os.getenv("SESSION_LIFETIME_MINUTES", "30"))

    app.config.update(
        # 1. Cookie Flags (Anti-XSS și Anti-CSRF la nivel de browser)
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=cookie_secure,
        SESSION_COOKIE_SAMESITE='Lax',

        # 2. Token Expiry (Limităm fereastra de oportunitate a unui atacator)
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=session_lifetime)
    )
