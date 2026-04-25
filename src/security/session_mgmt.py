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
    
    app.config.update(
        # 1. Cookie Flags (Anti-XSS și Anti-CSRF la nivel de browser)
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True, # Protecție pe rețea (necesită HTTPS)
        SESSION_COOKIE_SAMESITE='Lax',
        
        # 2. Token Expiry (Limităm fereastra de oportunitate a unui atacator)
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
    )
