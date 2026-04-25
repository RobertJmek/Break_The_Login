from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()

def init_csrf(app):
    """
    Security Control: CSRF Protection (Cross-Site Request Forgery).
    Asigură că cererile care modifică starea (POST, PUT, DELETE) vin dintr-un formular legitim 
    randat de noi sau conțin token-ul X-CSRFToken în headere (dacă folosim JSON/AJAX).
    """
    csrf.init_app(app)
