import re
from security.exceptions import AppValidationError

class InputValidation:
    """Security Control: Input Validation (anti Injection)."""
    
    @staticmethod
    def validate_password_complexity(password):
        # min 8 chars, 1 uppercase, 1 lowercase, 1 number
        if not password or len(password) < 8:
            raise AppValidationError("Parola trebuie să aibă cel puțin 8 caractere.")
        
        if not re.search(r"[a-z]", password):
            raise AppValidationError("Parola trebuie să conțină cel puțin o literă mică (a-z).")
            
        if not re.search(r"[A-Z]", password):
            raise AppValidationError("Parola trebuie să conțină cel puțin o literă mare (A-Z).")
            
        if not re.search(r"\d", password):
            raise AppValidationError("Parola trebuie să conțină cel puțin o cifră (0-9).")
            
        # Limităm lungimea maximă pentru a preveni atacuri DoS prin hashing
        if len(password) > 50:
            raise AppValidationError("Parola este prea lungă (maxim 50 caractere).")

    @staticmethod
    def validate_email(email):
        # Verificăm lungimea maximă pentru a preveni Buffer Overflows/DoS
        if not email or len(email) > 255:
            raise AppValidationError("Email-ul este obligatoriu și nu poate depăși 255 de caractere.")
            
        # Regex simplu și performant pentru validarea adreselor de email (previne ReDoS)
        email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        
        if not re.match(email_regex, email):
            raise AppValidationError("Adresa de email nu are un format valid.")
