from data.user_repo import UserRepo
from data.audit_repo import AuditRepo
from security.validation import InputValidation
from security.exceptions import AppValidationError
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import secrets

ph = PasswordHasher()

# Generăm un hash dummy la pornirea serverului pentru a-l folosi la mitigarea Timing Attacks
PAROLA_RANDOM = secrets.token_hex(8)
DUMMY_HASH = ph.hash(PAROLA_RANDOM)

class AuthService:
    """Security Control: AuthN, Logica securizată de login/register."""
    
    @staticmethod
    def register_user(email, plain_password):
        # 1. Validare input (Anti-Injection & Policy Enforcement)
        
        InputValidation.validate_email(email)
        InputValidation.validate_password_complexity(plain_password)
        
        # 2. Hashing cu Argon2 (KDF modern, rezistent la atacuri offline/GPU)
        # Argon2 generează și gestionează 'salt-ul' automat.

        password_hash = ph.hash(plain_password)
        
        # 3. Salvare (user_repo prinde erorile de tip UniqueViolation)

        user_id = UserRepo.create_user(email, password_hash)
        return user_id
        
    @staticmethod
    def authenticate_user(email, plain_password):
        # 1. Obținem datele (și aducem flag-ul de 'locked'!)
        user = UserRepo.get_user_by_email(email)
        
        # Prevenim 'Email Enumeration' și Timing Attacks la bază: 
        # Răspundem cu același mesaj generic și dacă nu există user-ul, și dacă parola e greșită.
        if not user:
            # Acum PUTEM și TREBUIE să folosim un dummy_hash pentru a balansa timpul de execuție perfect.
            try:
                ph.verify(DUMMY_HASH, plain_password)
            except VerifyMismatchError:
                pass
            raise AppValidationError("Credențiale invalide.")
            
        # 2. Verificăm dacă contul a fost blocat (Anti Brute-Force)
        if user["locked"]:
            # Pentru siguranță absolută, returnăm același mesaj generic să nu confirmăm existența contului
            raise AppValidationError("Credențiale invalide.")
            
        try:
            # 3. Verificarea parolei (comparare constant-time)
            ph.verify(user["password_hash"], plain_password)
            
            # 4. (Opțional, dar recomandat) Re-hashing dacă am crescut costurile Argon2 între timp
            
            if ph.check_needs_rehash(user["password_hash"]):
                new_hash = ph.hash(plain_password)
                UserRepo.update_password(user["id"], new_hash)
                
            return user
        except VerifyMismatchError:
            # Aici am putea înregistra logica de incrementare a încercărilor eșuate
            # și să chemăm UserRepo.update_locked_status(user["id"], True) dacă depășește pragul.
            raise AppValidationError("Credențiale invalide.")

    @staticmethod
    def update_password(user_id, new_password):
        InputValidation.validate_password_complexity(new_password)
        new_hash = ph.hash(new_password)
        UserRepo.update_password(user_id, new_hash)
