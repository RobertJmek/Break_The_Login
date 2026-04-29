import logging
import secrets
from datetime import datetime, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from data.user_repo import UserRepo
from security.validation import InputValidation
from security.exceptions import AppValidationError

ph = PasswordHasher()

# Generăm un hash dummy la pornirea serverului pentru a-l folosi la mitigarea Timing Attacks.
# Verificarea dummy costă același timp ca o verificare reală, indiferent dacă user-ul există.
_DUMMY_PASSWORD = secrets.token_hex(8)
_DUMMY_HASH = ph.hash(_DUMMY_PASSWORD)


class AuthService:
    """Security Control: AuthN, Logica securizată de login/register."""
    
    @staticmethod
    def register_user(email, plain_password):
        # 1. Validare input (Anti-Injection & Policy Enforcement)
        InputValidation.validate_email(email)
        InputValidation.validate_password_complexity(plain_password)
        
        # 2. Hashing cu Argon2 (KDF modern, rezistent la atacuri offline/GPU).
        #    Argon2 generează și gestionează salt-ul automat.
        password_hash = ph.hash(plain_password)
        
        # 3. Salvare (user_repo prinde erorile de tip UniqueViolation)
        user_id = UserRepo.create_user(email, password_hash)
        return user_id
        
    @staticmethod
    def authenticate_user(email, plain_password):
        # 1. Fetch user — we need all lockout fields from the DB.
        user = UserRepo.get_user_by_email(email)
        
        # --- Unknown user path ---
        # Run dummy verify so response time is indistinguishable from a real failure.
        # This prevents both email enumeration and timing-based user discovery.
        if not user:
            try:
                ph.verify(_DUMMY_HASH, plain_password)
            except VerifyMismatchError:
                pass
            raise AppValidationError("Credențiale invalide.")

        # 2. Permanent admin lock — checked before anything else.
        if user["locked"]:
            raise AppValidationError("Credențiale invalide.")

        # 3. Time-based auto-lockout from brute-force protection.
        locked_until = user["locked_until"]
        if locked_until is not None:
            # psycopg2 returns TIMESTAMPTZ as timezone-aware datetime.
            now = datetime.now(timezone.utc)
            if locked_until > now:
                # Log internally for monitoring, but never expose the reason to the client.
                remaining = int((locked_until - now).total_seconds())
                logging.warning(
                    f"SECURITY: Login blocked for user {user['id']} "
                    f"— auto-lockout active for {remaining}s more."
                )
                raise AppValidationError("Credențiale invalide.")
            # Lockout has expired — fall through to normal password check.

        try:
            # 4. Constant-time password verification.
            ph.verify(user["password_hash"], plain_password)

            # 5. Successful login → reset failure counter and any expired lockout.
            UserRepo.reset_failed_attempts(user["id"])

            # 6. Re-hash if Argon2 parameters have been upgraded since last login.
            if ph.check_needs_rehash(user["password_hash"]):
                new_hash = ph.hash(plain_password)
                UserRepo.update_password(user["id"], new_hash)

            return user

        except VerifyMismatchError:
            # 7. Failed attempt — increment counter atomically.
            #    record_failed_attempt applies the lockout in the DB if threshold is reached.
            UserRepo.record_failed_attempt(user["id"])
            raise AppValidationError("Credențiale invalide.")

    @staticmethod
    def update_password(user_id, new_password):
        InputValidation.validate_password_complexity(new_password)
        new_hash = ph.hash(new_password)
        UserRepo.update_password(user_id, new_hash)
