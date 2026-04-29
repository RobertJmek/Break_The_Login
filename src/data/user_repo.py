import os
from contextlib import closing
from psycopg2.errors import UniqueViolation, InvalidTextRepresentation
from data.database import get_db_connection
from security.exceptions import AppValidationError

# Security policy — tunable per environment without code changes.
# Defaults are intentionally strict; override in .env if needed.
MAX_FAILED_ATTEMPTS = int(os.getenv("MAX_FAILED_ATTEMPTS", "5"))
# Stored as minutes (integer) and formatted into a PostgreSQL INTERVAL string.
LOCKOUT_DURATION = f"{int(os.getenv('LOCKOUT_DURATION_MINUTES', '15'))} minutes"

class UserRepo:
    """Nivelul Data Layer (Baza de date): Manipulare tabela users."""
    
    @staticmethod
    def create_user(email, password_hash):
        try:
            with closing(get_db_connection()) as conn:
                with conn:
                    with conn.cursor() as cursor:
                        query = "INSERT INTO users (email, password_hash) VALUES (%s, %s) RETURNING id;"
                        cursor.execute(query, (email, password_hash))
                        return cursor.fetchone()[0]
        except UniqueViolation:
            raise AppValidationError("Acest email este deja înregistrat.")
        
    @staticmethod
    def get_user_by_email(email):
        with closing(get_db_connection()) as conn:
            with conn.cursor() as cursor:
                query = """
                    SELECT id, email, password_hash, role, locked, failed_attempts, locked_until
                    FROM users
                    WHERE email = %s;
                """
                cursor.execute(query, (email,))
                row = cursor.fetchone()
                
                if row:
                    return {
                        "id":              row[0],
                        "email":           row[1],
                        "password_hash":   row[2],
                        "role":            row[3],
                        "locked":          row[4],
                        "failed_attempts": row[5],
                        "locked_until":    row[6],  # datetime | None (timezone-aware)
                    }
                return None

    @staticmethod
    def record_failed_attempt(user_id: int) -> None:
        """
        Atomically increment the failure counter.
        If the counter reaches MAX_FAILED_ATTEMPTS after this increment,
        locked_until is set to NOW() + LOCKOUT_DURATION and the counter is reset to 0
        so the next N-attempt window starts clean after the lockout expires.

        Done in a single UPDATE to avoid TOCTOU races between concurrent requests.
        """
        with closing(get_db_connection()) as conn:
            with conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """
                        UPDATE users
                        SET
                            failed_attempts = CASE
                                WHEN failed_attempts + 1 >= %(max)s THEN 0
                                ELSE failed_attempts + 1
                            END,
                            locked_until = CASE
                                WHEN failed_attempts + 1 >= %(max)s
                                    THEN NOW() + %(duration)s::INTERVAL
                                ELSE locked_until
                            END
                        WHERE id = %(uid)s;
                        """,
                        {"max": MAX_FAILED_ATTEMPTS, "duration": LOCKOUT_DURATION, "uid": user_id}
                    )

    @staticmethod
    def reset_failed_attempts(user_id: int) -> None:
        """
        Called on successful authentication.
        Clears both the counter and any time-based lockout so legitimate users
        are never stuck after a correct login.
        """
        with closing(get_db_connection()) as conn:
            with conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = %s;",
                        (user_id,)
                    )

    @staticmethod
    def update_locked_status(user_id, locked):
        """Admin-controlled permanent lock (independent of the auto-lockout)."""
        with closing(get_db_connection()) as conn:
            with conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "UPDATE users SET locked = %s WHERE id = %s;",
                        (locked, user_id)
                    )

    @staticmethod
    def update_password(user_id, password_hash):
        with closing(get_db_connection()) as conn:
            with conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "UPDATE users SET password_hash = %s WHERE id = %s;",
                        (password_hash, user_id)
                    )

    @staticmethod
    def update_email(user_id, email):
        try:
            with closing(get_db_connection()) as conn:
                with conn:
                    with conn.cursor() as cursor:
                        cursor.execute(
                            "UPDATE users SET email = %s WHERE id = %s;",
                            (email, user_id)
                        )
        except UniqueViolation:
            raise AppValidationError("Acest email este deja înregistrat.")

    @staticmethod
    def update_role(user_id, role):
        try:
            with closing(get_db_connection()) as conn:
                with conn:
                    with conn.cursor() as cursor:
                        cursor.execute(
                            "UPDATE users SET role = %s WHERE id = %s;",
                            (role, user_id)
                        )
        except InvalidTextRepresentation:
            raise AppValidationError("Rolul specificat este invalid. Rolurile permise sunt: USER, ANALYST, MANAGER.")
