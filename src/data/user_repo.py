from contextlib import closing
from psycopg2.errors import UniqueViolation, InvalidTextRepresentation
from data.database import get_db_connection

class UserRepo:
    """Nivelul Data Layer (Baza de date): Manipulare tabela users."""
    
    @staticmethod
    def create_user(email, password_hash):
        try:
            with closing(get_db_connection()) as conn:
                with conn: # Face commit automat la succes și rollback la excepție
                    with conn.cursor() as cursor: # Închide automat cursorul
                        query = "INSERT INTO users (email, password_hash) VALUES (%s, %s) RETURNING id;"
                        cursor.execute(query, (email, password_hash))
                        return cursor.fetchone()[0]
        except UniqueViolation:
            raise ValueError("Acest email este deja înregistrat.")
        
    @staticmethod
    def get_user_by_email(email):
        with closing(get_db_connection()) as conn:
            with conn.cursor() as cursor:
                query = "SELECT id, email, password_hash, role, locked FROM users WHERE email = %s;"
                cursor.execute(query, (email,))
                row = cursor.fetchone()
                
                if row:
                    return {
                        "id": row[0],
                        "email": row[1],
                        "password_hash": row[2],
                        "role": row[3],
                        "locked": row[4]
                    }
                return None
        
    @staticmethod
    def update_locked_status(user_id, locked):
        with closing(get_db_connection()) as conn:
            with conn:
                with conn.cursor() as cursor:
                    query = "UPDATE users SET locked = %s WHERE id = %s;"
                    cursor.execute(query, (locked, user_id))

    @staticmethod
    def update_password(user_id, password_hash):
        with closing(get_db_connection()) as conn:
            with conn:
                with conn.cursor() as cursor:
                    query = "UPDATE users SET password_hash = %s WHERE id = %s;"
                    cursor.execute(query, (password_hash, user_id))

    @staticmethod
    def update_email(user_id, email):
        try:
            with closing(get_db_connection()) as conn:
                with conn:
                    with conn.cursor() as cursor:
                        query = "UPDATE users SET email = %s WHERE id = %s;"
                        cursor.execute(query, (email, user_id))
        except UniqueViolation:
            raise ValueError("Acest email este deja înregistrat.")

    @staticmethod
    def update_role(user_id, role):
        try:
            with closing(get_db_connection()) as conn:
                with conn:
                    with conn.cursor() as cursor:
                        query = "UPDATE users SET role = %s WHERE id = %s;"
                        cursor.execute(query, (role, user_id))
        except InvalidTextRepresentation:
            raise ValueError("Rolul specificat este invalid. Rolurile permise sunt: USER, ANALYST, MANAGER.")
                    
    
