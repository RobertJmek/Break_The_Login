from contextlib import closing
from psycopg2.errors import ForeignKeyViolation, InvalidTextRepresentation
from data.database import get_db_connection
from security.exceptions import AppValidationError

class AuditRepo:
    """Nivelul Data Layer (Baza de date): Manipulare tabela audit_logs."""
    
    @staticmethod
    def log_action(user_id, action, resource, resource_id, ip_address):
        try:
            with closing(get_db_connection()) as conn:
                with conn:
                    with conn.cursor() as cursor:
                        query = """
                            INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address) 
                            VALUES (%s, %s, %s, %s, %s) RETURNING id;
                        """
                        cursor.execute(query, (user_id, action, resource, resource_id, ip_address))
                        return cursor.fetchone()[0]
        except ForeignKeyViolation:
            raise AppValidationError("Utilizatorul specificat (user_id) nu există în DB.")
        except InvalidTextRepresentation:
            raise AppValidationError("Acțiune sau resursă invalidă. Verifică ENUM-urile.")

    @staticmethod
    def get_all_logs():
        with closing(get_db_connection()) as conn:
            with conn.cursor() as cursor:
                query = "SELECT id, user_id, action, resource, resource_id, timestamp, ip_address FROM audit_logs ORDER BY timestamp DESC;"
                cursor.execute(query)
                rows = cursor.fetchall()
                return [{"id": r[0], "user_id": r[1], "action": r[2], "resource": r[3], "resource_id": r[4], "timestamp": r[5], "ip_address": r[6]} for r in rows]

    @staticmethod
    def get_audit_logs_by_user(user_id):
        with closing(get_db_connection()) as conn:
            with conn.cursor() as cursor:
                query = "SELECT id, user_id, action, resource, resource_id, timestamp, ip_address FROM audit_logs WHERE user_id = %s ORDER BY timestamp DESC;"
                cursor.execute(query, (user_id,))
                rows = cursor.fetchall()
                return [{"id": r[0], "user_id": r[1], "action": r[2], "resource": r[3], "resource_id": r[4], "timestamp": r[5], "ip_address": r[6]} for r in rows]

    @staticmethod
    def get_audit_logs_by_action(action):
        try:
            with closing(get_db_connection()) as conn:
                with conn.cursor() as cursor:
                    query = "SELECT id, user_id, action, resource, resource_id, timestamp, ip_address FROM audit_logs WHERE action = %s ORDER BY timestamp DESC;"
                    cursor.execute(query, (action,))
                    rows = cursor.fetchall()
                    return [{"id": r[0], "user_id": r[1], "action": r[2], "resource": r[3], "resource_id": r[4], "timestamp": r[5], "ip_address": r[6]} for r in rows]
        except InvalidTextRepresentation:
            raise ValueError("Acțiune de audit invalidă (Ex: doar LOGIN, LOGOUT, CREATE, UPDATE, DELETE).")

    @staticmethod
    def get_audit_logs_by_resource(resource):
        try:
            with closing(get_db_connection()) as conn:
                with conn.cursor() as cursor:
                    query = "SELECT id, user_id, action, resource, resource_id, timestamp, ip_address FROM audit_logs WHERE resource = %s ORDER BY timestamp DESC;"
                    cursor.execute(query, (resource,))
                    rows = cursor.fetchall()
                    return [{"id": r[0], "user_id": r[1], "action": r[2], "resource": r[3], "resource_id": r[4], "timestamp": r[5], "ip_address": r[6]} for r in rows]
        except InvalidTextRepresentation:
            raise ValueError("Tip de resursă invalid (Ex: doar USER, TICKET).")

    @staticmethod
    def get_audit_logs_by_resource_id(resource_id):
        with closing(get_db_connection()) as conn:
            with conn.cursor() as cursor:
                query = "SELECT id, user_id, action, resource, resource_id, timestamp, ip_address FROM audit_logs WHERE resource_id = %s ORDER BY timestamp DESC;"
                cursor.execute(query, (resource_id,))
                rows = cursor.fetchall()
                return [{"id": r[0], "user_id": r[1], "action": r[2], "resource": r[3], "resource_id": r[4], "timestamp": r[5], "ip_address": r[6]} for r in rows]
