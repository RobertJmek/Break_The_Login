from contextlib import closing
from psycopg2.errors import ForeignKeyViolation, InvalidTextRepresentation
from data.database import get_db_connection

class TicketRepo:
    """Nivelul Data Layer (Baza de date): Manipulare tabela tickets."""
    
    @staticmethod
    def create_ticket(title, description, owner_id, priority):
        try:
            with closing(get_db_connection()) as conn:
                with conn:
                    with conn.cursor() as cursor:
                        # Parameterized query pentru prevenirea SQL Injection
                        query = """
                            INSERT INTO tickets (title, description, owner_id, priority) 
                            VALUES (%s, %s, %s, %s) RETURNING id;
                        """
                        cursor.execute(query, (title, description, owner_id, priority))
                        return cursor.fetchone()[0]
        except ForeignKeyViolation:
            raise ValueError("Utilizatorul specificat (owner) nu există.")
        except InvalidTextRepresentation:
            raise ValueError("Prioritate invalidă. Valorile permise sunt: LOW, MEDIUM, HIGH.")
        
    @staticmethod
    def get_ticket_by_id(ticket_id):
        with closing(get_db_connection()) as conn:
            with conn.cursor() as cursor:
                query = "SELECT id, title, description, status, priority, owner_id, created_at, updated_at FROM tickets WHERE id = %s;"
                cursor.execute(query, (ticket_id,))
                row = cursor.fetchone()
                if row:
                    return {
                        "id": row[0],
                        "title": row[1],
                        "description": row[2],
                        "status": row[3],
                        "priority": row[4],
                        "owner_id": row[5],
                        "created_at": row[6],
                        "updated_at": row[7]
                    }
                return None
        
    @staticmethod
    def get_all_tickets():
        with closing(get_db_connection()) as conn:
            with conn.cursor() as cursor:
                # Folosit de regulă de către MANAGER pentru a vedea toate tichetele
                query = "SELECT id, title, description, status, priority, owner_id, created_at, updated_at FROM tickets ORDER BY created_at DESC;"
                cursor.execute(query)
                rows = cursor.fetchall()
                return [{
                    "id": r[0], "title": r[1], "description": r[2], 
                    "status": r[3], "priority": r[4], "owner_id": r[5], 
                    "created_at": r[6], "updated_at": r[7]
                } for r in rows]
        
    @staticmethod
    def get_tickets_by_owner(owner_id):
        with closing(get_db_connection()) as conn:
            with conn.cursor() as cursor:
                # Folosit de ANALYST pentru a-și vedea exclusiv propriile tichete
                query = "SELECT id, title, description, status, priority, owner_id, created_at, updated_at FROM tickets WHERE owner_id = %s ORDER BY created_at DESC;"
                cursor.execute(query, (owner_id,))
                rows = cursor.fetchall()
                return [{
                    "id": r[0], "title": r[1], "description": r[2], 
                    "status": r[3], "priority": r[4], "owner_id": r[5], 
                    "created_at": r[6], "updated_at": r[7]
                } for r in rows]
        
    @staticmethod
    def update_ticket_status(ticket_id, status):
        try:
            with closing(get_db_connection()) as conn:
                with conn:
                    with conn.cursor() as cursor:
                        # Inclusiv actualizăm automat timestamp-ul la modificare!
                        query = "UPDATE tickets SET status = %s, updated_at = NOW() WHERE id = %s;"
                        cursor.execute(query, (status, ticket_id))
        except InvalidTextRepresentation:
            raise ValueError("Status invalid. Valorile permise sunt: OPEN, IN_PROGRESS, RESOLVED.")
