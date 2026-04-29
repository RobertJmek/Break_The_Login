from flask import g
from data.ticket_repo import TicketRepo
from security.exceptions import AppValidationError
from security.audit_logging import log_security_event

class TicketService:
    """Nivelul Business Modules: Tickets CRUD + Status, Search + Filters."""
    
    @staticmethod
    def create_ticket(user_id, title, description, priority, ip_address):
        # 1. Input Validation Minimal
        if not title or not description:
            raise AppValidationError("Titlul și descrierea sunt obligatorii.")
            
        if len(title) > 150:
            raise AppValidationError("Titlul este prea lung (maxim 150 de caractere).")

        if len(description) > 5000:
            raise AppValidationError("Descrierea este prea lungă (maxim 5000 de caractere).")
            
        # Whitelist (Lista albă) pentru prioritate - Prevenim Data Corruption
        if priority not in ['LOW', 'MEDIUM', 'HIGH']:
            raise AppValidationError("Prioritate invalidă. Valorile permise sunt: LOW, MEDIUM, HIGH.")
            
        # 2. Creare prin Repository
        ticket_id = TicketRepo.create_ticket(title, description, user_id, priority)
        
        # 3. Security Audit Logging (Folosind Dependency Injection pentru IP)
        log_security_event(user_id, "CREATE", "TICKET", ticket_id, ip_address)
        
        return ticket_id
        
    @staticmethod
    def get_user_tickets(user_id, role, limit: int = 50, offset: int = 0):
        # Business Logic: route by role, always with pagination
        if role == 'MANAGER':
            return TicketRepo.get_all_tickets(limit=limit, offset=offset)
        elif role == 'ANALYST':
            return TicketRepo.get_tickets_by_owner(user_id, limit=limit, offset=offset)
        else:
            raise AppValidationError("Nu ai permisiunea de a vizualiza tichete.")
        
    @staticmethod
    def view_ticket(ticket_id, current_user_id, current_user_role):
        # Optimizare performanță (Zero-Cost): 
        # Dacă AuthZ a interogat deja DB-ul și l-a pus în 'g', refolosim rezultatul!
        ticket = getattr(g, 'ticket', None)
        
        # Fallback dacă funcția e apelată din altă parte fără AuthZ
        if not ticket:
            ticket = TicketRepo.get_ticket_by_id(ticket_id)
        
        if not ticket:
            raise AppValidationError("Tichetul solicitat nu există.")
            
        return ticket
        
    @staticmethod
    def update_status(ticket_id, status, user_id, ip_address):
        # Whitelist
        if status not in ['OPEN', 'IN_PROGRESS', 'RESOLVED']:
            raise AppValidationError("Status invalid.")
            
        TicketRepo.update_ticket_status(ticket_id, status)
        log_security_event(user_id, "UPDATE", "TICKET", ticket_id, ip_address)
