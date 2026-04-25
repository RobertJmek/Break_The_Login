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
            
        # Whitelist (Lista albă) pentru prioritate - Prevenim Data Corruption
        if priority not in ['LOW', 'MEDIUM', 'HIGH']:
            raise AppValidationError("Prioritate invalidă. Valorile permise sunt: LOW, MEDIUM, HIGH.")
            
        # 2. Creare prin Repository
        ticket_id = TicketRepo.create_ticket(title, description, user_id, priority)
        
        # 3. Security Audit Logging (Folosind Dependency Injection pentru IP)
        log_security_event(user_id, "CREATE_TICKET", "Ticket", ticket_id, ip_address)
        
        return ticket_id
        
    @staticmethod
    def get_user_tickets(user_id, role):
        # 1. Logica de Business: Direcționare pe baza rolului
        if role == 'MANAGER':
            return TicketRepo.get_all_tickets()
        elif role == 'ANALYST':
            return TicketRepo.get_tickets_by_owner(user_id)
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
        log_security_event(user_id, "UPDATE", "Ticket", ticket_id, ip_address)
