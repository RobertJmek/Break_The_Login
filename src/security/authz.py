from functools import wraps
from flask import session, g
from werkzeug.exceptions import Unauthorized, Forbidden, NotFound
from data.ticket_repo import TicketRepo
import logging

# Nivelul Security Controls: AuthZ (RBAC + Ownership)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            raise Unauthorized("Autentificare necesară.")
        return f(*args, **kwargs)
    return decorated_function

def manager_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'MANAGER':
            raise Forbidden("Acces respins. Rol de MANAGER necesar.")
        return f(*args, **kwargs)
    return decorated_function

def analyst_or_manager_required(f):
    """RBAC: Permite accesul doar Analiștilor și Managerilor. Blochează rolul de bază USER."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        role = session.get('role')
        if role not in ['ANALYST', 'MANAGER']:
            raise Forbidden("Acces respins. Funcționalitate destinată exclusiv echipei (Analyst/Manager).")
        return f(*args, **kwargs)
    return decorated_function

def require_ticket_ownership_or_manager(f):
    """
    IDOR Prevention & RBAC.
    Verifică strict rolurile și apartenența datelor (Ownership).
    - USER: Nu are acces la tichete.
    - MANAGER: Are acces la orice tichet.
    - ANALYST: Are acces DOAR la tichetele proprii.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        role = session.get('role')
        
        # 1. RBAC (Role Check): USER nu are voie să interacționeze cu tichetele
        if role == 'USER':
            raise Forbidden("Acces respins. Utilizatorii simpli (USER) nu au acces la tichete.")
            
        ticket_id = kwargs.get('ticket_id')
        if not ticket_id:
            # Dacă funcția nu a cerut ticket_id în URL (de ex. e ruta generală de listare), trecem mai departe
            return f(*args, **kwargs)
            
        ticket = TicketRepo.get_ticket_by_id(ticket_id)
        if not ticket:
            raise NotFound("Tichetul nu a fost găsit.")
            
        user_id = session.get('user_id')
        
        # 2. Ownership Check (IDOR Prevention): Analistul trebuie să dețină resursa
        if role == 'ANALYST' and ticket['owner_id'] != user_id:
            logging.warning(f"SECURITY ALERT: IDOR Attempt la tichetul {ticket_id} de catre Analystul {user_id}")
            raise Forbidden("Acces respins. Nu ești proprietarul acestui tichet!")
            
        # Optimizare: Salvăm tichetul în obiectul global al request-ului
        # pentru a preveni interogarea dublă a bazei de date în TicketService
        g.ticket = ticket
            
        return f(*args, **kwargs)
    return decorated_function
