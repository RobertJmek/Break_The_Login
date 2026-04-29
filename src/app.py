import os
import time
from flask import Flask, request, jsonify, render_template, session
from dotenv import load_dotenv

# Importuri din layer-ele aplicației
from security.authn import AuthService  # AuthN e in Security Controls in diagrama
from services.ticket_service import TicketService
from services.audit_service import AuditService
from security.authz import login_required, manager_required
from security.error_handling import register_error_handlers
from security.csrf_protection import init_csrf
from security.rate_limiting import init_rate_limiting, limiter
from security.output_encoding import OutputEncoding
from security.headers import init_security_headers
from security.authz import require_ticket_ownership_or_manager, manager_required, analyst_or_manager_required

load_dotenv()

# Nivelul Backend API

app = Flask(__name__)

# Read once at startup — never re-read per-request.
# Set DEBUG=false (or omit entirely) in any environment that is not local dev.
DEBUG = os.getenv("DEBUG", "false").lower() == "true"

# Minimum response time for /forgot POST (seconds).
# Enforces a constant-time response so an attacker cannot distinguish
# "email exists" from "email not found" via response timing.
# Must be comfortably above the slowest legitimate code path (DB write ~ 50-100ms).
FORGOT_MIN_RESPONSE_SECONDS = float(os.getenv("FORGOT_MIN_RESPONSE_SECONDS", "0.3"))

from security.session_mgmt import init_session_mgmt

# Inițializăm modulele de securitate globale
init_session_mgmt(app)
register_error_handlers(app)
init_csrf(app)
init_rate_limiting(app)
init_security_headers(app)

from security.audit_logging import log_security_event
from data.user_repo import UserRepo
from data.token_repo import TokenRepo

# Pagination defaults — MAX_PAGE_SIZE is a security cap that prevents
# an attacker from requesting per_page=999999 to cause an unbounded DB fetch.
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE     = 100

def _parse_pagination():
    """Extract and sanitise ?page=&per_page= from the current request query string."""
    try:
        page     = max(1, int(request.args.get('page', 1)))
        per_page = min(MAX_PAGE_SIZE, max(1, int(request.args.get('per_page', DEFAULT_PAGE_SIZE))))
    except (ValueError, TypeError):
        page, per_page = 1, DEFAULT_PAGE_SIZE
    offset = (page - 1) * per_page
    return per_page, offset

@app.route('/', methods=['GET'])
def main_page():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per hour")  # Prevenim crearea în masă de conturi (Spam/Boți)
def register():
    if request.method == 'GET':
        return render_template('register.html')
        
    data = request.form if request.form else request.json
    email = data.get('email')
    password = data.get('password')
    
    # 1. Autentificare & Validare (Security Control)
    user_id = AuthService.register_user(email, password)
    
    from flask import flash, redirect, url_for
    # 2. Audit Logging
    log_security_event(user_id, "CREATE", "USER", user_id, request.remote_addr)
    
    flash("Înregistrare reușită. Te poți autentifica.", "success")
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Prevenim atacurile Brute-Force (ex: Hydra, Burp Intruder)
def login():
    if request.method == 'GET':
        return render_template('login.html')
        
    data = request.form if request.form else request.json
    email = data.get('email')
    password = data.get('password')
    
    # 1. Autentificare securizată (Timing Attack safe)
    user = AuthService.authenticate_user(email, password)
    
    # 2. Session Fixation Prevention
    session.clear()
    
    # 3. Preluăm datele curate în sesiune
    session['user_id'] = user['id']
    session['role'] = user['role']
    
    # 4. Activăm sesiunea permanentă ("Capcana 1")
    # Asta face ca PERMANENT_SESSION_LIFETIME să funcționeze pe bune!
    session.permanent = True
    
    # 5. Audit Logging
    log_security_event(user['id'], "LOGIN", "USER", user['id'], request.remote_addr)
    
    flash(f"Bine ai revenit! Ești autentificat ca {user['role']}.", "success")
    return redirect(url_for('ticket_management'))

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    user_id = session.get('user_id')
    
    # 1. Audit Logging
    log_security_event(user_id, "LOGOUT", "USER", user_id, request.remote_addr)
    
    # 2. Invalidare Sesiune la Logout (Best Practice)
    session.clear()
    
    flash("Sesiune încheiată complet.", "info")
    return redirect(url_for('login'))
@app.route('/forgot', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def forgot_password():
    if request.method == 'GET':
        return render_template('forgot.html')

    # Start the clock BEFORE any logic so both branches are measured equally.
    _start = time.monotonic()

    email = request.form.get('email') or request.json.get('email')
    user = UserRepo.get_user_by_email(email)

    if user:
        token = TokenRepo.generate_token()
        TokenRepo.store_token(user['id'], token)
        log_security_event(user['id'], "UPDATE", "USER", user['id'], request.remote_addr)
        response = {"message": "Dacă email-ul există, s-a trimis un link."}
        if DEBUG:
            response["mock_link"] = f"/reset/{token}"
    else:
        response = {"message": "Dacă email-ul există, s-a trimis un link."}

    # Pad response time so both branches always take ≥ FORGOT_MIN_RESPONSE_SECONDS.
    # This prevents timing-based email enumeration: an attacker measuring response
    # latency cannot distinguish a found email from a missing one.
    _elapsed = time.monotonic() - _start
    _remaining = FORGOT_MIN_RESPONSE_SECONDS - _elapsed
    if _remaining > 0:
        time.sleep(_remaining)

    flash("Dacă email-ul există, s-a trimis un link de resetare.", "info")
    return redirect(url_for('forgot_password'))

@app.route('/reset/<token>', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def reset_password(token):
    if request.method == 'GET':
        return render_template('reset.html', token=token)

    data = request.form if request.form else request.json
    new_password = data.get('password')

    # Atomically consume the token — returns user_id if valid, None if not found / used / expired.
    user_id = TokenRepo.consume_token(token)
    if user_id is None:
        return jsonify({"error": "Token invalid sau deja utilizat."}), 400

    AuthService.update_password(user_id, new_password)
    session.clear()
    log_security_event(user_id, "UPDATE", "USER", user_id, request.remote_addr)
    
    flash("Parolă resetată cu succes. Te poți autentifica.", "success")
    return redirect(url_for('login'))

@app.route('/ticket', methods=['GET', 'POST'])
@login_required
@limiter.limit("30 per minute")
def ticket_management():
    if request.method == 'GET':
        limit, offset = _parse_pagination()
        tickets = TicketService.get_user_tickets(session['user_id'], session['role'], limit=limit, offset=offset)
        # Output Encoding Security Control (Anti-XSS Defense in Depth)
        safe_tickets = OutputEncoding.sanitize_dict({"tickets": tickets})['tickets']
        return render_template('ticket_list.html', tickets=safe_tickets)
        
    # POST - Create Ticket
    data = request.form if request.form else request.json
    title = data.get('title')
    description = data.get('description')
    priority = data.get('priority')
    
    TicketService.create_ticket(session['user_id'], title, description, priority, request.remote_addr)
    return jsonify({"message": "Tichet creat cu succes."}), 201

@app.route('/ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
@require_ticket_ownership_or_manager
def view_or_update_ticket(ticket_id):
    if request.method == 'GET':
        ticket = TicketService.view_ticket(ticket_id, session['user_id'], session['role'])
        safe_ticket = OutputEncoding.sanitize_dict(ticket)
        return render_template('ticket_view.html', ticket=safe_ticket)
        
    # POST - Update Status
    if session['role'] != 'MANAGER':
        return jsonify({"error": "Doar managerii pot actualiza statusul."}), 403
        
    data = request.form if request.form else request.json
    status = data.get('status')
    
    TicketService.update_status(ticket_id, status, session['user_id'], request.remote_addr)
    return jsonify({"message": "Status actualizat cu succes."})

@app.route('/audit', methods=['GET'])
@login_required
@manager_required
def view_audit_logs():
    limit, offset = _parse_pagination()
    logs = AuditService.view_audit_logs(session['role'], limit=limit, offset=offset)
    safe_logs = OutputEncoding.sanitize_dict({"logs": logs})['logs']
    return render_template('audit_logs.html', logs=safe_logs)

import atexit
import data.database

@atexit.register
def close_db_pool():
    if data.database._pool:
        data.database._pool.closeall()
        print("Toate conexiunile la baza de date au fost închise curat.")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)