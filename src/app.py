import os
from flask import Flask, request, jsonify, render_template, session
from dotenv import load_dotenv

# Importuri din layer-ele aplicației
from data.database import get_db_connection
from security.authn import AuthService  # AuthN e in Security Controls in diagrama
from services.ticket_service import TicketService
from services.audit_service import AuditService
from security.authz import login_required, manager_required
from security.error_handling import register_error_handlers
from security.csrf_protection import init_csrf
from security.rate_limiting import init_rate_limiting, limiter
from security.output_encoding import OutputEncoding
from security.authz import require_ticket_ownership_or_manager, manager_required, analyst_or_manager_required

load_dotenv()

# Nivelul Backend API

app = Flask(__name__)

from security.session_mgmt import init_session_mgmt

# Inițializăm modulele de securitate globale
init_session_mgmt(app)
register_error_handlers(app)
init_csrf(app)
init_rate_limiting(app)

from security.audit_logging import log_security_event
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from data.user_repo import UserRepo

def get_serializer():
    return URLSafeTimedSerializer(app.secret_key)

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
    
    # 2. Audit Logging
    log_security_event(user_id, "REGISTER", "User", user_id, request.remote_addr)
    
    return jsonify({"message": "Înregistrare reușită. Te poți autentifica."}), 201

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
    
    # 2. Session Fixation Prevention (Cea mai importantă mutare!)
    # Distrugem absolut orice Cookie anterior pentru a nu permite unui atacator 
    # să ne seteze un ID știut de el (Fixation Attack).
    session.clear()
    
    # 3. Preluăm datele curate în sesiune
    session['user_id'] = user['id']
    session['role'] = user['role']
    
    # 4. Activăm sesiunea permanentă ("Capcana 1")
    # Asta face ca PERMANENT_SESSION_LIFETIME să funcționeze pe bune!
    session.permanent = True
    
    # 5. Audit Logging
    log_security_event(user['id'], "LOGIN_SUCCESS", "System", user['id'], request.remote_addr)
    
    return jsonify({"message": "Autentificare reușită.", "role": user['role']})

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    user_id = session.get('user_id')
    
    # 1. Audit Logging
    log_security_event(user_id, "LOGOUT", "System", user_id, request.remote_addr)
    
    # 2. Invalidare Sesiune la Logout (Best Practice)
    session.clear()
    
    return jsonify({"message": "Sesiune încheiată complet."})
@app.route('/forgot', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def forgot_password():
    if request.method == 'GET':
        return render_template('forgot.html')
        
    email = request.form.get('email') or request.json.get('email')
    user = UserRepo.get_user_by_email(email)
    
    if user:
        s = get_serializer()
        token = s.dumps(user['id'], salt='password-reset-salt')
        log_security_event(user['id'], "UPDATE", "User", user['id'], request.remote_addr)
        
        reset_link = f"/reset/{token}"
        return jsonify({"message": "Dacă email-ul există, s-a trimis un link.", "mock_link": reset_link})
        
    # Prevenim Email Enumeration returnând mereu același mesaj
    return jsonify({"message": "Dacă email-ul există, s-a trimis un link."})

@app.route('/reset/<token>', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def reset_password(token):
    s = get_serializer()
    try:
        # Expiră în 15 minute (900 secunde)
        user_id = s.loads(token, salt='password-reset-salt', max_age=900)
    except SignatureExpired:
        return jsonify({"error": "Token expirat."}), 400
    except BadSignature:
        return jsonify({"error": "Token invalid."}), 400

    if request.method == 'GET':
        return render_template('reset.html', token=token)
        
    data = request.form if request.form else request.json
    new_password = data.get('password')
    
    AuthService.update_password(user_id, new_password)
    
    # IMPORTANT: Invalidăm complet orice sesiune activă a acestui browser
    session.clear()
    
    log_security_event(user_id, "UPDATE", "User", user_id, request.remote_addr)
    
    return jsonify({"message": "Parolă resetată. Te poți autentifica."})

@app.route('/ticket', methods=['GET', 'POST'])
@login_required
@limiter.limit("30 per minute")
def ticket_management():
    if request.method == 'GET':
        tickets = TicketService.get_user_tickets(session['user_id'], session['role'])
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
    logs = AuditService.view_audit_logs(session['role'])
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