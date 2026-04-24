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

load_dotenv()

# Nivelul Backend API

app = Flask(__name__)

# Security Controls: Session Mgmt

secret_key = os.getenv("FLASK_SECRET_KEY")
if not secret_key:
    raise ValueError("CRITICAL: FLASK_SECRET_KEY is missing from environment variables!")
app.secret_key = secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True, # Ar trebui activat in productie (HTTPS)
    SESSION_COOKIE_SAMESITE='Lax',
)

@app.route('/', methods=['GET'])
def main_page():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Afișează formularul (GET) și procesează înregistrarea (POST)
    pass

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Afișează formularul (GET) și procesează autentificarea (POST)
    pass

@app.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    # Generează și afișează token de resetare
    pass

@app.route('/reset', methods=['GET', 'POST'])
def reset_password():
    # Preia token din URL (GET) și actualizează parola (POST)
    pass

@app.route('/ticket', methods=['GET', 'POST'])
@login_required
def create_ticket():
    # Afișează formularul (GET) și inserează tichet nou (POST)
    pass

@app.route('/ticket/<int:ticket_id>', methods=['GET'])
@login_required
def view_ticket(ticket_id):
    # Returnează detaliile unui tichet
    pass

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    # Șterge cookie-ul de autentificare
    session.clear()
    return jsonify({"message": "Logged out"}), 200

@app.route('/audit', methods=['GET'])
@login_required
@manager_required
def audit_logs():
    # Funcționalitate specifică managerului pentru audit_logs
    pass

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)