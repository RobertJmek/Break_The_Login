import os
import hashlib
import base64
from flask import Flask, request, jsonify, render_template, make_response
from dotenv import load_dotenv
from database import get_db_connection

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "cheie_de_rezerva_nesigura")

@app.route('/', methods=['GET']) # Information Exposure vulnerability
def health_check():
    try:
        conn = get_db_connection()
        conn.close()
        db_status = "Conexiunea cu baza de date a reușit!"
    except Exception as e:
        db_status = f"Eroare la conectarea DB: {str(e)}"
        
    return jsonify({
        "status": "Deskly API v1 (Vulnerable) este online!",
        "database_status": db_status
    }), 200

    # FUNCȚIE AJUTĂTOARE PENTRU AUDIT
def log_event(action, user_id=None, resource=None, resource_id=None):
    # Dacă nu avem user_id (ex: utilizator neautentificat), punem NULL în SQL
    db_user_id = user_id if user_id else "NULL"
    db_resource = f"'{resource}'" if resource else "NULL"
    db_resource_id = resource_id if resource_id else "NULL"
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # VULNERABILITATE: Inserăm direct acțiunea în DB, fără nicio validare
        cursor.execute(f"INSERT INTO audit_logs (action, user_id, resource, resource_id) VALUES ('{action}', {db_user_id}, {db_resource}, {db_resource_id})")
        conn.commit()
    except Exception as e:
        print(f"Eroare la salvarea logului: {e}")
    finally:
        if 'cursor' in locals() and cursor: cursor.close()
        if 'conn' in locals() and conn: conn.close()

# RUTA NOUĂ PENTRU ÎNREGISTRARE
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Dacă utilizatorul doar accesează pagina (GET), îi arătăm formularul HTML
    if request.method == 'GET':
        return render_template('register.html')
    
    # Dacă a apăsat butonul de submit (POST), preluăm datele
    if request.method == 'POST':
        # În formularele HTML clasice, datele vin prin request.form, nu prin request.json
        email = request.form.get('email')
        password = request.form.get('password')
        
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        conn = get_db_connection()
        cursor = conn.cursor()
        query = f"INSERT INTO users (email, password_hash) VALUES ('{email}', '{hashed_password}') RETURNING id"
        cursor.execute(query)
        new_user = cursor.fetchone()
        if new_user:
            log_event('CREATE', user_id=new_user[0], resource='USER', resource_id=new_user[0])

        conn.commit()
        conn.close()
        return jsonify({"message": "Utilizator inregistrat cu succes!"}) # fara validare in backend -> SQL Injection vulnerability

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'GET':
        return render_template('login.html')

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        conn = get_db_connection()
        cursor = conn.cursor()
        # ETAPA 1: Verificăm DOAR dacă există emailul (User Enumeration)
        cursor.execute(f"SELECT * FROM users WHERE email='{email}'")
        user_exists = cursor.fetchone()
        
        if not user_exists:
            conn.close()
            # Vulnerabilitate: Îi confirmăm hackerului că acest email NU e în baza de date
            return jsonify({"message": "Acest email nu există în sistem!"}), 404
            
        # ETAPA 2: Dacă emailul există, verificăm parola
        query = f"SELECT * FROM users WHERE email='{email}' AND password_hash='{hashed_password}'"
        cursor.execute(query)
        valid_login = cursor.fetchone()
        conn.close()
        
        if valid_login:
            user_id = valid_login[0]
            log_event('LOGIN', user_id=user_id, resource='USER', resource_id=user_id)
            # Creăm răspunsul pe care îl vom trimite browserului
            raspuns = make_response(jsonify({"message": "Login successful!"}))
            
            # VULNERABILITĂȚI INTENȚIONATE (Session Management):
            # Creăm un token fals și nesigur (doar email-ul în clar)
            token_nesigur = f"user_token_{email}"
            
            # Setăm cookie-ul cu toate steagurile de securitate oprite
            raspuns.set_cookie(
                'auth_cookie',                  # Numele cookie-ului
                value=token_nesigur,            # Valoarea (care e doar text în clar, altă vulnerabilitate)
                max_age=60 * 60 * 24 * 365, # Expirare prea lungă: 1 an
                httponly=False,                 # Fără HttpOnly (Vulnerabil la XSS)
                secure=False,                   # Fără Secure (Vulnerabil pe rețele nesecurizate)
                samesite=None                   # Fără SameSite (Vulnerabil la CSRF)
            )
            
            return raspuns, 200
            
        # Vulnerabilitate: confirmam ca emailul este bun, dar parola este gresita
        return jsonify({"message": "Parolă incorectă pentru acest utilizator!"}), 401

        # RUTA PENTRU CERERE RESETARE PAROLĂ
@app.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        return render_template('forgot.html')
        
    if request.method == 'POST':
        email = request.form.get('email')
        
        # VULNERABILITATE: Token predictibil (Base64), fără expirare!
        # Transformăm email-ul în bytes, îl codăm base64, apoi îl facem înapoi text

        token = base64.b64encode(email.encode()).decode()
        
        # În realitate am trimite un email. Aici, aruncăm link-ul direct pe ecran (Information Disclosure)

        link_resetare = f"http://localhost:5000/reset?token={token}"
        
        return jsonify({
            "message": "Dacă emailul există, vei primi un link de resetare.", 
            "link_resetare_primit_pe_email": link_resetare
        }), 200

# RUTA PENTRU RESETAREA EFECTIVĂ A PAROLEI

@app.route('/reset', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'GET':
        # Luăm token-ul din URL ca să-l punem invizibil în formular
        token_din_url = request.args.get('token')
        return render_template('reset.html', token=token_din_url)
        
    if request.method == 'POST':
        token = request.form.get('token')
        new_password = request.form.get('new_password')
        
        try:
            # VULNERABILITATE: Resetare fără control. Pur și simplu decodăm token-ul ca să aflăm cine e
            email_decodat = base64.b64decode(token).decode()
        except:
            return jsonify({"error": "Token invalid!"}), 400
            
        hashed_password = hashlib.md5(new_password.encode()).hexdigest()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # VULNERABILITATE: Token reutilizabil. Îl folosim ca să schimbăm parola, dar nu-l anulăm nicăieri!

        cursor.execute(f"UPDATE users SET password_hash='{hashed_password}' WHERE email='{email_decodat}' RETURNING id")
        updated_user = cursor.fetchone()
        if updated_user:
            log_event('UPDATE', user_id=updated_user[0], resource='USER', resource_id=updated_user[0])
        conn.commit()
        conn.close()
        
        return jsonify({"message": f"Parola pentru {email_decodat} a fost schimbată cu succes!"})

# RUTA PENTRU CREAREA UNUI TICHET
@app.route('/ticket', methods=['GET', 'POST'])
def create_ticket():
    if request.method == 'GET':
        return render_template('ticket.html')

    if request.method == 'POST':
        auth_cookie = request.cookies.get('auth_cookie')
        if not auth_cookie:
            return jsonify({"error": "Nu ești autentificat!"}), 401
            
        email_presupus = auth_cookie.replace("user_token_", "")
        
        # Preluăm datele trimise de utilizator
        # VULNERABILITATE: Nu validăm inputul (XSS)

        titlu = request.form.get('title', 'Tichet Fara Titlu')
        descriere = request.form.get('description', 'Fara descriere')
        priority = request.form.get('priority', 'MEDIUM')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Găsim ID-ul utilizatorului pe baza email-ului din cookie

        cursor.execute(f"SELECT id FROM users WHERE email='{email_presupus}'")
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({"error": "Utilizator invalid!"}), 404
            
        user_id = user[0]
        
        # Inserăm tichetul în baza de date

        cursor.execute(f"INSERT INTO tickets (title, description, priority, owner_id) VALUES ('{titlu}', '{descriere}', '{priority}', {user_id}) RETURNING id")
        new_ticket_id = cursor.fetchone()[0]
        
        log_event('CREATE', user_id=user_id, resource='TICKET', resource_id=new_ticket_id)
        
        conn.commit()
        conn.close()
        
        return jsonify({"message": "Tichet creat cu succes!", "ticket_id": new_ticket_id}), 201


# RUTA PENTRU VIZUALIZAREA UNUI TICHET (Vulnerabilă la IDOR și Falsificare Identitate)
@app.route('/ticket/<int:ticket_id>', methods=['GET'])
def view_ticket(ticket_id):
    

    auth_cookie = request.cookies.get('auth_cookie')
    if not auth_cookie:
        return jsonify({"error": "Nu ești autentificat! Lipsește cookie-ul."}), 401

    # VULNERABILITATE (Identitate): Ne încredem orbește în cookie
    email_presupus = auth_cookie.replace("user_token_", "")

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Extragem tichetul din baza de date
    cursor.execute(f"SELECT id, title, description, status, owner_id FROM tickets WHERE id = {ticket_id}")
    ticket = cursor.fetchone()
    conn.close()

    if not ticket:
        return jsonify({"error": "Tichetul nu există!"}), 404

    # VULNERABILITATE MAJORĂ (Autorizare / IDOR):
    # Avem tichetul, știm cine este utilizatorul, dar NU verificăm dacă tichetul îi aparține!
    # Codul sigur ar fi fost: if ticket[4] != user_id: return "Interzis", 403
    
    return jsonify({
        "vizitator_curent": email_presupus,
        "date_tichet": {
            "id": ticket[0],
            "titlu": ticket[1],
            "descriere": ticket[2],
            "status": ticket[3]
        }
    }), 200

# RUTA DE LOGOUT (Vulnerabilă la Session Hijacking)

@app.route('/logout', methods=['GET'])
def logout():
    auth_cookie = request.cookies.get('auth_cookie')
    user_id = None
    if auth_cookie:
        email_presupus = auth_cookie.replace("user_token_", "")
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(f"SELECT id FROM users WHERE email='{email_presupus}'")
        user = cursor.fetchone()
        if user:
            user_id = user[0]
        conn.close()

    log_event('LOGOUT', user_id=user_id, resource='USER', resource_id=user_id)
    
    # VULNERABILITATE: Ștergem cookie-ul doar din browser (vizual), dar NU pe server!
    raspuns = make_response(jsonify({"message": "Te-ai delogat cu succes"}))
    raspuns.set_cookie('auth_cookie', '', expires=0)
    return raspuns


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000) 