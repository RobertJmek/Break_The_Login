import os
# AM ADĂUGAT render_template la importuri
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv
from database import get_db_connection

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "cheie_de_rezerva_nesigura")

@app.route('/', methods=['GET'])
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
        
        # Deocamdată doar returnăm un mesaj ca să confirmăm că a mers
        return jsonify({
            "message": "Formular interceptat cu succes!",
            "email_primit": email,
            "parola_primita": password
        })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)