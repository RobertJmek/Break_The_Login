import os
import psycopg2
from psycopg2 import OperationalError
from dotenv import load_dotenv

load_dotenv()

def get_db_connection():
    """Creează și returnează o conexiune sigură la baza de date PostgreSQL."""
    
    # 1. Aplicația face "Fail-Fast": Validarea prezenței variabilelor critice
    required_vars = ["POSTGRES_HOST", "POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD"]
    for var in required_vars:
        if not os.getenv(var):
            raise ValueError(f"CRITICAL ERROR: Baza de date nu poate porni. Lipsește variabila {var}!")

    try:
        # 2. Conexiune criptată SSL/TLS
        conn = psycopg2.connect(
            host=os.getenv("POSTGRES_HOST"),
            port=os.getenv("POSTGRES_PORT", "5432"),
            database=os.getenv("POSTGRES_DB"),
            user=os.getenv("POSTGRES_USER"),
            password=os.getenv("POSTGRES_PASSWORD"),
            sslmode=os.getenv("POSTGRES_SSLMODE", "require") # Forțăm SSL conform directivelor
        )
        return conn
    except OperationalError:
        # 3. Tratarea erorilor (Information Disclosure): 
        # Prindem eroarea originală care poate conține adrese IP sau parole
        # și ridicăm o eroare generică
        raise ConnectionError("Baza de date este indisponibilă.")
