import os
import psycopg2
from dotenv import load_dotenv

# Încărcăm variabilele aici, ca baza de date să le aibă gata pregătite
load_dotenv()

def get_db_connection():
    """Creează și returnează o conexiune la baza de date PostgreSQL."""
    conn = psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "db"),
        port=os.getenv("POSTGRES_PORT", "5432"),
        database=os.getenv("POSTGRES_DB"),
        user=os.getenv("POSTGRES_USER"),
        password=os.getenv("POSTGRES_PASSWORD")
    )
    return conn