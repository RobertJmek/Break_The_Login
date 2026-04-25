import os
from psycopg2 import OperationalError
from psycopg2.pool import ThreadedConnectionPool
from dotenv import load_dotenv

load_dotenv()

# Definim pool-ul global
_pool = None

class PooledConnectionWrapper:
    """Un wrapper care interceptează '.close()' pentru a returna conexiunea în pool."""
    def __init__(self, pool, conn):
        self._pool = pool
        self._conn = conn

    def close(self):
        self._pool.putconn(self._conn)

    def __getattr__(self, item):
        return getattr(self._conn, item)

    def __enter__(self):
        return self._conn.__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._conn.__exit__(exc_type, exc_val, exc_tb)


def get_db_connection():
    """Obține o conexiune din ThreadedConnectionPool."""
    global _pool

    if _pool is None:
        required_vars = ["POSTGRES_HOST", "POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD"]
        for var in required_vars:
            if not os.getenv(var):
                raise ValueError(f"CRITICAL ERROR: Baza de date nu poate porni. Lipsește variabila {var}!")
        
        try:
            _pool = ThreadedConnectionPool(
                minconn=1,
                maxconn=20,
                host=os.getenv("POSTGRES_HOST"),
                port=os.getenv("POSTGRES_PORT", "5432"),
                database=os.getenv("POSTGRES_DB"),
                user=os.getenv("POSTGRES_USER"),
                password=os.getenv("POSTGRES_PASSWORD"),
                sslmode=os.getenv("POSTGRES_SSLMODE", "require")
            )
        except OperationalError:
            raise ConnectionError("Baza de date este indisponibilă.")

    # Returnăm conexiunea învelită, astfel încât "closing()" din codul tău să o pună la loc
    conn = _pool.getconn()
    return PooledConnectionWrapper(_pool, conn)
