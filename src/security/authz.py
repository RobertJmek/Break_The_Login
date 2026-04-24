from functools import wraps
from flask import session, jsonify

# Nivelul Security Controls: AuthZ (RBAC + Ownership)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function

def manager_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'MANAGER':
            return jsonify({"error": "Forbidden: Managers only"}), 403
        return f(*args, **kwargs)
    return decorated_function
