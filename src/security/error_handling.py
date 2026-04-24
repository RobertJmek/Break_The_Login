from flask import jsonify

def register_error_handlers(app):
    """Security Control: Error Handling (no stack traces to client)."""
    
    @app.errorhandler(500)
    def internal_error(error):
        # Log error to server console, return generic message
        return jsonify({"error": "A aparut o eroare interna pe server. Contactati suportul."}), 500

    @app.errorhandler(404)
    def not_found_error(error):
        return jsonify({"error": "Resursa nu a fost gasita."}), 404
