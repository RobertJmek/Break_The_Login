import logging
import traceback
from flask import jsonify, request
from werkzeug.exceptions import HTTPException
from security.exceptions import AppValidationError

def register_error_handlers(app):
    """Security Control: Error Handling (no stack traces to client)."""
    
    # 1. Prinde erorile noastre custom de validare (100% sigur de trimis catre client)
    @app.errorhandler(AppValidationError)
    def handle_value_error(error):
        return jsonify(error.to_dict()), error.status_code

    # 2. Prinde erorile HTTP Standard generate de Flask (ex: 405 Method Not Allowed, 404 Not Found)
    @app.errorhandler(HTTPException)
    def handle_http_exception(error):
        return jsonify({"error": error.description}), error.code

    # 3. Prinde orice altă excepție și adaugă CONTEXT complet la logare
    @app.errorhandler(Exception)
    def internal_error(error):
        # Logăm tehnic pe server cu context (Metoda și URL-ul unde a crăpat)
        logging.error(f"Eroare tehnică neașteptată la {request.method} {request.url}: {str(error)}")
        logging.error(traceback.format_exc())
        
        # Returnăm mereu un mesaj generic clientului
        return jsonify({"error": "A apărut o eroare internă pe server. Contactați suportul."}), 500
