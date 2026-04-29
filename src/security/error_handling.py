import logging
import traceback
from flask import flash, redirect, request, url_for
from flask_wtf.csrf import CSRFError
from werkzeug.exceptions import HTTPException
from security.exceptions import AppValidationError


def register_error_handlers(app):
    """Security Control: Error Handling — no stack traces, no raw JSON to browser clients."""

    @app.errorhandler(AppValidationError)
    def handle_validation_error(error):
        """Erori de validare custom (email invalid, parolă slabă, etc.)"""
        flash(error.message, "error")
        # Redirect back to the page the user came from, fall back to home.
        return redirect(request.referrer or url_for('main_page'))

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        """Token CSRF lipsă sau invalid — sesiunea poate fi expirată."""
        flash("Cerere invalidă sau sesiunea a expirat. Reîncercați.", "error")
        return redirect(request.referrer or url_for('main_page'))

    @app.errorhandler(HTTPException)
    def handle_http_exception(error):
        """Erori HTTP standard (401, 403, 404, 405, etc.)"""
        if error.code == 401:
            flash("Trebuie să fii autentificat pentru a accesa această pagină.", "error")
            return redirect(url_for('login'))
        if error.code == 403:
            flash("Acces interzis. Nu ai permisiunea necesară.", "error")
            return redirect(url_for('main_page'))
        if error.code == 404:
            flash("Pagina sau resursa căutată nu a fost găsită.", "error")
            return redirect(url_for('main_page'))
        # Any other HTTP error (405, 429, etc.)
        flash(f"Eroare: {error.description}", "error")
        return redirect(url_for('main_page'))

    @app.errorhandler(Exception)
    def internal_error(error):
        """Excepții neașteptate — logăm detalii pe server, mesaj generic către client."""
        logging.error(f"Eroare tehnică neașteptată la {request.method} {request.url}: {str(error)}")
        logging.error(traceback.format_exc())
        flash("A apărut o eroare internă pe server. Contactați suportul.", "error")
        return redirect(url_for('main_page'))
