import os
from flask import Flask


def init_security_headers(app: Flask) -> None:
    """
    Security Control: HTTP Security Headers.
    Applied to every response via an after_request hook.

    Headers added:
    - X-Content-Type-Options   : blocks MIME-type sniffing
    - X-Frame-Options          : prevents clickjacking (also covered by CSP frame-ancestors)
    - Referrer-Policy          : limits referrer leakage
    - Content-Security-Policy  : restricts resource origins & inline execution
    - Strict-Transport-Security: forces HTTPS (production only — skipped when DEBUG=true)
    - Permissions-Policy       : disables browser features this app doesn't use
    """
    # Read once at hook-registration time, not per-request.
    debug = os.getenv("DEBUG", "false").lower() == "true"

    @app.after_request
    def add_security_headers(response):
        # Prevents the browser from guessing the content type from the response body.
        # Mitigates content-type confusion attacks.
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Belt-and-suspenders clickjacking protection alongside CSP frame-ancestors.
        response.headers["X-Frame-Options"] = "DENY"

        # Send the full origin only on same-origin requests; send nothing cross-origin.
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Content Security Policy — tight policy for a server-rendered app with no CDN.
        # 'unsafe-inline' for style-src only: needed for the inline style="display:inline"
        # attribute on the logout form in base.html. Script-src has no unsafe-inline.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "form-action 'self'; "        # forms may only POST to this origin
            "frame-ancestors 'none'; "    # no embedding in iframes anywhere
            "base-uri 'self'; "           # prevents <base> tag hijacking
            "object-src 'none';"          # blocks Flash/plugin embeds
        )

        # HSTS tells browsers to connect only over HTTPS for the next year.
        # Intentionally skipped in development (DEBUG=true) because the dev server
        # runs on plain HTTP — setting HSTS there would break the browser for a year.
        if not debug:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        # Opt out of browser features this application has no reason to use.
        response.headers["Permissions-Policy"] = (
            "geolocation=(), camera=(), microphone=(), payment=()"
        )

        return response
