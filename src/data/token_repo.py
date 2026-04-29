import hmac
import hashlib
import os
import secrets
from datetime import datetime, timezone, timedelta
from contextlib import closing
from data.database import get_db_connection


# Single source of truth for token lifetime.
# Used by both store_token (expires_at) and implicitly enforced by the DB
# in consume_token (expires_at > NOW()).
TOKEN_LIFETIME_SECONDS = 900  # 15 minutes


def _get_hmac_key() -> bytes:
    """
    Load the HMAC key used to sign stored token hashes.
    A dedicated key (TOKEN_HMAC_KEY) is preferred over reusing FLASK_SECRET_KEY
    so that rotating one doesn't invalidate the other.
    """
    key = os.getenv("TOKEN_HMAC_KEY")
    if not key:
        raise ValueError("CRITICAL: TOKEN_HMAC_KEY is missing from environment variables!")
    return key.encode("utf-8")


def _hash_token(raw_token: str) -> str:
    """
    HMAC-SHA256 of the raw token, keyed on TOKEN_HMAC_KEY.

    Why HMAC instead of plain SHA-256?
    - With plain SHA-256, a full DB dump is enough to attempt offline brute-force.
    - HMAC requires the secret key in addition to the hash, so the DB contents are
      useless to an attacker who doesn't also have TOKEN_HMAC_KEY.
    """
    return hmac.new(_get_hmac_key(), raw_token.encode("utf-8"), hashlib.sha256).hexdigest()


class TokenRepo:
    """
    Data Layer: manages the password_reset_tokens table.
    Owns the full token lifecycle: generate → store → consume.
    """

    @staticmethod
    def generate_token() -> str:
        """
        Generate a cryptographically secure random opaque token (256-bit entropy).
        URL-safe so it can be embedded in a reset link directly.
        """
        return secrets.token_urlsafe(32)

    @staticmethod
    def store_token(user_id: int, raw_token: str) -> None:
        """
        Persist an HMAC of the token for the given user.
        Any previously unused tokens for this user are invalidated first
        (one active reset request at a time — prevents token stockpiling).
        """
        token_hash = _hash_token(raw_token)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=TOKEN_LIFETIME_SECONDS)

        with closing(get_db_connection()) as conn:
            with conn:  # auto commit/rollback
                with conn.cursor() as cursor:
                    # Invalidate any existing unused tokens for this user before inserting.
                    cursor.execute(
                        "UPDATE password_reset_tokens SET used = TRUE WHERE user_id = %s AND used = FALSE;",
                        (user_id,)
                    )
                    cursor.execute(
                        """
                        INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
                        VALUES (%s, %s, %s);
                        """,
                        (user_id, token_hash, expires_at)
                    )

    @staticmethod
    def consume_token(raw_token: str) -> int | None:
        """
        Atomically verify and consume a token in a single UPDATE statement.

        Returns the user_id if the token is valid and successfully consumed.
        Returns None if the token was not found, already used, or expired.

        Using a single atomic UPDATE prevents TOCTOU race conditions that
        a SELECT-then-UPDATE pattern would introduce.
        """
        token_hash = _hash_token(raw_token)

        with closing(get_db_connection()) as conn:
            with conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """
                        UPDATE password_reset_tokens
                        SET used = TRUE, used_at = NOW()
                        WHERE token_hash = %s
                          AND used = FALSE
                          AND expires_at > NOW()
                        RETURNING user_id;
                        """,
                        (token_hash,)
                    )
                    result = cursor.fetchone()

        return result[0] if result else None
