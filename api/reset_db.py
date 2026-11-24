"""Database schema and initialization for Password Reset workflow."""

from api.db import execute_query
from api.utils import safe_print


def create_password_reset_table():
    """Create the password_resets table integrated with existing users(uid)."""
    password_resets_table = """
    CREATE TABLE IF NOT EXISTS password_resets (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL,
        otp_hash VARCHAR(128) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        attempts INT NOT NULL DEFAULT 0,
        reset_token_hash VARCHAR(128),
        token_expires_at TIMESTAMP,
        is_used BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        CONSTRAINT fk_password_resets_user FOREIGN KEY (user_id) REFERENCES users(uid) ON DELETE CASCADE
    );
    """
    try:
        execute_query(password_resets_table)
        execute_query(
            "CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id, is_used);"
        )
        execute_query(
            "CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(reset_token_hash);"
        )
        execute_query(
            "CREATE INDEX IF NOT EXISTS idx_password_resets_exp ON password_resets(expires_at);"
        )
        return True
    except Exception as e:
        safe_print(f"Error creating password_resets table: {e}")
        return False


def init_reset_db():
    """Verify and initialize password reset table."""
    try:
        return create_password_reset_table()
    except Exception as e:
        safe_print(f"Password reset DB init error: {e}")
        return False
