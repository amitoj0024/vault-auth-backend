# Description: Token generation and HMAC-SHA256 verification utilities.

from dotenv import load_dotenv
import hashlib
import hmac
import os
import re
import secrets
import time
from pathlib import Path

load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")
load_dotenv()

_TOKEN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{4,128}$")


def _get_token_secret():
    return os.getenv("TOKEN_SECRET") or os.getenv("SECRET_KEY") or "default-secret-token"


def _sign_payload(payload_str):
    secret = _get_token_secret()
    return hmac.new(
        secret.encode("utf-8"),
        payload_str.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def generate_token(data, uid=None):
    """Generate a 32-char hex token identifier via keyed HMAC-SHA256 and nonce."""
    c_date = time.strftime("%Y-%m-%d")
    if isinstance(data, dict):
        username = data.get("username") or data.get("user") or ""
        user_uid = data.get("uid") if data.get("uid") is not None else data.get("id", "")
    else:
        username = str(data)
        user_uid = uid if uid is not None else ""

    nonce = secrets.token_hex(8)
    digest = _sign_payload(f"{username}:{user_uid}:{c_date}:{nonce}")[:32]
    return digest, c_date


def session_token(token_id, expiration_seconds=None):
    """Create a cryptographically signed session token: <id>.<exp>.<hmac_sig>."""
    if isinstance(token_id, (tuple, list)):
        token_id = token_id[0]
    raw_id = str(token_id).strip()
    if expiration_seconds is None:
        expiration_seconds = int(os.getenv("TOKEN_EXPIRATION", "3600") or 3600)
    expiration = int(time.time()) + int(expiration_seconds)
    payload = f"{raw_id}.{expiration}"
    signature = _sign_payload(payload)
    return f"{payload}.{signature}"


def verify_token(token):
    """Verify session token structure, expiration, and HMAC-SHA256 signature."""
    try:
        if not token or not isinstance(token, str):
            return False
        parts = token.strip().split(".")
        if len(parts) != 3:
            return False
        token_id, expiration, signature = parts[0].strip(), parts[1].strip(), parts[2].strip()
        if not token_id or not _TOKEN_ID_RE.match(token_id):
            return False
        if not expiration.isdigit():
            return False
        if int(expiration) < int(time.time()):
            return False
        if not signature or len(signature) != 64:
            return False
        expected_sig = _sign_payload(f"{token_id}.{expiration}")
        return hmac.compare_digest(expected_sig, signature)
    except (ValueError, TypeError, AttributeError):
        return False
