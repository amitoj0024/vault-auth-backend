"""Security utilities: rate limiting, input validation, security headers, logging."""

import re
import time
import logging
import hashlib
import secrets
from collections import defaultdict
from functools import wraps
from flask import request, jsonify, g
from api.utils import safe_print

# ─── Security Logger ───────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SECURITY] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)
security_logger = logging.getLogger("vault_auth_security")

def log_security_event(event_type, uid=None, ip=None, details=None):
    """Log a security-relevant event. Never logs passwords, OTPs, or tokens."""
    ip = ip or (request.remote_addr if request else "unknown")
    # Scrub any accidental secrets
    safe_details = str(details or "")
    for pattern in [r'password["\s:=]+\S+', r'otp["\s:=]+\d+', r'token["\s:=]+\S{20,}']:
        safe_details = re.sub(pattern, "[REDACTED]", safe_details, flags=re.IGNORECASE)
    security_logger.info(f"event={event_type} uid={uid} ip={ip} {safe_details}")


# ─── In-Memory Rate Limiter ────────────────────────────────────────────────────
# Structure: {key: [(timestamp, count), ...]}
_rate_buckets = defaultdict(list)

def _get_client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"

def rate_limit(max_requests=5, window_seconds=60, key_prefix="rl"):
    """Decorator: allow at most max_requests per window_seconds per client IP."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            ip = _get_client_ip()
            bucket_key = f"{key_prefix}:{ip}"
            now = time.time()
            cutoff = now - window_seconds
            # Prune old entries
            _rate_buckets[bucket_key] = [t for t in _rate_buckets[bucket_key] if t > cutoff]
            if len(_rate_buckets[bucket_key]) >= max_requests:
                retry_after = int(window_seconds - (now - _rate_buckets[bucket_key][0]))
                log_security_event("RATE_LIMITED", ip=ip, details=f"endpoint={request.path}")
                return jsonify({
                    "success": False,
                    "message": f"Too many requests. Please wait {retry_after} seconds.",
                    "retry_after": max(1, retry_after)
                }), 429
            _rate_buckets[bucket_key].append(now)
            return f(*args, **kwargs)
        return decorated
    return decorator


# ─── Input Sanitization ────────────────────────────────────────────────────────
_DANGEROUS_PATTERNS = re.compile(
    r"(<script|</script|javascript:|on\w+=|<iframe|<object|<embed|'|\"|;|--|/\*|\*/)",
    re.IGNORECASE
)

def sanitize_string(value, max_length=255):
    """Strip dangerous characters and enforce max length. Returns cleaned string or raises ValueError."""
    if value is None:
        return None
    value = str(value).strip()
    if len(value) > max_length:
        raise ValueError(f"Input exceeds maximum length of {max_length} characters")
    if _DANGEROUS_PATTERNS.search(value):
        raise ValueError("Input contains disallowed characters")
    return value

def validate_email(email):
    """Basic RFC 5321-compliant email validation."""
    if not email or not isinstance(email, str):
        raise ValueError("Email is required")
    email = email.strip().lower()
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        raise ValueError("Invalid email format")
    if len(email) > 254:
        raise ValueError("Email address too long")
    return email

def validate_username(username):
    """Username: 3-50 chars, alphanumeric + underscores/hyphens only."""
    if not username or not isinstance(username, str):
        raise ValueError("Username is required")
    username = username.strip()
    if len(username) < 3:
        raise ValueError("Username must be at least 3 characters")
    if len(username) > 50:
        raise ValueError("Username must not exceed 50 characters")
    if not re.match(r'^[a-zA-Z0-9_\-]+$', username):
        raise ValueError("Username may only contain letters, numbers, underscores, and hyphens")
    return username


# ─── Password Strength Validator ──────────────────────────────────────────────
def validate_password_strength(password):
    """
    Enforce strong password policy.
    Returns (is_valid: bool, strength: str, errors: list[str])
    Policy:
      - Minimum 8 characters
      - At least one uppercase letter
      - At least one lowercase letter
      - At least one digit
      - At least one special character
    """
    if not password or not isinstance(password, str):
        return False, "Weak", ["Password is required"]
    errors = []
    if len(password) < 8:
        errors.append("Password must be at least 8 characters")
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one digit")
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        errors.append("Password must contain at least one special character")
    if errors:
        return False, "Weak", errors
    # Strength grading
    score = 0
    if len(password) >= 12:
        score += 1
    if len(password) >= 16:
        score += 1
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?].*[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        score += 1
    strength = "Strong" if score >= 2 else ("Medium" if score == 1 else "Weak")
    return True, strength, []


# ─── Security Headers ──────────────────────────────────────────────────────────
def add_security_headers(response):
    """Add security headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    # Remove server fingerprinting
    response.headers.pop("Server", None)
    return response
