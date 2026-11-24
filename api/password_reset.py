"""Secure Forgot Password & Reset Password service layer."""

from datetime import datetime, timedelta
import hashlib
import hmac
import os
import secrets

from werkzeug.security import generate_password_hash
from flask import has_app_context, current_app

from api.admin import get_runtime_security_settings, record_audit_log
from api.db import db_transaction
from api.mailer import send_password_reset_email
from api.security import log_security_event, validate_email, validate_reset_password
from api.utils import safe_print

OTP_EXPIRY_SECONDS = 300        # 5 minutes
RESET_TOKEN_EXPIRY_SECONDS = 600  # 10 minutes
MAX_OTP_ATTEMPTS = 5
RESEND_COOLDOWN_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 5
RATE_LIMIT_WINDOW_MINUTES = 15


def _get_reset_limits():
    if has_app_context() and current_app.config.get("TESTING"):
        return OTP_EXPIRY_SECONDS, MAX_OTP_ATTEMPTS, 8
    cfg = get_runtime_security_settings()
    return (
        cfg.get("otp_expiry_seconds", OTP_EXPIRY_SECONDS),
        cfg.get("max_failed_attempts", MAX_OTP_ATTEMPTS),
        cfg.get("password_min_length", 8),
    )


def _get_hmac_secret():
    return (
        os.getenv("SECRET_KEY")
        or os.getenv("TOKEN_SECRET")
        or "vault-auth-dev-secret-key-change-in-production"
    )


def hash_reset_otp(user_id, otp_code):
    """Derive a keyed HMAC-SHA256 digest for a password reset OTP."""
    secret = _get_hmac_secret()
    msg = f"reset-otp:{int(user_id)}:{str(otp_code).strip()}"
    return hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()


def hash_reset_token(raw_token):
    """Derive a keyed HMAC-SHA256 digest for a password reset authorization token."""
    secret = _get_hmac_secret()
    msg = f"reset-token:{str(raw_token).strip()}"
    return hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()


def _cleanup_expired_records(cursor, now):
    """Purge stale expired/used password reset records inside the current transaction."""
    stale_otp_cutoff = now - timedelta(hours=1)
    stale_used_cutoff = now - timedelta(hours=24)
    cursor.execute(
        """
        DELETE FROM password_resets
        WHERE (expires_at < %s AND reset_token_hash IS NULL)
           OR (token_expires_at IS NOT NULL AND token_expires_at < %s)
           OR (is_used = TRUE AND created_at < %s)
        """,
        (stale_otp_cutoff, stale_otp_cutoff, stale_used_cutoff),
    )


def _find_user_by_email(cursor, clean_email):
    """Fetch minimal user record matching a lowercased email address."""
    cursor.execute(
        "SELECT uid, username, email, is_active FROM users WHERE LOWER(email) = %s LIMIT 1",
        (clean_email,),
    )
    return cursor.fetchone()


def _generic_forgot_response(cooldown=RESEND_COOLDOWN_SECONDS):
    return {
        "success": True,
        "message": "If an account with that email exists, a password reset verification code has been sent.",
        "expires_in": OTP_EXPIRY_SECONDS,
        "cooldown": cooldown,
    }


def request_password_reset(raw_email, client_ip="127.0.0.1", enforce_cooldown=False):
    """
    Generate and dispatch a password reset 6-digit OTP via SMTP/mailer.
    - Returns a generic enumeration-safe response on /forgot-password.
    - Enforces 60-second cooldown and per-user rate limit when enforce_cooldown=True (resend endpoint).
    Returns: (payload_dict, error_str, http_status)
    """
    try:
        clean_email = validate_email(raw_email)
    except ValueError as ve:
        return {"success": False, "message": str(ve)}, str(ve), 400

    now = datetime.now()
    otp_expiry_seconds, _, _ = _get_reset_limits()
    generated_otp = None
    target_user = None
    reset_record_id = None

    try:
        with db_transaction() as cursor:
            _cleanup_expired_records(cursor, now)
            user = _find_user_by_email(cursor, clean_email)

            if not user or user.get("is_active") is False:
                log_security_event(
                    "PASSWORD_RESET_REQUEST_IGNORED",
                    ip=client_ip,
                    details="reason=account_not_found_or_inactive",
                )
                return _generic_forgot_response(), None, 200

            user_id = user["uid"]
            target_user = user

            if enforce_cooldown:
                # Cooldown check: must wait 60s between OTP sends
                cursor.execute(
                    "SELECT created_at FROM password_resets WHERE user_id = %s ORDER BY id DESC LIMIT 1",
                    (user_id,),
                )
                last_row = cursor.fetchone()
                if last_row and last_row.get("created_at"):
                    last_created = last_row["created_at"]
                    if isinstance(last_created, str):
                        last_created = datetime.fromisoformat(last_created)
                    elapsed = (now - last_created).total_seconds()
                    if elapsed < RESEND_COOLDOWN_SECONDS:
                        remaining = max(1, int(RESEND_COOLDOWN_SECONDS - elapsed))
                        return (
                            {
                                "success": False,
                                "message": f"Please wait {remaining} seconds before requesting a new verification code.",
                                "retry_after": remaining,
                                "cooldown": remaining,
                            },
                            "Cooldown active",
                            429,
                        )

                # Rate-limit check per account in sliding 15-min window
                window_start = now - timedelta(minutes=RATE_LIMIT_WINDOW_MINUTES)
                cursor.execute(
                    "SELECT COUNT(*) AS cnt FROM password_resets WHERE user_id = %s AND created_at >= %s",
                    (user_id, window_start),
                )
                cnt_row = cursor.fetchone()
                recent_count = (cnt_row.get("cnt") if cnt_row else 0) or 0
                if recent_count >= RATE_LIMIT_MAX_REQUESTS:
                    return (
                        {
                            "success": False,
                            "message": "Too many password reset requests. Please try again in 15 minutes.",
                            "retry_after": RATE_LIMIT_WINDOW_MINUTES * 60,
                        },
                        "Rate limit exceeded",
                        429,
                    )

            # Invalidate any prior unused reset requests for this user
            cursor.execute(
                "UPDATE password_resets SET is_used = TRUE WHERE user_id = %s AND is_used = FALSE",
                (user_id,),
            )

            # Generate CSPRNG 6-digit OTP and store only HMAC-SHA256 hash
            generated_otp = f"{secrets.randbelow(900000) + 100000}"
            otp_hash = hash_reset_otp(user_id, generated_otp)
            expires_at = now + timedelta(seconds=otp_expiry_seconds)

            cursor.execute(
                """
                INSERT INTO password_resets (user_id, otp_hash, expires_at, attempts, is_used, created_at)
                VALUES (%s, %s, %s, 0, FALSE, %s)
                RETURNING id
                """,
                (user_id, otp_hash, expires_at, now),
            )
            inserted = cursor.fetchone()
            reset_record_id = inserted["id"] if inserted else None
    except Exception as e:
        safe_print(f"[Password Reset Request DB Error]: {e}")
        return {"success": False, "message": "Unable to process password reset request."}, str(e), 500

    # Send OTP email outside the DB transaction so DB lock isn't held during network I/O
    email_sent, email_err = send_password_reset_email(
        target_user["email"],
        generated_otp,
        username=target_user.get("username"),
    )

    if not email_sent:
        # Clean up undelivered reset record so invalid OTP cannot linger
        if reset_record_id is not None:
            try:
                with db_transaction() as cursor:
                    cursor.execute("DELETE FROM password_resets WHERE id = %s", (reset_record_id,))
            except Exception:
                pass
        log_security_event(
            "PASSWORD_RESET_EMAIL_FAILED",
            uid=target_user["uid"],
            ip=client_ip,
            details=f"reason={email_err}",
        )
        if enforce_cooldown:
            return (
                {"success": False, "message": f"Email delivery failed: {email_err}"},
                email_err,
                500,
            )
        # Preserve account-enumeration safety on /forgot-password
        return _generic_forgot_response(), None, 200

    log_security_event(
        "PASSWORD_RESET_OTP_SENT",
        uid=target_user["uid"],
        ip=client_ip,
        details="action=resend" if enforce_cooldown else "action=initial",
    )
    return _generic_forgot_response(), None, 200


def verify_reset_otp(raw_email, otp_code, client_ip="127.0.0.1"):
    """
    Verify a password reset OTP against stored HMAC hash.
    Enforces 5-minute expiry, 5-attempt lockout, and single-use conversion into
    a short-lived reset authorization token.
    Returns: (payload_dict, error_str, http_status)
    """
    try:
        clean_email = validate_email(raw_email)
    except ValueError:
        return {"success": False, "message": "Valid email and verification code are required."}, "Invalid email", 400

    code = str(otp_code or "").strip()
    if not code:
        return {"success": False, "message": "Verification code is required."}, "Missing OTP", 400

    now = datetime.now()
    _, max_attempts, _ = _get_reset_limits()

    try:
        with db_transaction() as cursor:
            user = _find_user_by_email(cursor, clean_email)
            if not user or user.get("is_active") is False:
                log_security_event("PASSWORD_RESET_VERIFY_FAILED", ip=client_ip, details="reason=invalid_target")
                return {"success": False, "message": "Invalid or expired verification code."}, "Invalid target", 400

            user_id = user["uid"]

            cursor.execute(
                """
                SELECT id, otp_hash, expires_at, attempts, is_used
                FROM password_resets
                WHERE user_id = %s AND is_used = FALSE AND reset_token_hash IS NULL
                ORDER BY id DESC
                LIMIT 1
                FOR UPDATE
                """,
                (user_id,),
            )
            record = cursor.fetchone()

            if not record:
                log_security_event("PASSWORD_RESET_VERIFY_FAILED", uid=user_id, ip=client_ip, details="reason=no_active_otp")
                return {"success": False, "message": "Invalid or expired verification code."}, "No active OTP", 400

            reset_id = record["id"]
            attempts = record.get("attempts") or 0
            expires_at = record["expires_at"]
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at)

            if attempts >= max_attempts:
                cursor.execute("UPDATE password_resets SET is_used = TRUE WHERE id = %s", (reset_id,))
                log_security_event("PASSWORD_RESET_OTP_LOCKED", uid=user_id, ip=client_ip, details="reason=max_attempts")
                return (
                    {
                        "success": False,
                        "message": "Maximum verification attempts exceeded. Please request a new verification code.",
                    },
                    "Max attempts exceeded",
                    429,
                )

            if expires_at < now:
                cursor.execute("UPDATE password_resets SET is_used = TRUE WHERE id = %s", (reset_id,))
                log_security_event("PASSWORD_RESET_VERIFY_FAILED", uid=user_id, ip=client_ip, details="reason=expired")
                return (
                    {
                        "success": False,
                        "message": "Verification code has expired. Please request a new code.",
                    },
                    "OTP expired",
                    400,
                )

            is_numeric_six = len(code) == 6 and code.isdigit()
            expected_hash = hash_reset_otp(user_id, code) if is_numeric_six else ""
            is_match = is_numeric_six and hmac.compare_digest(expected_hash, record["otp_hash"])

            if not is_match:
                new_attempts = attempts + 1
                if new_attempts >= max_attempts:
                    cursor.execute(
                        "UPDATE password_resets SET attempts = %s, is_used = TRUE WHERE id = %s",
                        (new_attempts, reset_id),
                    )
                    log_security_event("PASSWORD_RESET_OTP_LOCKED", uid=user_id, ip=client_ip, details=f"attempts={new_attempts}")
                    return (
                        {
                            "success": False,
                            "message": "Maximum verification attempts exceeded. Please request a new verification code.",
                        },
                        "Max attempts exceeded",
                        429,
                    )

                cursor.execute(
                    "UPDATE password_resets SET attempts = %s WHERE id = %s",
                    (new_attempts, reset_id),
                )
                remaining = max_attempts - new_attempts
                log_security_event(
                    "PASSWORD_RESET_VERIFY_FAILED",
                    uid=user_id,
                    ip=client_ip,
                    details=f"reason=mismatch remaining={remaining}",
                )
                return (
                    {
                        "success": False,
                        "message": f"Invalid verification code. {remaining} attempt(s) remaining.",
                        "attempts_remaining": remaining,
                    },
                    "Invalid OTP",
                    400,
                )

            # OTP matches: issue single-use short-lived reset token & consume OTP slot
            raw_reset_token = secrets.token_urlsafe(32)
            token_hash = hash_reset_token(raw_reset_token)
            token_expires_at = now + timedelta(seconds=RESET_TOKEN_EXPIRY_SECONDS)

            cursor.execute(
                """
                UPDATE password_resets
                SET reset_token_hash = %s, token_expires_at = %s
                WHERE id = %s AND is_used = FALSE
                """,
                (token_hash, token_expires_at, reset_id),
            )

        log_security_event("PASSWORD_RESET_OTP_VERIFIED", uid=user_id, ip=client_ip)
        return (
            {
                "success": True,
                "message": "Verification code verified. You may now create a new password.",
                "reset_token": raw_reset_token,
                "expires_in": RESET_TOKEN_EXPIRY_SECONDS,
            },
            None,
            200,
        )
    except Exception as e:
        safe_print(f"[Verify Reset OTP Error]: {e}")
        return {"success": False, "message": "Verification failed. Please try again."}, str(e), 500


def complete_password_reset(reset_token, new_password, confirm_password=None, client_ip="127.0.0.1"):
    """
    Validate a single-use reset authorization token, enforce password complexity,
    update the user's password hash atomically, invalidate reset credentials, and
    revoke all existing user sessions and tokens.
    Returns: (payload_dict, error_str, http_status)
    """
    token_str = str(reset_token or "").strip()
    if not token_str or not new_password:
        return (
            {"success": False, "message": "Reset token and new password are required."},
            "Missing fields",
            400,
        )

    if confirm_password is not None and new_password != confirm_password:
        return (
            {"success": False, "message": "New password and confirmation do not match."},
            "Password mismatch",
            400,
        )

    _, _, pwd_min_length = _get_reset_limits()
    is_valid, strength, pwd_errors = validate_reset_password(new_password, min_length=pwd_min_length)
    if not is_valid:
        return (
            {
                "success": False,
                "message": pwd_errors[0] if pwd_errors else "Password does not meet complexity requirements.",
                "errors": pwd_errors,
            },
            "Weak password",
            400,
        )

    token_hash = hash_reset_token(token_str)
    now = datetime.now()
    _, max_attempts, _ = _get_reset_limits()

    try:
        user_id = None
        username = None

        with db_transaction() as cursor:
            cursor.execute(
                """
                SELECT pr.id, pr.user_id, pr.token_expires_at, pr.is_used,
                       u.username, u.email, u.is_active
                FROM password_resets pr
                JOIN users u ON pr.user_id = u.uid
                WHERE pr.reset_token_hash = %s
                LIMIT 1
                FOR UPDATE OF pr
                """,
                (token_hash,),
            )
            record = cursor.fetchone()

            if not record:
                log_security_event("PASSWORD_RESET_TOKEN_INVALID", ip=client_ip, details="reason=not_found")
                return (
                    {"success": False, "message": "Invalid or expired reset authorization token."},
                    "Invalid reset token",
                    400,
                )

            reset_id = record["id"]
            user_id = record["user_id"]
            username = record.get("username")

            if record.get("is_used"):
                log_security_event("PASSWORD_RESET_TOKEN_REUSE", uid=user_id, ip=client_ip)
                return (
                    {"success": False, "message": "This reset token has already been used. Please request a new reset."},
                    "Token already used",
                    400,
                )

            token_expires_at = record.get("token_expires_at")
            if isinstance(token_expires_at, str):
                token_expires_at = datetime.fromisoformat(token_expires_at)

            if not token_expires_at or token_expires_at < now:
                cursor.execute("UPDATE password_resets SET is_used = TRUE WHERE id = %s", (reset_id,))
                log_security_event("PASSWORD_RESET_TOKEN_EXPIRED", uid=user_id, ip=client_ip)
                return (
                    {"success": False, "message": "Your reset session has expired. Please start over."},
                    "Reset token expired",
                    400,
                )

            if record.get("is_active") is False:
                return {"success": False, "message": "Account is deactivated."}, "Account deactivated", 403

            # Hash password using Werkzeug PBKDF2/scrypt utilities
            hashed_pw = generate_password_hash(new_password)

            # 1. Update user password
            cursor.execute("UPDATE users SET password = %s WHERE uid = %s", (hashed_pw, user_id))

            # 2. Invalidate all reset tokens and OTPs for this user
            cursor.execute(
                "UPDATE password_resets SET is_used = TRUE WHERE user_id = %s AND is_used = FALSE",
                (user_id,),
            )
            cursor.execute(
                "UPDATE otps SET used = TRUE WHERE uid = %s AND used = FALSE",
                (user_id,),
            )

            # 3. Revoke all active sessions & legacy auth tokens
            cursor.execute(
                "UPDATE active_sessions SET is_active = FALSE, revoked_at = NOW() WHERE uid = %s",
                (user_id,),
            )
            cursor.execute("DELETE FROM tokens WHERE uid = %s", (user_id,))

            # 4. Update dashboard password security metadata if present
            try:
                cursor.execute(
                    """
                    UPDATE user_security_settings
                    SET password_last_changed = NOW(), password_strength = %s
                    WHERE uid = %s
                    """,
                    (strength, user_id),
                )
            except Exception:
                pass

            # 5. Cleanup stale reset records
            _cleanup_expired_records(cursor, now)

        log_security_event("PASSWORD_RESET_SUCCESS", uid=user_id, ip=client_ip, details="sessions_revoked=true")
        record_audit_log(
            "PASSWORD_RESET_SUCCESS",
            actor_uid=user_id,
            actor_username=username,
            target_uid=user_id,
            target_username=username,
            ip_address=client_ip,
            details="Password updated and all active sessions revoked",
        )

        return (
            {
                "success": True,
                "message": "Your password has been reset successfully. Please log in with your new password.",
            },
            None,
            200,
        )
    except Exception as e:
        safe_print(f"[Complete Password Reset Error]: {e}")
        return (
            {"success": False, "message": "Password reset failed. Please try again."},
            str(e),
            500,
        )
