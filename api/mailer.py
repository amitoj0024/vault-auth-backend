"""Transactional email delivery for VaultAuth SSO via SMTP (TLS/SSL) and Plunk."""

import email.utils
import html
import json
import os
import smtplib
import urllib.error
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from api.utils import safe_print


def _get_smtp_config():
    """Read SMTP settings cleanly from environment variables without logging secrets."""
    smtp_user = (
        os.getenv("SMTP_EMAIL")
        or os.getenv("SMTP_USER")
        or os.getenv("GMAIL_USER")
        or ""
    ).strip()
    smtp_pass = (
        os.getenv("SMTP_PASSWORD")
        or os.getenv("SMTP_APP_PASSWORD")
        or os.getenv("SMTP_PASS")
        or os.getenv("GMAIL_APP_PASSWORD")
        or ""
    ).strip()
    smtp_host = (os.getenv("SMTP_HOST") or "smtp.gmail.com").strip()
    port_raw = (os.getenv("SMTP_PORT") or "587").strip()
    smtp_port = int(port_raw) if port_raw.isdigit() else 587
    use_tls_raw = os.getenv("SMTP_USE_TLS", "true").strip().lower()
    smtp_use_tls = use_tls_raw in ("true", "1", "yes", "on")
    smtp_from = (os.getenv("SMTP_FROM") or f"VaultAuth SSO <{smtp_user}>").strip()
    return {
        "user": smtp_user,
        "password": smtp_pass,
        "host": smtp_host,
        "port": smtp_port,
        "use_tls": smtp_use_tls,
        "from": smtp_from,
    }


def is_smtp_configured():
    """Return True when SMTP username and password are present."""
    cfg = _get_smtp_config()
    return bool(cfg["user"] and cfg["password"])


def is_plunk_configured():
    """Return True when Plunk API key is configured."""
    return bool((os.getenv("PLUNK_API_KEY") or "").strip())


def is_email_configured():
    """Return True when any transactional email provider (SMTP or Plunk) is configured."""
    return is_smtp_configured() or is_plunk_configured()


def _send_via_smtp(cfg, to_email, subject, html_content, text_content, context_label):
    """Send email over SMTP supporting STARTTLS (587) and implicit SSL (465)."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = cfg["from"]
    msg["To"] = to_email
    msg.attach(MIMEText(text_content, "plain", "utf-8"))
    msg.attach(MIMEText(html_content, "html", "utf-8"))

    try:
        if cfg["port"] == 465:
            with smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=10) as server:
                server.ehlo()
                server.login(cfg["user"], cfg["password"])
                server.send_message(msg)
        else:
            with smtplib.SMTP(cfg["host"], cfg["port"], timeout=10) as server:
                server.ehlo()
                if cfg["use_tls"]:
                    server.starttls()
                    server.ehlo()
                server.login(cfg["user"], cfg["password"])
                server.send_message(msg)
        safe_print(f"[SMTP Success] {context_label} email dispatched")
        return True, None
    except smtplib.SMTPAuthenticationError:
        safe_print(f"[SMTP Error] Authentication failed while sending {context_label} email")
        return False, "SMTP authentication failed. Please verify SMTP_EMAIL and SMTP_PASSWORD."
    except Exception as e:
        safe_print(f"[SMTP Error] Failed to send {context_label} email: {e}")
        return False, f"SMTP delivery failed: {e}"


def _send_via_plunk(plunk_key, to_email, subject, html_content, context_label):
    """Send email using Plunk REST API as fallback provider."""
    plunk_from = os.getenv(
        "PLUNK_FROM",
        "VaultAuth SSO <no-reply@vaultauthsso.proplays2312.eu.org>",
    )
    sender_name, sender_addr = email.utils.parseaddr(plunk_from)
    sender_addr = sender_addr.strip() if sender_addr else plunk_from.strip()
    sender_name = sender_name.strip() if sender_name else "VaultAuth SSO"

    payload = {
        "to": to_email,
        "subject": subject,
        "body": html_content,
        "from": sender_addr,
        "name": sender_name,
    }

    req = urllib.request.Request(
        "https://next-api.useplunk.com/v1/send",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {plunk_key.strip()}",
            "Content-Type": "application/json",
            "User-Agent": "VaultAuth/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10):
            safe_print(f"[Plunk Success] {context_label} email dispatched")
            return True, None
    except urllib.error.HTTPError as e:
        try:
            err_body = json.loads(e.read().decode("utf-8"))
            err_msg = err_body.get("message") or err_body.get("error") or str(err_body)
        except Exception:
            err_msg = str(e)
        safe_print(f"[Plunk Error] {e.code}: {err_msg}")
        return False, f"Plunk error: {err_msg}"
    except urllib.error.URLError as e:
        safe_print(f"[Plunk URLError] {e}")
        return False, f"Plunk network error: {e}"
    except Exception as e:
        safe_print(f"[Plunk Error] {e}")
        return False, f"Plunk dispatch failed: {e}"


def _dispatch_email(to_email, subject, html_content, text_content, context_label):
    """Dispatch email via SMTP if configured, falling back to Plunk API if available."""
    smtp_cfg = _get_smtp_config()
    plunk_key = (os.getenv("PLUNK_API_KEY") or "").strip()

    if smtp_cfg["user"] and smtp_cfg["password"]:
        ok, smtp_err = _send_via_smtp(
            smtp_cfg, to_email, subject, html_content, text_content, context_label
        )
        if ok:
            return True, None
        if plunk_key:
            safe_print(f"[Mailer] SMTP failed ({smtp_err}); attempting Plunk fallback")
            plunk_ok, plunk_err = _send_via_plunk(
                plunk_key, to_email, subject, html_content, context_label
            )
            if plunk_ok:
                return True, None
            return False, f"{smtp_err} (Plunk fallback also failed: {plunk_err})"
        return False, smtp_err

    if plunk_key:
        return _send_via_plunk(
            plunk_key, to_email, subject, html_content, context_label
        )

    return False, (
        "Email delivery not configured. Add SMTP_EMAIL and SMTP_PASSWORD "
        "(or PLUNK_API_KEY) to .env."
    )


def _render_otp_email_html(title, display_name, intro_text, safe_code, expiry_minutes, warning_text):
    """Render a branded VaultAuth SSO transactional security email."""
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      background-color: #0f172a;
      color: #f8fafc;
      margin: 0;
      padding: 30px;
    }}
    .container {{ max-width: 520px; margin: 0 auto; background: #1e293b; border-radius: 12px; border: 1px solid #334155; padding: 32px; box-shadow: 0 10px 25px rgba(0,0,0,0.45); }}
    .header {{ text-align: center; margin-bottom: 24px; }}
    .brand {{ font-size: 24px; font-weight: 700; letter-spacing: -0.5px; color: #38bdf8; }}
    .title {{ font-size: 18px; color: #e2e8f0; margin-top: 8px; font-weight: 600; }}
    .otp-box {{ margin: 26px 0; text-align: center; background: #0f172a; border: 2px dashed #38bdf8; border-radius: 10px; padding: 18px; }}
    .otp-code {{ font-size: 36px; font-weight: 800; letter-spacing: 8px; color: #38bdf8; font-family: 'SF Mono', Consolas, Monaco, monospace; }}
    .info {{ font-size: 14px; color: #cbd5e1; line-height: 1.6; margin-top: 14px; }}
    .warning {{ margin-top: 20px; padding: 12px 14px; background: rgba(245, 158, 11, 0.12); border-left: 3px solid #f59e0b; border-radius: 6px; font-size: 13px; color: #fde68a; line-height: 1.5; }}
    .footer {{ margin-top: 28px; padding-top: 16px; border-top: 1px solid #334155; font-size: 12px; color: #94a3b8; text-align: center; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">VaultAuth SSO</div>
      <div class="title">{title}</div>
    </div>
    <p class="info">Hello <strong>{display_name}</strong>,</p>
    <p class="info">{intro_text} This code will expire in <strong>{expiry_minutes} minutes</strong>.</p>
    <div class="otp-box"><div class="otp-code">{safe_code}</div></div>
    <div class="warning">{warning_text}</div>
    <div class="footer">&copy; VaultAuth SSO Security &bull; Automated identity protection notice</div>
  </div>
</body>
</html>
"""


def send_otp_email(to_email, otp_code, username=None):
    """Send a login verification OTP email via SMTP or Plunk."""
    raw_display = username or to_email
    display_name = html.escape(str(raw_display))
    safe_otp = html.escape(str(otp_code))
    subject = f"{otp_code} is your Vault Auth verification code"

    html_content = _render_otp_email_html(
        title="Login Verification Code",
        display_name=display_name,
        intro_text="Use the following One-Time Password (OTP) to complete your login.",
        safe_code=safe_otp,
        expiry_minutes=5,
        warning_text="If you did not request this login verification code, please ignore this email and ensure your account password is secure.",
    )
    text_content = (
        f"VaultAuth SSO - Verification Code\n\n"
        f"Hello {raw_display},\n\n"
        f"Your login verification code is: {otp_code}\n\n"
        f"This code is valid for 5 minutes.\n"
        f"If you did not request this, please ignore this email."
    )
    return _dispatch_email(to_email, subject, html_content, text_content, "OTP")


def send_password_reset_email(to_email, otp_code, username=None):
    """Send a password reset verification OTP email via SMTP or Plunk."""
    raw_display = username or to_email
    display_name = html.escape(str(raw_display))
    safe_otp = html.escape(str(otp_code))
    subject = "VaultAuth SSO – Password Reset Verification"

    html_content = _render_otp_email_html(
        title="Password Reset Verification",
        display_name=display_name,
        intro_text="We received a request to reset your VaultAuth SSO password. Enter the verification code below to continue.",
        safe_code=safe_otp,
        expiry_minutes=5,
        warning_text="Security Warning: If you did not request a password reset, do NOT share this code with anyone. Your password remains unchanged unless you verify this code.",
    )
    text_content = (
        f"VaultAuth SSO – Password Reset Verification\n\n"
        f"Hello {raw_display},\n\n"
        f"Your password reset verification OTP is: {otp_code}\n"
        f"This code will expire in 5 minutes.\n\n"
        f"Security Warning: If you did not request this password reset, you can safely ignore this email "
        f"and review your account security settings."
    )
    return _dispatch_email(to_email, subject, html_content, text_content, "Password Reset")
