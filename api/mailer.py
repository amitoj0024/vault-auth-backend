"""Transactional email delivery for VaultAuth SSO via SMTP (TLS/SSL) and Plunk."""

import datetime
import email.utils
import html
import json
import os
from pathlib import Path
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


def _render_otp_email_html(title, display_name, intro_text, safe_code, expiry_minutes, warning_text, to_email=None):
    """Render a branded black-and-gold VaultAuth SSO transactional OTP email."""
    year = datetime.datetime.now().year
    safe_email = html.escape(str(to_email)) if to_email else display_name
    return f"""<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="x-apple-disable-message-reformatting">
  <meta name="color-scheme" content="dark">
  <meta name="supported-color-schemes" content="dark">
  <title>{title} – VaultAuth SSO</title>
</head>
<body bgcolor="#000000" style="margin:0; padding:0; width:100%; background-color:#000000;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#000000" style="background-color:#000000;">
    <tr>
      <td align="center" style="padding:36px 16px;">
        <table role="presentation" width="560" cellpadding="0" cellspacing="0" border="0" bgcolor="#000000" style="width:560px; max-width:560px; background-color:#000000; border-radius:16px; border:1px solid #1F1F1F; overflow:hidden;">
          <tr>
            <td style="height:5px; line-height:5px; font-size:0; background-color:#FACC15; border-radius:16px 16px 0 0;">&nbsp;</td>
          </tr>
          <tr>
            <td align="center" style="padding:36px 40px 0 40px;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" align="center">
                <tr>
                  <td align="center" valign="middle" width="42" height="42" bgcolor="#FACC15" style="width:42px; height:42px; background-color:#FACC15; border-radius:11px; color:#000000; font-family:Arial, Helvetica, sans-serif; font-size:21px; font-weight:800; line-height:42px; text-align:center;">V</td>
                  <td valign="middle" style="padding-left:12px; font-family:Arial, Helvetica, sans-serif; font-size:22px; font-weight:700; color:#FFFFFF; letter-spacing:-0.3px;">VaultAuth<span style="color:#FACC15;"> SSO</span></td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td align="center" style="padding:32px 40px 0 40px;">
              <h1 style="margin:0; font-family:Arial, Helvetica, sans-serif; font-size:28px; line-height:36px; font-weight:700; color:#FFFFFF; letter-spacing:-0.4px;">{title}</h1>
              <p style="margin:14px 0 0 0; font-family:Arial, Helvetica, sans-serif; font-size:15.5px; line-height:24px; color:#D4D4D8;">{intro_text}</p>
            </td>
          </tr>
          <tr>
            <td align="center" style="padding:28px 40px 0 40px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#1A1608" style="background-color:#1A1608; border:1px solid #4A3D12; border-radius:12px;">
                <tr>
                  <td align="center" style="padding:22px 16px 8px 16px; font-family:Arial, Helvetica, sans-serif; font-size:12px; line-height:16px; font-weight:700; letter-spacing:1.8px; color:#EAB308; text-transform:uppercase;">
                    YOUR VERIFICATION CODE
                  </td>
                </tr>
                <tr>
                  <td align="center" style="padding:0 16px 24px 16px;">
                    <div style="font-family:'SF Mono', Menlo, Consolas, 'Courier New', monospace; font-size:40px; line-height:48px; font-weight:700; letter-spacing:12px; padding-left:12px; color:#FFFFFF;">{safe_code}</div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td align="center" style="padding:20px 40px 0 40px; font-family:Arial, Helvetica, sans-serif; font-size:14px; line-height:22px; color:#A1A1AA;">
              This code expires in <strong style="color:#FFFFFF;">{expiry_minutes} minutes</strong> and can be used only once.
            </td>
          </tr>
          <tr>
            <td style="padding:26px 40px 0 40px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#1A1608" style="background-color:#1A1608; border:1px solid #3D3310; border-left:4px solid #EAB308; border-radius:8px;">
                <tr>
                  <td style="padding:14px 18px; font-family:Arial, Helvetica, sans-serif; font-size:13.5px; line-height:21px; color:#E4E4E7;">
                    {warning_text}
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding:24px 40px 36px 40px; font-family:Arial, Helvetica, sans-serif; font-size:14px; line-height:22px; color:#A1A1AA;">
              Didn&rsquo;t request this code? You can safely ignore this email &mdash; no changes will be made to your account. If you keep receiving these emails, please contact your administrator.
            </td>
          </tr>
          <tr>
            <td style="padding:0 40px;">
              <div style="height:1px; line-height:1px; font-size:0; background-color:#262626;">&nbsp;</div>
            </td>
          </tr>
          <tr>
            <td align="center" style="padding:24px 40px 32px 40px; font-family:Arial, Helvetica, sans-serif; font-size:12px; line-height:19px; color:#71717A;">
              <strong style="color:#A1A1AA;">VaultAuth SSO</strong> &middot; Unified Identity &amp; Enterprise Access Management<br>
              This is an automated message &mdash; please do not reply to this email.<br>
              &copy; {year} VaultAuth SSO &middot; Zero Trust Workspace
            </td>
          </tr>
        </table>
        <table role="presentation" width="560" cellpadding="0" cellspacing="0" border="0" style="width:560px; max-width:560px;">
          <tr>
            <td align="center" style="padding:16px 40px 0 40px; font-family:Arial, Helvetica, sans-serif; font-size:11.5px; line-height:18px; color:#52525B;">
              Sent to {safe_email} because a verification was requested for this address.
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""


_OTP_TEMPLATE_PATH = Path(__file__).resolve().parent / "templates" / "vaultauth_otp_email.html"


def _render_otp_template(to_email, safe_otp):
    """Load and populate vaultauth_otp_email.html for Gmail/email clients."""
    if _OTP_TEMPLATE_PATH.is_file():
        tpl = _OTP_TEMPLATE_PATH.read_text(encoding="utf-8")
        return (
            tpl.replace("{{ otp }}", safe_otp)
            .replace("{{ email }}", html.escape(str(to_email)))
            .replace("{{ year }}", str(datetime.datetime.now().year))
        )
    return None


def send_otp_email(to_email, otp_code, username=None):
    """Send a login verification OTP email via SMTP or Plunk."""
    raw_display = username or to_email
    display_name = html.escape(str(raw_display))
    safe_otp = html.escape(str(otp_code))
    subject = f"{otp_code} is your Vault Auth verification code"

    html_content = _render_otp_template(to_email, safe_otp) or _render_otp_email_html(
        title="Verify Your Email Address",
        display_name=display_name,
        intro_text="Welcome to VaultAuth SSO. Enter the code below to confirm your email and finish securing your account.",
        safe_code=safe_otp,
        expiry_minutes=5,
        warning_text='<strong style="color:#FFFFFF;">Never share this code with anyone.</strong> VaultAuth staff will never ask you for it by email, phone, or chat.',
        to_email=to_email,
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
        warning_text='<strong style="color:#FFFFFF;">Never share this code with anyone.</strong> If you did not request a password reset, your password remains unchanged.',
        to_email=to_email,
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
