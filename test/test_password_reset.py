"""Comprehensive tests for Forgot Password & Reset Password workflow."""

from contextlib import contextmanager
from datetime import datetime, timedelta
import pytest
from werkzeug.security import check_password_hash, generate_password_hash

from api import password_reset, security


class FakeResetDatabase:
    """Stateful relational simulator backing users, password_resets, otps, active_sessions, and tokens."""

    def __init__(self):
        self.users = [
            {
                "uid": 101,
                "username": "alice_reset",
                "email": "alice.reset@vaultauth.io",
                "password": generate_password_hash("OldPass@123!"),
                "full_name": "Alice Reset",
                "is_active": True,
            },
            {
                "uid": 102,
                "username": "inactive_user",
                "email": "inactive@vaultauth.io",
                "password": generate_password_hash("OldPass@123!"),
                "full_name": "Inactive User",
                "is_active": False,
            },
        ]
        self.password_resets = []
        self.otps = []
        self.active_sessions = [
            {
                "id": 1,
                "uid": 101,
                "session_id": "sess_active_1",
                "session_token": "oldhash1234567890abcdef12345678.9999999999",
                "is_active": True,
                "revoked_at": None,
            }
        ]
        self.tokens = [{"uid": 101, "md5": "legacytoken123", "cr_date": "2026-01-01"}]
        self._next_reset_id = 1
        self._cursor_result = []

    def cursor(self):
        return _FakeCursor(self)

    def execute_query(self, query, params=None):
        cur = _FakeCursor(self)
        cur.execute(query, params)
        return cur.fetchall() if "SELECT" in query.upper() or "RETURNING" in query.upper() else ()


class _FakeCursor:
    def __init__(self, db: FakeResetDatabase):
        self.db = db
        self._rows = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def execute(self, query, params=None):
        q = " ".join(query.split())
        q_upper = q.upper()
        self._rows = []

        if q_upper.startswith("DELETE FROM PASSWORD_RESETS"):
            cutoff_otp, cutoff_tok, cutoff_used = params
            self.db.password_resets = [
                r
                for r in self.db.password_resets
                if not (
                    (r["expires_at"] < cutoff_otp and r["reset_token_hash"] is None)
                    or (r["token_expires_at"] is not None and r["token_expires_at"] < cutoff_tok)
                    or (r["is_used"] and r["created_at"] < cutoff_used)
                )
            ]
            return

        if "FROM USERS WHERE LOWER(EMAIL)" in q_upper:
            target = params[0].lower()
            self._rows = [dict(u) for u in self.db.users if u["email"].lower() == target][:1]
            return

        if "FROM USERS WHERE USERNAME = %S OR LOWER(EMAIL) = %S" in q_upper or "FROM USERS WHERE USERNAME = %S OR EMAIL = %S" in q_upper:
            a, b = params[0], params[1]
            self._rows = [
                dict(u)
                for u in self.db.users
                if u["username"] == a or u["email"].lower() == str(b).lower()
            ]
            return

        if "SELECT CREATED_AT FROM PASSWORD_RESETS WHERE USER_ID" in q_upper:
            uid = params[0]
            rows = [r for r in self.db.password_resets if r["user_id"] == uid]
            rows.sort(key=lambda x: x["id"], reverse=True)
            self._rows = [{"created_at": rows[0]["created_at"]}] if rows else []
            return

        if "SELECT COUNT(*) AS CNT FROM PASSWORD_RESETS" in q_upper:
            uid, since = params
            cnt = sum(
                1
                for r in self.db.password_resets
                if r["user_id"] == uid and r["created_at"] >= since
            )
            self._rows = [{"cnt": cnt}]
            return

        if q_upper.startswith("UPDATE PASSWORD_RESETS SET IS_USED = TRUE WHERE USER_ID"):
            uid = params[0]
            for r in self.db.password_resets:
                if r["user_id"] == uid and not r["is_used"]:
                    r["is_used"] = True
            return

        if q_upper.startswith("INSERT INTO PASSWORD_RESETS"):
            uid, otp_hash, expires_at, created_at = params
            row = {
                "id": self._db_next_id(),
                "user_id": uid,
                "otp_hash": otp_hash,
                "expires_at": expires_at,
                "attempts": 0,
                "reset_token_hash": None,
                "token_expires_at": None,
                "is_used": False,
                "created_at": created_at,
            }
            self.db.password_resets.append(row)
            self._rows = [{"id": row["id"]}]
            return

        if q_upper.startswith("DELETE FROM PASSWORD_RESETS WHERE ID = %S"):
            rid = params[0]
            self.db.password_resets = [r for r in self.db.password_resets if r["id"] != rid]
            return

        if "FROM PASSWORD_RESETS WHERE USER_ID = %S AND IS_USED = FALSE AND RESET_TOKEN_HASH IS NULL" in q_upper:
            uid = params[0]
            rows = [
                dict(r)
                for r in self.db.password_resets
                if r["user_id"] == uid and not r["is_used"] and r["reset_token_hash"] is None
            ]
            rows.sort(key=lambda x: x["id"], reverse=True)
            self._rows = rows[:1]
            return

        if q_upper.startswith("UPDATE PASSWORD_RESETS SET IS_USED = TRUE WHERE ID = %S"):
            rid = params[0]
            for r in self.db.password_resets:
                if r["id"] == rid:
                    r["is_used"] = True
            return

        if q_upper.startswith("UPDATE PASSWORD_RESETS SET ATTEMPTS = %S, IS_USED = TRUE"):
            attempts, rid = params
            for r in self.db.password_resets:
                if r["id"] == rid:
                    r["attempts"] = attempts
                    r["is_used"] = True
            return

        if q_upper.startswith("UPDATE PASSWORD_RESETS SET ATTEMPTS = %S WHERE ID = %S"):
            attempts, rid = params
            for r in self.db.password_resets:
                if r["id"] == rid:
                    r["attempts"] = attempts
            return

        if q_upper.startswith("UPDATE PASSWORD_RESETS SET RESET_TOKEN_HASH"):
            token_hash, token_expires_at, rid = params
            for r in self.db.password_resets:
                if r["id"] == rid and not r["is_used"]:
                    r["reset_token_hash"] = token_hash
                    r["token_expires_at"] = token_expires_at
            return

        if "FROM PASSWORD_RESETS PR JOIN USERS U" in q_upper:
            token_hash = params[0]
            for r in self.db.password_resets:
                if r["reset_token_hash"] == token_hash:
                    user = next((u for u in self.db.users if u["uid"] == r["user_id"]), None)
                    if user:
                        self._rows = [{
                            "id": r["id"],
                            "user_id": r["user_id"],
                            "token_expires_at": r["token_expires_at"],
                            "is_used": r["is_used"],
                            "username": user["username"],
                            "email": user["email"],
                            "is_active": user["is_active"],
                        }]
                        return
            return

        if q_upper.startswith("UPDATE USERS SET PASSWORD = %S WHERE UID = %S"):
            new_pw, uid = params
            for u in self.db.users:
                if u["uid"] == uid:
                    u["password"] = new_pw
            return

        if q_upper.startswith("UPDATE OTPS SET USED = TRUE WHERE UID = %S"):
            uid = params[0]
            for o in self.db.otps:
                if o["uid"] == uid:
                    o["used"] = True
            return

        if q_upper.startswith("UPDATE ACTIVE_SESSIONS SET IS_ACTIVE = FALSE"):
            uid = params[0]
            for s in self.db.active_sessions:
                if s["uid"] == uid:
                    s["is_active"] = False
                    s["revoked_at"] = datetime.now()
            return

        if q_upper.startswith("DELETE FROM TOKENS WHERE UID = %S"):
            uid = params[0]
            self.db.tokens = [t for t in self.db.tokens if t["uid"] != uid]
            return

        if "FROM ACTIVE_SESSIONS S JOIN USERS U ON S.UID = U.UID" in q_upper:
            tok = params[0]
            for s in reversed(self.db.active_sessions):
                if s["session_token"] == tok:
                    u = next((usr for usr in self.db.users if usr["uid"] == s["uid"]), None)
                    if u:
                        self._rows = [{
                            "session_id": s["id"],
                            "uid": s["uid"],
                            "session_active": s["is_active"],
                            "username": u["username"],
                            "email": u["email"],
                            "full_name": u["full_name"],
                            "is_active": u["is_active"],
                        }]
                        return
            return

    def _db_next_id(self):
        val = self.db._next_reset_id
        self.db._next_reset_id += 1
        return val

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


@pytest.fixture
def reset_env(monkeypatch):
    """Set up stateful DB and captured email spy for deterministic password reset tests."""
    security._rate_buckets.clear()
    db = FakeResetDatabase()
    sent_emails = []

    @contextmanager
    def fake_tx():
        yield db.cursor()

    def fake_send_email(to_email, otp_code, username=None):
        sent_emails.append({"to": to_email, "otp": otp_code, "username": username})
        return True, None

    monkeypatch.setattr(password_reset, "db_transaction", fake_tx)
    monkeypatch.setattr(password_reset, "send_password_reset_email", fake_send_email)
    monkeypatch.setattr(password_reset, "record_audit_log", lambda *args, **kwargs: None)

    import opperation
    from api import auth_middleware
    monkeypatch.setattr(opperation, "execute_query", db.execute_query)
    monkeypatch.setattr(auth_middleware, "execute_query", db.execute_query)
    monkeypatch.setattr("main.record_login_activity", lambda *args, **kwargs: None)
    monkeypatch.setattr("main.create_user_session", lambda *args, **kwargs: None)
    monkeypatch.setattr("main.ensure_default_user_dashboard_data", lambda *args, **kwargs: None)

    return db, sent_emails


# ─── Step 1 & Enumeration Protection Tests ───────────────────────────────────


def test_registered_email_receives_otp_and_generic_response(client, reset_env):
    db, sent_emails = reset_env

    res = client.post("/api/auth/forgot-password", json={"email": "alice.reset@vaultauth.io"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "otp" not in data
    assert len(sent_emails) == 1
    assert sent_emails[0]["to"] == "alice.reset@vaultauth.io"
    assert len(sent_emails[0]["otp"]) == 6
    assert sent_emails[0]["otp"].isdigit()

    # Plaintext OTP must NEVER be stored in database
    assert len(db.password_resets) == 1
    assert db.password_resets[0]["otp_hash"] != sent_emails[0]["otp"]
    assert len(db.password_resets[0]["otp_hash"]) == 64


def test_unregistered_email_returns_identical_generic_response(client, reset_env):
    db, sent_emails = reset_env

    res_reg = client.post("/api/auth/forgot-password", json={"email": "alice.reset@vaultauth.io"})
    res_unreg = client.post("/api/auth/forgot-password", json={"email": "nobody@vaultauth.io"})

    assert res_reg.status_code == res_unreg.status_code == 200
    assert res_reg.get_json()["message"] == res_unreg.get_json()["message"]
    assert res_reg.get_json()["expires_in"] == res_unreg.get_json()["expires_in"]
    # Only the registered user received an email
    assert len(sent_emails) == 1


# ─── Step 2 & 3: OTP Verification Security Tests ──────────────────────────────


def test_correct_otp_issues_reset_token_and_rejects_reuse(client, reset_env):
    _, sent_emails = reset_env
    client.post("/api/auth/forgot-password", json={"email": "alice.reset@vaultauth.io"})
    otp = sent_emails[0]["otp"]

    # Correct OTP succeeds
    res = client.post(
        "/api/auth/verify-reset-otp",
        json={"email": "alice.reset@vaultauth.io", "otp": otp},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "reset_token" in data and len(data["reset_token"]) > 20

    # Reusing the same OTP must fail
    reuse_res = client.post(
        "/api/auth/verify-reset-otp",
        json={"email": "alice.reset@vaultauth.io", "otp": otp},
    )
    assert reuse_res.status_code == 400
    assert reuse_res.get_json()["success"] is False


def test_incorrect_otp_rejected_and_five_attempts_block(client, reset_env):
    _, sent_emails = reset_env
    client.post("/api/auth/forgot-password", json={"email": "alice.reset@vaultauth.io"})
    real_otp = sent_emails[0]["otp"]
    wrong_otp = "000001" if real_otp != "000001" else "000002"

    for i in range(4):
        res = client.post(
            "/api/auth/verify-reset-otp",
            json={"email": "alice.reset@vaultauth.io", "otp": wrong_otp},
        )
        assert res.status_code == 400
        assert res.get_json()["attempts_remaining"] == 4 - i

    # 5th failed attempt locks out with 429
    res5 = client.post(
        "/api/auth/verify-reset-otp",
        json={"email": "alice.reset@vaultauth.io", "otp": wrong_otp},
    )
    assert res5.status_code == 429
    assert "maximum" in res5.get_json()["message"].lower()

    # Subsequent attempt even with the previously valid OTP must fail
    res_after = client.post(
        "/api/auth/verify-reset-otp",
        json={"email": "alice.reset@vaultauth.io", "otp": real_otp},
    )
    assert res_after.status_code in (400, 429)


def test_expired_otp_rejected(client, reset_env):
    db, sent_emails = reset_env
    client.post("/api/auth/forgot-password", json={"email": "alice.reset@vaultauth.io"})
    otp = sent_emails[0]["otp"]

    # Force expiry in the past
    db.password_resets[0]["expires_at"] = datetime.now() - timedelta(seconds=10)

    res = client.post(
        "/api/auth/verify-reset-otp",
        json={"email": "alice.reset@vaultauth.io", "otp": otp},
    )
    assert res.status_code == 400
    assert "expired" in res.get_json()["message"].lower()


def test_resend_cooldown_and_previous_otp_invalidation(client, reset_env):
    db, sent_emails = reset_env
    client.post("/api/auth/forgot-password", json={"email": "alice.reset@vaultauth.io"})
    first_otp = sent_emails[0]["otp"]

    # Immediate resend must be blocked by 60s cooldown
    cooldown_res = client.post(
        "/api/auth/resend-reset-otp",
        json={"email": "alice.reset@vaultauth.io"},
    )
    assert cooldown_res.status_code == 429
    assert cooldown_res.get_json()["retry_after"] > 0

    # Fast-forward timestamp > 60 seconds ago
    db.password_resets[0]["created_at"] = datetime.now() - timedelta(seconds=65)

    resend_res = client.post(
        "/api/auth/resend-reset-otp",
        json={"email": "alice.reset@vaultauth.io"},
    )
    assert resend_res.status_code == 200
    assert len(sent_emails) == 2
    second_otp = sent_emails[1]["otp"]

    # Previous OTP must be invalidated
    old_attempt = client.post(
        "/api/auth/verify-reset-otp",
        json={"email": "alice.reset@vaultauth.io", "otp": first_otp},
    )
    assert old_attempt.status_code == 400

    # New OTP works
    new_attempt = client.post(
        "/api/auth/verify-reset-otp",
        json={"email": "alice.reset@vaultauth.io", "otp": second_otp},
    )
    assert new_attempt.status_code == 200


# ─── Step 4 & 5: Reset Token Validation, Password Hashing, Session Revocation ─


def test_invalid_and_expired_reset_tokens_rejected(client, reset_env):
    db, sent_emails = reset_env

    # Completely invalid token
    bad = client.post(
        "/api/auth/reset-password",
        json={"reset_token": "totally-invalid-token", "new_password": "NewValid@2026!"},
    )
    assert bad.status_code == 400

    # Expired token
    client.post("/api/auth/forgot-password", json={"email": "alice.reset@vaultauth.io"})
    otp = sent_emails[0]["otp"]
    v = client.post("/api/auth/verify-reset-otp", json={"email": "alice.reset@vaultauth.io", "otp": otp})
    token = v.get_json()["reset_token"]
    db.password_resets[0]["token_expires_at"] = datetime.now() - timedelta(minutes=1)

    exp = client.post(
        "/api/auth/reset-password",
        json={"reset_token": token, "new_password": "NewValid@2026!"},
    )
    assert exp.status_code == 400
    assert "expired" in exp.get_json()["message"].lower()


def test_password_complexity_validation_enforced(client, reset_env):
    _, sent_emails = reset_env
    client.post("/api/auth/forgot-password", json={"email": "alice.reset@vaultauth.io"})
    v = client.post(
        "/api/auth/verify-reset-otp",
        json={"email": "alice.reset@vaultauth.io", "otp": sent_emails[0]["otp"]},
    )
    token = v.get_json()["reset_token"]

    weak_passwords = [
        "Short1!",          # < 8 chars
        "alllowercase1!",   # no uppercase
        "ALLUPPERCASE1!",   # no lowercase
        "NoNumbersHere!",   # no number
        "NoSpecial1234",    # no special char
    ]
    for pwd in weak_passwords:
        res = client.post(
            "/api/auth/reset-password",
            json={"reset_token": token, "new_password": pwd},
        )
        assert res.status_code == 400
        assert res.get_json()["success"] is False


def test_full_password_reset_hashes_revokes_sessions_and_updates_login(client, reset_env):
    db, sent_emails = reset_env
    old_session_token = db.active_sessions[0]["session_token"]

    # Confirm old password works before reset
    login_old = client.post("/api/login", json={"login": "alice.reset@vaultauth.io", "password": "OldPass@123!"})
    assert login_old.status_code == 200

    # Request reset & verify OTP
    client.post("/api/auth/forgot-password", json={"email": "alice.reset@vaultauth.io"})
    v = client.post(
        "/api/auth/verify-reset-otp",
        json={"email": "alice.reset@vaultauth.io", "otp": sent_emails[0]["otp"]},
    )
    reset_token = v.get_json()["reset_token"]

    # Complete reset
    new_pwd = "StrongNew@2026!"
    reset_res = client.post(
        "/api/auth/reset-password",
        json={
            "reset_token": reset_token,
            "new_password": new_pwd,
            "confirm_password": new_pwd,
        },
    )
    assert reset_res.status_code == 200
    assert reset_res.get_json()["message"] == (
        "Your password has been reset successfully. Please log in with your new password."
    )

    # Password in DB is securely hashed with Werkzeug
    stored_pw = db.users[0]["password"]
    assert stored_pw != new_pwd
    assert check_password_hash(stored_pw, new_pwd)

    # Reset token cannot be reused
    reuse_tok = client.post(
        "/api/auth/reset-password",
        json={"reset_token": reset_token, "new_password": "AnotherStrong@2026!"},
    )
    assert reuse_tok.status_code == 400

    # All existing sessions & tokens revoked
    assert all(s["is_active"] is False for s in db.active_sessions)
    assert len(db.tokens) == 0

    # Protected route rejects previously active session token
    protected = client.get("/api/users", headers={"Authorization": f"Bearer {old_session_token}"})
    assert protected.status_code == 401

    # Old password fails to log in with 401 Invalid email or password (not 404 User not found)
    old_login_after = client.post("/api/login", json={"login": "alice.reset@vaultauth.io", "password": "OldPass@123!"})
    assert old_login_after.status_code == 401
    assert "invalid" in old_login_after.get_json()["message"].lower()

    # New password logs in successfully and includes user payload
    new_login_after = client.post("/api/login", json={"login": "alice.reset@vaultauth.io", "password": new_pwd})
    assert new_login_after.status_code == 200
    login_data = new_login_after.get_json()
    assert "token" in login_data
    assert login_data["user"]["email"] == "alice.reset@vaultauth.io"


# ─── Mailer SMTP & TLS Integration Tests ──────────────────────────────────────


def test_mailer_password_reset_smtp_tls_and_branding(monkeypatch):
    from email.header import decode_header
    import smtplib
    from api.mailer import send_password_reset_email

    captured = {}

    class MockSMTP:
        def __init__(self, host, port, timeout=10):
            captured["host"] = host
            captured["port"] = port

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

        def ehlo(self):
            captured["ehlo"] = captured.get("ehlo", 0) + 1

        def starttls(self):
            captured["starttls"] = True

        def login(self, user, password):
            captured["login_user"] = user
            captured["login_pass"] = password

        def send_message(self, msg):
            raw_subj = decode_header(msg["Subject"])
            subj_decoded = "".join(
                part.decode(enc or "utf-8") if isinstance(part, bytes) else part
                for part, enc in raw_subj
            )
            captured["subject"] = subj_decoded
            captured["to"] = msg["To"]
            bodies = [
                part.get_payload(decode=True).decode("utf-8")
                for part in msg.get_payload()
            ]
            captured["payload"] = "\n".join(bodies)

    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_EMAIL", "noreply@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "app-secret-pass")
    monkeypatch.setenv("SMTP_USE_TLS", "true")
    monkeypatch.setattr(smtplib, "SMTP", MockSMTP)

    ok, err = send_password_reset_email("recipient@example.com", "849201", username="alice")
    assert ok is True
    assert err is None
    assert captured["host"] == "smtp.example.com"
    assert captured["port"] == 587
    assert captured["starttls"] is True
    assert captured["login_user"] == "noreply@example.com"
    assert captured["subject"] == "VaultAuth SSO \u2013 Password Reset Verification"
    assert "849201" in captured["payload"]
    assert "VaultAuth SSO" in captured["payload"]
    assert "5 minutes" in captured["payload"]
