def test_get_users_unauthenticated(client):
    response = client.get("/api/users")
    assert response.status_code == 401


def test_get_users_success(client, monkeypatch):
    mock_users = [{"uid": 1, "username": "alice", "email": "alice@example.com"}]
    monkeypatch.setattr("main.get_users", lambda uid: mock_users)
    monkeypatch.setattr("api.rbac.get_user_role", lambda uid: "admin")
    from api.token import session_token
    token = session_token("testhash")
    monkeypatch.setattr("api.auth_middleware.resolve_user_from_token", lambda tok: {"uid": 1, "username": "alice"})

    response = client.get("/api/users", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.get_json() == mock_users


def test_get_users_non_admin_forbidden_403(client, monkeypatch):
    monkeypatch.setattr("api.rbac.get_user_role", lambda uid: "user")
    monkeypatch.setattr("main.get_user_role", lambda uid: "user")
    from api.token import session_token
    token = session_token("testhash")
    monkeypatch.setattr(
        "api.auth_middleware.resolve_user_from_token",
        lambda tok: {"uid": 1, "username": "alice", "email": "alice@example.com"},
    )

    # Full directory denied for non-admin
    res_list = client.get("/api/users", headers={"Authorization": f"Bearer {token}"})
    assert res_list.status_code == 403

    # Foreign user lookup denied for non-admin
    res_other = client.get("/api/users/2", headers={"Authorization": f"Bearer {token}"})
    assert res_other.status_code == 403


def test_get_user_by_id_found(client, monkeypatch):
    mock_user = [{"uid": 1, "username": "alice", "email": "alice@example.com"}]
    monkeypatch.setattr("main.get_users", lambda uid: mock_user)
    monkeypatch.setattr("main.get_user_role", lambda uid: "user")
    from api.token import session_token
    token = session_token("testhash")
    monkeypatch.setattr("api.auth_middleware.resolve_user_from_token", lambda tok: {"uid": 1, "username": "alice"})

    response = client.get("/api/users/1", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.get_json() == mock_user


def test_get_user_by_id_not_found(client, monkeypatch):
    monkeypatch.setattr("main.get_users", lambda uid: None)
    monkeypatch.setattr("main.get_user_role", lambda uid: "admin")
    from api.token import session_token
    token = session_token("testhash")
    monkeypatch.setattr("api.auth_middleware.resolve_user_from_token", lambda tok: {"uid": 1, "username": "alice"})

    response = client.get("/api/users/999", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 404
    assert response.get_json()["message"] == "Error: User not found"


def test_register_missing_data(client):
    response = client.post("/api/register", data="null", content_type="application/json")
    assert response.status_code == 400
    assert response.get_json()["message"] == "Data is null"


def test_register_success(client, monkeypatch):
    monkeypatch.setattr("main.register", lambda data: True)

    payload = {"username": "bob", "password": "secure123", "email": "bob@example.com", "uid": 2}
    response = client.post("/api/register", json=payload)
    assert response.status_code == 200
    assert response.get_json() is True


def test_register_missing_fields(client):
    payload = {"username": "bob"}
    response = client.post("/api/register", json=payload)
    assert response.status_code == 400
    assert "required" in response.get_json()["message"]


def test_register_duplicate_failure_400(client, monkeypatch):
    monkeypatch.setattr("main.register", lambda data: False)

    payload = {"username": "existing_user", "password": "secure123", "email": "existing@example.com"}
    response = client.post("/api/register", json=payload)
    assert response.status_code == 400
    assert "taken" in response.get_json()["message"]


def test_register_with_require_otp_returns_challenge(client, monkeypatch):
    monkeypatch.setattr("main.register", lambda data: True)
    monkeypatch.setattr(
        "main.create_otp",
        lambda ident, expires_in_seconds=300: (
            {
                "otp": "654321",
                "email": ident,
                "expires_in": expires_in_seconds,
                "cooldown": 60,
                "email_sent": True,
                "email_err": None,
            },
            None,
        ),
    )

    payload = {
        "username": "otp_new_user",
        "password": "VaultUser@2026!",
        "email": "otpuser@example.com",
        "require_otp": True,
    }
    response = client.post("/api/register", json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data["otp_required"] is True
    assert data["requires_otp"] is True
    assert data["identifier"] == "otpuser@example.com"
    assert data["email_sent"] is True
    assert "otp" not in data


def test_register_with_require_otp_handles_delivery_failure_gracefully(client, monkeypatch):
    monkeypatch.setattr("main.register", lambda data: True)
    monkeypatch.setattr(
        "main.create_otp",
        lambda ident, expires_in_seconds=300: (
            {"email_sent": False, "email_err": "SMTP not configured"},
            None,
        ),
    )

    payload = {
        "username": "otp_retry_user",
        "password": "VaultUser@2026!",
        "email": "otpretry@example.com",
        "require_otp": True,
    }
    response = client.post("/api/register", json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data["otp_required"] is True
    assert data["email_sent"] is False
    assert data["cooldown"] == 0


def test_login_missing_data(client):
    response = client.post("/api/login", data="null", content_type="application/json")
    assert response.status_code == 400
    assert response.get_json()["message"] == "Data is null"


def test_login_invalid_credentials(client, monkeypatch):
    monkeypatch.setattr("main.auth_user", lambda login, pwd: None)

    response = client.post("/api/login", json={"login": "nobody", "password": "wrongpassword"})
    assert response.status_code == 404
    assert response.get_json()["message"] == "User not found"


def test_login_success(client, monkeypatch):
    mock_user = {"uid": 1, "username": "alice", "email": "alice@example.com"}
    monkeypatch.setattr("main.auth_user", lambda login, pwd: mock_user)
    monkeypatch.setattr("main.record_login_activity", lambda *a, **k: None)
    monkeypatch.setattr("main.create_user_session", lambda *a, **k: None)
    monkeypatch.setattr("main.ensure_default_user_dashboard_data", lambda *a, **k: None)
    monkeypatch.setattr("main.record_connected_app_signin", lambda *a, **k: None)

    response = client.post("/api/login", json={"login": "alice", "password": "secretpassword"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["message"] == "Login successful"
    assert "token" in data
    assert "." in data["token"]


def test_openapi_spec(client):
    response = client.get("/openapi.json")
    assert response.status_code == 200
    data = response.get_json()
    assert data["openapi"] == "3.0.3"
    assert data["info"]["title"] == "Vault Auth API"
    assert "/api/login" in data["paths"]
    assert "/api/register" in data["paths"]
    assert "/api/users" in data["paths"]


def test_swagger_ui_docs(client):
    response = client.get("/docs")
    assert response.status_code == 200
    assert "SwaggerUIBundle" in response.get_data(as_text=True)


def test_verify_token_success(client):
    from api.token import session_token
    token = session_token("testmd5hash")

    # Via Authorization Header
    res = client.get("/api/verify", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.get_json()["valid"] is True

    # Via JSON body
    res_post = client.post("/api/verify", json={"token": token})
    assert res_post.status_code == 200
    assert res_post.get_json()["valid"] is True


def test_verify_token_failure(client):
    # Missing token
    res = client.get("/api/verify")
    assert res.status_code == 401
    assert res.get_json()["valid"] is False

    # Expired / malformed token
    res_bad = client.get("/api/verify", headers={"Authorization": "Bearer bad.100"})
    assert res_bad.status_code == 401
    assert res_bad.get_json()["valid"] is False


def test_logout_success(client):
    with client.session_transaction() as sess:
        sess["token"] = "valid.token"

    res = client.post("/api/logout")
    assert res.status_code == 200
    assert res.get_json()["message"] == "Logout successful"


def test_health_check(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.get_json()["status"] == "ok"


def test_send_otp_success(client, monkeypatch):
    mock_otp_info = {
        "otp": "654321",
        "email": "alice@vault.io",
        "expires_in": 300
    }
    monkeypatch.setattr("main.create_otp", lambda ident: (mock_otp_info, None))

    res = client.post("/api/otp/send", json={"identifier": "alice"})
    assert res.status_code == 200
    data = res.get_json()
    assert "OTP sent" in data["message"]
    assert data["identifier"] == "alice"
    assert "otp" not in data


def test_send_otp_email_delivery_failed_500(client, monkeypatch):
    mock_otp_info = {
        "otp": "654321",
        "email": "alice@vault.io",
        "expires_in": 300,
        "email_sent": False,
        "email_err": "Gmail credentials not configured"
    }
    monkeypatch.setattr("main.create_otp", lambda ident: (mock_otp_info, None))

    res = client.post("/api/otp/send", json={"identifier": "alice"})
    assert res.status_code == 500
    data = res.get_json()
    assert "Email delivery failed" in data["message"]


def test_send_otp_not_found(client, monkeypatch):
    monkeypatch.setattr("main.create_otp", lambda ident: (None, "User not found"))
    res = client.post("/api/otp/send", json={"identifier": "unknown"})
    assert res.status_code == 404
    assert res.get_json()["message"] == "User not found"


def test_verify_otp_endpoint_success(client, monkeypatch):
    mock_user = {"uid": 2, "username": "alice", "email": "alice@vault.io"}
    monkeypatch.setattr("main.verify_otp", lambda ident, code: (mock_user, None))
    monkeypatch.setattr("main.record_login_activity", lambda *a, **k: None)
    monkeypatch.setattr("main.create_user_session", lambda *a, **k: None)
    monkeypatch.setattr("main.ensure_default_user_dashboard_data", lambda *a, **k: None)
    monkeypatch.setattr("main.record_connected_app_signin", lambda *a, **k: None)

    res = client.post("/api/otp/verify", json={"identifier": "alice", "otp": "654321"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["message"] == "OTP login successful"
    assert "token" in data
    assert data["user"]["username"] == "alice"


def test_verify_otp_endpoint_invalid(client, monkeypatch):
    monkeypatch.setattr("main.verify_otp", lambda ident, code: (None, "Invalid or expired OTP"))
    res = client.post("/api/otp/verify", json={"identifier": "alice", "otp": "000000"})
    assert res.status_code == 401
    assert res.get_json()["message"] == "Invalid or expired OTP"


def test_send_otp_endpoint_cooldown_429(client, monkeypatch):
    monkeypatch.setattr(
        "main.create_otp",
        lambda ident: ({"cooldown_remaining": 45}, "Please wait 45 seconds before requesting a new OTP.")
    )
    res = client.post("/api/otp/send", json={"identifier": "alice"})
    assert res.status_code == 429
    data = res.get_json()
    assert data["retry_after"] == 45
    assert "Please wait 45 seconds" in data["message"]


def test_send_otp_endpoint_deactivated_403(client, monkeypatch):
    monkeypatch.setattr("main.create_otp", lambda ident: (None, "Account is deactivated"))
    res = client.post("/api/otp/send", json={"identifier": "deactivated_user"})
    assert res.status_code == 403
    assert "deactivated" in res.get_json()["message"]


def test_verify_otp_endpoint_deactivated_403(client, monkeypatch):
    monkeypatch.setattr("main.verify_otp", lambda ident, code: (None, "Account is deactivated"))
    res = client.post("/api/otp/verify", json={"identifier": "deactivated_user", "otp": "123456"})
    assert res.status_code == 403
    assert "deactivated" in res.get_json()["message"]


def test_verify_endpoint_rejects_forged_token_401(client):
    res_unsigned = client.get("/api/verify", headers={"Authorization": "Bearer abc12345.9999999999"})
    assert res_unsigned.status_code == 401
    res_forged = client.get("/api/verify", headers={"Authorization": f"Bearer abc12345.9999999999.{'f' * 64}"})
    assert res_forged.status_code == 401


def test_verify_otp_endpoint_includes_user_role(client, monkeypatch):
    mock_user = {"uid": 1, "username": "admin_alice", "email": "admin@vault.io", "role": "admin"}
    monkeypatch.setattr("main.verify_otp", lambda ident, code: (mock_user, None))
    monkeypatch.setattr("main.record_login_activity", lambda *a, **k: None)
    monkeypatch.setattr("main.create_user_session", lambda *a, **k: None)
    monkeypatch.setattr("main.ensure_default_user_dashboard_data", lambda *a, **k: None)

    res = client.post("/api/otp/verify", json={"identifier": "admin_alice", "otp": "654321"})
    assert res.status_code == 200
    assert res.get_json()["user"]["role"] == "admin"


def test_change_password_endpoint(client, monkeypatch):
    from werkzeug.security import generate_password_hash
    from api.token import session_token
    token = session_token("pwuserhash")
    monkeypatch.setattr(
        "api.auth_middleware.resolve_user_from_token",
        lambda tok: {"uid": 7, "username": "bob", "email": "bob@vault.io"},
    )
    executed = []

    def mock_exec(query, params=None):
        executed.append((query, params))
        if "SELECT password, is_active FROM users" in query:
            return [{"password": generate_password_hash("OldStrong@123!"), "is_active": True}]
        return ()

    monkeypatch.setattr("main.execute_query", mock_exec)
    monkeypatch.setattr("main.record_audit_log", lambda *a, **k: None)

    # Wrong current password -> 401
    bad_res = client.post(
        "/api/auth/change-password",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "current_password": "WrongPassword@1",
            "new_password": "NewStrong@2026!",
            "confirm_password": "NewStrong@2026!",
        },
    )
    assert bad_res.status_code == 401

    # Valid update -> 200 and revokes other active sessions
    ok_res = client.post(
        "/api/auth/change-password",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "current_password": "OldStrong@123!",
            "new_password": "NewStrong@2026!",
            "confirm_password": "NewStrong@2026!",
        },
    )
    assert ok_res.status_code == 200
    assert ok_res.get_json()["success"] is True
    assert any("UPDATE users SET password" in q for q, _ in executed)


def test_admin_settings_smtp_detection_and_create_user_email_normalization(monkeypatch):
    from api import admin

    monkeypatch.setenv("SMTP_EMAIL", "sender@gmail.com")
    monkeypatch.setenv("SMTP_PASSWORD", "app-password")
    monkeypatch.delenv("PLUNK_API_KEY", raising=False)
    monkeypatch.setattr(admin, "execute_query", lambda q, p=None: [{"setting_key": "app_name", "setting_value": "VaultAuth SSO"}])

    settings = admin.get_admin_settings()
    assert settings["smtp_configured"] is True
    assert settings["otp_configured"] is True
    assert settings["mail_provider"] == "SMTP"

    inserted_params = []

    def mock_insert(q, p=None):
        if "INSERT INTO users" in q:
            inserted_params.append(p)
            return [{"uid": 55}]
        return ()

    monkeypatch.setattr(admin, "execute_query", mock_insert)
    ok, _ = admin.admin_create_user("Alice_User", "MixedCase@VaultAuth.IO", "StrongPass@123!")
    assert ok is True
    assert inserted_params[0][2] == "mixedcase@vaultauth.io"
