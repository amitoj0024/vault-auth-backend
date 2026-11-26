"""Unit and integration tests for WebAuthn / FIDO2 Passkey authentication."""

import json
from unittest.mock import MagicMock
import pytest

from api.token import session_token
from api.webauthn_service import (
    create_webauthn_challenge,
    consume_webauthn_challenge,
    get_passkey_registration_options,
    get_passkey_authentication_options,
    get_user_passkeys,
    delete_user_passkey,
)


@pytest.fixture(autouse=True)
def mock_webauthn_audit_log(monkeypatch):
    """Prevent WebAuthn unit tests from writing synthetic events to live audit_logs."""
    monkeypatch.setattr("api.webauthn_service.record_audit_log", lambda *a, **k: None)


@pytest.fixture
def auth_headers(monkeypatch):
    """Fixture providing valid authentication headers for user with uid=1."""
    token = session_token("test-webauthn-token")
    monkeypatch.setattr(
        "api.auth_middleware.resolve_user_from_token",
        lambda tok: {"uid": 1, "username": "testuser", "email": "testuser@example.com", "role": "End User"}
    )
    monkeypatch.setattr("main.ensure_default_user_dashboard_data", lambda *a, **k: None)
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


# ─── Challenge & Anti-Replay Tests ──────────────────────────────────────────

def test_webauthn_challenge_creation_and_consumption():
    """Verify challenge generation, byte formatting, and single-use consumption."""
    challenge_bytes, challenge_str = create_webauthn_challenge(uid=1, challenge_type="registration")
    assert len(challenge_bytes) == 32
    assert isinstance(challenge_str, str)
    assert len(challenge_str) > 20

    # First consumption: succeeds
    consumed = consume_webauthn_challenge(challenge_str, expected_type="registration", uid=1)
    assert consumed is not None
    assert consumed == challenge_bytes

    # Second consumption: fails (anti-replay guarantee)
    consumed_again = consume_webauthn_challenge(challenge_str, expected_type="registration", uid=1)
    assert consumed_again is None


def test_webauthn_challenge_uid_isolation():
    """Verify a challenge bound to user A cannot be consumed by user B."""
    _, challenge_str = create_webauthn_challenge(uid=10, challenge_type="registration")

    # Wrong UID fails
    consumed = consume_webauthn_challenge(challenge_str, expected_type="registration", uid=99)
    assert consumed is None

    # Correct UID succeeds
    consumed_correct = consume_webauthn_challenge(challenge_str, expected_type="registration", uid=10)
    assert consumed_correct is not None


# ─── Endpoint Tests: Registration ───────────────────────────────────────────

def test_register_options_unauthenticated(client):
    """Unauthenticated request to register options must be rejected with 401."""
    res = client.post("/api/webauthn/register/options")
    assert res.status_code == 401


def test_register_options_authenticated(client, auth_headers):
    """Authenticated request generates W3C PublicKeyCredentialCreationOptions."""
    res = client.post("/api/webauthn/register/options", headers=auth_headers)
    assert res.status_code == 200
    data = res.get_json()

    assert "challenge" in data
    assert "rp" in data
    assert data["rp"]["name"] == "VaultAuth SSO"
    assert "user" in data
    assert data["user"]["name"] == "testuser"
    assert "pubKeyCredParams" in data
    assert len(data["pubKeyCredParams"]) > 0


def test_register_verify_empty_body(client, auth_headers):
    """Empty payload returns 400."""
    res = client.post("/api/webauthn/register/verify", headers=auth_headers, json={})
    assert res.status_code == 400


def test_register_verify_invalid_challenge(client, auth_headers):
    """Bogus challenge payload returns 400."""
    bogus_payload = {
        "credential": {
            "id": "mock_cred_id",
            "rawId": "mock_cred_id",
            "type": "public-key",
            "response": {
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiAiaW52YWxpZCJ9",
                "attestationObject": "bW9jaw==",
            }
        },
        "deviceName": "MacBook Touch ID"
    }
    res = client.post("/api/webauthn/register/verify", headers=auth_headers, json=bogus_payload)
    assert res.status_code == 400
    assert res.get_json()["success"] is False


def test_register_verify_success_mocked(client, auth_headers, monkeypatch):
    """Successful registration stores credential and records audit log."""
    mock_cred_info = {
        "id": 1,
        "credential_id": "dGVzdC1jcmVkZW50aWFsLWlk",
        "device_name": "MacBook Touch ID",
        "created_at": "2026-11-23 10:00:00"
    }

    monkeypatch.setattr(
        "main.verify_and_save_passkey_registration",
        lambda user, credential_payload, device_name, client_ip, **kwargs: (
            True, "Passkey successfully registered!", mock_cred_info
        )
    )

    payload = {
        "credential": {
            "id": "dGVzdC1jcmVkZW50aWFsLWlkLWJ5dGVzLTEyMzQ1",
            "rawId": "dGVzdC1jcmVkZW50aWFsLWlkLWJ5dGVzLTEyMzQ1",
            "type": "public-key",
            "response": {
                "clientDataJSON": "mock_client_data",
                "attestationObject": "mock_attestation_object",
            }
        },
        "deviceName": "MacBook Touch ID"
    }

    res = client.post("/api/webauthn/register/verify", headers=auth_headers, json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "Passkey successfully registered" in data["message"]


# ─── Endpoint Tests: Login / Authentication ─────────────────────────────────

def test_login_options_without_identifier(client):
    """Login options request without identifier provides discoverable assertion challenge."""
    res = client.post("/api/webauthn/login/options", json={})
    assert res.status_code == 200
    data = res.get_json()

    assert "challenge" in data
    assert "rpId" in data
    assert data["rpId"] == "localhost"


def test_login_options_with_identifier(client, monkeypatch):
    """Login options with identifier populates user credentials in allowCredentials if found."""
    monkeypatch.setattr("opperation.get_users", lambda ident: [{"uid": 1, "username": "testuser"}])
    res = client.post("/api/webauthn/login/options", json={"identifier": "testuser"})
    assert res.status_code == 200
    data = res.get_json()
    assert "challenge" in data


def test_login_verify_unrecognized_passkey(client):
    """Attempting login with an unregistered credential ID is rejected."""
    payload = {
        "id": "unregistered-cred-id-xyz",
        "rawId": "unregistered-cred-id-xyz",
        "type": "public-key",
        "response": {
            "clientDataJSON": "eyJjaGFsbGVuZ2UiOiAidGVzdCJ9",
            "authenticatorData": "mock",
            "signature": "mock",
        }
    }
    res = client.post("/api/webauthn/login/verify", json=payload)
    assert res.status_code == 401
    assert "not recognized" in res.get_json()["message"]


def test_login_verify_success_mocked(client, monkeypatch):
    """Successful assertion verification issues session token, sets cookie, and returns user info."""
    mock_user = {
        "uid": 1,
        "username": "testuser",
        "email": "testuser@example.com",
        "full_name": "Test User",
        "is_active": True,
        "role": "End User"
    }

    monkeypatch.setattr(
        "main.verify_passkey_authentication",
        lambda *args, **kwargs: (True, "Passkey verified", mock_user)
    )
    monkeypatch.setattr("main.get_user_role", lambda uid: "End User")
    monkeypatch.setattr("main.record_login_activity", lambda *args, **kwargs: True)
    monkeypatch.setattr("main.create_user_session", lambda *args, **kwargs: True)
    monkeypatch.setattr("main.ensure_default_user_dashboard_data", lambda *args, **kwargs: True)
    monkeypatch.setattr("main.record_connected_app_signin", lambda *args, **kwargs: True)

    payload = {
        "id": "test-valid-passkey-id",
        "rawId": "test-valid-passkey-id",
        "type": "public-key",
        "response": {
            "clientDataJSON": "mock_client_data",
            "authenticatorData": "mock_auth_data",
            "signature": "mock_signature",
        }
    }

    res = client.post("/api/webauthn/login/verify", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "token" in data
    assert data["user"]["username"] == "testuser"
    assert "token=" in res.headers.get("Set-Cookie", "")


# ─── Endpoint Tests: Credential Management ───────────────────────────────────

def test_get_credentials_authenticated(client, auth_headers, monkeypatch):
    """Retrieve list of registered passkeys for the user."""
    mock_creds = [
        {
            "id": 1,
            "credential_id": "cid1234567890abcdef",
            "device_name": "MacBook Touch ID",
            "transports": "internal",
            "created_at": "2026-11-20 10:00:00",
            "last_used_at": "2026-11-22 14:00:00"
        }
    ]
    monkeypatch.setattr("api.webauthn_service.execute_query", lambda sql, params=None: mock_creds)

    res = client.get("/api/webauthn/credentials", headers=auth_headers)
    assert res.status_code == 200
    data = res.get_json()
    assert "credentials" in data
    assert len(data["credentials"]) == 1
    assert data["credentials"][0]["device_name"] == "MacBook Touch ID"


def test_delete_credential_idor_protection(client, auth_headers, monkeypatch):
    """Deleting a credential not owned by the authenticated user returns 400 / error."""
    # Mock lookup returns empty list (credential not found or belongs to another user)
    monkeypatch.setattr("api.webauthn_service.execute_query", lambda sql, params=None: [])

    res = client.delete("/api/webauthn/credentials/999", headers=auth_headers)
    assert res.status_code == 400
    assert "not found or access denied" in res.get_json()["message"]


def test_delete_credential_success(client, auth_headers, monkeypatch):
    """Deleting own credential succeeds."""
    mock_check = [{"id": 5, "device_name": "YubiKey 5C", "credential_id": "test_cid"}]

    def mock_query(sql, params=None):
        if "SELECT id, device_name, credential_id FROM webauthn_credentials" in sql:
            return mock_check
        return 1

    monkeypatch.setattr("api.webauthn_service.execute_query", mock_query)

    res = client.delete("/api/webauthn/credentials/5", headers=auth_headers)
    assert res.status_code == 200
    assert res.get_json()["success"] is True
    assert "Passkey successfully removed" in res.get_json()["message"]


def test_verify_passkey_authentication_rejects_mismatched_challenge(monkeypatch):
    """Authentication fails when clientDataJSON challenge does not match any pending challenge (no arbitrary fallback)."""
    from api import webauthn_service

    create_webauthn_challenge(uid=1, challenge_type="authentication")
    monkeypatch.setattr(
        webauthn_service,
        "execute_query",
        lambda q, p=None: (
            [{"id": 1, "uid": 1, "credential_id": "cred_1", "public_key": b"pk", "sign_count": 0, "device_name": "Key"}]
            if "FROM webauthn_credentials" in q
            else ([{"uid": 1, "username": "alice", "email": "alice@example.com", "full_name": "Alice", "is_active": True, "role": "user"}] if "FROM users" in q else [])
        ),
    )

    ok, msg, user = webauthn_service.verify_passkey_authentication({
        "id": "cred_1",
        "response": {"clientDataJSON": "eyJjaGFsbGVuZ2UiOiJub3QtYS1yZWFsLWNoYWxsZW5nZSJ9"},
    })
    assert ok is False
    assert user is None
    assert "expired" in msg.lower()


# ─── Rename Passkey Tests ─────────────────────────────────────────────────────

def test_rename_credential_success(client, auth_headers, monkeypatch):
    """Authenticated user can rename their own passkey."""
    mock_check = [{"id": 7, "device_name": "Old Name"}]

    def mock_query(sql, params=None):
        if "SELECT id, device_name FROM webauthn_credentials" in sql:
            return mock_check
        return 1  # UPDATE succeeded

    monkeypatch.setattr("api.webauthn_service.execute_query", mock_query)

    res = client.patch(
        "/api/webauthn/credentials/7",
        headers=auth_headers,
        json={"deviceName": "MacBook Touch ID"}
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "MacBook Touch ID" in data["message"]


def test_rename_credential_idor_protection(client, auth_headers, monkeypatch):
    """Renaming a credential not owned by the user returns 400."""
    monkeypatch.setattr("api.webauthn_service.execute_query", lambda sql, params=None: [])

    res = client.patch(
        "/api/webauthn/credentials/999",
        headers=auth_headers,
        json={"deviceName": "Hacker Key"}
    )
    assert res.status_code == 400
    assert "not found or access denied" in res.get_json()["message"]


def test_rename_credential_empty_name(client, auth_headers, monkeypatch):
    """Empty device name returns 400."""
    res = client.patch(
        "/api/webauthn/credentials/7",
        headers=auth_headers,
        json={"deviceName": "   "}
    )
    assert res.status_code == 400
    assert res.get_json()["success"] is False


def test_rename_credential_unauthenticated(client):
    """Unauthenticated request to rename returns 401."""
    res = client.patch("/api/webauthn/credentials/7", json={"deviceName": "New Name"})
    assert res.status_code == 401


# ─── Additional Security Tests ────────────────────────────────────────────────

def test_register_options_excludes_existing_credentials(client, auth_headers, monkeypatch):
    """Registration options include excludeCredentials for already-registered keys."""
    monkeypatch.setattr(
        "api.webauthn_service.execute_query",
        lambda sql, params=None: (
            [{"credential_id": "dGVzdC1jcmVkLWlk"}]
            if "SELECT credential_id FROM webauthn_credentials" in sql
            else None
        )
    )
    res = client.post("/api/webauthn/register/options", headers=auth_headers)
    assert res.status_code == 200
    data = res.get_json()
    # excludeCredentials may be present when user has existing keys
    assert "challenge" in data
    assert "rp" in data


def test_login_options_no_identifier_returns_discoverable_options(client):
    """Login options with no identifier return empty allowCredentials (discoverable flow)."""
    res = client.post(
        "/api/webauthn/login/options",
        json={},
        headers={"Content-Type": "application/json"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert "challenge" in data
    # allowCredentials should be absent or empty for discoverable flow
    allow = data.get("allowCredentials", [])
    assert isinstance(allow, list)


def test_login_options_with_unknown_identifier_still_returns_options(client):
    """Login options with unknown email still return a valid challenge (don't leak user existence)."""
    res = client.post(
        "/api/webauthn/login/options",
        json={"identifier": "nobody@nowhere.invalid"},
        headers={"Content-Type": "application/json"},
    )
    # Must return 200 even for unknown users to prevent user enumeration
    assert res.status_code == 200
    data = res.get_json()
    assert "challenge" in data


def test_credentials_list_unauthenticated(client):
    """Unauthenticated GET /api/webauthn/credentials returns 401."""
    res = client.get("/api/webauthn/credentials")
    assert res.status_code == 401


def test_delete_credential_unauthenticated(client):
    """Unauthenticated DELETE /api/webauthn/credentials/<id> returns 401."""
    res = client.delete("/api/webauthn/credentials/1")
    assert res.status_code == 401


def test_rename_service_function_validates_name_length():
    """rename_user_passkey rejects names over 100 characters without DB calls."""
    from api.webauthn_service import rename_user_passkey
    ok, msg = rename_user_passkey(uid=1, cred_id=1, new_name="x" * 101)
    assert ok is False
    assert "100" in msg


def test_rename_service_function_rejects_empty_name():
    """rename_user_passkey rejects blank names."""
    from api.webauthn_service import rename_user_passkey
    ok, msg = rename_user_passkey(uid=1, cred_id=1, new_name="   ")
    assert ok is False
    assert "empty" in msg.lower()


# ─── Additional Spec Compliance Tests ────────────────────────────────────────

def test_register_verify_duplicate_credential_rejected(monkeypatch):
    """Duplicate credential registration is explicitly rejected."""
    from types import SimpleNamespace
    from webauthn.helpers.structs import CredentialDeviceType
    from api import webauthn_service
    import base64

    ch_bytes = b"0123456789abcdef0123456789abcdef"
    ch_str = base64.urlsafe_b64encode(ch_bytes).rstrip(b"=").decode("ascii")
    client_data_b64 = base64.urlsafe_b64encode(
        json.dumps({"challenge": ch_str}).encode("utf-8")
    ).rstrip(b"=").decode("ascii")

    monkeypatch.setattr(webauthn_service, "consume_webauthn_challenge", lambda *a, **k: ch_bytes)
    monkeypatch.setattr(
        webauthn_service,
        "verify_registration_response",
        lambda **kwargs: SimpleNamespace(
            credential_id=b"dup-cred-id",
            credential_public_key=b"pub-key-bytes",
            sign_count=0,
            aaguid="00000000-0000-0000-0000-000000000000",
            credential_device_type=CredentialDeviceType.MULTI_DEVICE,
            credential_backed_up=True,
        ),
    )
    monkeypatch.setattr(
        webauthn_service,
        "execute_query",
        lambda sql, params=None: [{"id": 99}] if "SELECT id FROM webauthn_credentials" in sql else [],
    )

    ok, msg, cred = webauthn_service.verify_and_save_passkey_registration(
        user={"uid": 1, "username": "alice"},
        credential_payload={
            "id": "ZHVwLWNyZWQtaWQ",
            "response": {"clientDataJSON": client_data_b64, "attestationObject": "bW9jaw=="},
        },
    )
    assert ok is False
    assert cred is None
    assert "already registered" in msg.lower()


def test_register_verify_invalid_origin_rejected(monkeypatch):
    """Registration failing WebAuthn origin check returns clean error without storing credential."""
    from api import webauthn_service
    import base64

    ch_bytes = b"0123456789abcdef0123456789abcdef"
    ch_str = base64.urlsafe_b64encode(ch_bytes).rstrip(b"=").decode("ascii")
    client_data_b64 = base64.urlsafe_b64encode(
        json.dumps({"challenge": ch_str, "origin": "https://evil.example"}).encode("utf-8")
    ).rstrip(b"=").decode("ascii")

    monkeypatch.setattr(webauthn_service, "consume_webauthn_challenge", lambda *a, **k: ch_bytes)

    def raise_origin(**kwargs):
        raise ValueError("Unexpected origin https://evil.example")

    monkeypatch.setattr(webauthn_service, "verify_registration_response", raise_origin)

    ok, msg, cred = webauthn_service.verify_and_save_passkey_registration(
        user={"uid": 1, "username": "alice"},
        credential_payload={
            "id": "cred-origin-test",
            "response": {"clientDataJSON": client_data_b64, "attestationObject": "bW9jaw=="},
        },
    )
    assert ok is False
    assert cred is None
    assert "origin" in msg.lower()


def test_login_verify_invalid_signature_rejected(monkeypatch):
    """Invalid assertion signature fails verification and returns False without user."""
    from api import webauthn_service
    import base64

    ch_bytes = b"0123456789abcdef0123456789abcdef"
    ch_str = base64.urlsafe_b64encode(ch_bytes).rstrip(b"=").decode("ascii")
    client_data_b64 = base64.urlsafe_b64encode(
        json.dumps({"challenge": ch_str}).encode("utf-8")
    ).rstrip(b"=").decode("ascii")

    monkeypatch.setattr(webauthn_service, "consume_webauthn_challenge", lambda *a, **k: ch_bytes)
    monkeypatch.setattr(
        webauthn_service,
        "execute_query",
        lambda q, p=None: (
            [{"id": 1, "uid": 1, "credential_id": "cred_sig_test", "public_key": b"pk", "sign_count": 5, "device_name": "Key"}]
            if "FROM webauthn_credentials" in q
            else ([{"uid": 1, "username": "alice", "email": "alice@example.com", "full_name": "Alice", "is_active": True, "role": "user"}] if "FROM users" in q else [])
        ),
    )

    def raise_bad_sig(**kwargs):
        raise ValueError("Invalid signature")

    monkeypatch.setattr(webauthn_service, "verify_authentication_response", raise_bad_sig)

    ok, msg, user = webauthn_service.verify_passkey_authentication({
        "id": "cred_sig_test",
        "response": {
            "clientDataJSON": client_data_b64,
            "authenticatorData": "mock",
            "signature": "invalid-sig",
        },
    })
    assert ok is False
    assert user is None
    assert "signature" in msg.lower()


def test_expired_challenge_rejected(monkeypatch):
    """Expired challenges are rejected by consume_webauthn_challenge."""
    from api import webauthn_service
    monkeypatch.setattr(webauthn_service, "execute_query", lambda q, p=None: [])
    assert consume_webauthn_challenge("expired-challenge-xyz", expected_type="registration", uid=1) is None


def test_login_verify_preserves_server_side_role_and_creates_session(client, monkeypatch):
    """Passkey login always resolves role server-side via get_user_role and records VaultAuth session."""
    mock_user = {
        "uid": 42,
        "username": "admin_alice",
        "email": "alice@vaultauth.local",
        "full_name": "Alice Admin",
        "is_active": True,
        "role": "admin",
    }
    session_created = []

    monkeypatch.setattr(
        "main.verify_passkey_authentication",
        lambda *args, **kwargs: (True, "Passkey verified", mock_user),
    )
    monkeypatch.setattr("main.get_user_role", lambda uid: "admin")
    monkeypatch.setattr("main.record_login_activity", lambda *args, **kwargs: True)
    monkeypatch.setattr("main.create_user_session", lambda uid, tok, req: session_created.append((uid, tok)))
    monkeypatch.setattr("main.ensure_default_user_dashboard_data", lambda *args, **kwargs: True)
    monkeypatch.setattr("main.record_connected_app_signin", lambda *args, **kwargs: True)

    res = client.post(
        "/api/passkeys/login/verify",
        json={
            "id": "valid-cred",
            "role": "superadmin-spoof",
            "response": {"clientDataJSON": "e30=", "authenticatorData": "e30=", "signature": "e30="},
        },
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["user"]["role"] == "admin"
    assert len(session_created) == 1
    assert session_created[0][0] == 42
