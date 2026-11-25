"""Unit tests for live admin metrics, active sessions, and connected applications tracking."""

from datetime import datetime, timezone
import pytest
from main import app
from api import admin, dashboard
from api.token import generate_token, session_token


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def admin_headers(monkeypatch):
    mock_admin = {
        "uid": 24,
        "username": "amy",
        "email": "amy492998@gmail.com",
        "full_name": "Amy Admin",
        "is_active": True,
        "role": "admin",
    }
    raw_token, _ = generate_token({"username": "amy", "uid": 24, "role": "admin"})
    token = session_token(raw_token)
    from api import auth_middleware

    monkeypatch.setattr(auth_middleware, "resolve_user_from_token", lambda tok: mock_admin if tok == token else None)
    monkeypatch.setattr("api.rbac.get_user_role", lambda uid: "admin")
    return {"Authorization": f"Bearer {token}"}, token


def test_admin_connected_apps_aggregation_live(client, admin_headers, monkeypatch):
    headers, _ = admin_headers
    sample_rows = [
        {
            "id": 10,
            "uid": 24,
            "email": "amy492998@gmail.com",
            "username": "amy",
            "app_key": "vaultauth",
            "app_name": "VaultAuth SSO",
            "app_desc": "Primary workspace",
            "logo_char": "V",
            "logo_bg": "#2563eb",
            "permissions": '["Single Sign-On"]',
            "connected_at": datetime.now(timezone.utc).replace(tzinfo=None),
            "last_used": datetime.now(timezone.utc).replace(tzinfo=None),
            "login_count": 4,
            "is_active": True,
        },
        {
            "id": 11,
            "uid": 5,
            "email": "amitoj0024@gmail.com",
            "username": "amitoj",
            "app_key": "slack",
            "app_name": "Slack",
            "app_desc": "Team messaging",
            "logo_char": "S",
            "logo_bg": "#5865F2",
            "permissions": '["Send messages"]',
            "connected_at": datetime.now(timezone.utc).replace(tzinfo=None),
            "last_used": datetime.now(timezone.utc).replace(tzinfo=None),
            "login_count": 1,
            "is_active": False,
        },
    ]
    monkeypatch.setattr(admin, "execute_query", lambda q, p=None: sample_rows)

    res = client.get("/api/admin/connected-apps", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data["summary"]["total_apps"] == 2
    assert data["summary"]["active_apps"] == 1
    assert data["summary"]["inactive_apps"] == 1
    assert data["summary"]["total_active_grants"] == 1
    assert data["summary"]["total_inactive_grants"] == 1
    vault_app = data["apps"][0]
    assert vault_app["app_key"] == "vaultauth"
    assert vault_app["total_logins"] == 4
    assert vault_app["connected_emails"] == ["amy492998@gmail.com"]


def test_admin_toggle_connected_app_endpoint(client, admin_headers, monkeypatch):
    headers, _ = admin_headers
    monkeypatch.setattr(
        admin,
        "execute_query",
        lambda q, p=None: [{"id": 11, "is_active": True}] if "SELECT" in q else [],
    )
    monkeypatch.setattr("main.record_audit_log", lambda *a, **kw: None)

    res = client.post("/api/admin/connected-apps/slack/toggle", headers=headers, json={"is_active": False})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["is_active"] is False


def test_record_connected_app_signin_updates_same_email_usage(monkeypatch):
    queries = []

    def fake_query(q, p=None):
        queries.append((q, p))
        if "SELECT id, is_active FROM connected_apps" in q:
            return [{"id": 56, "is_active": True}]
        return ()

    monkeypatch.setattr(dashboard, "execute_query", fake_query)
    dashboard.record_connected_app_signin(24, {"uid": 24, "email": "amy492998@gmail.com"})

    assert any("UPDATE connected_apps" in q and "login_count" in q for q, _ in queries)


def test_admin_sessions_active_filter_excludes_expired(monkeypatch):
    queries = []

    def fake_query(q, p=None):
        queries.append(q)
        if "COUNT(*)" in q:
            return [{"cnt": 1}]
        if "FROM active_sessions" in q:
            return [{
                "id": 91,
                "session_id": "sess_1",
                "session_token": "tok_current",
                "uid": 24,
                "username": "amy",
                "full_name": "Amy Admin",
                "email": "amy492998@gmail.com",
                "device_name": "MacBook Pro",
                "device_type": "laptop",
                "browser": "Chrome",
                "os": "macOS",
                "ip_address": "127.0.0.1",
                "location": "Bengaluru, India",
                "created_at": datetime.now(timezone.utc).replace(tzinfo=None),
                "last_activity": datetime.now(timezone.utc).replace(tzinfo=None),
                "is_active": True,
                "expires_at": None,
                "revoked_at": None,
            }]
        return ()

    monkeypatch.setattr(admin, "cleanup_expired_sessions", lambda: None)
    monkeypatch.setattr(admin, "execute_query", fake_query)

    res = admin.get_admin_all_sessions(status_filter="active", current_token="tok_current")
    assert res["total"] == 1
    assert len(res["sessions"]) == 1
    assert res["sessions"][0]["status"] == "Current"
    assert res["sessions"][0]["is_current"] is True
    assert any("expires_at > NOW()::timestamp" in q for q in queries)


def test_session_expiration_and_cleanup_align_on_utc(monkeypatch):
    inserted_exp = []
    cleanup_cutoffs = []

    def fake_exec(q, p=None):
        if "INSERT INTO active_sessions" in q and p and len(p) >= 10:
            inserted_exp.append(p[9])
        elif "UPDATE active_sessions SET is_active = FALSE" in q and p:
            cleanup_cutoffs.append(p[-1])
        return ()

    class FakeHeaders(dict):
        pass

    class FakeReq:
        headers = FakeHeaders({"User-Agent": "Chrome/158"})
        remote_addr = "127.0.0.1"

    monkeypatch.setattr(dashboard, "execute_query", fake_exec)
    raw_token, _ = generate_token({"username": "amy", "uid": 24, "role": "admin"})
    s_token = session_token(raw_token, expiration_seconds=3600)

    dashboard.create_user_session(24, s_token, FakeReq())
    dashboard.cleanup_expired_sessions(24)

    assert len(inserted_exp) == 1
    assert len(cleanup_cutoffs) == 1
    assert inserted_exp[0] > cleanup_cutoffs[0]
